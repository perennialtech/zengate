import fs from 'node:fs';
import path from 'node:path';

/**
 * A Model Context Protocol server (stdio) that lets an agent such as Claude
 * Code hand self-contained work to the gateway's models. Each `zen_ask`
 * call starts a fresh context, or continues one through the Responses API's
 * previous_response_id. Files named in the call are read here and sent to
 * the model, so their contents never pass through the calling agent.
 */

const SUPPORTED_PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const REQUEST_TIMEOUT_MS = 330000;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_FILE_BYTES = 1024 * 1024;
const PREFERRED_MODELS = ['big-pickle'];

export const SERVER_INSTRUCTIONS = [
    'zengate runs free OpenCode Zen models behind an OpenAI-compatible gateway on this machine.',
    'Use zen_ask to hand a self-contained subtask to one of them in a fresh context: summarising or searching large files',
    '(pass their paths in `files` so their contents never enter your own context), drafting, brainstorming, or a second opinion.',
    'Its answers can be wrong; check anything you act on. Pass the returned context_id to continue the same conversation',
    '(contexts expire after an hour or when the gateway restarts).',
    'Everything you send, including file contents, goes to OpenCode Zen; free models may log or train on it, so never send',
    'secrets, credentials or private data.',
].join(' ');

const TOOLS = [
    {
        name: 'zen_ask',
        description: 'Ask a free OpenCode Zen model to do a self-contained task in its own context and return its answer. '
            + 'Content sent here leaves the machine (OpenCode Zen); never include secrets.',
        inputSchema: {
            type: 'object',
            properties: {
                prompt: { type: 'string', description: 'The task or question, complete on its own: the model sees nothing else of your conversation.' },
                files: {
                    type: 'array',
                    items: { type: 'string' },
                    description: `Absolute paths of text files to include, read by this server (up to ${MAX_FILE_BYTES / 1024} KiB each, ${MAX_TOTAL_FILE_BYTES / 1024} KiB in all).`,
                },
                system: { type: 'string', description: 'Optional instructions for how the model should work or answer.' },
                model: { type: 'string', description: 'Model id from zen_models. Defaults to the configured or first available model.' },
                context_id: { type: 'string', description: 'context_id from an earlier zen_ask, to continue that conversation.' },
                max_output_tokens: { type: 'integer', minimum: 1, description: 'Approximate cap on the answer length.' },
            },
            required: ['prompt'],
            additionalProperties: false,
        },
    },
    {
        name: 'zen_models',
        description: 'List the models the zengate gateway can run right now.',
        inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    },
];

class ToolError extends Error {}

/** Read the files named in a call as text, within the size limits. */
export function readFiles(files, { read = fs.readFileSync, stat = fs.statSync } = {}) {
    if (files === undefined) return [];
    if (!Array.isArray(files) || files.some((file) => typeof file !== 'string' || !file)) throw new ToolError('files must be a list of paths.');
    let total = 0;
    return files.map((file) => {
        if (!path.isAbsolute(file)) throw new ToolError(`${file}: use an absolute path.`);
        let info;
        try {
            info = stat(file);
        } catch (error) {
            throw new ToolError(`${file}: ${error.code || error.message}`);
        }
        if (!info.isFile()) throw new ToolError(`${file}: not a regular file.`);
        if (info.size > MAX_FILE_BYTES) throw new ToolError(`${file}: ${info.size} bytes is over the ${MAX_FILE_BYTES / 1024} KiB limit per file.`);
        total += info.size;
        if (total > MAX_TOTAL_FILE_BYTES) throw new ToolError(`The files add up to more than ${MAX_TOTAL_FILE_BYTES / 1024} KiB.`);
        const bytes = read(file);
        if (bytes.includes(0)) throw new ToolError(`${file}: looks binary; only text files can be included.`);
        return { file, text: bytes.toString('utf8') };
    });
}

/** The prompt with each file in its own tagged block. */
export function composeInput(prompt, files) {
    const blocks = files.map(({ file, text }) => `<file path="${file.replaceAll('"', '&quot;')}">\n${text}\n</file>`);
    return [...blocks, prompt].join('\n\n');
}

/** The assistant text of a Responses API response. */
export function outputText(response) {
    return (response?.output || [])
        .filter((item) => item?.type === 'message')
        .flatMap((item) => item.content || [])
        .filter((part) => part?.type === 'output_text')
        .map((part) => part.text)
        .join('');
}

/**
 * @param {{ baseUrl: string, apiKey: string, defaultModel?: string, fetchImpl?: typeof fetch,
 *           read?: Function, stat?: Function }} options
 */
export function createMcpServer({ baseUrl, apiKey, defaultModel = '', fetchImpl = fetch, read, stat }) {
    const base = String(baseUrl).replace(/\/+$/, '');

    async function call(method, route, body) {
        let response;
        try {
            response = await fetchImpl(`${base}/v1${route}`, {
                method,
                headers: { authorization: `Bearer ${apiKey}`, ...(body ? { 'content-type': 'application/json' } : {}) },
                body: body ? JSON.stringify(body) : undefined,
                signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
            });
        } catch (error) {
            throw new ToolError(`zengate is not reachable at ${base} (${error.cause?.code || error.message}). Is the service running?`);
        }
        const payload = await response.json().catch(() => null);
        if (!response.ok) {
            const error = payload?.error;
            const retry = error?.retry_after ? ` Retry after ${error.retry_after}s.` : '';
            throw new ToolError(`zengate answered HTTP ${response.status}${error?.code ? ` (${error.code})` : ''}: ${error?.message || 'no details'}${retry}`);
        }
        return payload;
    }

    async function models() {
        return ((await call('GET', '/models'))?.data || []).map((model) => model.id);
    }

    async function pickModel(requested) {
        if (requested) return requested;
        if (defaultModel) return defaultModel;
        const available = await models();
        const model = PREFERRED_MODELS.find((id) => available.includes(id)) || available[0];
        if (!model) throw new ToolError('zengate lists no models right now.');
        return model;
    }

    const tools = {
        async zen_models() {
            const ids = await models();
            return { text: ids.length ? ids.join('\n') : '(no models)', structured: { models: ids } };
        },
        async zen_ask(args) {
            if (typeof args.prompt !== 'string' || !args.prompt.trim()) throw new ToolError('prompt is required.');
            const files = readFiles(args.files, { ...(read ? { read } : {}), ...(stat ? { stat } : {}) });
            const model = await pickModel(args.model);
            const response = await call('POST', '/responses', {
                model,
                input: composeInput(args.prompt, files),
                ...(args.system ? { instructions: args.system } : {}),
                ...(args.context_id ? { previous_response_id: args.context_id } : {}),
                ...(args.max_output_tokens ? { max_output_tokens: args.max_output_tokens } : {}),
                store: true,
            });
            const answer = outputText(response);
            const structured = {
                answer,
                context_id: response.id,
                model: response.model || model,
                status: response.status,
                usage: response.usage ?? null,
            };
            const cut = response.status === 'incomplete' ? ' (cut at max_output_tokens)' : '';
            return { text: `${answer || '(empty answer)'}\n\n[zengate: model ${structured.model}, context_id ${response.id}${cut}]`, structured };
        },
    };

    const result = (id, value) => ({ jsonrpc: '2.0', id, result: value });
    const failure = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

    /** Handle one JSON-RPC message; returns the reply, or null for notifications. */
    async function handle(message) {
        const { id, method, params } = message || {};
        const isRequest = id !== undefined && id !== null;
        if (typeof method !== 'string') return isRequest ? failure(id, -32600, 'Invalid request') : null;
        if (!isRequest) return null;
        switch (method) {
            case 'initialize': {
                const requested = params?.protocolVersion;
                return result(id, {
                    protocolVersion: SUPPORTED_PROTOCOLS.includes(requested) ? requested : SUPPORTED_PROTOCOLS[0],
                    capabilities: { tools: {} },
                    serverInfo: { name: 'zengate', version: '1' },
                    instructions: SERVER_INSTRUCTIONS,
                });
            }
            case 'ping':
                return result(id, {});
            case 'tools/list':
                return result(id, { tools: TOOLS });
            case 'tools/call': {
                const tool = tools[params?.name];
                if (!tool) return failure(id, -32602, `Unknown tool: ${params?.name}`);
                try {
                    const { text, structured } = await tool(params.arguments || {});
                    return result(id, { content: [{ type: 'text', text }], structuredContent: structured, isError: false });
                } catch (error) {
                    if (!(error instanceof ToolError)) throw error;
                    return result(id, { content: [{ type: 'text', text: error.message }], isError: true });
                }
            }
            default:
                return failure(id, -32601, `Method not found: ${method}`);
        }
    }

    return Object.freeze({ handle });
}

/** Serve newline-delimited JSON-RPC on stdin/stdout until stdin closes. */
export function serveStdio(server, { input = process.stdin, output = process.stdout, log = (line) => process.stderr.write(`${line}\n`) } = {}) {
    let buffer = '';
    const write = (reply) => { if (reply) output.write(`${JSON.stringify(reply)}\n`); };
    input.setEncoding('utf8');
    input.on('data', (chunk) => {
        buffer += chunk;
        let newline;
        while ((newline = buffer.indexOf('\n')) !== -1) {
            const line = buffer.slice(0, newline).trim();
            buffer = buffer.slice(newline + 1);
            if (!line) continue;
            let message;
            try {
                message = JSON.parse(line);
            } catch {
                write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
                continue;
            }
            server.handle(message).then(write, (error) => {
                log(`zengate-mcp: ${error.stack || error.message}`);
                if (message?.id !== undefined && message?.id !== null) write({ jsonrpc: '2.0', id: message.id, error: { code: -32603, message: 'Internal error' } });
            });
        }
    });
    return new Promise((resolve) => input.once('end', resolve));
}
