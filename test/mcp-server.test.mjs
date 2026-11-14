import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SERVER_INSTRUCTIONS, composeInput, createMcpServer, outputText, readFiles } from '../src/mcp/server.js';
import { KEY, startStack } from './helpers/gateway.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zengate-mcp-test-'));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));
const MCP_ENTRY = fileURLToPath(new URL('../mcp.js', import.meta.url));

const call = (server, name, args, id = 1) => server.handle({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

describe('MCP helpers', () => {
    it('reads text files within the limits and refuses the rest', () => {
        const text = path.join(tmp, 'notes.md');
        fs.writeFileSync(text, '# notes\nhello');
        assert.deepEqual(readFiles([text]), [{ file: text, text: '# notes\nhello' }]);
        assert.deepEqual(readFiles(undefined), []);
        const binary = path.join(tmp, 'blob.bin');
        fs.writeFileSync(binary, Buffer.from([1, 0, 2]));
        assert.throws(() => readFiles([binary]), /looks binary/);
        assert.throws(() => readFiles(['relative.txt']), /absolute path/);
        assert.throws(() => readFiles([path.join(tmp, 'missing')]), /ENOENT/);
        assert.throws(() => readFiles([tmp]), /not a regular file/);
        assert.throws(() => readFiles('nope'), /list of paths/);
        const big = path.join(tmp, 'big.txt');
        fs.writeFileSync(big, 'x'.repeat(256 * 1024 + 1));
        assert.throws(() => readFiles([big]), /over the 256 KiB limit/);
        const part = path.join(tmp, 'part.txt');
        fs.writeFileSync(part, 'y'.repeat(250 * 1024));
        assert.throws(() => readFiles([part, part, part, part, part]), /more than 1024 KiB/);
    });

    it('puts files ahead of the prompt and extracts the answer text', () => {
        assert.equal(composeInput('Summarise.', [{ file: '/a "b".txt', text: 'body' }]), '<file path="/a &quot;b&quot;.txt">\nbody\n</file>\n\nSummarise.');
        assert.equal(outputText({ output: [{ type: 'reasoning' }, { type: 'message', content: [{ type: 'output_text', text: 'Hi' }, { type: 'output_text', text: '!' }] }] }), 'Hi!');
        assert.equal(outputText({}), '');
    });
});

describe('MCP protocol', () => {
    const server = createMcpServer({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k', fetchImpl: async () => { throw Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); } });

    it('negotiates the protocol and lists its tools', async () => {
        const init = await server.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
        assert.equal(init.result.protocolVersion, '2025-03-26');
        assert.equal(init.result.instructions, SERVER_INSTRUCTIONS);
        assert.deepEqual(init.result.capabilities, { tools: {} });
        const unknown = await server.handle({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '1999-01-01' } });
        assert.equal(unknown.result.protocolVersion, '2025-06-18');
        assert.equal(await server.handle({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
        const list = await server.handle({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
        assert.deepEqual(list.result.tools.map((tool) => tool.name), ['zen_ask', 'zen_models']);
        assert.deepEqual((await server.handle({ jsonrpc: '2.0', id: 4, method: 'ping' })).result, {});
        assert.equal((await server.handle({ jsonrpc: '2.0', id: 5, method: 'nope' })).error.code, -32601);
        assert.equal((await call(server, 'nope', {})).error.code, -32602);
    });

    it('reports an unreachable gateway and bad arguments as tool errors', async () => {
        const down = await call(server, 'zen_models', {});
        assert.equal(down.result.isError, true);
        assert.match(down.result.content[0].text, /not reachable at http:\/\/127\.0\.0\.1:1 \(ECONNREFUSED\)/);
        const empty = await call(server, 'zen_ask', { prompt: '  ' });
        assert.match(empty.result.content[0].text, /prompt is required/);
    });
});

describe('MCP tools against the gateway (fake OpenCode backend)', () => {
    let stack;
    let server;
    before(async () => {
        stack = await startStack();
        server = createMcpServer({ baseUrl: stack.base, apiKey: KEY });
    });
    after(async () => { await stack.stop(); });

    it('lists models and answers in a fresh context that can be continued', async () => {
        const models = await call(server, 'zen_models', {});
        assert.equal(models.result.isError, false);
        assert.ok(models.result.structuredContent.models.includes('big-pickle'));

        const file = path.join(tmp, 'input.txt');
        fs.writeFileSync(file, 'the file body');
        const first = await call(server, 'zen_ask', { prompt: 'Summarise it.', files: [file], system: 'Be brief' });
        assert.equal(first.result.isError, false, first.result.content[0].text);
        const { answer, context_id: contextId, model } = first.result.structuredContent;
        assert.equal(model, 'big-pickle', 'the preferred model is picked when none is named');
        assert.match(answer, /^Echo: /);
        assert.ok(answer.includes('the file body') && answer.includes('Summarise it.'), answer);
        assert.match(contextId, /^resp_/);
        assert.ok(first.result.content[0].text.endsWith(`[zengate: model big-pickle, context_id ${contextId}]`));
        const sent = stack.fake.state.prompts.at(-1).body;
        assert.match(sent.system, /Be brief$/);

        const next = await call(server, 'zen_ask', { prompt: 'And again?', context_id: contextId });
        assert.equal(next.result.isError, false, next.result.content[0].text);
        assert.notEqual(next.result.structuredContent.context_id, contextId);
        assert.match(next.result.structuredContent.answer, /And again\?/);
    });

    it('passes gateway errors through', async () => {
        const missing = await call(server, 'zen_ask', { prompt: 'x', context_id: 'resp_missing' });
        assert.equal(missing.result.isError, true);
        assert.match(missing.result.content[0].text, /HTTP 400 \(previous_response_not_found\)/);
        const badKey = createMcpServer({ baseUrl: stack.base, apiKey: 'wrong-key-0123456789' });
        assert.match((await call(badKey, 'zen_models', {})).result.content[0].text, /HTTP 401 \(invalid_api_key\)/);
    });

    it('serves newline-delimited JSON-RPC over stdio from mcp.js', { timeout: 20000 }, async () => {
        const proc = spawn(process.execPath, [MCP_ENTRY], {
            env: { ...process.env, ZENGATE_URL: stack.base, ZENGATE_API_KEY: KEY, CONFIG_FILE: path.join(tmp, 'none.json') },
            stdio: ['pipe', 'pipe', 'pipe'],
        });
        const replies = [];
        let buffer = '';
        proc.stdout.on('data', (chunk) => {
            buffer += chunk;
            const lines = buffer.split('\n');
            buffer = lines.pop();
            replies.push(...lines.filter(Boolean).map((line) => JSON.parse(line)));
        });
        const send = (message) => proc.stdin.write(`${JSON.stringify(message)}\n`);
        send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
        send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        proc.stdin.write('not json\n');
        send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'zen_ask', arguments: { prompt: 'over stdio' } } });
        const deadline = Date.now() + 15000;
        while (replies.length < 3 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
        proc.stdin.end();
        await new Promise((resolve) => proc.once('exit', resolve));
        assert.equal(replies.find((reply) => reply.id === 1)?.result.serverInfo.name, 'zengate');
        assert.equal(replies.find((reply) => reply.id === null)?.error.code, -32700);
        assert.match(replies.find((reply) => reply.id === 2)?.result.structuredContent.answer, /over stdio/);
    });

    it('refuses to start without an API key', async () => {
        const proc = spawn(process.execPath, [MCP_ENTRY], {
            env: { ...process.env, ZENGATE_API_KEY: '', CONFIG_FILE: path.join(tmp, 'none.json') },
            stdio: ['pipe', 'ignore', 'pipe'],
        });
        let stderr = '';
        proc.stderr.on('data', (chunk) => { stderr += chunk; });
        const code = await new Promise((resolve) => proc.once('exit', resolve));
        assert.equal(code, 1);
        assert.match(stderr, /no API key/);
    });
});
