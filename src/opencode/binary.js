import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);

function isFile(file) {
    try {
        return fs.statSync(file).isFile();
    } catch {
        return false;
    }
}

/**
 * `@opencode/cli` ships a shell-script stand-in at bin/opencode.exe that its
 * postinstall script replaces with the native executable. Package managers
 * that block install scripts (npm 12 does by default) leave the stand-in,
 * which only prints an error and exits.
 */
const PLACEHOLDER_MARKER = 'postinstall script was not run';
const PLACEHOLDER_MAX_BYTES = 4096;

function isPlaceholder(file) {
    try {
        if (fs.statSync(file).size > PLACEHOLDER_MAX_BYTES) return false;
        return fs.readFileSync(file, 'utf8').includes(PLACEHOLDER_MARKER);
    } catch {
        return false;
    }
}

function placeholderError(binary) {
    const postinstall = path.join(path.dirname(path.dirname(binary)), 'postinstall.mjs');
    return new Error([
        'The bundled OpenCode CLI was installed without running its postinstall script, so only a stand-in is present.',
        'npm 12 blocks dependency install scripts by default. Reinstall with `npm install -g --allow-scripts=@opencode/cli zengate`',
        `(or \`npx --allow-scripts=@opencode/cli zengate\`), or run \`node "${postinstall}"\` once.`,
    ].join(' '));
}

/** The binary shipped by the official `@opencode/cli` npm package (a dependency). */
function bundledBinary() {
    let binary;
    try {
        binary = path.join(path.dirname(require.resolve('@opencode/cli/package.json')), 'bin', 'opencode.exe');
    } catch {
        return null;
    }
    if (!isFile(binary)) return null;
    if (isPlaceholder(binary)) throw placeholderError(binary);
    return binary;
}

/** Contract tests must execute the installed dependency, with no environment/PATH fallback. */
export function resolveBundledOpencodeBinary() {
    const binary = fileURLToPath(new URL('../../node_modules/@opencode/cli/bin/opencode.exe', import.meta.url));
    if (!isFile(binary)) throw new Error('Bundled OpenCode CLI not found. Run `npm ci`; contract tests do not use OPENCODE_PATH or PATH.');
    if (isPlaceholder(binary)) throw placeholderError(binary);
    return { path: binary, source: 'bundled' };
}

function searchPath(names) {
    for (const dir of (process.env.PATH || process.env.Path || '').split(path.delimiter).filter(Boolean)) {
        for (const name of names) {
            const candidate = path.join(dir, name);
            if (isFile(candidate)) return candidate;
        }
    }
    return null;
}

/**
 * Locate the OpenCode CLI: explicit OPENCODE_PATH, otherwise the bundled
 * `@opencode/cli` package. An unrelated `opencode` on PATH is never picked up
 * on its own: the gateway's tool safety depends on the exact release it runs.
 * @param {string} configured OPENCODE_PATH ('' for automatic)
 * @returns {{ path: string, source: 'config'|'bundled'|'PATH' }}
 */
export function resolveOpencodeBinary(configured) {
    const windowsNames = ['opencode.exe', 'opencode.cmd', 'opencode.bat', 'opencode'];
    if (configured) {
        const looksLikePath = configured.includes('/') || configured.includes('\\');
        if (looksLikePath) {
            const full = path.resolve(configured);
            if (isFile(full)) return { path: full, source: 'config' };
            throw new Error(`OPENCODE_PATH does not point to a file: ${full}`);
        }
        const names = process.platform === 'win32' ? windowsNames.map((n) => n.replace('opencode', configured)) : [configured];
        const found = searchPath(names);
        if (found) return { path: found, source: 'config' };
        throw new Error(`OPENCODE_PATH '${configured}' was not found on PATH`);
    }
    const bundled = bundledBinary();
    if (bundled) return { path: bundled, source: 'bundled' };
    throw new Error('The bundled OpenCode CLI (@opencode/cli) is not installed. Reinstall zengate, or run `npm ci` in a source checkout.');
}

/**
 * Build spawn arguments. Windows .cmd/.bat shims need cmd.exe; the command
 * line is fully quoted and every argument is gateway-controlled.
 */
export function spawnCommand(binary, args) {
    const lower = binary.toLowerCase();
    if (process.platform === 'win32' && (lower.endsWith('.cmd') || lower.endsWith('.bat'))) {
        if (/["\r\n%]/.test(binary)) throw new Error('OPENCODE_PATH contains characters that cannot be run safely');
        const line = [`"${binary}"`, ...args.map((arg) => `"${arg}"`)].join(' ');
        return { command: process.env.ComSpec || 'cmd.exe', args: ['/d', '/s', '/c', `"${line}"`], windowsVerbatimArguments: true };
    }
    return { command: binary, args, windowsVerbatimArguments: false };
}
