import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Operating-system sandbox for the managed backend (Linux, bubblewrap).
 *
 * Tool rejection keeps OpenCode's host tools from running, but the backend
 * itself runs as the gateway's user. Under bubblewrap it sees only the system
 * directories it needs to run (read-only), its own scratch tree and a private
 * /tmp: not the user's home, other users' files, /run (agent and container
 * sockets) or the host /tmp. It keeps the network, which it needs for Zen.
 * Inside, the scratch tree always has the same path, so prompts never carry
 * a random host directory, and the hostname is fixed too.
 */
export const SANDBOX_MODES = Object.freeze(['auto', 'bwrap', 'off']);

export const INNER_ROOT = '/zengate';
const INNER_BIN = '/zengate-bin';
const HOSTNAME = 'zengate';
const PROBE_TIMEOUT_MS = 15000;

/** Top-level system directories mounted read-only (or recreated as the same symlink). */
const SYSTEM_DIRS = ['/usr', '/bin', '/sbin', '/lib', '/lib32', '/lib64', '/libx32'];
/** /etc entries needed for name resolution, TLS and time zones. Missing ones are skipped. */
const ETC_ENTRIES = [
    'resolv.conf', 'hosts', 'host.conf', 'nsswitch.conf', 'gai.conf', 'localtime',
    'ssl', 'ca-certificates', 'pki', 'crypto-policies', 'ca-certificates.conf',
];
/** Host variables that name CA files: mounted read-only so they still work inside. */
const CA_ENV = ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR'];

/** The scratch directories as the sandboxed backend sees them. */
export function innerDirs(dirs) {
    const inner = { root: INNER_ROOT };
    for (const name of Object.keys(dirs)) {
        if (name !== 'root') inner[name] = path.posix.join(INNER_ROOT, path.relative(dirs.root, dirs[name]).split(path.sep).join('/'));
    }
    return inner;
}

/** Where the backend binary appears inside the sandbox. */
export const innerBinary = (binary) => path.posix.join(INNER_BIN, path.basename(binary));

function systemMounts() {
    const args = [];
    for (const dir of SYSTEM_DIRS) {
        let stat;
        try {
            stat = fs.lstatSync(dir);
        } catch {
            continue;
        }
        if (stat.isSymbolicLink()) args.push('--symlink', fs.readlinkSync(dir), dir);
        else if (stat.isDirectory()) args.push('--ro-bind', dir, dir);
    }
    for (const entry of ETC_ENTRIES) args.push('--ro-bind-try', `/etc/${entry}`, `/etc/${entry}`);
    return args;
}

function caMounts(env) {
    const args = [];
    for (const key of CA_ENV) {
        const file = env[key];
        if (file && path.isAbsolute(file)) args.push('--ro-bind-try', file, file);
    }
    return args;
}

/**
 * bubblewrap arguments that run `binary` with `args` inside the sandbox.
 * @param {{ dirs: { root: string }, binary: string, args: string[], env: Record<string, string> }} options
 *        `dirs` are the host paths of the scratch tree, `env` the backend environment
 */
export function bwrapArgs({ dirs, binary, args, env = {} }) {
    const inner = innerDirs(dirs);
    return [
        '--unshare-all', '--share-net', '--hostname', HOSTNAME,
        '--die-with-parent', '--new-session',
        ...systemMounts(),
        ...caMounts(env),
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--ro-bind', path.dirname(binary), INNER_BIN,
        '--bind', dirs.root, INNER_ROOT,
        '--chdir', inner.workspace ?? INNER_ROOT,
        '--setenv', 'TMPDIR', '/tmp', '--setenv', 'TMP', '/tmp', '--setenv', 'TEMP', '/tmp',
        '--',
        innerBinary(binary), ...args,
    ];
}

/** The bubblewrap executable on PATH, or null. */
export function findBwrap(env = process.env) {
    for (const dir of (env.PATH || '').split(path.delimiter).filter(Boolean)) {
        const candidate = path.join(dir, 'bwrap');
        try {
            if (fs.statSync(candidate).isFile()) return candidate;
        } catch {
            // not here
        }
    }
    return null;
}

/**
 * Run `binary --version` inside the sandbox to prove it works here: user
 * namespaces can be disabled, or blocked by AppArmor, seccomp (Docker) or
 * systemd's RestrictNamespaces.
 * @returns {Promise<{ ok: true } | { ok: false, reason: string }>}
 */
export function probeSandbox({ bwrap, dirs, binary, env }) {
    return new Promise((resolve) => {
        let output = '';
        let settled = false;
        const finish = (result) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve(result);
        };
        const proc = spawn(bwrap, bwrapArgs({ dirs, binary, args: ['--version'], env }), { env, stdio: ['ignore', 'pipe', 'pipe'] });
        const collect = (chunk) => { output = `${output}${chunk}`.slice(-2000); };
        proc.stdout.on('data', collect);
        proc.stderr.on('data', collect);
        const timer = setTimeout(() => {
            proc.kill('SIGKILL');
            finish({ ok: false, reason: `bubblewrap did not finish within ${PROBE_TIMEOUT_MS / 1000}s` });
        }, PROBE_TIMEOUT_MS);
        proc.once('error', (error) => finish({ ok: false, reason: error.message }));
        proc.once('exit', (code, signal) => {
            if (code === 0) finish({ ok: true });
            else finish({ ok: false, reason: output.trim().split('\n').pop() || `exit ${signal || code}` });
        });
    });
}

/**
 * Decide how the backend runs, once per gateway. In `auto` mode a missing
 * or unusable bubblewrap falls back to running unsandboxed with a warning;
 * `bwrap` makes it fatal.
 * @returns {Promise<{ bwrap: string } | null>} the sandbox to use, or null
 */
export async function resolveSandbox({ mode, dirs, binary, env, logger, platform = process.platform, find = findBwrap, probe = probeSandbox }) {
    if (mode === 'off') {
        logger.debug('BACKEND_SANDBOX=off: the OpenCode backend runs without an OS sandbox');
        return null;
    }
    if (platform !== 'linux') {
        if (mode === 'bwrap') throw new Error('BACKEND_SANDBOX=bwrap is only available on Linux');
        logger.info('No OS sandbox for the OpenCode backend on this platform; host tools are kept from running by permission rejection only');
        return null;
    }
    const bwrap = find();
    const result = bwrap ? await probe({ bwrap, dirs, binary, env }) : { ok: false, reason: 'bwrap was not found on PATH (install the bubblewrap package)' };
    if (result.ok) {
        logger.debug('OpenCode backend sandboxed with bubblewrap', { bwrap });
        return { bwrap };
    }
    if (mode === 'bwrap') throw new Error(`BACKEND_SANDBOX=bwrap, but bubblewrap cannot run the backend: ${result.reason}`);
    logger.warn(`The OpenCode backend runs without an OS sandbox: ${result.reason}. Host tools are still rejected; set BACKEND_SANDBOX=off to silence this or BACKEND_SANDBOX=bwrap to require the sandbox.`);
    return null;
}
