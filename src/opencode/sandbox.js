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
 *
 * Sharing the network namespace also shares the host's abstract Unix
 * sockets (X11 displays, some D-Bus buses), so a seccomp filter refuses to
 * create Unix-domain sockets inside. Loopback TCP services stay reachable.
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
    'hosts', 'host.conf', 'nsswitch.conf', 'gai.conf', 'localtime',
    'ssl', 'ca-certificates', 'pki', 'crypto-policies', 'ca-certificates.conf',
];
const RESOLV_CONF = '/etc/resolv.conf';
/** The fd bubblewrap reads the seccomp program from (the child's fourth stdio slot). */
const SECCOMP_FD = 3;
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

/** Where the backend binary appears inside the sandbox (a directory only it is mounted into). */
export const innerBinary = (binary) => path.posix.join(INNER_BIN, path.basename(binary));

/**
 * resolv.conf as a live view. A bind mount of a single file pins its inode,
 * and resolvers (NetworkManager, systemd-resolved) replace the file on every
 * network change, so a symlink into /run is recreated with its target's
 * directory mounted instead. A plain file is still bound as a file;
 * `resolvConfPinned()` says when that happens so the caller can restart the
 * backend after a change.
 */
function resolvMounts() {
    let stat;
    try {
        stat = fs.lstatSync(RESOLV_CONF);
    } catch {
        return [];
    }
    if (!stat.isSymbolicLink()) return ['--ro-bind-try', RESOLV_CONF, RESOLV_CONF];
    let target;
    try {
        target = fs.realpathSync(RESOLV_CONF);
    } catch {
        return [];
    }
    if (!target.startsWith('/run/')) return ['--ro-bind-try', RESOLV_CONF, RESOLV_CONF];
    return ['--ro-bind', path.dirname(target), path.dirname(target), '--symlink', fs.readlinkSync(RESOLV_CONF), RESOLV_CONF];
}

/** Whether the sandbox sees a copy of resolv.conf that will not follow host changes. */
export function resolvConfPinned(file = RESOLV_CONF) {
    try {
        return !fs.lstatSync(file).isSymbolicLink() || !fs.realpathSync(file).startsWith('/run/');
    } catch {
        return false;
    }
}

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
    return [...args, ...resolvMounts()];
}

function caMounts(env) {
    const args = [];
    for (const key of CA_ENV) {
        const file = env[key];
        if (file && path.isAbsolute(file)) args.push('--ro-bind-try', file, file);
    }
    return args;
}

// Classic BPF for seccomp (struct sock_filter: u16 code, u8 jt, u8 jf, u32 k).
const LD_W_ABS = 0x20;
const JEQ_K = 0x15;
const JGE_K = 0x35;
const RET_K = 0x06;
const RET_ALLOW = 0x7fff0000;
const RET_ERRNO = 0x00050000;
const ENOSYS = 38;
const EAFNOSUPPORT = 97;
const AF_UNIX = 1;
const X32_SYSCALL_BIT = 0x40000000;
/** seccomp_data offsets: nr, arch, then args[0] (its low 32 bits on little-endian hosts). */
const DATA_NR = 0;
const DATA_ARCH = 4;
const DATA_ARG0 = 16;
const ARCHES = Object.freeze({
    x64: { audit: 0xc000003e, socket: 41, x32: true },
    arm64: { audit: 0xc00000b7, socket: 198, x32: false },
});

/**
 * The seccomp program for `arch` (a process.arch value), or null where none
 * is defined. It refuses socket(AF_UNIX, ...) with EAFNOSUPPORT, and every
 * system call made through another ABI (32-bit or x32 entry points, which
 * would bypass a filter written for native numbers) with ENOSYS.
 */
export function seccompProgram(arch = process.arch) {
    const spec = ARCHES[arch];
    if (!spec) return null;
    const ops = [
        [LD_W_ABS, 0, 0, DATA_ARCH],
        [JEQ_K, 1, 0, spec.audit],
        [RET_K, 0, 0, RET_ERRNO | ENOSYS],
        [LD_W_ABS, 0, 0, DATA_NR],
        ...(spec.x32 ? [[JGE_K, 0, 1, X32_SYSCALL_BIT], [RET_K, 0, 0, RET_ERRNO | ENOSYS]] : []),
        [JEQ_K, 0, 3, spec.socket],
        [LD_W_ABS, 0, 0, DATA_ARG0],
        [JEQ_K, 0, 1, AF_UNIX],
        [RET_K, 0, 0, RET_ERRNO | EAFNOSUPPORT],
        [RET_K, 0, 0, RET_ALLOW],
    ];
    const program = Buffer.alloc(ops.length * 8);
    ops.forEach(([code, jt, jf, k], index) => {
        program.writeUInt16LE(code, index * 8);
        program.writeUInt8(jt, index * 8 + 2);
        program.writeUInt8(jf, index * 8 + 3);
        program.writeUInt32LE(k >>> 0, index * 8 + 4);
    });
    return program;
}

/**
 * Write the seccomp program into the scratch tree and open it for the
 * child's fd 3. Returns the stdio entry, or null without a program.
 */
export function openSeccomp(dirs, arch = process.arch) {
    const program = seccompProgram(arch);
    if (!program) return null;
    const file = path.join(dirs.root, 'seccomp.bpf');
    fs.writeFileSync(file, program, { mode: 0o600 });
    return fs.openSync(file, 'r');
}

/**
 * bubblewrap arguments that run `binary` with `args` inside the sandbox.
 * @param {{ dirs: { root: string }, binary: string, args: string[], env: Record<string, string> }} options
 *        `dirs` are the host paths of the scratch tree, `env` the backend environment
 */
export function bwrapArgs({ dirs, binary, args, env = {}, seccomp = false }) {
    const inner = innerDirs(dirs);
    return [
        ...(seccomp ? ['--seccomp', String(SECCOMP_FD)] : []),
        '--unshare-all', '--share-net', '--hostname', HOSTNAME,
        '--die-with-parent', '--new-session',
        ...systemMounts(),
        ...caMounts(env),
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        // Only the file: the directory holding a custom OPENCODE_PATH may hold anything.
        '--ro-bind', binary, innerBinary(binary),
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
export function spawnSandboxed({ bwrap, dirs, binary, args, env, ...options }) {
    const seccomp = openSeccomp(dirs);
    try {
        return spawn(bwrap, bwrapArgs({ dirs, binary, args, env, seccomp: seccomp !== null }), {
            ...options,
            env,
            stdio: ['ignore', 'pipe', 'pipe', ...(seccomp !== null ? [seccomp] : [])],
        });
    } finally {
        if (seccomp !== null) fs.closeSync(seccomp);
    }
}

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
        const proc = spawnSandboxed({ bwrap, dirs, binary, args: ['--version'], env });
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
