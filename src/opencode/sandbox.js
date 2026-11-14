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
 * sockets (X11 displays, some D-Bus buses), so a seccomp filter
 * (seccompProgram) keeps Unix-domain sockets that could reach them from
 * being created inside. Loopback TCP services stay reachable.
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
 * Resolver directories under /run that hold only resolv.conf variants, so
 * mounting one exposes nothing else. A bind mount of a single file pins its
 * inode, and resolvers replace the file on every network change, so a
 * resolv.conf that resolves into one of these is recreated as a symlink to
 * its real target with that directory mounted. Anything else (a plain file,
 * NetworkManager's /run/NetworkManager, which also holds device state and
 * connection names) is bound as a file; `resolvConfPinned()` says so, and the
 * caller restarts the backend when the file changes.
 */
const LIVE_RESOLVER_DIRS = ['/run/systemd/resolve', '/run/resolvconf'];

/** The real resolv.conf when it lives in a resolver directory that can be mounted whole, or null. */
function liveResolvTarget(file = RESOLV_CONF) {
    try {
        if (!fs.lstatSync(file).isSymbolicLink()) return null;
        const target = fs.realpathSync(file);
        return LIVE_RESOLVER_DIRS.includes(path.dirname(target)) ? target : null;
    } catch {
        return null;
    }
}

function resolvMounts() {
    const target = liveResolvTarget();
    if (!target) return ['--ro-bind-try', RESOLV_CONF, RESOLV_CONF];
    return ['--ro-bind', path.dirname(target), path.dirname(target), '--symlink', target, RESOLV_CONF];
}

/** Whether the sandbox sees a copy of resolv.conf that will not follow host changes. */
export function resolvConfPinned(file = RESOLV_CONF) {
    return fs.existsSync(file) && !liveResolvTarget(file);
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
const AND_K = 0x54;
const JEQ_K = 0x15;
const JGE_K = 0x35;
const RET_K = 0x06;
const RET_ALLOW = 0x7fff0000;
const RET_ERRNO = 0x00050000;
const ENOSYS = 38;
const EAFNOSUPPORT = 97;
/** The socket families the backend needs: IPv4, IPv6, and netlink (interface lookups). */
const ALLOWED_FAMILIES = [2, 10, 16];
const SOCK_TYPE_MASK = 0xf;
const SOCK_DGRAM = 2;
/** io_uring_setup, io_uring_enter, io_uring_register (the same on x86_64 and arm64). */
const IO_URING_FIRST = 425;
const IO_URING_END = 428;
const X32_SYSCALL_BIT = 0x40000000;
/** seccomp_data offsets: nr, arch, then the low 32 bits of args[0] and args[1] (little-endian hosts). */
const DATA_NR = 0;
const DATA_ARCH = 4;
const DATA_ARG0 = 16;
const DATA_ARG1 = 24;
const ARCHES = Object.freeze({
    x64: { audit: 0xc000003e, socket: 41, socketpair: 53, x32: true },
    arm64: { audit: 0xc00000b7, socket: 198, socketpair: 199, x32: false },
});

/**
 * Assemble instructions whose jump targets are labels. Each entry is
 * [code, k], [code, k, jt, jf] with label names, or a string marking a label.
 */
function assemble(source) {
    const labels = new Map();
    const ops = [];
    for (const item of source) {
        if (typeof item === 'string') labels.set(item, ops.length);
        else ops.push(item);
    }
    const program = Buffer.alloc(ops.length * 8);
    ops.forEach(([code, k, jt, jf], index) => {
        const offset = (label) => {
            if (label === undefined) return 0;
            const target = labels.get(label);
            if (target === undefined || target <= index || target - index - 1 > 255) throw new Error(`bad BPF jump to ${label}`);
            return target - index - 1;
        };
        program.writeUInt16LE(code, index * 8);
        program.writeUInt8(offset(jt), index * 8 + 2);
        program.writeUInt8(offset(jf), index * 8 + 3);
        program.writeUInt32LE(k >>> 0, index * 8 + 4);
    });
    return program;
}

/**
 * The seccomp program for `arch` (a process.arch value), or null where none
 * is defined. With the network namespace shared, it is what keeps the host's
 * abstract Unix sockets out of reach:
 * - socket() only for IPv4, IPv6 and netlink (EAFNOSUPPORT otherwise);
 * - no datagram socketpair(), which could sendto() an abstract address
 *   (stream pairs, which Bun uses for subprocesses, cannot be re-addressed);
 * - no io_uring, whose IORING_OP_SOCKET creates sockets without socket();
 * - nothing through another ABI (32-bit or x32 entry points use other
 *   numbers and would slip past the checks above) - all ENOSYS.
 */
export function seccompProgram(arch = process.arch) {
    const spec = ARCHES[arch];
    if (!spec) return null;
    return assemble([
        [LD_W_ABS, DATA_ARCH],
        [JEQ_K, spec.audit, 'native', 'nosys'],
        'native',
        [LD_W_ABS, DATA_NR],
        ...(spec.x32 ? [[JGE_K, X32_SYSCALL_BIT, 'nosys', 'checks']] : []),
        'checks',
        [JGE_K, IO_URING_FIRST, 'uring', 'calls'],
        'uring',
        [JGE_K, IO_URING_END, 'calls', 'nosys'],
        'calls',
        [JEQ_K, spec.socket, 'socket', 'notsocket'],
        'notsocket',
        [JEQ_K, spec.socketpair, 'socketpair', 'allow'],
        'socket',
        [LD_W_ABS, DATA_ARG0],
        ...ALLOWED_FAMILIES.map((family, index) => [JEQ_K, family, 'allow', index === ALLOWED_FAMILIES.length - 1 ? 'nofamily' : `family${index + 1}`])
            .flatMap((op, index) => (index === 0 ? [op] : [`family${index}`, op])),
        'socketpair',
        [LD_W_ABS, DATA_ARG1],
        [AND_K, SOCK_TYPE_MASK],
        [JEQ_K, SOCK_DGRAM, 'nofamily', 'allow'],
        'nofamily',
        [RET_K, RET_ERRNO | EAFNOSUPPORT],
        'nosys',
        [RET_K, RET_ERRNO | ENOSYS],
        'allow',
        [RET_K, RET_ALLOW],
    ]);
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
