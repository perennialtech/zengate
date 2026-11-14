import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createLogger, silentLogger } from '../src/logger.js';
import { createManagedBackend } from '../src/opencode/backend.js';
import { resolveBundledOpencodeBinary } from '../src/opencode/binary.js';
import { backendEnv, createIsolatedRoot, removeIsolatedRoot } from '../src/opencode/isolation.js';
import {
    INNER_ROOT, bwrapArgs, findBwrap, innerBinary, innerDirs, openSeccomp, probeSandbox, resolveSandbox, seccompProgram, spawnSandboxed,
} from '../src/opencode/sandbox.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zengate-sandbox-test-'));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

function captureLogger() {
    const lines = [];
    const logger = createLogger({ level: 'debug', sink: { out: (line) => lines.push(line), err: (line) => lines.push(line) } });
    return { lines, logger };
}

const fakeDirs = () => {
    const root = path.join(tmp, 'zengate-abc123');
    return { root, home: path.join(root, 'home'), workspace: path.join(root, 'workspace'), config: path.join(root, 'config') };
};

/** Whether bubblewrap can create a sandbox here (user namespaces may be off, as in many containers and CI runners). */
function bwrapWorks() {
    if (process.platform !== 'linux') return false;
    const bwrap = findBwrap();
    return Boolean(bwrap) && spawnSync(bwrap, ['--unshare-all', '--ro-bind', '/', '/', 'true'], { stdio: 'ignore' }).status === 0;
}
const skipReal = bwrapWorks() ? false : 'bubblewrap cannot create a sandbox on this machine';

describe('sandbox arguments', () => {
    it('maps the scratch tree to a fixed path', () => {
        assert.deepEqual(innerDirs(fakeDirs()), { root: INNER_ROOT, home: `${INNER_ROOT}/home`, workspace: `${INNER_ROOT}/workspace`, config: `${INNER_ROOT}/config` });
        assert.equal(innerBinary('/opt/x/bin/opencode.exe'), '/zengate-bin/opencode.exe');
    });

    it('mounts only system directories, the binary and the scratch tree', () => {
        const dirs = fakeDirs();
        const args = bwrapArgs({ dirs, binary: '/opt/oc/bin/opencode', args: ['serve', '--port', '0'], env: { SSL_CERT_FILE: '/srv/ca.pem', NODE_EXTRA_CA_CERTS: 'relative.pem' }, seccomp: true });
        const pairs = (flag) => args.flatMap((arg, index) => (arg === flag ? [[args[index + 1], args[index + 2]]] : []));
        assert.ok(args.includes('--unshare-all') && args.includes('--share-net') && args.includes('--die-with-parent') && args.includes('--new-session'));
        assert.equal(args[args.indexOf('--seccomp') + 1], '3');
        const writable = ['--bind', '--bind-try', '--dev-bind', '--dev-bind-try'].flatMap(pairs);
        assert.deepEqual(writable, [[dirs.root, INNER_ROOT]], 'the scratch tree is the only writable mount');
        const readOnly = [...pairs('--ro-bind'), ...pairs('--ro-bind-try')].map(([source]) => source);
        assert.deepEqual(pairs('--ro-bind').find(([source]) => source.startsWith('/opt/')), ['/opt/oc/bin/opencode', '/zengate-bin/opencode'], 'only the binary file, not its directory');
        assert.ok(readOnly.includes('/srv/ca.pem'), 'CA files named in the environment are mounted');
        assert.ok(!readOnly.includes('relative.pem'));
        for (const source of readOnly) {
            const resolverDir = source === '/run/systemd/resolve' || source === '/run/resolvconf';
            assert.ok(!source.startsWith('/home') && (!source.startsWith('/run') || resolverDir) && !source.startsWith('/root') && source !== '/' && source !== '/etc', source);
            assert.ok(!source.startsWith(os.homedir()), source);
        }
        assert.equal(args[args.indexOf('--chdir') + 1], `${INNER_ROOT}/workspace`);
        assert.deepEqual(args.slice(args.indexOf('--') + 1), ['/zengate-bin/opencode', 'serve', '--port', '0']);
    });
});

/** A minimal classic-BPF interpreter for the instructions seccompProgram emits. */
function runFilter(program, { nr, arch, arg0 = 0, arg1 = 0 }) {
    const data = Buffer.alloc(64);
    data.writeUInt32LE(nr >>> 0, 0);
    data.writeUInt32LE(arch >>> 0, 4);
    data.writeUInt32LE(arg0 >>> 0, 16);
    data.writeUInt32LE(arg1 >>> 0, 24);
    let acc = 0;
    for (let pc = 0; pc < program.length / 8;) {
        const code = program.readUInt16LE(pc * 8);
        const jt = program.readUInt8(pc * 8 + 2);
        const jf = program.readUInt8(pc * 8 + 3);
        const k = program.readUInt32LE(pc * 8 + 4);
        pc += 1;
        if (code === 0x20) acc = data.readUInt32LE(k);
        else if (code === 0x54) acc = (acc & k) >>> 0;
        else if (code === 0x15) pc += acc === k ? jt : jf;
        else if (code === 0x35) pc += acc >= k ? jt : jf;
        else if (code === 0x06) return k;
        else throw new Error(`unexpected BPF code ${code}`);
    }
    throw new Error('fell off the end of the program');
}

describe('seccomp filter', () => {
    const ALLOW = 0x7fff0000;
    const errno = (value) => 0x00050000 | value;
    for (const [arch, audit, socketNr, pairNr, otherNr] of [['x64', 0xc000003e, 41, 53, 42], ['arm64', 0xc00000b7, 198, 199, 203]]) {
        it(`allows only the socket families the backend needs on ${arch}`, () => {
            const program = seccompProgram(arch);
            for (const [family, name] of [[1, 'AF_UNIX'], [40, 'AF_VSOCK'], [17, 'AF_PACKET'], [0, 'AF_UNSPEC']]) {
                assert.equal(runFilter(program, { arch: audit, nr: socketNr, arg0: family }), errno(97), `socket(${name})`);
            }
            for (const [family, name] of [[2, 'AF_INET'], [10, 'AF_INET6'], [16, 'AF_NETLINK']]) {
                assert.equal(runFilter(program, { arch: audit, nr: socketNr, arg0: family }), ALLOW, `socket(${name})`);
            }
            assert.equal(runFilter(program, { arch: audit, nr: otherNr, arg0: 1 }), ALLOW, 'other calls with a first argument of 1');
        });

        it(`refuses datagram socketpairs, io_uring and foreign ABIs on ${arch}`, () => {
            const program = seccompProgram(arch);
            const SOCK_CLOEXEC = 0x80000;
            assert.equal(runFilter(program, { arch: audit, nr: pairNr, arg0: 1, arg1: 2 }), errno(97), 'socketpair(SOCK_DGRAM)');
            assert.equal(runFilter(program, { arch: audit, nr: pairNr, arg0: 1, arg1: 2 | SOCK_CLOEXEC }), errno(97), 'socketpair(SOCK_DGRAM | SOCK_CLOEXEC)');
            assert.equal(runFilter(program, { arch: audit, nr: pairNr, arg0: 1, arg1: 1 | SOCK_CLOEXEC }), ALLOW, 'socketpair(SOCK_STREAM)');
            for (const nr of [425, 426, 427]) assert.equal(runFilter(program, { arch: audit, nr }), errno(38), `io_uring syscall ${nr}`);
            for (const nr of [424, 428]) assert.equal(runFilter(program, { arch: audit, nr }), ALLOW, `syscall ${nr}`);
            assert.equal(runFilter(program, { arch: 0x40000003, nr: 102, arg0: 1 }), errno(38), 'i386 entry point (socketcall)');
        });
    }
    it('refuses the x32 ABI on x64 and has no program for other architectures', () => {
        assert.equal(runFilter(seccompProgram('x64'), { arch: 0xc000003e, nr: 0x40000000 | 41, arg0: 1 }), errno(38));
        assert.equal(seccompProgram('riscv64'), null);
        assert.equal(openSeccomp({ root: tmp }, 'riscv64'), null);
    });
});

describe('resolveSandbox', () => {
    const base = { dirs: fakeDirs(), binary: '/opt/oc/bin/opencode', env: {} };
    const ok = async () => ({ ok: true });
    const broken = async () => ({ ok: false, reason: 'setting up uid map: Permission denied' });

    it('uses bubblewrap when it works', async () => {
        const { logger } = captureLogger();
        assert.deepEqual(await resolveSandbox({ ...base, mode: 'auto', logger, platform: 'linux', find: () => '/usr/bin/bwrap', probe: ok }), { bwrap: '/usr/bin/bwrap' });
        assert.deepEqual(await resolveSandbox({ ...base, mode: 'bwrap', logger, platform: 'linux', find: () => '/usr/bin/bwrap', probe: ok }), { bwrap: '/usr/bin/bwrap' });
    });

    it('falls back with a warning in auto mode and fails in bwrap mode', async () => {
        const { lines, logger } = captureLogger();
        assert.equal(await resolveSandbox({ ...base, mode: 'auto', logger, platform: 'linux', find: () => '/usr/bin/bwrap', probe: broken }), null);
        assert.ok(lines.some((line) => /\[warn\].*without an OS sandbox: setting up uid map/.test(line)), lines.join('\n'));
        assert.equal(await resolveSandbox({ ...base, mode: 'auto', logger, platform: 'linux', find: () => null, probe: ok }), null);
        assert.ok(lines.some((line) => /install the bubblewrap package/.test(line)));
        await assert.rejects(resolveSandbox({ ...base, mode: 'bwrap', logger, platform: 'linux', find: () => '/usr/bin/bwrap', probe: broken }), /BACKEND_SANDBOX=bwrap, but bubblewrap cannot run the backend/);
        await assert.rejects(resolveSandbox({ ...base, mode: 'bwrap', logger, platform: 'linux', find: () => null, probe: ok }), /bwrap was not found/);
    });

    it('is off when asked, and Linux-only', async () => {
        const { lines, logger } = captureLogger();
        const never = () => assert.fail('must not look for bubblewrap');
        assert.equal(await resolveSandbox({ ...base, mode: 'off', logger, platform: 'linux', find: never, probe: never }), null);
        assert.equal(await resolveSandbox({ ...base, mode: 'auto', logger, platform: 'win32', find: never, probe: never }), null);
        assert.ok(lines.some((line) => /No OS sandbox .* on this platform/.test(line)));
        await assert.rejects(resolveSandbox({ ...base, mode: 'bwrap', logger, platform: 'darwin', find: never, probe: never }), /only available on Linux/);
    });
});

describe('sandbox containment (real bubblewrap)', { skip: skipReal }, () => {
    const run = (dirs, script) => spawnSync(findBwrap(), bwrapArgs({ dirs, binary: '/bin/sh', args: ['-c', script] }), { encoding: 'utf8' });

    it('hides the host home, /run and /tmp, and allows writes only in the scratch tree', () => {
        const dirs = createIsolatedRoot();
        const outside = path.join(tmp, 'host-secret.txt');
        fs.writeFileSync(outside, 'host secret');
        try {
            const script = [
                `cat ${JSON.stringify(outside)} 2>/dev/null && echo LEAK-tmp`,
                `ls ${JSON.stringify(os.homedir())} >/dev/null 2>&1 && echo LEAK-home`,
                'ls /run >/dev/null 2>&1 && echo LEAK-run',
                'touch /usr/zengate-probe 2>/dev/null && echo LEAK-usr',
                `echo inside > ${INNER_ROOT}/workspace/written.txt && echo WROTE`,
                'pwd; hostname 2>/dev/null || cat /proc/sys/kernel/hostname',
            ].join('; ');
            const result = run(dirs, script);
            assert.equal(result.status, 0, result.stderr);
            assert.doesNotMatch(result.stdout, /LEAK/, result.stdout);
            assert.match(result.stdout, /WROTE\n\/zengate\/workspace\nzengate\n/);
            assert.equal(fs.readFileSync(path.join(dirs.workspace, 'written.txt'), 'utf8'), 'inside\n');
        } finally {
            removeIsolatedRoot(dirs.root);
        }
    });

    it('refuses Unix sockets inside, including the host abstract namespace it shares', { skip: process.arch in { x64: 1, arm64: 1 } ? false : 'no seccomp program for this architecture' }, async () => {
        const name = `zengate-test-${process.pid}-${Date.now()}`;
        const listener = net.createServer((socket) => { socket.on('error', () => {}); socket.destroy(); }).listen(`\0${name}`);
        await new Promise((resolve) => listener.once('listening', resolve));
        const dirs = createIsolatedRoot();
        try {
            const script = `const s = require('net').connect('\\0${name}'); s.on('connect', () => { console.log('CONNECTED'); process.exit(0); }); s.on('error', (e) => { console.log(e.code); process.exit(0); });`;
            const run = (seccomp) => new Promise((resolve) => {
                const options = { bwrap: findBwrap(), dirs, binary: fs.realpathSync(process.execPath), args: ['-e', script], env: { PATH: '/usr/bin:/bin' } };
                const proc = seccomp ? spawnSandboxed(options) : spawnSync(options.bwrap, bwrapArgs(options), { encoding: 'utf8' });
                if (!seccomp) return resolve(proc.stdout.trim());
                let out = '';
                proc.stdout.on('data', (chunk) => { out += chunk; });
                proc.once('exit', () => resolve(out.trim()));
                return undefined;
            });
            assert.equal(await run(false), 'CONNECTED', 'control: without the filter the shared abstract socket is reachable');
            assert.equal(await run(true), 'EAFNOSUPPORT');
        } finally {
            listener.close();
            removeIsolatedRoot(dirs.root);
        }
    });

    it('serves, restarts after a crash and stops cleanly as the managed backend', { timeout: 120000 }, async () => {
        // Only this test's backends: other gateways on the machine may be running sandboxed too.
        const existing = new Set(fs.readdirSync(os.tmpdir()));
        const descendants = (pid) => {
            let kids = [];
            try {
                kids = fs.readdirSync(`/proc/${pid}/task`).flatMap((task) => fs.readFileSync(`/proc/${pid}/task/${task}/children`, 'utf8').split(' ').filter(Boolean).map(Number));
            } catch {
                return [];
            }
            return kids.flatMap((kid) => [kid, ...descendants(kid)]);
        };
        for (const profile of ['compatible', 'chat']) {
            const backend = createManagedBackend({ opencodePath: '', profile, sandbox: 'bwrap', logger: silentLogger });
            let pids = [];
            try {
                await backend.start();
                assert.equal(backend.sandbox(), 'bwrap', profile);
                assert.equal((await backend.getClient().health()).healthy, true, profile);
                const backendPid = () => fs.readdirSync(os.tmpdir())
                    .filter((name) => name.startsWith('zengate-') && !existing.has(name))
                    .map((name) => path.join(os.tmpdir(), name, 'backend.pid'))
                    .filter((file) => fs.existsSync(file))
                    .map((file) => Number(fs.readFileSync(file, 'utf8')))
                    .filter((pid) => { try { return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').includes('/zengate-bin/'); } catch { return false; } });
                pids = backendPid();
                assert.equal(pids.length, 1, 'the sandboxed backend is running');
                const opencode = descendants(pids[0]).filter((pid) => {
                    try { return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').startsWith('/zengate-bin/'); } catch { return false; }
                });
                assert.ok(opencode.length >= 1, `${profile}: OpenCode runs inside bubblewrap`);
                for (const pid of opencode) {
                    assert.match(fs.readFileSync(`/proc/${pid}/status`, 'utf8'), /^Seccomp:\s+2$/m, `${profile}: the seccomp filter applies to OpenCode`);
                }
                const first = backend.getClient().baseUrl;
                for (const pid of pids) process.kill(pid, 'SIGKILL');
                const deadline = Date.now() + 30000;
                while (!(backend.isReady() && backend.getClient().baseUrl !== first) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 100));
                assert.ok(backend.isReady(), `${profile}: restarted in the sandbox`);
                pids = backendPid();
            } finally {
                await backend.stop();
            }
            await new Promise((resolve) => setTimeout(resolve, 500));
            for (const pid of pids) assert.throws(() => process.kill(pid, 0), /ESRCH/, `${profile}: pid ${pid} is gone after stop`);
        }
    });

    it('restarts the backend when a pinned resolv.conf is replaced', { timeout: 60000 }, async () => {
        const file = path.join(tmp, 'resolv.conf');
        fs.writeFileSync(file, 'nameserver 192.0.2.1\n');
        const { lines, logger } = captureLogger();
        const backend = createManagedBackend({ opencodePath: '', sandbox: 'bwrap', resolvWatch: { file, intervalMs: 100 }, logger });
        try {
            await backend.start();
            const first = backend.getClient().baseUrl;
            // Let fs.watchFile take its first stat, which it does asynchronously after starting.
            await new Promise((resolve) => setTimeout(resolve, 500));
            fs.writeFileSync(`${file}.new`, 'nameserver 192.0.2.1\n');
            fs.renameSync(`${file}.new`, file);
            await new Promise((resolve) => setTimeout(resolve, 500));
            assert.equal(backend.getClient().baseUrl, first, 'the same content does not restart the backend');
            fs.writeFileSync(`${file}.new`, 'nameserver 192.0.2.2\n');
            fs.renameSync(`${file}.new`, file);
            const deadline = Date.now() + 30000;
            while (!(backend.isReady() && backend.getClient().baseUrl !== first) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 100));
            assert.ok(lines.some((line) => /resolv\.conf changed; restarting the sandboxed OpenCode backend/.test(line)), lines.join('\n'));
            assert.ok(backend.isReady() && backend.getClient().baseUrl !== first, 'a new backend serves');
        } finally {
            await backend.stop();
        }
    });

    it('runs the bundled OpenCode CLI', { timeout: 30000 }, async () => {
        const dirs = createIsolatedRoot();
        try {
            assert.deepEqual(await probeSandbox({ bwrap: findBwrap(), dirs, binary: fs.realpathSync(resolveBundledOpencodeBinary().path), env: backendEnv(innerDirs(dirs), 'synthetic-password') }), { ok: true });
        } finally {
            removeIsolatedRoot(dirs.root);
        }
    });
});
