import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createLogger } from '../src/logger.js';
import { resolveBundledOpencodeBinary } from '../src/opencode/binary.js';
import { backendEnv, createIsolatedRoot, removeIsolatedRoot } from '../src/opencode/isolation.js';
import { INNER_ROOT, bwrapArgs, findBwrap, innerBinary, innerDirs, probeSandbox, resolveSandbox } from '../src/opencode/sandbox.js';

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
        const args = bwrapArgs({ dirs, binary: '/opt/oc/bin/opencode', args: ['serve', '--port', '0'], env: { SSL_CERT_FILE: '/srv/ca.pem', NODE_EXTRA_CA_CERTS: 'relative.pem' } });
        const pairs = (flag) => args.flatMap((arg, index) => (arg === flag ? [[args[index + 1], args[index + 2]]] : []));
        assert.ok(args.includes('--unshare-all') && args.includes('--share-net') && args.includes('--die-with-parent') && args.includes('--new-session'));
        assert.deepEqual(pairs('--bind'), [[dirs.root, INNER_ROOT]], 'the scratch tree is the only writable mount');
        const readOnly = [...pairs('--ro-bind'), ...pairs('--ro-bind-try')].map(([source]) => source);
        assert.ok(readOnly.includes('/opt/oc/bin'));
        assert.ok(readOnly.includes('/srv/ca.pem'), 'CA files named in the environment are mounted');
        assert.ok(!readOnly.includes('relative.pem'));
        for (const source of readOnly) {
            assert.ok(!source.startsWith('/home') && !source.startsWith('/run') && !source.startsWith('/root') && source !== '/' && source !== '/etc', source);
        }
        assert.equal(args[args.indexOf('--chdir') + 1], `${INNER_ROOT}/workspace`);
        assert.deepEqual(args.slice(args.indexOf('--') + 1), ['/zengate-bin/opencode', 'serve', '--port', '0']);
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

    it('runs the bundled OpenCode CLI', { timeout: 30000 }, async () => {
        const dirs = createIsolatedRoot();
        try {
            assert.deepEqual(await probeSandbox({ bwrap: findBwrap(), dirs, binary: fs.realpathSync(resolveBundledOpencodeBinary().path), env: backendEnv(innerDirs(dirs), 'synthetic-password') }), { ok: true });
        } finally {
            removeIsolatedRoot(dirs.root);
        }
    });
});
