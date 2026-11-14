import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import { backendOrigin, createOpencodeClient } from './client.js';
import { probeBackend } from './detect.js';
import { createOpencodeClientV2 } from './client-v2.js';
import { CHAT_RUNTIME_VERSION, installChatProfile } from './chat-profile.js';
import { VALIDATED_OPENCODE_VERSION } from './runtime.js';
import { innerDirs, resolvConfPinned, resolveSandbox, spawnSandboxed } from './sandbox.js';
import { resolveOpencodeBinary, spawnCommand } from './binary.js';
import {
    backendEnv, createIsolatedRoot, HEARTBEAT_MS, randomPassword, recordBackendPid, removeIsolatedRoot, sweepStaleRoots, touchIsolatedRoot,
} from './isolation.js';

const START_TIMEOUT_MS = 60000;
// Sweeping now and then (not only at start) also clears trees that were
// still too fresh to judge when this gateway started.
const SWEEP_EVERY_BEATS = 10;
const MAX_RESTART_DELAY_MS = 30000;
const ANSI = /\x1b\[[0-9;]*m/g;
const RESOLV_WATCH = Object.freeze({ file: '/etc/resolv.conf', intervalMs: 5000 });

const LISTENING = /listening on http:\/\/127\.0\.0\.1:(\d{1,5})\b/;

/**
 * The port OpenCode reports once it has bound it. OpenCode picks the port
 * itself (--port 0), so no other process can take it between being chosen
 * and being bound and then pose as the backend.
 */
function boundPort(proc, timeoutMs) {
    return new Promise((resolve, reject) => {
        let seen = '';
        const onData = (chunk) => {
            seen = `${seen}${chunk}`.slice(-4096);
            const port = Number(LISTENING.exec(seen.replace(ANSI, ''))?.[1]);
            if (port > 0 && port < 65536) finish(null, port);
        };
        const onExit = () => finish(new Error('OpenCode exited during startup'));
        const timer = setTimeout(() => finish(new Error(`OpenCode did not start listening in ${timeoutMs / 1000}s`)), timeoutMs);
        function finish(error, port) {
            clearTimeout(timer);
            proc.stdout.off('data', onData);
            proc.off('exit', onExit);
            proc.off('error', onExit);
            if (error) reject(error);
            else resolve(port);
        }
        proc.stdout.on('data', onData);
        proc.once('exit', onExit);
        proc.once('error', onExit);
    });
}

function killTree(child) {
    if (!child?.pid || child.exitCode !== null) return;
    if (process.platform === 'win32') {
        execFile('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true }, () => {});
        return;
    }
    try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
    setTimeout(() => {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ }
    }, 3000).unref();
}

/** Wait until the backend answers, and learn which API generation it speaks. */
async function waitHealthy(options, deadline, isDead) {
    let lastError = null;
    while (Date.now() < deadline) {
        if (isDead()) throw new Error('OpenCode exited during startup');
        try {
            const found = await probeBackend(options);
            if (found) return found;
        } catch (error) {
            lastError = error;
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(`OpenCode did not become healthy in ${START_TIMEOUT_MS / 1000}s${lastError ? `: ${lastError.message}` : ''}`);
}

function pipeLogs(stream, logger) {
    let pending = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
        pending += chunk;
        const lines = pending.split(/\r?\n/);
        pending = lines.pop();
        for (const line of lines) {
            const text = line.replace(ANSI, '').trim();
            if (text) logger.debug(`[opencode] ${text}`);
        }
    });
}

/**
 * Refuse a backend whose version differs from the one the gateway's tool
 * rejection was validated against, unless the operator opted in.
 * @returns {boolean} whether the version is the validated one
 */
export function checkRuntimeVersion(version, { api = 'v2', allowUnvalidated }) {
    // The validated protections (execute/browser denial) live in the OpenCode 2 client.
    if (version === VALIDATED_OPENCODE_VERSION && api === 'v2') return true;
    if (allowUnvalidated) return false;
    const found = `${version || '(unknown version)'}${api === 'v2' ? '' : ` speaking the ${api} API`}`;
    throw new Error(`OpenCode ${found} is not the validated ${VALIDATED_OPENCODE_VERSION} runtime. `
        + 'Tool safety depends on how that exact release handles permissions. Use the bundled CLI (unset OPENCODE_PATH), '
        + 'or set ALLOW_UNVALIDATED_BACKEND=true to accept an untested version.');
}

/**
 * Starts and supervises a private `opencode serve` bound to 127.0.0.1 on a
 * port it picks itself, with a random password. It restarts with backoff if it crashes.
 * Only the validated OpenCode release is accepted unless `allowUnvalidated` is set.
 * `sandbox` is a BACKEND_SANDBOX mode (see sandbox.js).
 */
export function createManagedBackend({ opencodePath, profile = 'compatible', allowUnvalidated = false, sandbox: sandboxMode = 'auto', resolvWatch = RESOLV_WATCH, logger }) {
    let client = null;
    let child = null;
    let dirs = null;
    let version = null;
    let stopping = false;
    let restartDelay = 1000;
    let ready = false;
    let heartbeat = null;
    /** undefined until decided on the first launch, then the sandbox to use or null. */
    let sandbox;
    let watchingResolv = false;
    /** The resolv.conf content the running backend started with. */
    let resolvSeen = null;

    const readResolv = () => {
        try {
            return fs.readFileSync(resolvWatch.file, 'utf8');
        } catch {
            return null;
        }
    };

    /**
     * A sandbox holding a pinned resolv.conf keeps the copy it started with.
     * When the host's content changes (a new network or VPN), restart the
     * backend so it resolves names with the new servers. Only a serving
     * backend is restarted: one that is starting reads the file afresh.
     */
    function onResolvChange() {
        if (stopping || !ready || !child) return;
        const content = readResolv();
        if (content === null || content === resolvSeen) return;
        logger.info(`${resolvWatch.file} changed; restarting the sandboxed OpenCode backend so it uses the new DNS settings`);
        killTree(child);
    }

    function watchResolv() {
        if (!sandbox || !resolvConfPinned(resolvWatch.file)) return;
        resolvSeen = readResolv();
        if (watchingResolv) return;
        watchingResolv = true;
        fs.watchFile(resolvWatch.file, { interval: resolvWatch.intervalMs, persistent: false }, onResolvChange);
    }

    function unwatchResolv() {
        if (!watchingResolv) return;
        fs.unwatchFile(resolvWatch.file, onResolvChange);
        watchingResolv = false;
    }

    async function launch() {
        const binary = resolveOpencodeBinary(opencodePath);
        // The sandbox mounts the binary file itself, so follow symlinks to it.
        const binaryPath = fs.realpathSync(binary.path);
        dirs = createIsolatedRoot();
        const { root } = dirs;
        const deadline = Date.now() + START_TIMEOUT_MS;
        const password = randomPassword();
        if (sandbox === undefined) {
            sandbox = await resolveSandbox({ mode: sandboxMode, dirs, binary: binaryPath, env: backendEnv(innerDirs(dirs), password), logger });
        }
        // Inside the sandbox the scratch tree is always at the same path.
        const seen = sandbox ? innerDirs(dirs) : dirs;
        const env = backendEnv(seen, password);
        if (profile === 'chat') env.OPENCODE_CONFIG_CONTENT = JSON.stringify(installChatProfile(dirs, seen));
        const serveArgs = ['serve', '--hostname', '127.0.0.1', '--port', '0'];
        logger.debug('Starting OpenCode backend', { binary: binary.path, source: binary.source, sandbox: sandbox ? 'bwrap' : 'none' });
        const options = { cwd: dirs.workspace, detached: process.platform !== 'win32', windowsHide: true };
        let proc;
        if (sandbox) {
            proc = spawnSandboxed({ bwrap: sandbox.bwrap, dirs, binary: binaryPath, args: serveArgs, env, ...options });
        } else {
            const { command, args, windowsVerbatimArguments } = spawnCommand(binary.path, serveArgs);
            proc = spawn(command, args, { ...options, env, stdio: ['ignore', 'pipe', 'pipe'], windowsVerbatimArguments });
        }
        child = proc;
        if (proc.pid) recordBackendPid(root, proc.pid);
        pipeLogs(proc.stdout, logger);
        pipeLogs(proc.stderr, logger);
        let dead = false;
        let served = false;
        proc.once('error', (error) => { dead = true; logger.error('Could not start OpenCode', { error: error.message }); });
        proc.once('exit', (code, signal) => {
            dead = true;
            if (child === proc) ready = false;
            // A backend that dies while starting is handled by whoever is
            // waiting for launch(); only a crash after it served is restarted here.
            if (!stopping && served) onCrash(signal || code, root);
        });
        let port;
        let found;
        try {
            port = await boundPort(proc, START_TIMEOUT_MS);
            found = await waitHealthy({ baseUrl: `http://127.0.0.1:${port}`, username: 'opencode', password }, deadline, () => dead);
        } catch (error) {
            // The --version probe passed, but serving can still fail inside the sandbox.
            if (sandbox) error.message += ' (it runs under bubblewrap; LOG_LEVEL=debug shows its output, and BACKEND_SANDBOX=off rules the sandbox out)';
            throw error;
        }
        const reported = found.health.version || null;
        // Checked before the backend becomes current, so a refused restart leaves no trace in version() or getClient().
        if (!checkRuntimeVersion(reported, { api: found.client.api, allowUnvalidated })) {
            logger.warn(`OpenCode ${reported || '(unknown version)'} (${found.client.api} API) is not the validated ${VALIDATED_OPENCODE_VERSION} runtime; running it because ALLOW_UNVALIDATED_BACKEND is on`);
        }
        client = found.client;
        version = reported;
        if (profile === 'chat') {
            if (client.api !== 'v2' || version !== CHAT_RUNTIME_VERSION) throw new Error(`OPENCODE_PROFILE=chat requires the validated OpenCode ${CHAT_RUNTIME_VERSION} runtime`);
            client = createOpencodeClientV2({ baseUrl: `http://127.0.0.1:${port}`, username: 'opencode', password, profile });
            await client.verifyChatProfile();
        }
        ready = true;
        served = true;
        restartDelay = 1000;
        watchResolv();
        logger.info(`OpenCode ${version || ''} backend ready (managed, ${sandbox ? 'sandboxed' : 'isolated'}, tools disabled)`.replace('  ', ' '));
        logger.debug(`OpenCode speaks the ${client.api} API`);
    }

    /** Kill the current backend, if any, and wait (briefly) until it is gone. */
    async function terminate() {
        const proc = child;
        if (!proc?.pid || proc.exitCode !== null || proc.signalCode !== null) return;
        const exited = new Promise((resolve) => proc.once('exit', resolve));
        killTree(proc);
        await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5000).unref())]);
    }

    /** Relaunch with exponential backoff until a backend is up or the gateway stops. */
    async function restart(reason) {
        let why = reason;
        while (!stopping) {
            const delay = restartDelay;
            restartDelay = Math.min(MAX_RESTART_DELAY_MS, restartDelay * 2);
            await new Promise((resolve) => setTimeout(resolve, delay).unref());
            if (stopping) return;
            logger.warn(`OpenCode backend ${why}; restarting after ${delay / 1000}s`);
            try {
                await launch();
                return;
            } catch (error) {
                if (stopping) {
                    removeIsolatedRoot(dirs?.root);
                    return;
                }
                logger.error('OpenCode restart failed', { error: error.message });
                await terminate();
                removeIsolatedRoot(dirs?.root);
                why = 'failed to restart';
            }
        }
    }

    function onCrash(reason, root) {
        // Ctrl+C and service managers signal the whole process group, so OpenCode
        // can exit just before the gateway starts stopping. Only warn if the
        // restart actually goes ahead.
        logger.debug(`OpenCode backend exited (${reason})`);
        removeIsolatedRoot(root);
        void restart(`exited (${reason})`);
    }

    return Object.freeze({
        mode: 'managed',
        async start() {
            const sweep = async () => {
                const swept = await sweepStaleRoots();
                if (swept) logger.debug(`Removed ${swept} stale backend directories`);
            };
            await sweep();
            let beats = 0;
            heartbeat = setInterval(() => {
                if (dirs) touchIsolatedRoot(dirs.root);
                beats += 1;
                if (beats % SWEEP_EVERY_BEATS === 0) void sweep();
            }, HEARTBEAT_MS);
            heartbeat.unref();
            try {
                await launch();
            } catch (error) {
                stopping = true;
                clearInterval(heartbeat);
                unwatchResolv();
                await terminate();
                removeIsolatedRoot(dirs?.root);
                throw error;
            }
        },
        getClient() {
            if (!client) throw new Error('OpenCode backend is not started');
            return client;
        },
        isReady: () => ready,
        version: () => version,
        /** 'bwrap' or 'none' once started. */
        sandbox: () => (sandbox === undefined ? null : (sandbox ? 'bwrap' : 'none')),
        ownsAllSessions: true,
        async stop() {
            stopping = true;
            ready = false;
            clearInterval(heartbeat);
            unwatchResolv();
            await terminate();
            removeIsolatedRoot(dirs?.root);
        },
    });
}

/** Uses an OpenCode server someone else runs (OPENCODE_SERVER_URL). */
export function createAttachedBackend({ url, username, password, logger }) {
    // Until the server has been probed its API generation is unknown; OpenCode 1 is the default.
    let client = createOpencodeClient({ baseUrl: url, username, password });
    const shownUrl = backendOrigin(url);
    let ready = false;
    let version = null;
    let timer = null;

    async function probe() {
        let health = await client.health().catch(() => null);
        if (health?.healthy !== true) {
            // First contact, or the server was replaced by another OpenCode generation.
            health = await probeBackend({ baseUrl: url, username, password }).then(
                (found) => {
                    if (found && found.client.api !== client.api) logger.debug(`OpenCode speaks the ${found.client.api} API`);
                    if (found) client = found.client;
                    return found?.health;
                },
                () => null,
            );
        }
        ready = health?.healthy === true;
        version = health?.version || version;
        return ready;
    }

    return Object.freeze({
        mode: 'attached',
        async start() {
            if (!(await probe())) throw new Error(`OpenCode server at ${shownUrl} is not healthy (GET /global/health or /api/info). Check the URL and credentials.`);
            logger.info(`Using OpenCode ${version || ''} at ${shownUrl}`.replace('  ', ' '));
            logger.warn('Attached mode: the gateway rejects tool permissions for its own sessions, but the server\'s own configuration still applies. Prefer the managed backend.');
            timer = setInterval(probe, 10000);
            timer.unref();
        },
        getClient: () => client,
        isReady: () => ready,
        version: () => version,
        ownsAllSessions: false,
        async stop() {
            clearInterval(timer);
        },
    });
}
