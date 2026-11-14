/**
 * Stand-in for `opencode serve` used by the managed-backend tests. It answers
 * GET /global/health (with basic auth) and exits on GET /crash (no auth). With
 * --exit-immediately it exits at once, like a binary that fails to start.
 * --api v2 answers OpenCode 2's GET /api/info instead, and --version-file
 * reports the version written in that file when the process starts.
 */
import fs from 'node:fs';
import http from 'node:http';

const args = process.argv.slice(2);
if (args.includes('--exit-immediately')) process.exit(3);

const port = Number(args[args.indexOf('--port') + 1]);
const option = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : null);
const v2 = option('--api') === 'v2';
const version = option('--version-file') ? fs.readFileSync(option('--version-file'), 'utf8').trim() : '7.7.7-fake';
const announce = !args.includes('--never-listen');
const expected = `Basic ${Buffer.from(`opencode:${process.env.OPENCODE_SERVER_PASSWORD || ''}`).toString('base64')}`;
process.stdout.write('\x1b[32mfake opencode starting\x1b[0m\npartial line without newline');
process.stderr.write('warning line\n\n');

http.createServer((req, res) => {
    if (req.url === '/crash') {
        res.writeHead(200).end('bye', () => process.exit(1));
        return;
    }
    if (req.headers.authorization !== expected) {
        res.writeHead(401).end();
        return;
    }
    const info = v2 ? (req.url === '/api/info' ? { version, urls: [] } : null) : { healthy: true, version };
    if (!info) {
        res.writeHead(404).end();
        return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(info));
}).listen(port, '127.0.0.1', function announcePort() {
    // Like OpenCode, report the port actually bound (--port 0 picks one).
    if (announce) process.stdout.write(`\x1b[1mopencode server listening on http://127.0.0.1:${this.address().port}\x1b[0m\n`);
});
