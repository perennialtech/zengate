#!/usr/bin/env node
// MCP server (stdio) for agents such as Claude Code: see "Use it from Claude Code" in the README.
import './src/node-version.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readConfigFile } from './src/config.js';
import { createMcpServer, serveStdio } from './src/mcp/server.js';
import { defaultConfigPath } from './src/paths.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const configPath = defaultConfigPath({ root });
let file = {};
try {
    file = readConfigFile(configPath);
} catch (error) {
    process.stderr.write(`zengate-mcp: ${error.message}\n`);
}
const apiKey = process.env.ZENGATE_API_KEY || file.API_KEY || (Array.isArray(file.API_KEYS) ? file.API_KEYS[0] : '');
if (!apiKey) {
    process.stderr.write(`zengate-mcp: no API key. Set ZENGATE_API_KEY, or CONFIG_FILE to the gateway's config.json (looked in ${configPath}).\n`);
    process.exit(1);
}
const host = !file.HOST || ['0.0.0.0', '::'].includes(file.HOST) ? '127.0.0.1' : file.HOST;
const baseUrl = process.env.ZENGATE_URL || `http://${host.includes(':') ? `[${host}]` : host}:${file.PORT || 8083}`;
await serveStdio(createMcpServer({ baseUrl, apiKey, defaultModel: process.env.ZENGATE_MODEL || '' }));
