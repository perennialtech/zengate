import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
export { CHAT_AGENT, CHAT_PLUGIN_ID, CHAT_RUNTIME_VERSION } from './chat-plugin.js';

/**
 * Install only our self-contained plugin into the private managed root.
 * `seen` are the same directories as the backend sees them (inside a sandbox
 * they have other paths); the plugin is written through `dirs`.
 */
export function installChatProfile(dirs, seen = dirs) {
    const directory = path.join(dirs.config, 'zengate-chat-plugin');
    const pluginUrl = pathToFileURL(path.join(seen.config, 'zengate-chat-plugin')).href;
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify({ name: 'zengate-chat-plugin', type: 'module', main: './index.js' }), { mode: 0o600 });
    fs.copyFileSync(new URL('./chat-plugin.js', import.meta.url), path.join(directory, 'index.js'));
    return {
        autoupdate: false,
        plugins: [pluginUrl],
        default_agent: 'zengate-chat',
        permissions: [{ action: '*', resource: '*', effect: 'deny' }],
        compaction: { auto: false },
    };
}
