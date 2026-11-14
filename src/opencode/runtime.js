/**
 * The OpenCode release whose permission handling this gateway has been
 * validated against: with it, `npm run test:backend-contract` and
 * `npm run test:leak` show that every tool asks and that the gateway's
 * rejection stops it. The managed backend refuses any other version unless
 * ALLOW_UNVALIDATED_BACKEND is set.
 *
 * It is the strict chat plugin's constant (the plugin is copied into the
 * backend on its own, so it cannot import this module). Bump it together
 * with the `@opencode/cli` dependency, and only after rerunning both checks;
 * a unit test keeps the two in step.
 */
export { CHAT_RUNTIME_VERSION as VALIDATED_OPENCODE_VERSION } from './chat-plugin.js';
