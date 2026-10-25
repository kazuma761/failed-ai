// Offline harness: runs prguard-policies.mjs without failproofai installed.
// Shims the `failproofai` module, reads a JSON array of {tool, input} cases on stdin and
// prints [{decision, reason}] as JSON. Used by tests/test_failproofai_policy.py.
//   echo '[{"tool":"mcp__prguard__merge_pull_request","input":{}}]' | node failproofai/harness.mjs
import { registerHooks } from "node:module";
import { readFileSync } from "node:fs";

const SHIM = `
const r = (decision) => (reason) => ({ decision, reason });
export const allow = r("allow"), deny = r("deny"), instruct = r("instruct");
export const customPolicies = { add: (hook) => globalThis.__prguardHooks.push(hook) };
`;
globalThis.__prguardHooks = [];
registerHooks({
  resolve: (spec, context, next) =>
    spec === "failproofai" ? { url: "prguard-shim:failproofai", shortCircuit: true } : next(spec, context),
  load: (url, context, next) =>
    url === "prguard-shim:failproofai" ? { format: "module", source: SHIM, shortCircuit: true } : next(url, context),
});
await import("./prguard-policies.mjs");

const [hook] = globalThis.__prguardHooks;
if (globalThis.__prguardHooks.length !== 1 || hook.name !== "prguard-tool-gateway") throw new Error("expected one prguard-tool-gateway hook");

const out = [];
// A case may add top-level `payload` fields (e.g. `prguard`), as the real hook payload has them.
for (const { tool, input, payload: extra } of JSON.parse(readFileSync(0, "utf8"))) {
  const payload = { hook_event_name: "PreToolUse", tool_name: tool, tool_input: input, ...extra };
  const { decision, reason = "" } = await hook.fn({ eventType: "PreToolUse", payload, toolName: tool, toolInput: input });
  out.push({ decision, reason });
}
console.log(JSON.stringify(out));
