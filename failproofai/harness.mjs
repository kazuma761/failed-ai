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
// argv[2]: another policy file to load (e.g. a single-policy Cloud copy); default: the local file.
await import(process.argv[2] ? new URL(process.argv[2], `file://${process.cwd()}/`).href : "./prguard-policies.mjs");

const hooks = globalThis.__prguardHooks;
if (!hooks.length) throw new Error("no PRGuard policy registered");

const out = [];
// A case may add top-level `payload` fields (e.g. `prguard`), as the real hook payload has them.
// Like failproofai: every registered policy sees the call, and any deny wins.
for (const { tool, input, payload: extra } of JSON.parse(readFileSync(0, "utf8"))) {
  const payload = { hook_event_name: "PreToolUse", tool_name: tool, tool_input: input, ...extra };
  const ctx = { eventType: "PreToolUse", payload, toolName: tool, toolInput: input };
  const denials = [];
  for (const hook of hooks) {
    const { decision, reason = "" } = await hook.fn(ctx);
    if (decision === "deny") denials.push({ policy: hook.name, reason });
  }
  if (denials.length > 1) throw new Error(`more than one PRGuard policy denied: ${denials.map((d) => d.policy)}`);
  out.push(denials.length ? { decision: "deny", ...denials[0] } : { decision: "allow", reason: "", policy: "" });
}
console.log(JSON.stringify(out));
