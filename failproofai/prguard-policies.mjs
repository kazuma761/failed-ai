// PRGuard's access policy for FailproofAI: a mirror of PolicyEngine.evaluate
// (backend/gateway/policy_engine.py) over backend/policies/prguard.policy.yaml.
// Same order, rule names and reason text; tests/test_failproofai_policy.py keeps them in sync.
//
// The gateway sends each PRGuard tool call as `mcp__prguard__<tool>` with the trusted task
// in tool_input._prguard. Copied to .failproofai/policies/ by scripts/failproofai_setup.sh.
import { customPolicies, allow, deny } from "failproofai";

const PREFIX = "mcp__prguard__";

// The YAML, hard-coded: failproofai's loader has no YAML parser.
const reviewer = {
  allow: [
    { tool: ["get_pull_request", "get_pull_request_files", "get_pull_request_diff"],
      where: { repo: "{task.repo}", pull_number: "{task.pr_number}" } },
    { tool: "get_file_contents",
      where: { repo: "{task.repo}", ref: "{task.head_sha}" },
      deny_paths: [".env*", "**/secrets/**", "**/*.pem", "**/*.key"] },
    { tool: "search_code", where: { repo: "{task.repo}" }, deny_qualifiers: ["repo", "org", "user", "owner"] },
  ],
};

const POLICY = {
  always_deny: {
    tools: ["merge_pull_request", "push_files", "delete_file", "create_or_update_file"],
    cross_repo: true,
  },
  roles: {
    "prguard-orchestrator": reviewer,
    "prguard-security": reviewer,
    "prguard-quality": reviewer,
    "prguard-tests": reviewer,
    "prguard-docs": reviewer,
    "prguard-aggregator": {
      allow: [
        { tool: "create_pull_request_review",
          where: { repo: "{task.repo}", pull_number: "{task.pr_number}", event: ["COMMENT", "REQUEST_CHANGES"] } },
        { tool: "create_pull_request_review",
          where: { repo: "{task.repo}", pull_number: "{task.pr_number}", event: "APPROVE" },
          requires: "human_approved" },
      ],
    },
    "prguard-ci-fixer": {
      allow: [
        { tool: ["list_workflow_runs", "get_job_logs", "rerun_failed_jobs"], where: { repo: "{task.repo}" } },
      ],
    },
  },
};

// Python str() and repr() for the values a JSON payload can carry, so reasons match exactly.
function pyStr(v) {
  if (v === undefined || v === null) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "string" || typeof v === "number") return String(v);
  return JSON.stringify(v);
}
function pyRepr(v) {
  if (typeof v !== "string") return pyStr(v);
  const q = v.includes("'") && !v.includes('"') ? '"' : "'";
  return q + v.replaceAll("\\", "\\\\").replaceAll(q, "\\" + q) + q;
}

function globToRegex(pattern) {
  let out = "";
  for (let i = 0; i < pattern.length; ) {
    if (pattern.startsWith("**/", i)) { out += "(?:.*/)?"; i += 3; }
    else if (pattern.startsWith("**", i)) { out += ".*"; i += 2; }
    else if (pattern[i] === "*") { out += "[^/]*"; i += 1; }
    else { out += pattern[i].replace(/[.*+?^${}()|[\]\\\/-]/g, "\\$&"); i += 1; }
  }
  // Case-insensitive: `x.PEM` is as secret as `x.pem`.
  return new RegExp(`^${out}$`, "i");
}

// The path goes into the GitHub URL as is: `%2Eenv` decodes to `.env`, `?ref=` overrides the pinned ref.
const UNSAFE_PATH = /[%?#\\\x00-\x1f\x7f]/;

export function pathDenied(path, patterns) {
  // Refuse URL-significant characters and traversal outright rather than trying to normalise them.
  if (UNSAFE_PATH.test(path)) return "unsafe characters";
  const clean = path.replace(/^[ /]+|[ /]+$/g, "");  // Python's path.strip(" /")
  if (clean.split("/").some((seg) => seg === "" || seg === "." || seg === "..")) return "..";
  const basename = clean.split("/").pop();
  for (const pattern of patterns) {
    const rx = globToRegex(pattern);
    if (rx.test(clean) || (!pattern.includes("/") && rx.test(basename))) return pattern;
  }
  return null;
}

export function queryQualifier(query, qualifiers) {
  if (!qualifiers.length) return null;
  // Explicit ASCII boundary, not \b: Python's \b is Unicode-aware and JS's is not.
  const alt = qualifiers.map((q) => q.replace(/[.*+?^${}()|[\]\\\/-]/g, "\\$&")).join("|");
  const match = new RegExp(`(?:^|[^A-Za-z0-9_])(${alt}):`, "i").exec(query);
  return match ? match[1].toLowerCase() : null;
}

function taskValue(template, task) {
  const mapping = { "{task.repo}": task.repo, "{task.pr_number}": task.pr_number, "{task.head_sha}": task.head_sha };
  return typeof template === "string" && Object.hasOwn(mapping, template) ? mapping[template] : template;
}

const has = (obj, key) => Object.hasOwn(obj, key) && obj[key] !== undefined && obj[key] !== null;

// PolicyEngine.evaluate, line for line. Returns [allowed, reason, rule].
export function evaluate(agentId, task, tool, args) {
  const repo = has(args, "repo") ? args.repo : null;
  if (POLICY.always_deny.cross_repo && repo !== null && repo !== task.repo)
    return [false, `repo ${pyStr(repo)} is outside this task (${task.repo})`, "always_deny.cross_repo"];

  if (POLICY.always_deny.tools.includes(tool))
    return [false, `${tool} is never permitted for a PRGuard agent`, "always_deny.tools"];

  if (has(args, "pull_number") && pyStr(args.pull_number) !== pyStr(task.pr_number))
    return [false, `pull_number ${pyStr(args.pull_number)} is outside this task (PR #${task.pr_number})`, "task_scope.pull_number"];

  const role = Object.hasOwn(POLICY.roles, agentId) ? POLICY.roles[agentId] : null;
  if (role === null) return [false, `unknown agent ${agentId}`, "default"];

  let nearMiss = "";
  for (const [index, rule] of (role.allow || []).entries()) {
    const tools = Array.isArray(rule.tool) ? rule.tool : [rule.tool];
    if (!tools.includes(tool)) continue;
    const name = `roles.${agentId}.allow[${index}]`;

    let mismatch = "";
    for (const [key, template] of Object.entries(rule.where || {})) {
      const expected = taskValue(template, task);
      const actual = has(args, key) ? args[key] : null;
      const accepted = Array.isArray(expected) ? expected : [expected];
      if (actual === null || !accepted.map(pyStr).includes(pyStr(actual))) {
        mismatch = `${key}=${pyRepr(actual)} not allowed (expected ${accepted.map(pyStr).join(" or ")})`;
        break;
      }
    }
    if (mismatch) { nearMiss = nearMiss || mismatch; continue; }

    const blocked = Object.hasOwn(args, "path")
      ? pathDenied(has(args, "path") ? pyStr(args.path) : "None", rule.deny_paths || []) : null;
    if (blocked) return [false, `path ${pyStr(args.path)} matches denied pattern ${blocked}`, name];

    const qualifier = queryQualifier(Object.hasOwn(args, "query") ? pyStr(args.query) : "", rule.deny_qualifiers || []);
    if (qualifier) return [false, `query uses the search qualifier ${qualifier}:`, name];

    if (rule.requires === "human_approved" && task.human_approved !== true) {
      nearMiss = "requires human approval for this task";
      continue;
    }
    return [true, "allowed by role policy", name];
  }

  if (nearMiss) return [false, nearMiss, `roles.${agentId}`];
  return [false, `${tool} is not permitted for role ${agentId}`, "default"];
}

const say = (rule, reason) => `PRGuard policy [${rule}]: ${reason}`;

customPolicies.add({
  name: "prguard-tool-gateway",
  description: "PRGuard: just-for-task access for PRGuard's agents on the prguard GitHub MCP server",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const toolName = ctx.toolName ?? ctx.payload?.tool_name;
    if (typeof toolName !== "string" || !toolName.toLowerCase().startsWith(PREFIX)) return allow();  // not ours
    try {
      const input = ctx.toolInput ?? ctx.payload?.tool_input ?? {};
      // Python gets these types from TaskContext; a gap here would let e.g. ref="None" match a missing head_sha.
      const valid = (task) => task && typeof task === "object" && typeof task.agent_id === "string"
        && typeof task.repo === "string" && Number.isInteger(task.pr_number) && typeof task.head_sha === "string"
        && typeof task.human_approved === "boolean";
      // The daemon path does not always keep `_prguard` in tool_input, so the gateway sends the task three ways.
      // Every carrier that is present must be a valid task and the same one: a mismatch means tampering.
      const carried = [input._prguard, input.prguard_task, ctx.payload?.prguard].filter((t) => t !== undefined);
      const canon = (t) => JSON.stringify(Object.entries(t).sort(([a], [b]) => (a < b ? -1 : 1)));
      const task = carried.every(valid) && new Set(carried.map(canon)).size === 1 ? carried[0] : null;
      if (carried.length > 1 && !task && carried.some(valid))
        return deny(say("default", "conflicting PRGuard task context"));
      if (!task) {
        const seen = `tool_input keys: ${Object.keys(input).join(",")}; payload keys: ${Object.keys(ctx.payload ?? {}).join(",")}`;
        return deny(say("default", `no PRGuard task context (${seen})`));
      }
      const { _prguard, prguard_task, ...args } = input;
      const [allowed, reason, rule] = evaluate(task.agent_id, task, toolName.slice(PREFIX.length), args);
      // allow() with a reason reaches the agent as an instruct note; PRGuard's policy never instructs.
      return allowed ? allow() : deny(say(rule, reason));
    } catch {
      return deny(say("default", "policy error"));
    }
  },
});
