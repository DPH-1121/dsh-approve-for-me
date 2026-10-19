/**
 * dsh-approve-for-me — the deterministic rule engine.
 *
 * Pure module: no `ctx`, no I/O beyond the rules document its loader is handed,
 * so every verdict below is reproducible from a plain object.
 *
 * The vocabulary is Codex's:
 *
 *   allow   — run it, do not bother the human
 *   prompt  — hand the decision to the human (the honest "I cannot tell")
 *   deny    — refuse it, and tell the model why
 *
 * Two structural facts drive the design.
 *
 * **A shell line is not one action.** `npm test && rm -rf build` is two. A rule
 * table that only inspects the start of a line is bypassed by appending
 * anything, so a command is split on `&&`, `||`, `;`, `|` and newlines, each
 * segment is classified on its own, and the worst verdict wins
 * (deny > prompt > allow).
 *
 * **The preset this table backs runs unconfined.** The harness's permission
 * presets bundle a sandbox mode with an approval policy, and the only free slot
 * for a fourth preset is `danger-full-access + ask`. The kernel is therefore not
 * the fence: this table is. That is why an unmatched shell command defaults to
 * `prompt` and not to `allow` — "trust everything you have not thought about"
 * is not a fence, it is the absence of one.
 *
 * @module dsh-approve-for-me/rules
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** The preset's display identity. */
export const PRESET_TITLE = 'Approve for me'

/** Where the rules document lives, relative to `$DSH_HOME`. */
export const RULES_RELATIVE_PATH = path.join('approve-for-me', 'rules.json')

/** Ordered verdicts, mildest first, so severity is an index comparison. */
const SEVERITY = ['allow', 'prompt', 'deny']

/** What a shell treats as "and then", "or else", a pipe, or a new line. */
const SEGMENT_SEPARATOR = /(?:&&|\|\||;|\||\r?\n)/

/**
 * The shipped rule table.
 *
 * `match` strings are regular expressions compiled case-insensitively and
 * matched unanchored, so one rule fires wherever its shape appears in a segment.
 * Rules are evaluated in array order and the first match wins inside a segment,
 * which is why `deny` rules come first.
 */
export const DEFAULT_RULES = Object.freeze({
  version: 1,
  /** Verdict for a shell segment no rule matched. Codex's `untrusted` posture. */
  shellDefault: 'prompt',
  /** Verdict for any other tool no rule matched. */
  toolDefault: 'prompt',
  /**
   * File-writing tools are governed by the path rule below rather than by name:
   * inside the session workspace they are ordinary project work.
   */
  pathTools: ['write', 'edit'],
  /** Locations a write may never reach, whatever the workspace is. */
  denyPaths: [
    String.raw`^[a-z]:\\windows(?:\\|$)`,
    String.raw`^[a-z]:\\program files(?: \(x86\))?(?:\\|$)`,
    String.raw`^/(?:etc|usr|bin|sbin|boot|sys|proc)(?:/|$)`,
    String.raw`\\system32(?:\\|$)`,
  ],
  /** Tools that cannot change durable state; never worth a prompt. */
  readTools: [
    'read',
    'read_image',
    'glob',
    'grep',
    'list_agents',
    'job_output',
    'job_list',
    'schedule_list',
    'ask_user_question',
    'todo_write',
    'exit_plan_mode',
  ],
  /**
   * Per-tool verdicts. The special value `command` means "classify the shell
   * string in `arguments.command` with the command table".
   */
  tools: Object.freeze({
    pwsh: 'command',
    bash: 'command',
    shell: 'command',
  }),
  /** First matching command rule decides its segment. Order matters. */
  commands: Object.freeze([
    // ── hard denials: nothing here can be authorised by a click ─────────────
    {
      id: 'delete-root',
      decision: 'deny',
      match: String.raw`\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:/|~|\$home|\*)\s*$`,
      reason: 'recursive deletion of a root, home or wildcard path',
    },
    {
      id: 'delete-drive-root',
      decision: 'deny',
      match: String.raw`\bremove-item\b[^\n]*-(?:recurse|r)\b[^\n]*(?:['"]?[a-z]:\\?['"]?|['"]?\$env:systemdrive)`,
      reason: 'recursive deletion of a drive root',
    },
    {
      id: 'format-disk',
      decision: 'deny',
      match: String.raw`\b(?:format-volume|diskpart|mkfs(?:\.\w+)?)\b|\bdd\s+if=`,
      reason: 'disk formatting or raw device write',
    },
    {
      id: 'power-state',
      decision: 'deny',
      match: String.raw`\b(?:shutdown|reboot|halt|poweroff)\b`,
      reason: 'machine power state change',
    },
    {
      id: 'pipe-to-shell',
      decision: 'deny',
      // `wholeLine`: the pipe IS the evidence, so this rule must see the
      // unsplit line — segment splitting would leave only `sh` in view.
      wholeLine: true,
      match: String.raw`\|\s*(?:ba|z|da|k|fi)?sh\b|\|\s*(?:iex|invoke-expression)\b|\|\s*sudo\b`,
      reason: 'piping a download straight into a shell',
    },
    {
      id: 'force-push',
      decision: 'deny',
      match: String.raw`\bgit\s+push\b[^\n]*(?:--force\b|(?:^|\s)-f\b|--force-with-lease\b)`,
      reason: 'force push rewrites shared history',
    },
    {
      id: 'machine-registry',
      decision: 'deny',
      match: String.raw`\breg\s+(?:add|delete)\b[^\n]*\bhklm\b|\bhklm:`,
      reason: 'machine-wide registry change',
    },
    {
      id: 'disable-security',
      decision: 'deny',
      match: String.raw`\b(?:set-mppreference|add-mppreference)\b[^\n]*-disable|\bnetsh\s+advfirewall\s+set\b[^\n]*\boff\b`,
      reason: 'disabling a security control',
    },

    // ── prompts: legitimate, but the human should see them ──────────────────
    {
      id: 'publish',
      decision: 'prompt',
      match: String.raw`\b(?:npm|pnpm|yarn)\s+publish\b`,
      reason: 'publishing a package',
    },
    {
      id: 'remote-write',
      decision: 'prompt',
      match: String.raw`\bgit\s+push\b|\bgh\s+(?:pr|release|repo)\s+(?:create|edit|delete)\b|\bgit\s+remote\s+add\b`,
      reason: 'writing to a remote repository',
    },
    {
      id: 'install-code',
      decision: 'prompt',
      match: String.raw`\b(?:npm|pnpm|yarn)\s+(?:i|install|add|dlx)\b|\bpip3?\s+install\b|\bwinget\s+install\b|\bchoco\s+install\b|\bscoop\s+install\b|\buv\s+(?:pip\s+)?(?:add|install|tool)\b`,
      reason: 'installing third-party code',
    },
    {
      id: 'container',
      decision: 'prompt',
      match: String.raw`\b(?:docker|podman)\s+(?:run|push|build)\b|\bdocker\s+buildx\s+build\b`,
      reason: 'running or publishing a container image',
    },
    {
      id: 'remote-host',
      decision: 'prompt',
      match: String.raw`\b(?:ssh|scp|sftp|rsync|telnet)\b`,
      reason: 'reaching another machine',
    },
    {
      id: 'send-data',
      decision: 'prompt',
      match: String.raw`\b(?:curl|iwr|invoke-webrequest|invoke-restmethod)\b[^\n]*(?:-x\s*post|--request\s+post|-method\s+post|--data|--upload-file|-t\s|--form)`,
      reason: 'sending data off this machine',
    },
    {
      id: 'system-path',
      decision: 'prompt',
      match: String.raw`[a-z]:\\(?:windows|program files(?: \(x86\))?)(?:\\|\b)|/(?:etc|usr|bin|sbin|boot|sys|proc)(?:/|\b)`,
      reason: 'touching a system location outside the workspace',
    },
    {
      id: 'schedule',
      decision: 'prompt',
      match: String.raw`\b(?:schtasks|new-scheduledtask|crontab|systemctl\s+(?:enable|start))\b`,
      reason: 'installing a scheduled task or service',
    },
    {
      id: 'history-rewrite',
      decision: 'prompt',
      match: String.raw`\bgit\s+(?:reset\s+--hard|rebase\b|filter-branch\b|reflog\s+expire\b|update-ref\s+-d\b|clean\s+-[a-z]*f)`,
      reason: 'rewriting or discarding local history',
    },
    {
      id: 'recursive-delete',
      decision: 'prompt',
      match: String.raw`\b(?:rm|del|erase|remove-item|rd|rmdir)\b[^\n]*(?:-[a-z]*r[a-z]*\b|/s\b|\s-r\b)`,
      reason: 'recursive deletion inside the workspace',
    },
    {
      id: 'credential-path',
      decision: 'prompt',
      match: String.raw`\.ssh[\\/]|id_rsa\b|id_ed25519\b|\.aws[\\/]credentials|\.credentials\b|\.env\b`,
      reason: 'reading a credential store',
    },
    {
      id: 'git-write',
      decision: 'prompt',
      match: String.raw`\bgit\s+(?:commit|merge|revert|cherry-pick|tag\s+-d|branch\s+-[dD]|stash\s+(?:drop|clear))\b`,
      reason: 'changing repository history or state',
    },

    // ── trusted reads: the everyday path stays quiet ────────────────────────
    {
      id: 'read-git',
      decision: 'allow',
      match: String.raw`^\s*git\s+(?:status|diff|log|show|branch\s*$|branch\s+-[av]|rev-parse|remote\s+-v|blame|describe|ls-files|ls-tree|cat-file|shortlog|grep)\b`,
      reason: 'read-only git query',
    },
    {
      id: 'read-files',
      decision: 'allow',
      match: String.raw`^\s*(?:ls|dir|pwd|cat|type|head|tail|wc|findstr|where(?:\.exe)?|get-childitem|get-content|select-string|test-path|resolve-path|get-location|measure-object|compare-object|sort-object|select-object|out-string|foreach-object)\b`,
      reason: 'read-only filesystem query',
    },
    {
      id: 'toolchain-version',
      decision: 'allow',
      match: String.raw`^\s*(?:node|npm|pnpm|yarn|python|pip|git|dsh|pwsh|powershell|dotnet|go|cargo|rustc|java|tsc|vitest|jest|eslint|prettier)\s+(?:--version|-v|version)\b`,
      reason: 'toolchain version check',
    },
    {
      id: 'print-text',
      decision: 'allow',
      match: String.raw`^\s*(?:echo|write-output|write-host|printf)\b`,
      reason: 'printing text',
    },
    {
      id: 'build-test',
      decision: 'allow',
      match: String.raw`^\s*(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:test|build|lint|typecheck|check|format)\b|\b(?:vitest|jest|pytest|cargo\s+(?:test|check|build)|go\s+(?:test|build|vet)|dotnet\s+(?:test|build)|tsc\s+(?:-p|--noemit))\b`,
      reason: 'build, test, lint or typecheck',
    },
    {
      id: 'git-read-subcommand',
      decision: 'allow',
      match: String.raw`^\s*git\s+(?:fetch|describe)\b`,
      reason: 'read-only remote metadata query',
    },
  ]),
})

/**
 * Whether a value is one of the three verdicts.
 * @param value - candidate.
 * @returns true for `allow`, `prompt` or `deny`.
 */
export function isDecision(value) {
  return value === 'allow' || value === 'prompt' || value === 'deny'
}

/**
 * Fold two verdicts into the more severe one.
 * @param left - current verdict.
 * @param right - candidate verdict.
 * @returns the more severe of the two.
 */
export function worse(left, right) {
  return SEVERITY.indexOf(right) > SEVERITY.indexOf(left) ? right : left
}

/**
 * Attach a compiled regex to every command rule, preserving evaluation order.
 * @param rules - a rules document.
 * @returns the compiled table.
 */
export function compileCommands(rules) {
  return (rules.commands ?? []).map((rule) => ({
    ...rule,
    regex: new RegExp(rule.match, 'i'),
  }))
}

/**
 * Split one shell line into independently classified segments.
 * @param command - the raw command string.
 * @returns trimmed, non-empty segments in source order.
 */
export function segmentsOf(command) {
  return String(command)
    .split(SEGMENT_SEPARATOR)
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0)
}

/**
 * Classify one shell command by folding its segments.
 *
 * `wholeLine` rules are checked first against the unsplit line: a pipe into a
 * shell is only visible when the pipe is still there, so splitting first would
 * hide the very evidence the rule exists to see.
 *
 * @param command - the raw command string.
 * @param compiled - the compiled command table.
 * @param fallback - verdict for a segment no rule matched.
 * @returns the worst verdict, plus the rule and segment that produced it.
 */
export function classifyCommand(command, compiled, fallback) {
  const line = String(command)
  if (segmentsOf(line).length === 0) {
    return { decision: fallback, rule: 'empty-command', reason: 'empty command' }
  }
  let verdict
  const consider = (candidate, segment) => {
    if (
      verdict === undefined ||
      verdict.decision === 'allow' ||
      SEVERITY.indexOf(candidate.decision) > SEVERITY.indexOf(verdict.decision)
    ) {
      verdict = { ...candidate, segment }
    }
  }

  for (const rule of compiled) {
    if (rule.wholeLine !== true || !rule.regex.test(line)) continue
    consider({ decision: rule.decision, rule: rule.id, reason: rule.reason ?? 'matched a command rule' }, line)
  }
  for (const segment of segmentsOf(line)) {
    const rule = compiled.find((candidate) => candidate.wholeLine !== true && candidate.regex.test(segment))
    consider(
      rule === undefined
        ? { decision: fallback, rule: 'shell-default', reason: 'no rule matched this command' }
        : { decision: rule.decision, rule: rule.id, reason: rule.reason ?? 'matched a command rule' },
      segment,
    )
  }
  return verdict
}

/**
 * Compile the per-workspace path rules.
 * @param denyPaths - the deny patterns from the rules document.
 * @returns one regex per pattern.
 */
export function compilePaths(denyPaths) {
  return (denyPaths ?? []).map((pattern) => new RegExp(pattern, 'i'))
}

/**
 * Decide one file path against the session workspace.
 *
 * Inside the workspace a write is ordinary project work; at a system location it
 * is refused outright; anywhere else it is the human's call.
 *
 * @param target - the raw path argument.
 * @param workspaceRoot - the session's effective directory, when known.
 * @param deny - the compiled deny patterns.
 * @returns the verdict.
 */
export function classifyPath(target, workspaceRoot, deny) {
  if (typeof target !== 'string' || target.trim().length === 0) {
    return { decision: 'prompt', rule: 'missing-path', reason: 'file tool without a path argument' }
  }
  const resolved = path.resolve(workspaceRoot ?? process.cwd(), target)
  if (deny.some((pattern) => pattern.test(resolved))) {
    return { decision: 'deny', rule: 'system-path', reason: `"${resolved}" is a system location` }
  }
  if (workspaceRoot === undefined || workspaceRoot === null) {
    return { decision: 'prompt', rule: 'unknown-workspace', reason: 'the session workspace is unknown' }
  }
  const root = path.resolve(workspaceRoot)
  const inside =
    process.platform === 'win32'
      ? resolved.toLowerCase().startsWith(root.toLowerCase() + path.sep) || resolved.toLowerCase() === root.toLowerCase()
      : resolved === root || resolved.startsWith(root + path.sep)
  if (inside) {
    return { decision: 'allow', rule: 'workspace-write', reason: `"${resolved}" is inside the workspace` }
  }
  return { decision: 'prompt', rule: 'outside-workspace', reason: `"${resolved}" is outside the workspace` }
}

/**
 * Classify one pending tool call.
 *
 * @param exec - the tool execution: `{ name, arguments }`.
 * @param rules - the effective rules document.
 * @param compiled - its compiled command table.
 * @param deny - its compiled path deny list.
 * @param workspaceRoot - the calling session's directory, when known.
 * @returns `{ decision, rule, reason }`.
 */
export function classifyExecution(exec, rules, compiled, deny = [], workspaceRoot) {
  const tool = typeof exec?.name === 'string' ? exec.name : ''
  const pathTools = new Set(rules.pathTools ?? [])
  const readTools = new Set(rules.readTools ?? [])

  if (pathTools.has(tool)) {
    const target = exec?.arguments?.file_path ?? exec?.arguments?.path
    return { ...classifyPath(target, workspaceRoot, deny), tool }
  }
  const mapped = readTools.has(tool) ? 'allow' : rules.tools?.[tool] ?? rules.toolDefault
  if (!isDecision(mapped) && mapped !== 'command') {
    return { decision: rules.toolDefault, rule: 'invalid-tool-mapping', reason: `tool "${tool}" has an invalid mapping` }
  }
  if (mapped === 'command') {
    const command = exec?.arguments?.command
    if (typeof command !== 'string' || command.trim().length === 0) {
      return { decision: 'prompt', rule: 'missing-command', reason: 'shell call without a command string', tool }
    }
    return { ...classifyCommand(command, compiled, rules.shellDefault), tool }
  }
  if (mapped === 'allow') {
    return { decision: 'allow', rule: readTools.has(tool) ? 'read-tool' : 'tool-allow', reason: `tool "${tool}" is trusted`, tool }
  }
  if (mapped === 'deny') {
    return { decision: 'deny', rule: 'tool-deny', reason: `tool "${tool}" is denied by the rule table`, tool }
  }
  return { decision: 'prompt', rule: 'tool-prompt', reason: `tool "${tool}" requires a decision`, tool }
}

/**
 * Resolve `$DSH_HOME`, mirroring `@deepseek-ai/dsh-home-paths`.
 * @param env - the environment to read.
 * @returns the harness home directory.
 */
export function resolveHome(env = process.env) {
  const raw = typeof env.DSH_HOME === 'string' && env.DSH_HOME.length > 0 ? env.DSH_HOME : undefined
  if (raw === undefined) return path.join(os.homedir(), '.dsh')
  if (raw === '~') return os.homedir()
  if (raw.startsWith('~/') || raw.startsWith('~\\')) return path.join(os.homedir(), raw.slice(2))
  return raw
}

/**
 * Merge one parsed document over the shipped defaults.
 *
 * Arrays are replaced wholesale, never concatenated: a rule table a user wrote
 * should be that table, not the defaults plus their edits.
 *
 * @param document - parsed JSON, possibly partial or malformed.
 * @returns the effective rules and the problems found.
 */
export function mergeRules(document) {
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    return { rules: structuredClone(DEFAULT_RULES), problems: ['the rules document must be a JSON object'] }
  }
  const problems = []
  const merged = { ...structuredClone(DEFAULT_RULES), ...document }

  for (const key of ['shellDefault', 'toolDefault']) {
    if (!isDecision(merged[key])) {
      problems.push(`${key} must be allow, prompt or deny (got ${JSON.stringify(merged[key])}); using the shipped value`)
      merged[key] = DEFAULT_RULES[key]
    }
  }
  if (!Array.isArray(merged.readTools)) {
    problems.push('readTools must be an array; using the shipped list')
    merged.readTools = [...DEFAULT_RULES.readTools]
  }
  if (!Array.isArray(merged.pathTools)) {
    problems.push('pathTools must be an array; using the shipped list')
    merged.pathTools = [...DEFAULT_RULES.pathTools]
  }
  if (!Array.isArray(merged.denyPaths)) {
    problems.push('denyPaths must be an array; using the shipped list')
    merged.denyPaths = [...DEFAULT_RULES.denyPaths]
  } else {
    merged.denyPaths = merged.denyPaths.filter((pattern, index) => {
      if (typeof pattern !== 'string') {
        problems.push(`denyPaths[${index}] must be a string; dropping it`)
        return false
      }
      try {
        // eslint-disable-next-line no-new
        new RegExp(pattern, 'i')
        return true
      } catch {
        problems.push(`denyPaths[${index}] is not a valid regex; dropping it`)
        return false
      }
    })
  }
  if (merged.tools === null || typeof merged.tools !== 'object' || Array.isArray(merged.tools)) {
    problems.push('tools must be an object; using the shipped table')
    merged.tools = { ...DEFAULT_RULES.tools }
  } else {
    for (const [tool, decision] of Object.entries(merged.tools)) {
      if (decision !== 'command' && !isDecision(decision)) {
        problems.push(`tools.${tool} must be allow, prompt, deny or command; dropping it`)
        delete merged.tools[tool]
      }
    }
  }
  if (!Array.isArray(merged.commands)) {
    problems.push('commands must be an array; using the shipped table')
    merged.commands = structuredClone(DEFAULT_RULES.commands)
  } else {
    const kept = []
    merged.commands.forEach((rule, index) => {
      if (rule === null || typeof rule !== 'object') {
        problems.push(`commands[${index}] must be an object; dropping the rule`)
        return
      }
      if (!isDecision(rule.decision)) {
        problems.push(`commands[${index}].decision must be allow, prompt or deny; dropping the rule`)
        return
      }
      if (typeof rule.match !== 'string' || rule.match.length === 0) {
        problems.push(`commands[${index}].match must be a non-empty string; dropping the rule`)
        return
      }
      try {
        // eslint-disable-next-line no-new
        new RegExp(rule.match, 'i')
      } catch {
        problems.push(`commands[${index}].match is not a valid regex; dropping the rule`)
        return
      }
      kept.push({
        id: typeof rule.id === 'string' && rule.id.length > 0 ? rule.id : `rule-${index}`,
        decision: rule.decision,
        match: rule.match,
        ...typeof rule.reason === 'string' ? { reason: rule.reason } : {},
      })
    })
    merged.commands = kept
  }
  return { rules: merged, problems }
}

/**
 * Read the rules document, creating it when absent.
 *
 * Never throws. A broken or unreadable file degrades to the shipped table, but
 * the problems are kept on the result: the plugin refuses to publish its preset
 * while any problem stands, because a preset that silently judges by different
 * rules than the file says is worse than no preset.
 *
 * @param options - `{ env, logger }`.
 * @returns `{ rules, file, source, problems }`.
 */
export function loadRules({ env = process.env, logger } = {}) {
  const override =
    typeof env.DSH_APPROVE_FOR_ME_RULES === 'string' && env.DSH_APPROVE_FOR_ME_RULES.length > 0
      ? env.DSH_APPROVE_FOR_ME_RULES
      : undefined
  const file = override ?? path.join(resolveHome(env), RULES_RELATIVE_PATH)
  let problems = []
  let source = 'defaults'
  let document

  try {
    if (fs.existsSync(file)) {
      document = JSON.parse(fs.readFileSync(file, 'utf8'))
      source = 'file'
    } else if (override === undefined) {
      fs.mkdirSync(path.dirname(file), { recursive: true })
      fs.writeFileSync(file, `${JSON.stringify(DEFAULT_RULES, null, 2)}\n`, 'utf8')
      source = 'created'
    } else {
      problems.push(`the rules file named by DSH_APPROVE_FOR_ME_RULES does not exist: ${file}`)
    }
  } catch (error) {
    problems.push(`cannot read ${file}: ${String(error)}`)
    source = 'defaults'
    document = undefined
  }

  const merged = mergeRules(document ?? {})
  // A file this plugin just created is the shipped table itself, so it cannot
  // contribute problems of its own; only a file that already existed is checked.
  const all = [...problems, ...(source === 'created' ? [] : merged.problems)]
  for (const problem of all) logger?.warn?.(`approve-for-me: ${problem}`)
  return { rules: merged.rules, file, source, problems: all }
}
