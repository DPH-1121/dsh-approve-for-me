/**
 * dsh-approve-for-me — host half.
 *
 * Adds a fourth permission preset beside `read-only` / `workspace-write` /
 * `danger-full-access`, called **Approve for me**, and answers the approvals
 * that preset raises with a deterministic Codex-style rule table:
 *
 *   allow   — the call runs; nobody is asked
 *   prompt  — the human is asked, exactly as before
 *   deny    — the call is refused with a reason the model can read
 *
 * Why the preset is `danger-full-access + ask`. A harness permission preset is a
 * bundle of two knobs, and the `ask | never` policy is evaluated *before* the
 * answerer waterfall: under `never`, every ask is rejected without consulting
 * anyone. So the only bundle that actually hands decisions to a rule table is
 * `+ ask`. Of the four possible combinations the three shipped presets already
 * claim three, leaving `danger-full-access + ask` — which is also the honest
 * reading: this preset trades the sandbox for the rule table.
 *
 * Two seams are used, and only these two.
 *
 * `approval/request` (waterfall) — the authoritative seam. Every ask a tool or a
 * sandbox escalation raises passes here before the UI answerer; returning an
 * outcome claims it, calling `next()` delegates to the human. The harness logs
 * the `approval/asked` + `approval/decided` pair for the session either way, so a
 * rule-table grant is exactly as auditable as a click.
 *
 * `tools/pre-execute` (waterfall) — the pre-dispatch seam. This layer only ever
 * DENIES. Asking the approval service from inside a pre-execute listener would
 * re-enter the same waterfall, and a grant here would skip the audit pair; a
 * "deny" from the rule table is the one verdict this layer can carry.
 *
 * @module dsh-approve-for-me
 */

import { classifyExecution, compileCommands, compilePaths, loadRules } from './rules.js'

/** The Cordis plugin name; identical to the package name and the patch row id. */
export const name = 'approve-for-me'

/** The preset key, kept in one place because cordis.patch.yml and this file must agree. */
export const PRESET = 'approve-for-me'

/** Every line this plugin logs carries it, so the source of a diagnostic is never in doubt. */
const PREFIX = 'approve-for-me:'

/** The prompt section name; nothing else claims it, and per-agent scopes shadow globals by name. */
const SECTION_NAME = 'approve-for-me:policy'

/**
 * The model-facing statement of the active policy.
 *
 * Written as one paragraph on purpose: it is re-read at every step, and a policy
 * the model can quote back is what keeps a refusal from being retried under a
 * different spelling.
 *
 * @param rules - the effective rule table.
 * @returns the section text.
 */
function policyText(rules) {
  return (
    'Approval policy: approve-for-me. A deterministic rule table answers approval requests for this session. ' +
    'Calls it trusts run without asking; calls it classifies as risky are refused with the rule that refused them; ' +
    'everything it cannot classify is still sent to the human. ' +
    `A shell command no rule matched is treated as "${rules.shellDefault}". ` +
    'A refusal is final for that call: do not retry the same action under a different spelling, and do not route around a denied action.'
  )
}

/**
 * Mount the preset gate.
 *
 * Everything hangs off `ctx.effect`, so unloading the row unwinds the listeners
 * and the prompt section together. Each listener also catches its own failure:
 * an approval helper that can fail a turn is worse than no helper.
 *
 * @param ctx - the plugin's Cordis context.
 */
export function apply(ctx) {
  const loaded = loadRules({ logger: ctx.logger })
  const rules = loaded.rules
  const compiled = compileCommands(rules)
  const denyPaths = compilePaths(rules.denyPaths)

  /** Flipped before the teardown sweep, so no decision outlives the plugin. */
  let accepting = true
  /** Cancels in-flight work the moment the row unloads. */
  const lifecycle = new AbortController()

  ctx.logger.info(
    `${PREFIX} rules ${loaded.source} (${loaded.file}); ${compiled.length} command rules, shell default "${rules.shellDefault}"`,
  )
  for (const problem of loaded.problems) {
    // A broken rules file must be loud: the preset is still published (so the
    // picker does not change shape under the user), but every session using it
    // falls back to "ask the human", which is the safe direction.
    ctx.logger.error(`${PREFIX} rules problem — this preset will ask instead of deciding: ${problem}`)
  }

  /**
   * Whether one session is on this preset right now.
   *
   * `permissionPresets.current()` folds the session's own knob events and is the
   * same answer the picker shows, so there is one truth and no private mirror.
   */
  const isOn = (session) => {
    try {
      return ctx.permissionPresets.current(session) === PRESET
    } catch (error) {
      ctx.logger.warn(`${PREFIX} cannot read the permission preset: ${String(error)}`)
      return false
    }
  }

  /** Refuse to decide anything while the table is untrustworthy. */
  const degraded = loaded.problems.length > 0

  ctx.effect(
    function* () {
      // ── the authoritative seam ────────────────────────────────────────────
      yield ctx.on('approval/request', async (request, next) => {
        try {
          const agent = request.agent
          if (agent === undefined || !isOn(agent.session)) return next()
          if (!accepting || lifecycle.signal.aborted) return 'cancelled'
          if (request.signal?.aborted === true) return 'cancelled'
          if (degraded) return next()
          const verdict = classifyApproval(request)
          if (verdict.decision === 'allow') {
            ctx.logger.info(`${PREFIX} allowed approval for "${request.toolName}" (${verdict.rule})`)
            return 'allowed-once'
          }
          if (verdict.decision === 'deny') {
            ctx.logger.info(`${PREFIX} refused approval for "${request.toolName}" (${verdict.rule})`)
            return 'rejected'
          }
          // `prompt` is the honest "I cannot tell": the human decides.
          return next()
        } catch (error) {
          ctx.logger.warn(`${PREFIX} approval listener failed, delegating: ${String(error)}`)
          return next()
        }
      })

      // ── the pre-dispatch seam ─────────────────────────────────────────────
      yield ctx.on('tools/pre-execute', async (exec, next) => {
        try {
          const agent = exec.agent
          if (agent === undefined || !isOn(agent.session)) return next()
          if (!accepting || lifecycle.signal.aborted) return { kind: 'cancel' }
          if (degraded) return next()
          const workspaceRoot = safeWorkspace(ctx, agent)
          const verdict = classifyExecution(exec, rules, compiled, denyPaths, workspaceRoot)
          if (verdict.decision !== 'deny') return next()
          ctx.logger.info(`${PREFIX} refused tool "${exec.name}" (${verdict.rule})`)
          return {
            kind: 'deny',
            reason:
              `approve-for-me refused tool "${exec.name}": ${verdict.reason}. ` +
              'The call did not run; do not retry it under a different spelling.',
            info: { name: 'ApproveForMeDeniedError', code: 'APPROVE_FOR_ME_DENIED' },
          }
        } catch (error) {
          ctx.logger.warn(`${PREFIX} pre-execute listener failed, delegating: ${String(error)}`)
          return next()
        }
      })

      // ── tell the model how its calls are judged ───────────────────────────
      ctx.inject(['systemPrompt'], (scope) => {
        scope.systemPrompt.section({
          name: SECTION_NAME,
          order: scope.systemPrompt.getContextOrder('APPROVAL_POLICY') + 1,
          text: (context) => {
            const agent = context.agent
            if (agent === undefined) return ''
            try {
              return isOn(agent.session) ? policyText(rules) : ''
            } catch {
              return ''
            }
          },
        })
      })

      // ── teardown ──────────────────────────────────────────────────────────
      //
      // The preset lives in the profile patch, not in this process, so unloading
      // the row would leave sessions on a preset whose gate no longer exists —
      // which reads as "everything asks" and is safe, but silently wrong. Move
      // anyone still on it to the closest shipped preset and say so.
      yield async () => {
        accepting = false
        lifecycle.abort(new Error('approve-for-me integration disposed'))
        for (const session of safeSessions(ctx)) {
          try {
            if (ctx.permissionPresets.current(session) !== PRESET) continue
            ctx.permissionPresets.set(session, 'danger-full-access')
            ctx.logger.info(`${PREFIX} moved session ${session.id} off ${PRESET}`)
          } catch (error) {
            ctx.logger.warn(`${PREFIX} could not move session ${String(session?.id)}: ${String(error)}`)
          }
        }
      }
    },
    'approve-for-me lifecycle',
  )
}

/**
 * Read one agent's effective directory without throwing.
 * @param ctx - the plugin context.
 * @param agent - the calling agent.
 * @returns the directory, or undefined when it is not resolvable yet.
 */
function safeWorkspace(ctx, agent) {
  try {
    return ctx.workingDirectory?.get?.(agent.session)
  } catch {
    return undefined
  }
}

/**
 * List live sessions without throwing.
 * @param ctx - the plugin context.
 * @returns every session the host currently holds, or an empty list.
 */
function safeSessions(ctx) {
  try {
    return ctx.sessions.list()
  } catch {
    return []
  }
}

/**
 * Classify one approval request raised by a tool or a sandbox escalation.
 *
 * Kept here rather than in `rules.js` because it is about the harness's ask
 * vocabulary — the escalation sentence in particular — rather than about the
 * rule table's own command grammar.
 *
 * @param request - `{ toolName, reason, displayReason }`.
 * @returns the verdict.
 */
function classifyApproval(request) {
  const reason = typeof request?.reason === 'string' ? request.reason : ''
  const escalation = /^escalate sandbox to ([a-z-]+):/.exec(reason)
  if (escalation !== null) {
    const target = escalation[1]
    if (target === 'workspace-write') {
      return { decision: 'allow', rule: 'escalation-confined', reason: 'the escalation stays inside the workspace fence' }
    }
    return { decision: 'prompt', rule: 'escalation-unconfined', reason: `escaping to ${target} is the human's call` }
  }
  return { decision: 'prompt', rule: 'approval-unknown', reason: 'no rule claims this approval request' }
}
