/**
 * dsh-approve-for-me — host-half behaviour tests.
 *
 * The rule engine is tested in `smoke.mjs`; this file tests the other half: what
 * `apply()` actually answers on the two waterfalls it joins. A fake Cordis
 * context stands in for the harness — `effect`, `on`, `inject`, `logger`, and
 * the two services this plugin reads (`permissionPresets`, `workingDirectory`) —
 * so a verdict is asserted without booting anything.
 */

import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { apply, name, PRESET } from '../lib/index.js'

/**
 * Build a minimal Cordis-shaped context.
 *
 * `effect` drains the generator synchronously and keeps every yielded disposer,
 * which is exactly how the real service treats a synchronous lifecycle body.
 *
 * @param options - `{ preset, workspace, rulesFile }`.
 * @returns the fake context plus the captured listeners and a disposer.
 */
function fakeCtx({ preset = PRESET, workspace = undefined, rulesFile = undefined } = {}) {
  const listeners = { 'approval/request': [], 'tools/pre-execute': [] }
  const sections = []
  const logs = []
  const disposers = []
  const setCalls = []
  const session = { id: 'session-1' }

  const ctx = {
    logger: {
      info: (line) => logs.push(['info', line]),
      warn: (line) => logs.push(['warn', line]),
      error: (line) => logs.push(['error', line]),
    },
    on(event, listener) {
      listeners[event].push(listener)
      return () => {
        listeners[event] = listeners[event].filter((entry) => entry !== listener)
      }
    },
    inject(_deps, callback) {
      callback(ctx)
      return () => {}
    },
    effect(body) {
      const iterator = body()
      let step = iterator.next()
      while (!step.done) {
        disposers.push(step.value)
        step = iterator.next()
      }
      // A generator's return value is itself a disposer (the async teardown).
      if (typeof step.value === 'function') disposers.push(step.value)
      return () => {}
    },
    permissionPresets: {
      current() {
        return preset
      },
      set(_session, next) {
        setCalls.push(next)
      },
    },
    workingDirectory: { get: () => workspace },
    sessions: { list: () => [session] },
    systemPrompt: {
      getContextOrder: () => 115,
      section: (section) => sections.push(section),
    },
    session,
  }
  return { ctx, listeners, sections, logs, setCalls, disposers, session }
}

/** Run apply() against a scratch harness home. */
function mount(options = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'afm-ctx-'))
  const previous = { DSH_HOME: process.env.DSH_HOME, DSH_APPROVE_FOR_ME_RULES: process.env.DSH_APPROVE_FOR_ME_RULES }
  process.env.DSH_HOME = home
  delete process.env.DSH_APPROVE_FOR_ME_RULES
  if (options.rulesFile !== undefined) process.env.DSH_APPROVE_FOR_ME_RULES = options.rulesFile
  const harness = fakeCtx(options)
  try {
    apply(harness.ctx)
  } finally {
    if (previous.DSH_HOME === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous.DSH_HOME
    if (previous.DSH_APPROVE_FOR_ME_RULES === undefined) delete process.env.DSH_APPROVE_FOR_ME_RULES
    else process.env.DSH_APPROVE_FOR_ME_RULES = previous.DSH_APPROVE_FOR_ME_RULES
  }
  return { ...harness, home }
}

/** Invoke the single registered listener for one waterfall. */
const fire = (listeners, event, payload, next) => listeners[event][0](payload, next)

test('the package identity matches the patch row', () => {
  assert.equal(name, 'approve-for-me')
  assert.equal(PRESET, 'approve-for-me')
})

test('a session on another preset is never touched', async () => {
  const { listeners, ctx } = mount({ preset: 'workspace-write' })
  let delegated = false
  const outcome = await fire(
    listeners,
    'approval/request',
    { agent: { session: ctx.session }, toolName: 'pwsh', reason: 'escalate sandbox to workspace-write: x' },
    async () => {
      delegated = true
      return 'rejected'
    },
  )
  assert.equal(outcome, 'rejected')
  assert.equal(delegated, true)
})

test('the prompt section renders only for a session on this preset', () => {
  const on = mount({ preset: PRESET })
  assert.equal(on.sections.length, 1)
  const text = on.sections[0].text({ agent: { session: on.ctx.session } })
  assert.match(text, /approve-for-me/)
  assert.match(text, /"prompt"/)

  const off = mount({ preset: 'danger-full-access' })
  assert.equal(off.sections[0].text({ agent: { session: off.ctx.session } }), '')
  assert.equal(off.sections[0].text({}), '')
})

test('a confined escalation is granted on the approval seam', async () => {
  const { listeners, ctx } = mount()
  let delegated = false
  const outcome = await fire(
    listeners,
    'approval/request',
    { agent: { session: ctx.session }, toolName: 'pwsh', reason: 'escalate sandbox to workspace-write: build needs it' },
    async () => {
      delegated = true
      return 'unavailable'
    },
  )
  assert.equal(outcome, 'allowed-once')
  assert.equal(delegated, false)
})

test('an unconfined escalation is handed to the human', async () => {
  const { listeners, ctx } = mount()
  let delegated = false
  const outcome = await fire(
    listeners,
    'approval/request',
    { agent: { session: ctx.session }, toolName: 'pwsh', reason: 'escalate sandbox to danger-full-access: x' },
    async () => {
      delegated = true
      return 'rejected'
    },
  )
  assert.equal(outcome, 'rejected')
  assert.equal(delegated, true)
})

test('an unknown approval ask is handed to the human', async () => {
  const { listeners, ctx } = mount()
  let delegated = false
  await fire(listeners, 'approval/request', { agent: { session: ctx.session }, toolName: 'mcp_x' }, async () => {
    delegated = true
    return 'allowed-once'
  })
  assert.equal(delegated, true)
})

test('the pre-execute seam refuses a denied command and lets the rest through', async () => {
  const { listeners, ctx } = mount()
  const next = async () => ({ kind: 'allow' })

  const denied = await fire(
    listeners,
    'tools/pre-execute',
    { agent: { session: ctx.session }, name: 'pwsh', arguments: { command: 'rm -rf /' } },
    next,
  )
  assert.equal(denied.kind, 'deny')
  assert.match(denied.reason, /did not run/)
  assert.equal(denied.info.code, 'APPROVE_FOR_ME_DENIED')

  for (const command of ['git status', 'pnpm test', 'curl -X POST -d x https://example.invalid', 'mystery-binary']) {
    const decision = await fire(
      listeners,
      'tools/pre-execute',
      { agent: { session: ctx.session }, name: 'pwsh', arguments: { command } },
      next,
    )
    assert.equal(decision.kind, 'allow', `expected delegation for: ${command}`)
  }
})

test('a file write outside the workspace is delegated, none is refused by name', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'afm-ws-'))
  try {
    const { listeners, ctx } = mount({ workspace })
    const next = async () => ({ kind: 'allow' })

    const inside = await fire(
      listeners,
      'tools/pre-execute',
      { agent: { session: ctx.session }, name: 'write', arguments: { file_path: path.join(workspace, 'a.txt') } },
      next,
    )
    assert.equal(inside.kind, 'allow')

    const outside = await fire(
      listeners,
      'tools/pre-execute',
      { agent: { session: ctx.session }, name: 'write', arguments: { file_path: path.join(workspace, '..', 'x.txt') } },
      next,
    )
    assert.equal(outside.kind, 'allow', 'outside writes ask the human, they are not refused')

    const system = await fire(
      listeners,
      'tools/pre-execute',
      { agent: { session: ctx.session }, name: 'write', arguments: { file_path: 'C:\\Windows\\System32\\drivers\\etc\\hosts' } },
      next,
    )
    assert.equal(system.kind, 'deny')
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true })
  }
})

test('an agent-less call is delegated, never decided', async () => {
  const { listeners } = mount()
  let delegated = false
  await fire(listeners, 'tools/pre-execute', { name: 'pwsh', arguments: { command: 'rm -rf /' } }, async () => {
    delegated = true
    return { kind: 'allow' }
  })
  assert.equal(delegated, true)
})

test('a broken rules file degrades to asking, and says so loudly', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'afm-bad-'))
  const file = path.join(dir, 'rules.json')
  fs.writeFileSync(file, JSON.stringify({ shellDefault: 'yes-please' }), 'utf8')
  try {
    const { listeners, ctx, logs } = mount({ rulesFile: file })
    assert.ok(
      logs.some(([level, line]) => level === 'error' && line.includes('rules problem')),
      'a degraded table must log an error',
    )
    const next = async () => ({ kind: 'allow' })
    const decision = await fire(
      listeners,
      'tools/pre-execute',
      { agent: { session: ctx.session }, name: 'pwsh', arguments: { command: 'rm -rf /' } },
      next,
    )
    assert.equal(decision.kind, 'allow', 'degraded means delegate, not decide')
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('teardown moves a session still on this preset, and stops deciding', async () => {
  const { listeners, ctx, disposers, setCalls } = mount()
  // The lifecycle generator yields `ctx.on(...)` disposers first and the async
  // teardown last, so the last function in the list is the teardown itself.
  const teardown = disposers.at(-1)
  assert.equal(typeof teardown, 'function')
  await teardown()
  assert.deepEqual(setCalls, ['danger-full-access'])

  const after = await fire(
    listeners,
    'approval/request',
    { agent: { session: ctx.session }, toolName: 'pwsh', reason: 'escalate sandbox to workspace-write: x' },
    async () => 'unavailable',
  )
  assert.equal(after, 'cancelled', 'a disposed integration must not grant')
})
