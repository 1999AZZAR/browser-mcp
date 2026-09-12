/*
 * C1 provider-side HeLaResult envelope (self-contained mirror of the canonical
 * shape in chaining-mcp/src/agent/hela-result.ts; this repo is a standalone
 * package and must not import across repos).
 *
 * Flag-gated: set HELA_ENVELOPE=true to wrap tool payloads in the canonical
 * HelaResult envelope. Default (unset/anything else) returns the legacy raw
 * payload identical to before.
 *
 * Wiring: single choke point in src/server.js — the CallTool handler wraps
 * `handleToolCall` results via withEnvelope(). Internal recursive
 * handleToolCall calls (batch/parallel workflows) stay raw; the envelope is
 * applied once at the server boundary. withEnvelope() is additionally
 * idempotent (already-enveloped text is left alone) as defense in depth.
 */

const SERVER_NAME = 'general-browser-agent';

// Read-only prefixes: observation / query tools with no page or host effects.
const READ_ONLY_PREFIXES = [
  'browser_get_',
  'browser_list_',
  'browser_extract_',
  'browser_assert',
  'browser_observe',
  'browser_console_messages',
  'browser_network_requests',
  'browser_get_captured_apis',
  'browser_cache_stats',
  'browser_health',
  'browser_performance',
  'browser_state_diff',
  'browser_ocr',
  'browser_intercept_list',
  'browser_wait_',
];

// Read-only by name (don't match a prefix above).
const READ_ONLY_NAMES = new Set([
  'browser_generate_playwright_test',
  'browser_record_macro',
]);

// File-producing tools.
const EXPORT_TOOLS = new Set([
  'browser_print_to_pdf',
  'browser_download_click',
  'browser_export_state',
  'browser_save_session',
  'browser_start_trace',
  'browser_stop_trace',
]);

function sideEffectsFor(toolName) {
  if (toolName === 'browser_screenshot') return ['browser-capture'];
  if (EXPORT_TOOLS.has(toolName)) return ['browser-export'];
  if (READ_ONLY_NAMES.has(toolName)) return [];
  for (const prefix of READ_ONLY_PREFIXES) {
    if (toolName.startsWith(prefix)) return [];
  }
  return ['browser-act'];
}

function isEnvelopeEnabled() {
  return process.env['HELA_ENVELOPE'] === 'true';
}

function baseExecution(toolName) {
  const meta = {
    serverName: SERVER_NAME,
    toolName,
    completedAt: new Date().toISOString(),
  };
  if (process.env['HELA_RUN_ID'] !== undefined) meta.run_id = process.env['HELA_RUN_ID'];
  if (process.env['HELA_STEP_ID'] !== undefined) meta.step_id = process.env['HELA_STEP_ID'];
  return meta;
}

function wrapResult(toolName, data, summary) {
  return {
    ok: true,
    summary: summary || `${toolName} ok`,
    data,
    artifacts: [],
    provenance: [],
    warnings: [],
    sideEffects: sideEffectsFor(toolName),
    execution: baseExecution(toolName),
    redaction: { applied: false, fields: [] },
  };
}

function wrapError(toolName, message) {
  return {
    ok: false,
    summary: `${toolName} failed: ${message}`,
    data: null,
    artifacts: [],
    provenance: [],
    warnings: [],
    sideEffects: sideEffectsFor(toolName),
    execution: baseExecution(toolName),
    redaction: { applied: false, fields: [] },
    error: message,
  };
}

function parseData(text) {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// Already-enveloped text (ours) is left alone — makes wrapping idempotent.
function isEnveloped(text) {
  try {
    const parsed = JSON.parse(text);
    return (
      parsed !== null &&
      typeof parsed === 'object' &&
      typeof parsed.ok === 'boolean' &&
      parsed.execution !== null &&
      typeof parsed.execution === 'object' &&
      parsed.execution.serverName === SERVER_NAME
    );
  } catch {
    return false;
  }
}

/**
 * Post-hoc result wrapper. Envelope off: SDK result untouched (same ref).
 * Envelope on: text blocks become envelope JSON; image/other blocks and
 * extra result keys (e.g. structuredContent) preserved. isError results map
 * to ok:false envelopes; the isError flag is kept.
 */
function withEnvelope(toolName, result) {
  if (!isEnvelopeEnabled()) return result;
  if (!result || !Array.isArray(result.content)) return result;
  const isErr = result.isError === true;
  let replaced = false;
  const content = result.content.map((block) => {
    if (!replaced && block && block.type === 'text' && typeof block.text === 'string' && !isEnveloped(block.text)) {
      replaced = true;
      const data = parseData(block.text);
      const env = isErr ? wrapError(toolName, block.text) : wrapResult(toolName, data);
      return { type: 'text', text: JSON.stringify(env, null, 2) };
    }
    return block;
  });
  if (!replaced) return result;
  return { ...result, content };
}

/**
 * Error responder. Envelope off: legacy `{isError: true, content: [Error: msg]}`
 * shape preserved exactly (key order included). Envelope on: ok:false envelope.
 */
function errorResult(toolName, message) {
  if (!isEnvelopeEnabled()) {
    return {
      isError: true,
      content: [{ type: 'text', text: `Error: ${message}` }],
    };
  }
  return {
    isError: true,
    content: [{ type: 'text', text: JSON.stringify(wrapError(toolName, message), null, 2) }],
  };
}

module.exports = {
  SERVER_NAME,
  sideEffectsFor,
  isEnvelopeEnabled,
  wrapResult,
  wrapError,
  withEnvelope,
  errorResult,
};
