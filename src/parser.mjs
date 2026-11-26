/**
 * RFC 3164 & RFC 5424 Syslog wire parser, bounded ring buffer,
 * and sliding-window host burst detector (zero external dependencies).
 */

export const FACILITY_NAMES = [
  "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
  "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
  "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

export const SEVERITY_NAMES = [
  "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

const RFC5424_RE = /^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/s;
const RFC3164_PRI_RE = /^<(\d{1,3})>(.*)$/s;
const RFC3164_BODY_RE =
  /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:[\s]+)(?:\[(\d+)\])?:\s*(.*)$/s;

/**
 * Decode numeric Syslog PRI (0..191) into facility and severity fields.
 */
export function decodePri(priValue) {
  const pri = Number.isInteger(priValue) && priValue >= 0 && priValue <= 191 ? priValue : 13;
  const facility = pri >> 3;
  const severity = pri & 0x07;
  return {
    pri,
    facility,
    facility_name: FACILITY_NAMES[facility] ?? `fac${facility}`,
    severity,
    severity_name: SEVERITY_NAMES[severity] ?? `sev${severity}`,
  };
}

function stripStructuredData(rest) {
  if (rest.startsWith("-")) {
    return rest.replace(/^-\s*/, "");
  }
  if (rest.startsWith("[")) {
    return rest.replace(/^(?:\[(?:\\.|[^\]])*\])+\s*/, "");
  }
  return rest;
}

/**
 * Parse a raw UDP Syslog payload (Buffer or string) into a normalized record.
 */
export function parseSyslogPacket(rawInput, remoteAddress = "127.0.0.1", receivedAt = new Date()) {
  const text = (Buffer.isBuffer(rawInput) ? rawInput.toString("utf8") : String(rawInput)).trim();
  const isoNow = receivedAt.toISOString();

  // 1. Check modern RFC 5424 format (default on util-linux logger in Ubuntu / Pop!_OS)
  const m5424 = RFC5424_RE.exec(text);
  if (m5424) {
    const [, priStr, ts, host, app, procId, , tail] = m5424;
    const priMeta = decodePri(Number.parseInt(priStr, 10));
    return {
      received_at: isoNow,
      rfc_format: "RFC5424",
      source_ip: remoteAddress,
      host: host === "-" ? remoteAddress : host,
      app: app === "-" ? "unknown" : app,
      pid: procId === "-" ? null : procId,
      wire_timestamp: ts === "-" ? isoNow : ts,
      ...priMeta,
      message: stripStructuredData(tail).trim(),
    };
  }

  // 2. Check classic BSD RFC 3164 format (<PRI>Mmm dd hh:mm:ss host app[pid]: msg)
  let priMeta = decodePri(13); // user.notice fallback
  let body = text;
  const mPri = RFC3164_PRI_RE.exec(text);
  if (mPri) {
    priMeta = decodePri(Number.parseInt(mPri[1], 10));
    body = mPri[2];
  }

  const m3164 = RFC3164_BODY_RE.exec(body);
  if (m3164) {
    const [, wireTs, host, app, pid, msg] = m3164;
    return {
      received_at: isoNow,
      rfc_format: "RFC3164",
      source_ip: remoteAddress,
      host,
      app,
      pid: pid ?? null,
      wire_timestamp: wireTs,
      ...priMeta,
      message: msg.trim(),
    };
  }

  // 3. Graceful fallback for unformatted datagrams
  return {
    received_at: isoNow,
    rfc_format: "RAW",
    source_ip: remoteAddress,
    host: remoteAddress,
    app: "unstructured",
    pid: null,
    wire_timestamp: isoNow,
    ...priMeta,
    message: body.trim(),
  };
}

/**
 * Fixed-capacity circular buffer for fast in-memory NOC API queries.
 */
export class RingBuffer {
  constructor(capacity = 500) {
    this.capacity = capacity;
    this.items = [];
  }

  push(item) {
    if (this.items.length >= this.capacity) {
      this.items.shift();
    }
    this.items.push(item);
  }

  toArray() {
    return [...this.items];
  }
}

/**
 * Sliding-window burst detector to flag SSH brute-force or link-flap storms per host.
 */
export class SlidingWindowBurstDetector {
  constructor({ windowMs = 60_000, threshold = 5, maxSeverity = 4 } = {}) {
    this.windowMs = windowMs;
    this.threshold = threshold;
    this.maxSeverity = maxSeverity;
    this.historyByHost = new Map();
    this.lastAlertAtByHost = new Map();
  }

  evaluate(event, nowMs = Date.now()) {
    if (event.severity > this.maxSeverity) {
      return null;
    }

    const hostKey = event.host || event.source_ip;
    const cutoff = nowMs - this.windowMs;
    const timestamps = (this.historyByHost.get(hostKey) ?? []).filter((t) => t > cutoff);
    timestamps.push(nowMs);
    this.historyByHost.set(hostKey, timestamps);

    const lastAlertAt = this.lastAlertAtByHost.get(hostKey) ?? -Infinity;
    if (timestamps.length >= this.threshold && nowMs - lastAlertAt >= this.windowMs) {
      this.lastAlertAtByHost.set(hostKey, nowMs);
      return {
        alert_type: "HIGH_FREQUENCY_SYSLOG_BURST",
        triggered_at: new Date(nowMs).toISOString(),
        host: hostKey,
        source_ip: event.source_ip,
        event_count_in_window: timestamps.length,
        window_sec: Math.round(this.windowMs / 1000),
        latest_app: event.app,
        latest_severity: event.severity_name,
        sample_message: event.message,
      };
    }

    return null;
  }
}
