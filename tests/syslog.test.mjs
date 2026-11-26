import assert from "node:assert/strict";
import dgram from "node:dgram";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  RingBuffer,
  SlidingWindowBurstDetector,
  decodePri,
  parseSyslogPacket,
} from "../src/parser.mjs";
import { createCollectorServer } from "../src/server.mjs";

test("decodePri extracts bitwise facility and severity per RFC 5424", () => {
  // PRI 130 = (16 << 3) | 2 -> local0.crit
  const meta = decodePri(130);
  assert.equal(meta.facility, 16);
  assert.equal(meta.facility_name, "local0");
  assert.equal(meta.severity, 2);
  assert.equal(meta.severity_name, "crit");
});

test("parseSyslogPacket decodes RFC 5424 with structured data and RFC 3164 packets", () => {
  const rfc5424Raw =
    '<130>1 2026-11-26T12:00:00Z router-hq bgpd 412 - [timeQuality tzKnown="1"] BGP neighbor 10.0.0.1 Down';
  const ev5424 = parseSyslogPacket(rfc5424Raw, "192.168.10.1");
  assert.equal(ev5424.rfc_format, "RFC5424");
  assert.equal(ev5424.facility_name, "local0");
  assert.equal(ev5424.severity_name, "crit");
  assert.equal(ev5424.host, "router-hq");
  assert.equal(ev5424.app, "bgpd");
  assert.equal(ev5424.pid, "412");
  assert.equal(ev5424.message, "BGP neighbor 10.0.0.1 Down");

  const rfc3164Raw =
    "<83>Nov 26 19:45:01 edge-fw sshd[2099]: Failed password for invalid user root";
  const ev3164 = parseSyslogPacket(rfc3164Raw, "192.168.1.1");
  assert.equal(ev3164.rfc_format, "RFC3164");
  assert.equal(ev3164.facility_name, "authpriv");
  assert.equal(ev3164.severity_name, "err");
  assert.equal(ev3164.host, "edge-fw");
  assert.equal(ev3164.app, "sshd");
  assert.equal(ev3164.pid, "2099");
  assert.equal(ev3164.message, "Failed password for invalid user root");
});

test("RingBuffer enforces fixed memory capacity", () => {
  const buf = new RingBuffer(3);
  buf.push("a");
  buf.push("b");
  buf.push("c");
  buf.push("d");
  assert.deepEqual(buf.toArray(), ["b", "c", "d"]);
});

test("SlidingWindowBurstDetector triggers alert on error spike and respects cooldown", () => {
  const detector = new SlidingWindowBurstDetector({
    windowMs: 60_000,
    threshold: 3,
    maxSeverity: 4,
  });

  const infoEvent = { host: "sw-core", source_ip: "10.0.0.2", severity: 6, severity_name: "info", app: "snmpd", message: "ok" };
  assert.equal(detector.evaluate(infoEvent, 1_000), null);

  const errEvent = { host: "sw-core", source_ip: "10.0.0.2", severity: 3, severity_name: "err", app: "sshd", message: "Auth fail" };
  assert.equal(detector.evaluate(errEvent, 2_000), null);
  assert.equal(detector.evaluate(errEvent, 3_000), null);

  const alert = detector.evaluate(errEvent, 4_000);
  assert.ok(alert);
  assert.equal(alert.alert_type, "HIGH_FREQUENCY_SYSLOG_BURST");
  assert.equal(alert.event_count_in_window, 3);

  // Cooldown suppresses duplicate burst spam inside the same 60s window
  assert.equal(detector.evaluate(errEvent, 5_000), null);
});

test("Live UDP ingestion -> burst correlation -> HTTP REST query -> NDJSON archive", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "syslog-collector-test-"));
  const logFilePath = path.join(tmpDir, "events.ndjson");

  const collector = createCollectorServer({
    host: "127.0.0.1",
    udpPort: 0,
    httpPort: 0,
    logFilePath,
    burstThreshold: 4,
    burstWindowMs: 60_000,
  });

  const info = await collector.start();
  const sender = dgram.createSocket("udp4");

  const sendDatagram = (payload) =>
    new Promise((resolve, reject) => {
      sender.send(Buffer.from(payload, "utf8"), info.udpPort, "127.0.0.1", (err) =>
        err ? reject(err) : resolve()
      );
    });

  try {
    for (let i = 1; i <= 4; i += 1) {
      await sendDatagram(
        `<83>Nov 26 19:50:0${i} fw-perimeter sshd[310${i}]: Failed password attempt #${i}`
      );
    }
    await sendDatagram("<30>Nov 26 19:50:05 fw-perimeter systemd[1]: Started session cleanup");

    // Poll /health until all 5 UDP packets are processed
    let health = null;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const res = await fetch(`http://127.0.0.1:${info.httpPort}/health`);
      health = await res.json();
      if (health.packets_ingested === 5) break;
      await new Promise((r) => setTimeout(r, 20));
    }

    assert.equal(health.packets_ingested, 5);
    assert.equal(health.burst_alerts_total, 1);

    const critRes = await fetch(`http://127.0.0.1:${info.httpPort}/api/events?severity_max=3`);
    const critBody = await critRes.json();
    assert.equal(critBody.count, 4);

    const alertRes = await fetch(`http://127.0.0.1:${info.httpPort}/api/alerts`);
    const alertBody = await alertRes.json();
    assert.equal(alertBody.count, 1);
    assert.equal(alertBody.alerts[0].host, "fw-perimeter");
  } finally {
    sender.close();
    await collector.stop();
  }

  const lines = fs.readFileSync(logFilePath, "utf8").trim().split("\n");
  assert.equal(lines.length, 6); // 5 syslog events + 1 correlated BURST_ALERT
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
