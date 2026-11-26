/**
 * Asynchronous UDP Syslog collector, NDJSON archiver, and HTTP REST + SSE server.
 */

import dgram from "node:dgram";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  SEVERITY_NAMES,
  RingBuffer,
  SlidingWindowBurstDetector,
  parseSyslogPacket,
} from "./parser.mjs";

export function createCollectorServer({
  host = process.env.SYSLOG_HOST ?? "127.0.0.1",
  udpPort = Number.parseInt(process.env.SYSLOG_UDP_PORT ?? "5514", 10),
  httpPort = Number.parseInt(process.env.SYSLOG_HTTP_PORT ?? "8080", 10),
  logFilePath = path.resolve(process.cwd(), "logs", "syslog-events.ndjson"),
  bufferCapacity = 500,
  burstWindowMs = 60_000,
  burstThreshold = 5,
} = {}) {
  fs.mkdirSync(path.dirname(logFilePath), { recursive: true });
  const ndjsonStream = fs.createWriteStream(logFilePath, { flags: "a", encoding: "utf8" });

  const eventBuffer = new RingBuffer(bufferCapacity);
  const alertBuffer = new RingBuffer(100);
  const burstDetector = new SlidingWindowBurstDetector({
    windowMs: burstWindowMs,
    threshold: burstThreshold,
  });

  const sseClients = new Set();
  const startedAtMs = Date.now();
  let packetsIngested = 0;
  const severityCounts = Object.fromEntries(SEVERITY_NAMES.map((name) => [name, 0]));

  const udpSocket = dgram.createSocket("udp4");

  function broadcastSse(eventName, payload) {
    const frame = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
    for (const clientRes of sseClients) {
      clientRes.write(frame);
    }
  }

  udpSocket.on("message", (msg, rinfo) => {
    const now = new Date();
    const record = parseSyslogPacket(msg, rinfo.address, now);
    packetsIngested += 1;
    severityCounts[record.severity_name] = (severityCounts[record.severity_name] ?? 0) + 1;

    eventBuffer.push(record);
    ndjsonStream.write(`${JSON.stringify(record)}\n`);
    broadcastSse("syslog", record);

    const burstAlert = burstDetector.evaluate(record, now.getTime());
    if (burstAlert) {
      alertBuffer.push(burstAlert);
      ndjsonStream.write(`${JSON.stringify({ record_type: "BURST_ALERT", ...burstAlert })}\n`);
      broadcastSse("burst_alert", burstAlert);
    }
  });

  function sendJson(res, statusCode, body) {
    const payload = JSON.stringify(body, null, 2);
    res.writeHead(statusCode, {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(payload),
    });
    res.end(payload);
  }

  const httpServer = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

    if (req.method === "GET" && url.pathname === "/health") {
      const boundUdp = udpSocket.address();
      const boundHttp = httpServer.address();
      return sendJson(res, 200, {
        status: "ok",
        uptime_sec: Math.round((Date.now() - startedAtMs) / 1000),
        udp_port: typeof boundUdp === "object" ? boundUdp.port : udpPort,
        http_port: typeof boundHttp === "object" ? boundHttp.port : httpPort,
        packets_ingested: packetsIngested,
        burst_alerts_total: alertBuffer.toArray().length,
        active_sse_clients: sseClients.size,
        severity_counts: severityCounts,
      });
    }

    if (req.method === "GET" && url.pathname === "/api/events") {
      const sevMaxParam = url.searchParams.get("severity_max");
      const hostFilter = url.searchParams.get("host");
      const limit = Math.min(200, Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "50", 10)));

      let items = eventBuffer.toArray();
      if (sevMaxParam !== null) {
        const sevMax = Number.parseInt(sevMaxParam, 10);
        if (!Number.isNaN(sevMax)) {
          items = items.filter((ev) => ev.severity <= sevMax);
        }
      }
      if (hostFilter) {
        items = items.filter((ev) => ev.host === hostFilter);
      }

      const sliced = items.slice(-limit).reverse();
      return sendJson(res, 200, { count: sliced.length, events: sliced });
    }

    if (req.method === "GET" && url.pathname === "/api/alerts") {
      const alerts = alertBuffer.toArray().reverse();
      return sendJson(res, 200, { count: alerts.length, alerts });
    }

    if (req.method === "GET" && url.pathname === "/api/stream") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
      });
      res.flushHeaders();
      res.write(`: connected to syslog stream at ${new Date().toISOString()}\n\n`);
      sseClients.add(res);

      req.on("close", () => {
        sseClients.delete(res);
      });
      return;
    }

    return sendJson(res, 404, { error: "Endpoint not found" });
  });

  async function start() {
    await new Promise((resolve, reject) => {
      udpSocket.once("error", reject);
      udpSocket.bind(udpPort, host, () => {
        udpSocket.removeListener("error", reject);
        resolve();
      });
    });

    await new Promise((resolve, reject) => {
      httpServer.once("error", reject);
      httpServer.listen(httpPort, host, () => {
        httpServer.removeListener("error", reject);
        resolve();
      });
    });

    return {
      host,
      udpPort: udpSocket.address().port,
      httpPort: httpServer.address().port,
      logFilePath,
    };
  }

  async function stop() {
    for (const clientRes of sseClients) {
      clientRes.end();
    }
    sseClients.clear();

    await new Promise((resolve) => udpSocket.close(() => resolve()));
    await new Promise((resolve) => httpServer.close(() => resolve()));
    await new Promise((resolve) => ndjsonStream.end(() => resolve()));
  }

  return { start, stop };
}

const isMainModule =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMainModule) {
  const collector = createCollectorServer();
  const info = await collector.start();
  console.log(
    `[syslog-collector] Listening UDP ${info.host}:${info.udpPort} | HTTP/SSE http://${info.host}:${info.httpPort} | Archive: ${info.logFilePath}`
  );

  const shutdown = async (signal) => {
    console.log(`\n[syslog-collector] Caught ${signal}, draining streams and closing sockets...`);
    await collector.stop();
    process.exit(0);
  };

  process.once("SIGINT", () => shutdown("SIGINT"));
  process.once("SIGTERM", () => shutdown("SIGTERM"));
}
