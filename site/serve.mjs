/**
 * Static file server for the SENTINEL landing page.
 *
 * Dependency-free, so `npm run site:dev` works on a clean checkout without an
 * install step. Binds 0.0.0.0 so a hosted preview or another device on the
 * network can reach it.
 *
 * Usage: node site/serve.mjs [port]
 */
import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)));
const PORT = Number(process.argv[2] ?? process.env.PORT ?? 4321);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
  ".map": "application/json; charset=utf-8",
};

/** Resolve a URL path inside ROOT, or null if it tries to escape. */
function safePath(urlPath) {
  // decodeURIComponent throws URIError on a malformed escape (/%E0%A4%A), and
  // an async handler that throws becomes an uncaughtException that kills the
  // server. A bad path is a client error: degrade to null and answer 404.
  const bare = urlPath.split("?")[0].split("#")[0];
  let decoded;
  try {
    decoded = decodeURIComponent(bare);
  } catch {
    return null;
  }
  const relative = normalize(decoded).replace(/^([/\\])+/, "");
  const full = resolve(ROOT, relative);
  if (full !== ROOT && !full.startsWith(ROOT + sep)) return null;
  return full;
}

const server = createServer(async (req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { allow: "GET, HEAD" }).end("Method not allowed");
    return;
  }

  let urlPath = req.url === "/" ? "/index.html" : req.url;
  let filePath = safePath(urlPath);

  if (filePath === null) {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" }).end("Not found");
    return;
  }

  try {
    let info = await stat(filePath);
    if (info.isDirectory()) {
      filePath = join(filePath, "index.html");
      info = await stat(filePath);
    }
    res.writeHead(200, {
      "content-type": MIME[extname(filePath).toLowerCase()] ?? "application/octet-stream",
      "content-length": info.size,
      "cache-control": "no-cache",
    });
    if (req.method === "HEAD") {
      res.end();
      return;
    }
    createReadStream(filePath).pipe(res);
  } catch {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" }).end("Not found");
  }
});

server.listen(PORT, "0.0.0.0", () => {
  process.stdout.write(`SENTINEL landing page → http://0.0.0.0:${PORT}\n`);
});
