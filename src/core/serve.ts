/**
 * Shared HTTP listener bootstrap.
 *
 * Every long-lived server in SENTINEL (MCP tool server, web console, scan API)
 * goes through `listenOrExit`, so a port conflict is reported as one actionable
 * line instead of a raw `EADDRINUSE` stack trace from an unhandled `error`
 * event on the underlying socket.
 */
import { serve } from "@hono/node-server";
import type { Hono } from "hono";
import { pathToFileURL } from "node:url";

/**
 * True when the calling file was launched directly rather than imported.
 * Pass the caller's own `import.meta.url`: this module compares it against
 * `process.argv[1]`, and `import.meta.url` inside this file would be wrong.
 */
export function isEntrypoint(callerUrl: string): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return callerUrl === pathToFileURL(entry).href;
  } catch {
    return false;
  }
}

/**
 * Start serving, or print one clear line and exit non-zero.
 *
 * The returned promise resolves with the bound port and a stop function; it
 * rejects only for reasons other than "port busy" (which exits in here).
 */
export async function listenOrExit(
  app: Hono,
  options: { port: number; hostname?: string; label: string },
): Promise<{ port: number; close: () => void }> {
  const { port, hostname = "0.0.0.0", label } = options;
  try {
    const server = serve({ fetch: app.fetch, port, hostname });
    return await new Promise((resolvePromise, rejectPromise) => {
      const onError = (cause: Error): void => {
        server.off("error", onError);
        if ("code" in cause && (cause as NodeJS.ErrnoException).code === "EADDRINUSE") {
          process.stderr.write(
            `${label}: port ${port} is already in use. ` +
              `Stop the other process or set a different port.\n`,
          );
          process.exit(1);
        }
        rejectPromise(cause);
      };
      server.once("error", onError);
      // The listen callback fires once the socket is actually bound, which is
      // what makes "resolve" mean the port really is ours.
      server.once("listening", () => {
        server.off("error", onError);
        resolvePromise({
          port,
          close: () => {
            server.close();
          },
        });
      });
    });
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    process.stderr.write(`${label}: failed to start (${message})\n`);
    process.exit(1);
  }
}
