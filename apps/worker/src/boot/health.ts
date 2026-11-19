import http from 'node:http';
import type { WorkerState } from '../runtime.js';

/**
 * Health endpoint for the hosting platform and external uptime monitoring. A tiny http server
 * bound to PORT (default 8080) that returns `{ ok: true }` on `/health` while
 * the worker process is alive.
 */
let started = false;

export function startHealthServer(state: WorkerState): void {
  // A boot retried after a Redis outage calls this again; one listener is enough.
  if (started) return;
  started = true;
  const healthPort = parseInt(process.env['PORT'] ?? '8080', 10);
  http
    .createServer((req, res) => {
      if (req.url === '/health' || req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            ok: true,
            ts: new Date().toISOString(),
            // null until the first CMEK tick (or always null when CMEK is
            // disabled in this worker process). The dashboard reads this
            // to render "last migration tick: 3s ago" on /security/encryption.
            cmek_tick_last_ran_at: state.cmekTickLastRanAt
              ? state.cmekTickLastRanAt.toISOString()
              : null,
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end('not found');
    })
    .listen(healthPort, '::', () => {
      console.log(`Worker health endpoint listening on :${healthPort}`);
    });
}
