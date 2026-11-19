import { createServer, type Server, type Socket } from 'node:net';

/**
 * A TCP server that accepts a connection and never answers: a Redis that
 * resolves and accepts TCP but never answers. A client on it never
 * reconnects, so only a command timeout ends a command.
 */
export async function startSilentRedis(): Promise<{ url: string; stop: () => Promise<void> }> {
  const sockets = new Set<Socket>();
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('silent redis did not bind a port');
  return {
    url: `redis://127.0.0.1:${address.port}`,
    stop: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
