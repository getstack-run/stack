import { createServer, type Server, type Socket } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import nodemailer from 'nodemailer';
import { SmtpEmailError, SmtpEmailService, smtpConfigFromUrl } from './smtp-email-service.js';

interface Received {
  from: string;
  to: string[];
  data: string;
}

/** A plain SMTP server on loopback that records what it is sent, and can refuse a recipient. */
function fakeSmtpServer(options: { refuseRecipient?: string } = {}): Promise<{
  port: number;
  received: Received[];
  close: () => Promise<void>;
}> {
  const received: Received[] = [];
  const sockets = new Set<Socket>();
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.setEncoding('utf8');
    let current: Received = { from: '', to: [], data: '' };
    let inData = false;
    let buffer = '';
    socket.write('220 fake.smtp ESMTP\r\n');
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      for (;;) {
        if (inData) {
          const end = buffer.indexOf('\r\n.\r\n');
          if (end === -1) return;
          current.data = buffer.slice(0, end);
          buffer = buffer.slice(end + 5);
          inData = false;
          received.push(current);
          current = { from: '', to: [], data: '' };
          socket.write('250 queued\r\n');
          continue;
        }
        const eol = buffer.indexOf('\r\n');
        if (eol === -1) return;
        const line = buffer.slice(0, eol);
        buffer = buffer.slice(eol + 2);
        const verb = line.slice(0, 4).toUpperCase();
        if (verb === 'EHLO' || verb === 'HELO') socket.write('250 fake.smtp\r\n');
        else if (verb === 'MAIL') {
          current.from = /<([^>]*)>/.exec(line)?.[1] ?? '';
          socket.write('250 ok\r\n');
        } else if (verb === 'RCPT') {
          const rcpt = /<([^>]*)>/.exec(line)?.[1] ?? '';
          if (options.refuseRecipient && rcpt === options.refuseRecipient) {
            socket.write('550 no such user\r\n');
          } else {
            current.to.push(rcpt);
            socket.write('250 ok\r\n');
          }
        } else if (verb === 'DATA') {
          inData = true;
          socket.write('354 go\r\n');
        } else if (verb === 'QUIT') {
          socket.write('221 bye\r\n');
          socket.end();
        } else socket.write('250 ok\r\n');
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      resolve({
        port,
        received,
        close: () =>
          new Promise<void>((done) => {
            for (const socket of sockets) socket.destroy();
            server.close(() => done());
          }),
      });
    });
  });
}

let closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(closers.map((close) => close()));
  closers = [];
});

describe('SmtpEmailService', () => {
  it('delivers the message exactly as composed, from the configured sender, with nothing appended', async () => {
    const smtp = await fakeSmtpServer();
    closers.push(smtp.close);
    const service = new SmtpEmailService({
      host: '127.0.0.1',
      port: smtp.port,
      secure: false,
      from: 'STACK <stack@corp.example>',
      replyTo: 'secops@corp.example',
    });
    const { id } = await service.sendEmail('ops@corp.example', 'Review needed', 'plain body', '<p>html body</p>', {
      skipSignature: true,
    });
    expect(id).toMatch(/@/);
    expect(smtp.received).toHaveLength(1);
    const message = smtp.received[0]!;
    expect(message.from).toBe('stack@corp.example');
    expect(message.to).toEqual(['ops@corp.example']);
    expect(message.data).toContain('Subject: Review needed');
    expect(message.data).toContain('Reply-To: secops@corp.example');
    expect(message.data).toContain('plain body');
    expect(message.data).toContain('html body');
    expect(message.data).not.toContain('getstack.run');
  });

  it('reports a refused recipient as a permanent rejection without echoing the address', async () => {
    const smtp = await fakeSmtpServer({ refuseRecipient: 'gone@corp.example' });
    closers.push(smtp.close);
    const service = new SmtpEmailService({
      host: '127.0.0.1',
      port: smtp.port,
      secure: false,
      from: 'stack@corp.example',
    });
    const failure = await service.sendEmail('gone@corp.example', 's', 't').catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(SmtpEmailError);
    expect((failure as SmtpEmailError).code).toBe(550);
    expect((failure as SmtpEmailError).permanent).toBe(true);
    expect(String((failure as Error).message)).not.toContain('gone@corp.example');
  });

  it('treats an unreachable relay as retriable', async () => {
    const smtp = await fakeSmtpServer();
    const port = smtp.port;
    await smtp.close();
    const service = new SmtpEmailService({
      host: '127.0.0.1',
      port,
      secure: false,
      from: 'stack@corp.example',
      requestTimeoutMs: 1_000,
    });
    const failure = await service.sendEmail('a@corp.example', 's', 't').catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(SmtpEmailError);
    expect((failure as SmtpEmailError).permanent).toBe(false);
  });

  it('refuses a recipient that could inject another header or address', async () => {
    const service = new SmtpEmailService(
      { host: 'relay.corp.example', port: 587, secure: false, from: 'stack@corp.example' },
      nodemailer.createTransport({ jsonTransport: true }),
    );
    for (const to of ['a@corp.example\r\nBcc: x@evil.example', 'a@corp.example, b@corp.example', 'not-an-address']) {
      await expect(service.sendEmail(to, 's', 't')).rejects.toBeInstanceOf(SmtpEmailError);
    }
  });
});

describe('SMTP configuration', () => {
  it('reads an smtps URL with credentials and an smtp URL with a default port', () => {
    const secure = smtpConfigFromUrl('smtps://user%40corp:p%40ss@relay.corp.example', { from: 'stack@corp.example' });
    expect(secure).toMatchObject({ host: 'relay.corp.example', port: 465, secure: true, user: 'user@corp', password: 'p@ss' });
    const starttls = smtpConfigFromUrl('smtp://relay.corp.example:2525', { from: 'stack@corp.example' });
    expect(starttls).toMatchObject({ port: 2525, secure: false });
    expect(starttls.user).toBeUndefined();
  });

  it('refuses a URL of another kind, a missing sender, and half a credential', () => {
    expect(() => smtpConfigFromUrl('https://relay.corp.example', { from: 'a@b.example' })).toThrow(/smtp:\/\//);
    expect(() => smtpConfigFromUrl('not a url', { from: 'a@b.example' })).toThrow(/not a valid URL/);
    expect(() => new SmtpEmailService({ host: 'h', port: 587, secure: false, from: '' })).toThrow(/EMAIL_FROM/);
    expect(
      () => new SmtpEmailService({ host: 'h', port: 587, secure: false, from: 'a@b.example', user: 'u' }),
    ).toThrow(/together/);
  });
});
