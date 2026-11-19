import { describe, it, expect } from 'vitest';
import { parseRawEmail, parseRfc822, parseAddressList, strictBase64Decode, RFC822_LIMITS } from './rfc822.js';
import { normalizeRequest } from './constraints.js';
import { deriveRequestEmail } from './derived-email.js';

const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
const parse = (s: string) => parseRfc822(Buffer.from(s, 'utf8'));

const simple = [
  'From: Agent <agent@acme.com>',
  'To: Alice <alice@acme.com>',
  'Subject: Q3 numbers',
  '',
  'Balance is 1,234,567.89',
].join('\r\n');

describe('rfc822 headers', () => {
  it('reads To, Cc, Bcc and From from a plain message', () => {
    const parsed = parse([
      'From: agent@acme.com',
      'To: Alice <Alice@Acme.com>, bob@acme.com',
      'Cc: "Carol, CFO" <carol@acme.com>',
      'Bcc: dave@acme.com',
      'Subject: hi',
      '',
      'body',
    ].join('\r\n'));
    expect(parsed?.recipients).toEqual(['alice@acme.com', 'bob@acme.com', 'carol@acme.com', 'dave@acme.com']);
    expect(parsed?.from).toEqual(['agent@acme.com']);
    expect(parsed?.text).toContain('body');
  });

  it('finds a Bcc hidden on a folded continuation line', () => {
    const parsed = parse('To: alice@acme.com\r\nSubject: x\r\nBcc: alice@acme.com,\r\n\tattacker@evil.com\r\n\r\nhi');
    expect(parsed?.recipients).toContain('attacker@evil.com');
  });

  it('finds every repeated recipient header, in any case, including Resent-*', () => {
    const parsed = parse('To: alice@acme.com\r\nbCC: one@evil.com\r\nBCC : two@evil.com\r\nResent-To: three@evil.com\r\n\r\nx');
    expect(parsed?.recipients).toEqual(expect.arrayContaining(['one@evil.com', 'two@evil.com', 'three@evil.com', 'alice@acme.com']));
  });

  it('accepts LF-only line ends', () => {
    expect(parse('To: alice@acme.com\nBcc: x@evil.com\n\nbody')?.recipients).toEqual(['alice@acme.com', 'x@evil.com']);
  });

  it('reads group syntax, including an empty group', () => {
    const parsed = parse('To: undisclosed-recipients:;\r\nCc: Team: a@acme.com, "B" <b@acme.com>;, c@acme.com\r\n\r\nx');
    expect(parsed?.recipients).toEqual(['a@acme.com', 'b@acme.com', 'c@acme.com']);
  });

  it('ignores comments but still finds the address', () => {
    expect(parse('To: alice@acme.com (Alice (the CFO))\r\n\r\nx')?.recipients).toEqual(['alice@acme.com']);
  });

  it('decodes an encoded-word display name and keeps the real address', () => {
    const parsed = parse('To: =?UTF-8?B?w4lyaWMsIENGTw==?= <eric@acme.com>\r\nSubject: =?utf-8?q?R=C3=A9sum=C3=A9?=\r\n\r\nx');
    expect(parsed?.recipients).toEqual(['eric@acme.com']);
    expect(parsed?.subject).toBe('Résumé');
  });

  it('refuses an address hidden inside an encoded word', () => {
    expect(parse('To: =?utf-8?q?attacker=40evil.com?=\r\n\r\nx')).toBeNull();
    expect(parse('To: =?utf-8?q?=3Cattacker=40evil.com=3E?= <alice@acme.com>\r\n\r\nx')).toBeNull();
    expect(parse('Bcc: =?utf-8?B?YXR0YWNrZXJAZXZpbC5jb20=?=\r\n\r\nx')).toBeNull();
  });

  it('refuses an undecodable encoded word in a recipient header', () => {
    expect(parse('To: =?x-unknown-charset?Q?hi?= <a@acme.com>\r\n\r\nx')).toBeNull();
    expect(parse('To: =?utf-8?Q?broken <a@acme.com>\r\n\r\nx')).toBeNull();
  });

  it('refuses malformed headers rather than guessing', () => {
    expect(parse(' To: leading-continuation@acme.com\r\n\r\nx')).toBeNull();
    expect(parse('To alice@acme.com\r\n\r\nx')).toBeNull();
    expect(parse('To: alice@acme.com\rBcc: hidden@evil.com\r\n\r\nx')).toBeNull();
    expect(parse('To: alice@acme.com\u0000\r\n\r\nx')).toBeNull();
    expect(parse('To: alice@acme.com, bob\r\n\r\nx')).toBeNull();
    expect(parse('To: "unterminated <a@acme.com>\r\n\r\nx')).toBeNull();
    expect(parse('To: <a@acme.com> <b@evil.com>\r\n\r\nx')).toBeNull();
    expect(parse('To: evil@x.com <alice@acme.com>\r\n\r\nx')).toBeNull();
    expect(parse('To: <@route.com:a@acme.com>\r\n\r\nx')).toBeNull();
    expect(parse('To: "quoted local"@acme.com\r\n\r\nx')).toBeNull();
    expect(parse('To: Group: a@acme.com\r\n\r\nx')).toBeNull();
    expect(parse('To: a(unclosed comment@acme.com\r\n\r\nx')).toBeNull();
    expect(parse('To: josé@acme.com\r\n\r\nx')).toBeNull();
  });

  it('caps comment nesting', () => {
    const deep = '('.repeat(RFC822_LIMITS.maxCommentDepth + 1) + ')'.repeat(RFC822_LIMITS.maxCommentDepth + 1);
    expect(parseAddressList(`a@acme.com ${deep}`)).toBeNull();
  });

  it('refuses an oversized header block and oversized input', () => {
    const big = `X-Pad: ${'a'.repeat(RFC822_LIMITS.maxHeaderBytes)}\r\nTo: a@acme.com\r\n\r\nx`;
    expect(parse(big)).toBeNull();
    expect(parseRawEmail('A'.repeat(RFC822_LIMITS.maxEncodedChars + 4), 'base64url')).toBeNull();
  });

  it('runs in linear time on adversarial address input', () => {
    const hostile = `To: ${'a.'.repeat(50_000)}@${'b-'.repeat(50_000)}\r\n\r\nx`;
    const started = Date.now();
    parse(hostile);
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});

describe('rfc822 base64 decoding', () => {
  it('round-trips base64url', () => {
    expect(parseRawEmail(b64url(simple), 'base64url')?.recipients).toEqual(['alice@acme.com']);
  });

  it('refuses characters outside the alphabet instead of skipping them', () => {
    const encoded = b64url(simple);
    expect(parseRawEmail(`${encoded.slice(0, 8)}*${encoded.slice(8)}`, 'base64url')).toBeNull();
    expect(strictBase64Decode('QUJD+0FC', 'base64url')).toBeNull(); // standard-alphabet "+" in base64url
    expect(strictBase64Decode('QUJD-0FC', 'base64')).toBeNull();    // url-alphabet "-" in standard base64
    expect(strictBase64Decode('QUJD 0FC', 'base64url')).toBeNull(); // whitespace is not skipped
    expect(strictBase64Decode('abc', 'base64url')?.toString('latin1')).toBe(Buffer.from('abc', 'base64url').toString('latin1'));
    expect(strictBase64Decode('a', 'base64url')).toBeNull();
    expect(strictBase64Decode('ab===', 'base64')).toBeNull();
  });

  it('refuses non-string and empty input', () => {
    expect(parseRawEmail(undefined, 'base64url')).toBeNull();
    expect(parseRawEmail({ raw: 'x' }, 'base64url')).toBeNull();
    expect(parseRawEmail('', 'base64url')).toBeNull();
  });

  it('refuses a media-upload string that cannot be octets', () => {
    expect(parseRawEmail('To: a@acme.com\r\n\r\n€', 'none')).toBeNull();
  });
});

describe('rfc822 body text', () => {
  it('decodes quoted-printable and base64 text parts in a multipart message', () => {
    const msg = [
      'To: alice@acme.com',
      'Subject: report',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="b1"',
      '',
      'preamble 42',
      '--b1',
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      'Account 12345678 has =E2=82=AC1,000',
      '--b1',
      'Content-Type: text/csv',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('iban,amount\nSE45 5000,99.10').toString('base64'),
      '--b1',
      'Content-Type: image/png',
      'Content-Transfer-Encoding: base64',
      '',
      'iVBORw0KGgo=',
      '--b1--',
      'epilogue 7',
    ].join('\r\n');
    const parsed = parse(msg);
    expect(parsed?.text).toContain('Account 12345678 has €1,000');
    expect(parsed?.text).toContain('SE45 5000,99.10');
    expect(parsed?.text).toContain('preamble 42');
    expect(parsed?.text).toContain('epilogue 7');
    expect(parsed?.opaque_parts).toBe(1);
  });

  it('reads a header-less MIME part as text/plain', () => {
    const msg = 'To: a@acme.com\r\nContent-Type: multipart/alternative; boundary=x\r\n\r\n--x\r\n\r\nplain part\r\n--x--\r\n';
    expect(parse(msg)?.text).toContain('plain part');
  });

  it('refuses malformed MIME', () => {
    expect(parse('To: a@acme.com\r\nContent-Type: multipart/mixed\r\n\r\nno boundary')).toBeNull();
    expect(parse('To: a@acme.com\r\nContent-Type: multipart/mixed; boundary=z\r\n\r\n--z\r\n\r\nnever closed')).toBeNull();
    expect(parse('To: a@acme.com\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!notbase64')).toBeNull();
    expect(parse('To: a@acme.com\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbody')).toBeNull();
    expect(parse('To: a@acme.com\r\nContent-Type: text/plain\r\nContent-Type: text/html\r\n\r\nbody')).toBeNull();
  });

  it('caps MIME nesting depth', () => {
    let body = 'leaf';
    for (let d = 0; d <= RFC822_LIMITS.maxMimeDepth + 1; d++) {
      body = `Content-Type: multipart/mixed; boundary=d${d}\r\n\r\n--d${d}\r\n${body}\r\n--d${d}--`;
    }
    expect(parse(`To: a@acme.com\r\n${body}`)).toBeNull();
  });

  it('does not count recipients of a forwarded message attachment', () => {
    const msg = [
      'To: alice@acme.com',
      'Content-Type: multipart/mixed; boundary=f',
      '',
      '--f',
      'Content-Type: message/rfc822',
      '',
      'To: someone-else@other.com',
      'Subject: inner',
      '',
      'inner body',
      '--f--',
    ].join('\r\n');
    const parsed = parse(msg);
    expect(parsed?.recipients).toEqual(['alice@acme.com']);
    expect(parsed?.text).toContain('inner body');
  });
});

describe('deriveRequestEmail', () => {
  const gmail = (body: unknown, url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', method = 'POST') =>
    normalizeRequest({ method, url, body, headers: {}, query: {} } as never);

  it('reads every Gmail recipient from raw, including a Bcc on a folded line', () => {
    expect(deriveRequestEmail(gmail({ raw: b64url(simple) }))?.recipients).toEqual(['alice@acme.com']);
    const sneaky = 'To: alice@acme.com\r\nBcc: alice@acme.com,\r\n attacker@evil.com\r\n\r\nx';
    expect(deriveRequestEmail(gmail({ raw: b64url(sneaky) }))?.recipients).toEqual(['alice@acme.com', 'attacker@evil.com']);
  });

  it('exposes the decoded text for content inspection', () => {
    const derived = deriveRequestEmail(gmail({ raw: b64url(simple) }));
    expect(derived?.provider).toBe('gmail');
    expect(derived?.text).toContain('1,234,567.89');
  });

  it('refuses an unparseable message', () => {
    expect(deriveRequestEmail(gmail({ raw: 'not base64!' }))).toBeUndefined();
    expect(deriveRequestEmail(gmail({}))).toBeUndefined();
  });

  it('reads drafts but not a draft sent by id', () => {
    expect(deriveRequestEmail(gmail({ message: { raw: b64url(simple) } }, 'https://gmail.googleapis.com/gmail/v1/users/me/drafts'))).toBeDefined();
    expect(deriveRequestEmail(gmail({ id: 'r123' }, 'https://gmail.googleapis.com/gmail/v1/users/me/drafts/send'))).toBeUndefined();
  });

  it('reads a simple media upload and refuses multipart or resumable uploads', () => {
    const upload = (uploadType: string, body: unknown) => normalizeRequest({ method: 'POST',
      url: 'https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send', body, headers: {}, query: { uploadType } } as never);
    expect(deriveRequestEmail(upload('media', simple))?.recipients).toEqual(['alice@acme.com']);
    expect(deriveRequestEmail(upload('media', 'To: attacker@evil.com\r\n\r\nx'))?.recipients).toEqual(['attacker@evil.com']);
    expect(deriveRequestEmail(upload('multipart', simple))).toBeUndefined();
    expect(deriveRequestEmail(upload('resumable', simple))).toBeUndefined();
  });

  it('does not derive on other hosts or endpoints', () => {
    expect(deriveRequestEmail(gmail({ raw: b64url(simple) }, 'https://evil.example/gmail/v1/users/me/messages/send'))).toBeUndefined();
    expect(deriveRequestEmail(gmail({ raw: b64url(simple) }, 'https://gmail.googleapis.com/gmail/v1/users/me/messages/import'))).toBeUndefined();
  });

  it('derives Outlook recipients from JSON and from MIME', () => {
    const graph = (body: unknown, path = '/v1.0/me/sendMail') => normalizeRequest({ method: 'POST', url: `https://graph.microsoft.com${path}`, body, headers: {}, query: {} } as never);
    const json = { message: { subject: 's', toRecipients: [{ emailAddress: { address: 'alice@acme.com' } }],
      bccRecipients: [{ emailAddress: { address: 'Attacker@Evil.com' } }] } };
    expect(deriveRequestEmail(graph(json))?.recipients).toEqual(['alice@acme.com', 'attacker@evil.com']);
    expect(deriveRequestEmail(graph(Buffer.from(simple).toString('base64')))?.recipients).toEqual(['alice@acme.com']);
    expect(deriveRequestEmail(graph({ message: { toRecipients: [{ emailAddress: {} }] } }))).toBeUndefined();
    expect(deriveRequestEmail(graph({ toRecipients: [{ emailAddress: { address: 'x@evil.com' } }] }, '/v1.0/me/messages/AAA/forward'))?.recipients).toEqual(['x@evil.com']);
    expect(deriveRequestEmail(graph({ comment: 'hi' }, '/v1.0/me/messages/AAA/reply'))).toBeUndefined();
  });
});
