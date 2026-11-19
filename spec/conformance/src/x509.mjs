// A self-signed X.509 certificate made with node:crypto alone, for the suites that play a TLS server (a syslog
// collector over TLS, an HTTPS collector): a conformance kit that needs the openssl program would not run everywhere
// the kit does. The certificate is ECDSA over P-256 with SHA-256, valid for a day around now, and names the hosts it
// was made for in its subject alternative name. It is a trust anchor for the one connection that is given it as `ca`;
// it is not for anything else.

import { createPrivateKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

const len = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
};
const der = (tag, ...content) => {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
};
const seq = (...c) => der(0x30, ...c);
const set = (...c) => der(0x31, ...c);
const oid = (dotted) => {
  const parts = dotted.split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const group = [part & 0x7f];
    for (let v = part >> 7; v > 0; v >>= 7) group.unshift((v & 0x7f) | 0x80);
    bytes.push(...group);
  }
  return der(0x06, Buffer.from(bytes));
};
const integer = (buffer) => {
  let b = buffer;
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
  return der(0x02, b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
};
const utf8 = (text) => der(0x0c, Buffer.from(text, 'utf8'));
const bitString = (buffer, unused = 0) => der(0x03, Buffer.from([unused]), buffer);
const utcTime = (date) => der(0x17, Buffer.from(`${date.toISOString().slice(2, 19).replace(/[-:T]/g, '')}Z`, 'ascii'));
const name = (commonName) => seq(set(seq(oid('2.5.4.3'), utf8(commonName))));
const ECDSA_SHA256 = seq(oid('1.2.840.10045.4.3.2'));

const pem = (label, buffer) => `-----BEGIN ${label}-----\n${buffer.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END ${label}-----\n`;

/**
 * @param {{ commonName?: string, dns?: string[], ips?: string[], now?: Date }} [options]
 * @returns {{ cert: string, key: string }} PEM certificate and PKCS#8 private key
 */
export function selfSignedCertificate({ commonName = 'localhost', dns = ['localhost'], ips = ['127.0.0.1'], now = new Date() } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const names = [
    ...dns.map((host) => der(0x82, Buffer.from(host, 'ascii'))),
    ...ips.map((ip) => der(0x87, Buffer.from(ip.split('.').map(Number)))),
  ];
  const extensions = der(0xa3, seq(
    seq(oid('2.5.29.19'), der(0x01, Buffer.from([0xff])), der(0x04, seq(der(0x01, Buffer.from([0xff]))))), // basicConstraints: CA
    seq(oid('2.5.29.15'), der(0x01, Buffer.from([0xff])), der(0x04, bitString(Buffer.from([0x86]), 1))), // keyUsage: digitalSignature, keyCertSign, cRLSign
    seq(oid('2.5.29.37'), der(0x04, seq(oid('1.3.6.1.5.5.7.3.1')))), // extKeyUsage: serverAuth
    seq(oid('2.5.29.17'), der(0x04, seq(...names))), // subjectAltName
  ));
  const tbs = seq(
    der(0xa0, der(0x02, Buffer.from([2]))), // v3
    integer(Buffer.concat([Buffer.from([0x01]), randomBytes(15)])),
    ECDSA_SHA256,
    name(commonName),
    seq(utcTime(new Date(now.getTime() - 3_600_000)), utcTime(new Date(now.getTime() + 86_400_000))),
    name(commonName),
    spki,
    extensions,
  );
  const signature = sign('sha256', tbs, { key: createPrivateKey(privateKey.export({ type: 'pkcs8', format: 'pem' })), dsaEncoding: 'der' });
  const certificate = seq(tbs, ECDSA_SHA256, bitString(signature));
  return { cert: pem('CERTIFICATE', certificate), key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}
