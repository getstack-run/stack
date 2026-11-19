import { deployment } from '../deployment/index.js';

/**
 * The page and the parts every transactional email is built from. The templates in `transactional.ts` say what an email
 * contains; the chrome says how it looks and who a person writes to about it.
 *
 * The engine's own chrome is neutral: system fonts, no logo, nothing loaded from anyone's server (so opening an email
 * tells no third party), and a footer that names the install. A deployment with its own look registers its chrome once at
 * boot with `setEmailChrome`; STACK's hosted deployment does that with a chrome of its own.
 */
export interface EmailChrome {
  /** The whole page around the body markup of one email. */
  shell(content: string): string;
  /** The email's one heading. Plain text: the chrome escapes it. */
  title(text: string): string;
  /** A paragraph. Plain text: the chrome escapes it. `after` is the space below it in pixels (18 unless given). */
  paragraph(text: string, after?: number): string;
  /** Small print under the main content. Markup, so a caller escapes what it puts in. `top` is the space above in pixels. */
  note(html: string, top?: number): string;
  /** A call to action. */
  button(label: string, url: string): string;
  /** A short label above the heading, such as a severity. Plain text. */
  eyebrow(text: string): string;
  /** A table of label and value pairs; pairs with no value are left out. */
  rows(rows: Array<[string, string | null]>): string;
  /** A short code the person types somewhere. Plain text. */
  code(text: string): string;
  /** A link inside note text. Plain label: the chrome escapes it. */
  link(label: string, url: string): string;
  /** The sentence that tells a person where to turn when an email about their account was not their doing. */
  securityLine(): string;
  /** A footer the mail service appends to every message it sends through a provider, or null for none. */
  signature(): { text: string; html: string } | null;
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
const MONO = 'Consolas,Monaco,monospace';

/**
 * The contact an install gives for security concerns, set with STACK_SECURITY_CONTACT (an email address or a link). An
 * install that sets none gives none, and the emails send the person to the install's administrator instead.
 */
export function configuredSecurityContact(env: Record<string, string | undefined> = process.env): string | null {
  const value = env['STACK_SECURITY_CONTACT']?.trim();
  return value ? value : null;
}

export const neutralEmailChrome: EmailChrome = {
  shell(content) {
    const host = escapeHtml(new URL(deployment().siteUrl).host);
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
  </head>
  <body style="margin:0;background:#ffffff;color:#1f1f1f;font-family:${FONT};overflow-wrap:anywhere;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;font-family:${FONT};">
      <tr><td align="center">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:560px;">
          <tr><td style="padding:40px 24px 48px;">
            ${content}
            <div style="border-top:1px solid #d6d6d6;margin-top:40px;padding-top:18px;color:#6b6b6b;font-size:12px;line-height:1.5;">
              ${host}
            </div>
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>`;
  },
  title: (text) => `<h1 style="font-size:24px;line-height:1.2;margin:0 0 18px;">${escapeHtml(text)}</h1>`,
  paragraph: (text, after = 18) =>
    `<p style="font-size:16px;line-height:1.6;margin:0 0 ${after}px;color:#3d3d3d;">${escapeHtml(text)}</p>`,
  note: (html, top = 24) => `<p style="font-size:13px;line-height:1.55;margin:${top}px 0 0;color:#6b6b6b;">${html}</p>`,
  button: (label, url) =>
    `<a href="${escapeHtml(url)}" style="display:inline-block;background:#1f1f1f;color:#ffffff;padding:12px 18px;text-decoration:none;font-size:14px;font-weight:700;">${escapeHtml(label)}</a>`,
  eyebrow: (text) => `<div style="font-size:12px;font-weight:700;letter-spacing:.08em;color:#6b6b6b;margin-bottom:14px;">${escapeHtml(text)}</div>`,
  rows(rows) {
    const visible = rows.filter((row): row is [string, string] => Boolean(row[1]));
    if (visible.length === 0) return '';
    return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 28px;border-top:1px solid #d6d6d6;">${visible
      .map(
        ([label, value]) =>
          `<tr><td style="width:110px;padding:10px 12px 10px 0;border-bottom:1px solid #d6d6d6;color:#6b6b6b;font-size:12px;vertical-align:top;">${escapeHtml(label)}</td><td style="padding:10px 0;border-bottom:1px solid #d6d6d6;font-family:${MONO};font-size:13px;line-height:1.45;vertical-align:top;overflow-wrap:anywhere;">${escapeHtml(value)}</td></tr>`,
      )
      .join('')}</table>`;
  },
  code: (text) =>
    `<div style="font-family:${MONO};font-size:24px;font-weight:700;letter-spacing:.16em;background:#f1f1f1;padding:12px 16px;display:inline-block;">${escapeHtml(text)}</div>`,
  link: (label, url) => `<a href="${escapeHtml(url)}" style="color:#6b6b6b;">${escapeHtml(label)}</a>`,
  signature: () => null,
  securityLine() {
    const contact = configuredSecurityContact();
    return contact ? `If this was not you, contact ${contact} immediately.` : 'If this was not you, contact your administrator immediately.';
  },
};

let active: EmailChrome | null = null;

/** Use `chrome` for every email this process renders from now on; null goes back to the neutral one. Called once at boot. */
export function setEmailChrome(chrome: EmailChrome | null): void {
  active = chrome;
}

export function emailChrome(): EmailChrome {
  return active ?? neutralEmailChrome;
}
