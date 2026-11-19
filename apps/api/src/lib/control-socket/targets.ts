// What a decision request says about each kind of action. One function per
// kind, each naming exactly the fields that leave STACK. Nothing here reads a
// message body, subject, prompt, model output, code, page text, typed text, call
// instruction, card number, credential or Passport token.
//
// Recipients are the customer's own agents' counterparts, sent to the
// customer's own server as plain addresses plus the domain: the customer
// chose them, and this is no new disclosure (one DPA and privacy-notice line
// covers it). Query strings are dropped from every URL, since they carry
// tokens and identifiers.

import type { ControlDecisionRequest } from '@stack/shared';

type Target = Record<string, unknown>;
type Amount = ControlDecisionRequest['amount'];

/** An origin and a path with no query or fragment, or nulls for something that is not a URL. */
export function originAndPath(raw: string): { origin: string | null; host: string | null; path: string | null } {
  try {
    const url = new URL(raw);
    return { origin: url.origin, host: url.host, path: url.pathname };
  } catch {
    return { origin: null, host: null, path: null };
  }
}

function emailDomain(address: string): string {
  const at = address.lastIndexOf('@');
  return at === -1 ? '' : address.slice(at + 1).toLowerCase();
}

export const controlTargets = {
  modelCall(input: { provider: string; model: unknown; stream: boolean; maxOutputTokens: number | null }): Target {
    return {
      provider: input.provider,
      model: typeof input.model === 'string' ? input.model.slice(0, 200) : null,
      stream: input.stream,
      max_output_tokens: input.maxOutputTokens,
    };
  },

  proxyCall(input: { service: string; connectionId: string | null; method: string; url: string }): Target {
    const { host, path } = originAndPath(input.url);
    return { service: input.service, connection_id: input.connectionId, method: input.method, host, path };
  },

  toolRun(input: { provider: string; endpoint: string; tool?: string }): Target {
    return { provider: input.provider, endpoint: input.endpoint, ...(input.tool ? { tool: input.tool } : {}) };
  },

  /** Everyone the email reaches: To, Cc and Bcc alike, once each (the decider is told who, never in which of them). */
  emailSend(input: { to: string | readonly string[] }): Target {
    const addresses = typeof input.to === 'string' ? [input.to] : input.to;
    return {
      recipients: addresses.map((address) => ({ address: address.toLowerCase(), domain: emailDomain(address) })),
      recipient_count: addresses.length,
    };
  },

  smsSend(input: { to: string }): Target {
    return { recipients: [{ number: input.to }], recipient_count: 1 };
  },

  /** The chat an agent answers on its own Telegram bot: its Telegram id (a number, or a negative one for a group), never the text. */
  telegramSend(input: { chatId: string }): Target {
    return { recipients: [{ chat_id: input.chatId }], recipient_count: 1 };
  },

  callStart(input: { to: string; maxSeconds: number }): Target {
    return { recipients: [{ number: input.to }], recipient_count: 1, max_seconds: input.maxSeconds };
  },

  /**
   * An incoming call the agent answers: who is calling (the number in E.164, or null when it was withheld or is not a number)
   * and what the carrier vouches for it with (STIR/SHAKEN: A, B or C, or null), and the longest the conversation may last.
   * A caller's number can be faked; the attestation is what the carrier checked.
   */
  callAnswer(input: { caller: string | null; attestation: 'A' | 'B' | 'C' | null; maxSeconds: number }): Target {
    return { caller: { number: input.caller, attestation: input.attestation }, max_seconds: input.maxSeconds };
  },

  /**
   * The agent joining the room of one of its own calendar events: the event's STACK id (never its title, guests or link) and the
   * longest the agent's part may last (null when the join names none: the event's own or the default applies).
   */
  meetingJoin(input: { eventId: string; maxSeconds: number | undefined }): Target {
    return { event_id: input.eventId, max_seconds: input.maxSeconds ?? null };
  },

  browserSessionStart(): Target {
    return {};
  },

  browserNavigate(input: { url: string }): Target {
    const { origin, path } = originAndPath(input.url);
    return { origin, path };
  },

  cardCheckout(input: { merchantOrigin: string; amountMinor: number; currency: string }): Target {
    return { merchant_origin: input.merchantOrigin, amount_minor: input.amountMinor, currency: input.currency.toUpperCase() };
  },

  /** A wallet payment passed on to the wallet provider: the typed data is the payment itself (payee, amount, validity), the signature is not sent. */
  walletPayment(typedData: Record<string, unknown>): Target {
    const message = (typedData['message'] ?? {}) as Record<string, unknown>;
    const domain = (typedData['domain'] ?? {}) as Record<string, unknown>;
    const text = (value: unknown) => (typeof value === 'string' || typeof value === 'number' ? String(value).slice(0, 80) : null);
    return {
      chain_id: text(domain['chainId']),
      token: text(domain['verifyingContract']),
      payee: text(message['to']),
      amount: text(message['value']),
      valid_before: text(message['validBefore']),
    };
  },

  /**
   * A command in the agent's workspace: how long it may run and what it is given, never the command, which is code. A command
   * started in the background has no limit to name: `timeoutSeconds` is null, which a rule capping how long a command may run refuses.
   */
  workspaceExec(input: { newWorkspace: boolean; timeoutSeconds: number | null; stackAccess: boolean; commandBytes: number }): Target {
    return {
      new_workspace: input.newWorkspace,
      timeout_seconds: input.timeoutSeconds,
      stack_access: input.stackAccess,
      command_bytes: input.commandBytes,
    };
  },

  accountOpen(input: { name: string; skip: readonly string[] }): Target {
    return { name: input.name.slice(0, 120), skipped_pieces: [...input.skip] };
  },

  /** `toAgents` is every agent the drop-off names; `to_agent` is the first. */
  dropoffCreate(input: { toAgents: readonly string[] }): Target {
    return { to_agent: input.toAgents[0] ?? '', to_agents: [...input.toAgents] };
  },

  dropoffDeposit(input: { toAgents: readonly string[]; payloadBytes: number }): Target {
    return { to_agent: input.toAgents[0] ?? '', to_agents: [...input.toAgents], payload_bytes: input.payloadBytes };
  },

  a2aSend(input: { toAgent: string; messageBytes: number }): Target {
    return { to_agent: input.toAgent, message_bytes: input.messageBytes };
  },

  skillInvoke(input: { skillId: string }): Target {
    return { skill_id: input.skillId };
  },

  passportDelegate(input: { bindingId: string }): Target {
    return { binding_id: input.bindingId };
  },

  /** A wake-up starting the account's agent: which kind of event, never what it said. */
  wakeDeliver(input: { source: string; ruleId: string | null; scheduleId: string | null }): Target {
    return { source: input.source, rule_id: input.ruleId, schedule_id: input.scheduleId };
  },

  /** What is stored, never the file name (it can carry a person's name) or a byte of the file. */
  driveUpload(input: { contentType: string; bytes: number; visibility: string; expiresInSeconds: number | null }): Target {
    return {
      content_type: input.contentType,
      bytes: input.bytes,
      visibility: input.visibility,
      expires_in_seconds: input.expiresInSeconds,
    };
  },

  /** A write to the account's memory: which of the three it is (`add_memory`, `add_triplet` or `summarize_saga`) and how long. Never what it says. */
  memoryWrite(input: { change: 'add_memory' | 'add_triplet' | 'summarize_saga'; chars: number }): Target {
    return { change: input.change, chars: input.chars };
  },

  /** A change to the account's own entity types (`types`): what is done to which type, never its description or fields. */
  memoryTypes(input: { op: 'create' | 'change' | 'retire'; name: string }): Target {
    return { change: 'types', op: input.op, name: input.name };
  },

  /**
   * A delete from the account's memory: which it is (`delete_episode`, `delete_entity_edge`, or `undo_write`, taking a write
   * back out). Never the id or what it holds.
   */
  memoryDelete(input: { change: 'delete_episode' | 'delete_entity_edge' | 'undo_write' }): Target {
    return { change: input.change };
  },

  /** Files added to the account's brain: how many, the pages AWS is expected to bill for reading them (an estimate from their size and type). Never a name or what a file holds. */
  brainAdd(input: { files: number; pages: number }): Target {
    return { files: input.files, pages: input.pages };
  },

  /** A share link lets someone outside STACK read the file: the file and how long and how often. */
  driveShare(input: { fileId: string; ttlSeconds: number; maxDownloads: number | null }): Target {
    return { file_id: input.fileId, ttl_seconds: input.ttlSeconds, max_downloads: input.maxDownloads };
  },

  /**
   * A change to the agent's public website: a new bundle (counts and sizes,
   * never a file name or content), a new address (the hostname the customer
   * chose to serve it on) or new x402 prices (how many).
   */
  sitePublish(
    input:
      | { kind: 'files'; fileCount: number; totalBytes: number; hasServer: boolean }
      | { kind: 'hostname'; hostname: string }
      | { kind: 'prices'; priceCount: number },
  ): Target {
    if (input.kind === 'files') {
      return { kind: 'files', file_count: input.fileCount, total_bytes: input.totalBytes, has_server_code: input.hasServer };
    }
    if (input.kind === 'hostname') return { kind: 'hostname', hostname: input.hostname.toLowerCase() };
    return { kind: 'prices', price_count: input.priceCount };
  },

  /** A payment link or checkout session on the customer's own Stripe: the price, never a name or a URL. */
  paymentRequest(input: { kind: 'payment_link' | 'checkout_session'; amountMinor: number; currency: string }): Target {
    return { kind: input.kind, amount_minor: input.amountMinor, currency: input.currency.toLowerCase() };
  },

  /** A letter or postcard: where it goes by country and ZIP, never the recipient's name or street. */
  letterSend(input: { country: string; postal_code: string; kind: string; pages: number; color: boolean; mail_class: string; use_type: string; extra_service: string | null }): Target {
    return { ...input };
  },

  postScan(input: { itemId: string }): Target {
    return { item_id: input.itemId };
  },

  postForward(input: { itemId: string; state: string | null; postalCode: string }): Target {
    return { item_id: input.itemId, destination_state: input.state, destination_postal_code: input.postalCode };
  },

  postShred(input: { itemId: string }): Target {
    return { item_id: input.itemId };
  },

  /** A quote: what is to be made and where it goes by country only. The recipient's name and address never leave. */
  makingQuote(input: { supplier: string | null; designFormat: string; designSha256: string; quantity: number; country: string }): Target {
    return {
      supplier: input.supplier,
      design_format: input.designFormat,
      design_sha256: input.designSha256,
      quantity: input.quantity,
      destination_country: input.country,
    };
  },

  /** An order: the supplier, how it is paid, the design and the price. */
  makingOrder(input: { supplier: string; payment: string; designSha256: string; quantity: number; country: string; totalCents: number }): Target {
    return {
      supplier: input.supplier,
      payment: input.payment,
      design_sha256: input.designSha256,
      quantity: input.quantity,
      destination_country: input.country,
      total_cents: input.totalCents,
    };
  },
};

/**
 * What a wallet payment costs in USD cents (USDC has six decimals, so a cent is
 * 10,000 atomic units), rounded up, or null when the typed data carries no
 * readable amount.
 */
export function walletAmountCents(typedData: Record<string, unknown>): number | null {
  const message = (typedData['message'] ?? {}) as Record<string, unknown>;
  const raw = message['value'];
  const text = typeof raw === 'string' || typeof raw === 'number' ? String(raw) : null;
  if (text === null || !/^\d{1,30}$/.test(text)) return null;
  const cents = (BigInt(text) + 9_999n) / 10_000n;
  return cents <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(cents) : null;
}

/** An amount in cents (USD), or null when the action has no price of its own. */
export function usdAmount(maxCents: number | null): Amount {
  return maxCents === null ? null : { max_cents: maxCents, currency: 'USD' };
}
