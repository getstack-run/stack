// Asking the person through the MCP client (elicitation).
//
// A client that supports elicitation renders a request to the person and
// returns the answer to this server, never to the model, so a prompt-injected
// model cannot answer it. The engine uses it for one thing: opening the
// approval page of a pending governance approval in the person's browser
// (URL-mode elicitation). The decision itself is made on that page.
//
// What a deployment can add on top of this (asking in the chat and relaying the
// answer with an attestation) is a `ToolCallConfirmer` passed to the server;
// see governance-confirm.ts. Doctrine: the governance step-up design.

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

/** How long a person has to answer a request made through the client. */
export const CHAT_CONFIRMATION_TIMEOUT_MS = 10 * 60 * 1000;

/** Options the transport passes for one MCP session. */
export interface ChatConfirmationOptions {
  /** Shared with the API. Absent or shorter than 32 characters: approvals fall back to the approval link. */
  attestationKey?: string;
  /** The MCP session id. Read lazily; it is assigned after initialize. */
  sessionId?: () => string | undefined;
  /** `operator:<id>` or `member:<id>` from /v1/auth/context. */
  principal?: string;
  /** True only when the session's bearer is an OAuth access token. */
  oauth?: boolean;
  /** Called with +1 when an elicitation starts and -1 when it settles. */
  onElicitationPending?: (delta: 1 | -1) => void;
  /** Override for tests. */
  timeoutMs?: number;
}

/** The `extra` the SDK passes to a tool handler, as far as this module needs it. */
export interface ToolCallExtra {
  requestId: string | number;
  signal?: AbortSignal;
}

const toolCall = new AsyncLocalStorage<ToolCallExtra>();

/** Run a tool handler with its request context available to nested API calls. */
export function runInToolCall<T>(extra: ToolCallExtra, fn: () => T): T {
  return toolCall.run(extra, fn);
}

export function currentToolCall(): ToolCallExtra | undefined {
  return toolCall.getStore();
}

export interface ApprovalDetail {
  approval: {
    id: string;
    action: string;
    resource_id: string;
    summary: string;
    status: string;
    expires_at: string;
    requested_via?: string;
    /** What an `agent_setup` covers, in full. */
    setup_preview?: unknown;
    /** What a widened grant covers, in full. */
    grant_preview?: unknown;
    /** What an intent approval covers: the lines the API built from the stored intent. */
    intent_preview?: unknown;
  };
  payload_hash: string;
  approval_url: string;
}

export type ChatDecision = 'approved' | 'rejected' | 'unavailable';

/** The requests one MCP session can make of its client, on the stream of the tool call in progress. */
export class Elicitor {
  constructor(
    readonly mcp: McpServer,
    private readonly options: Pick<ChatConfirmationOptions, 'onElicitationPending' | 'timeoutMs'>,
  ) {}

  /** What the connected client says it can render. */
  capabilities() {
    return this.mcp.server.getClientCapabilities()?.elicitation;
  }

  canOpenUrl(): boolean {
    return Boolean(this.capabilities()?.url);
  }

  /** Runs a request made of the client, counting it as pending while the person has not answered. */
  async run<T>(fn: (extra: ToolCallExtra) => Promise<T>): Promise<T> {
    const extra = currentToolCall();
    if (!extra) throw new Error('no tool call in progress');
    this.options.onElicitationPending?.(1);
    try {
      return await fn(extra);
    } finally {
      this.options.onElicitationPending?.(-1);
    }
  }

  requestOptions(extra: ToolCallExtra) {
    return {
      relatedRequestId: extra.requestId,
      timeout: this.options.timeoutMs ?? CHAT_CONFIRMATION_TIMEOUT_MS,
      ...(extra.signal ? { signal: extra.signal } : {}),
    };
  }

  /** Open the approval page in the person's browser (URL-mode elicitation). True once they say they are done. */
  async openApprovalPage(detail: { id: string; approval_url: string }): Promise<boolean> {
    const result = await this.run((extra) => this.mcp.server.elicitInput({
      mode: 'url',
      message: 'Open STACK to approve or reject this change. Return here when you are done.',
      url: detail.approval_url,
      elicitationId: randomUUID(),
    }, this.requestOptions(extra)));
    return result.action === 'accept';
  }
}
