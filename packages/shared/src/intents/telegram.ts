import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Telegram Bot API — https://core.telegram.org/bots/api. Base:
// api.telegram.org/bot{token}/{method}. The token is embedded in the
// URL path — we don't allowlist by token here (credential handles it)
// and match method names at the path's tail.
//
// Most scoping happens via body.chat_id (numeric for private chats,
// `@channelusername` or numeric for channels/groups).

const chatIdFmt = z.union([z.number().int(), z.string().min(1).max(128)]);
const chatIdList = z.union([chatIdFmt, z.array(chatIdFmt).min(1)]);
type ChatIdList = z.infer<typeof chatIdList>;

const toStringList = (v: ChatIdList): string[] => {
  const list = Array.isArray(v) ? v : [v];
  return list.map((x) => String(x));
};

function chatIdConstraint(chatId: ChatIdList): Constraint {
  const list = toStringList(chatId);
  return list.length === 1
    ? { path: 'body.chat_id', op: 'eq', value: list[0]! }
    : { path: 'body.chat_id', op: 'in', value: list };
}

function methodPath(method: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/bot[^/]+/${method}$`,
  };
}

export const telegramIntents = [
  defineIntent({
    name: 'telegram.send_message',
    effect: 'send',
    recipient_paths: ['body.chat_id'],
    description:
      'Send a text message to specific Telegram chats. Binds POST /bot{token}/sendMessage with body.chat_id allowlist.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('sendMessage'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.send_photo',
    effect: 'send',
    recipient_paths: ['body.chat_id'],
    description:
      'Send a photo to specific Telegram chats. Binds POST /bot{token}/sendPhoto with body.chat_id allowlist.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('sendPhoto'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.send_document',
    effect: 'send',
    recipient_paths: ['body.chat_id'],
    description:
      'Send a document/file to specific Telegram chats. Binds POST /bot{token}/sendDocument with body.chat_id allowlist.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('sendDocument'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.send_video',
    effect: 'send',
    recipient_paths: ['body.chat_id'],
    description:
      'Send a video to specific Telegram chats. Binds POST /bot{token}/sendVideo with body.chat_id allowlist.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('sendVideo'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.edit_message_text',
    effect: 'write',
    description:
      'Edit the text of a previously sent message in specific chats. Binds POST /bot{token}/editMessageText.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('editMessageText'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.delete_message',
    effect: 'destructive',
    description:
      'Delete a message in specific chats. Binds POST /bot{token}/deleteMessage — destructive.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('deleteMessage'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.forward_message',
    effect: 'send',
    recipient_paths: ['body.chat_id'],
    description:
      'Forward a message into specific chats. Binds POST /bot{token}/forwardMessage with destination chat_id allowlist.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('forwardMessage'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.copy_message',
    effect: 'send',
    recipient_paths: ['body.chat_id'],
    description:
      'Copy a message into specific chats without forward attribution. Binds POST /bot{token}/copyMessage.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('copyMessage'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.pin_chat_message',
    effect: 'write',
    description:
      'Pin a message in specific chats. Binds POST /bot{token}/pinChatMessage.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('pinChatMessage'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.unpin_chat_message',
    effect: 'write',
    description:
      'Unpin a message in specific chats. Binds POST /bot{token}/unpinChatMessage.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('unpinChatMessage'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.ban_chat_member',
    effect: 'write',
    description:
      'Ban a user from specific chats. Binds POST /bot{token}/banChatMember — destructive.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('banChatMember'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.unban_chat_member',
    effect: 'write',
    description:
      'Unban a previously banned user in specific chats. Binds POST /bot{token}/unbanChatMember.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('unbanChatMember'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.create_chat_invite_link',
    effect: 'write',
    description:
      'Create a new invite link for specific chats. Binds POST /bot{token}/createChatInviteLink.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('createChatInviteLink'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.revoke_chat_invite_link',
    effect: 'write',
    description:
      'Revoke an existing chat invite link. Binds POST /bot{token}/revokeChatInviteLink.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('revokeChatInviteLink'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.get_chat',
    effect: 'read',
    description:
      'Fetch metadata for specific chats. Binds POST /bot{token}/getChat.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('getChat'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.get_chat_member',
    effect: 'read',
    description:
      'Fetch a member profile in specific chats. Binds POST /bot{token}/getChatMember.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('getChatMember'),
      chatIdConstraint(chat_id),
    ],
  }),

  defineIntent({
    name: 'telegram.answer_callback_query',
    effect: 'send',
    description:
      'Answer an inline callback query from an InlineKeyboardButton. Binds POST /bot{token}/answerCallbackQuery.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('answerCallbackQuery'),
    ],
  }),

  defineIntent({
    name: 'telegram.get_updates',
    effect: 'read',
    description:
      'Long-poll for incoming updates (messages, callbacks). Binds POST /bot{token}/getUpdates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('getUpdates'),
    ],
  }),

  defineIntent({
    name: 'telegram.set_webhook',
    effect: 'write',
    description:
      'Register a webhook URL to receive updates. Binds POST /bot{token}/setWebhook — security-sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('setWebhook'),
    ],
  }),

  defineIntent({
    name: 'telegram.delete_webhook',
    effect: 'destructive',
    description:
      'Unregister the webhook URL. Binds POST /bot{token}/deleteWebhook.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('deleteWebhook'),
    ],
  }),

  defineIntent({
    name: 'telegram.get_me',
    effect: 'read',
    description:
      'Fetch the bot’s own identity. Binds POST /bot{token}/getMe.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('getMe'),
    ],
  }),

  defineIntent({
    name: 'telegram.send_chat_action',
    effect: 'write',
    description:
      'Broadcast a "typing"/"uploading" status to specific chats. Binds POST /bot{token}/sendChatAction.',
    params: z.object({ chat_id: chatIdList }),
    expand: ({ chat_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      methodPath('sendChatAction'),
      chatIdConstraint(chat_id),
    ],
  }),
];
