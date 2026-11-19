import { z } from 'zod';
import {
  COVERAGE_CAP_PERIODS,
  IssuePassportInputObject,
  MakingOrdersAllowance,
  MISSION_CAP_BEHAVIORS,
  MISSION_CAP_NAMES,
  MissionRecipientList,
  MissionRecipientPins,
  PassportIntentInput,
  isIanaTimeZone,
} from '@stack/shared';

// Passport issue fields for a Passport bound to a Mission the same call
// opens (operator form of stack_start_mission; partner tenant issue reuses
// the field set). Platform intents are STACK-staff only and never offered here.
const MissionPassportIntent = PassportIntentInput.omit({ platform_intent: true }).strict();
export const OperatorStartPassportInput = IssuePassportInputObject
  .omit({ agent_id: true, mission_ids: true })
  .extend({ intent: MissionPassportIntent.optional() })
  .strict();

// Mission spec fields shared by stack_open_mission and the operator form of
// stack_start_mission. Mirrors the API OpenBody (apps/api/src/routes/missions.ts).
export const missionSpecShape = {
  intent_summary: z
    .string()
    .min(1)
    .max(500)
    .describe(
      'Free-form human-readable intent. e.g. "process customer refund ord_123" or "publish blog post drafts".',
    ),
  intent_services: z
    .array(z.string())
    .max(64)
    .optional()
    .describe(
      'Services the mission expects to touch. The proxy gate denies actions to services NOT in this list. Empty = no narrowing.',
    ),
  expected_counterparties: z
    .array(z.string())
    .max(256)
    .optional()
    .describe(
      'Pre-registered counterparty URIs (wallet addresses, recipient emails, etc.). Pre-declaring a counterparty here suppresses the first-touch undeclared_target flag for it (the simulator treats declared counterparties as already-observed).',
    ),
  coverage_cap_cents: z
    .number()
    .int()
    .nonnegative()
    .nullable()
    .optional()
    .describe(
      'The most the Mission may spend, in cents (in one day with coverage_cap_period "day").',
    ),
  max_actions: z
    .number()
    .int()
    .positive()
    .nullable()
    .optional()
    .describe(
      'Total proxy + skill action count cap.',
    ),
  max_actions_per_service: z
    .record(z.string(), z.number().int().positive())
    .optional()
    .describe(
      'Per-service action sub-caps. Example: {stripe: 5, slack: 50} caps Stripe at 5 actions while allowing 50 Slack messages.',
    ),
  max_concurrent_intents: z
    .number()
    .int()
    .positive()
    .nullable()
    .optional()
    .describe(
      'At most N intents in-flight at once.',
    ),
  max_duration_seconds: z
    .number()
    .int()
    .positive()
    .nullable()
    .optional()
    .describe(
      'Wall-clock cap from mission start, in seconds. Worker auto-completes the mission past this point.',
    ),
  max_dropoff_bytes: z
    .number()
    .int()
    .nonnegative()
    .nullable()
    .optional()
    .describe(
      'Outbound drop-off envelope byte cap.',
    ),
  cap_behavior: z
    .record(z.enum(MISSION_CAP_NAMES), z.enum(MISSION_CAP_BEHAVIORS))
    .optional()
    .describe(
      'Per cap: pause (default: actions refused with MISSION_PAUSED until the owner decides), refuse_action or end_mission.',
    ),
  coverage_cap_period: z
    .enum(COVERAGE_CAP_PERIODS)
    .optional()
    .describe('mission (default) or day (ends at midnight in cap_time_zone).'),
  cap_time_zone: z
    .string()
    .min(1)
    .max(64)
    .refine(isIanaTimeZone, 'an IANA time zone, such as Europe/Stockholm')
    .optional()
    .describe('IANA time zone of coverage_cap_period day. Default UTC.'),
  making_orders_up_to_cents: MakingOrdersAllowance.optional().describe(
    'Owner-only: cents of print-on-demand orders approved without asking.',
  ),
  baseline_profile: z
    .record(z.unknown())
    .nullable()
    .optional()
    .describe(
      'Behavioral fingerprint recorded at issue time. Stored as provided, or null.',
    ),
  expected_output_shape: z
    .record(z.unknown())
    .nullable()
    .optional()
    .describe(
      'JSON Schema-ish object describing what success looks like. mission_close validates the submitted output against this.',
    ),
  expires_in_seconds: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      'Mission TTL in seconds. Default 900 (15 min), no maximum, and no limit is needed at any length. Worker auto-completes past this with terminal_state=completed_expired.',
    ),
  parent_passport_services: z
    .array(z.string())
    .optional()
    .describe(
      'When provided, validates intent_services is a subset of these. Typically passed at passport-issue time; can be omitted for standalone-mission flows.',
    ),
  recipients: MissionRecipientList.optional().describe(
    'Who this Mission may send to (exact addresses, numbers or ids), applied at every recipient field a send names, a recipient inside the URL included (the path or one of its segments, such as a channel id). A policy rule that leaves recipients to each Mission allows a send only to these. A recipient listed twice is kept once. The owner can add more to a running Mission.',
  ),
  recipient_pins: MissionRecipientPins.optional().describe(
    'Recipient pins for a policy rule that leaves recipients to each Mission: a list of up to 64 { path, op, value }. path is "*" (every recipient field a send names, the URL path included) or a request field such as body.to or url.pathname; op is eq (one exact value) or in (a list of exact values, up to 1,000 recipients); one pin per path. The owner can add more to a running Mission.',
  ),
  reply_to_message: z
    .string()
    .min(1)
    .max(200)
    .optional()
    .describe(
      'The id of a message you received, or of an incoming call you answered or declined (acall_*). The Mission may send only to the person who wrote it or called. Not found when the id is not an email, text, voicemail or answered or declined call of the agent\'s own account; an email whose sender could not be verified is refused with a plain message.',
    ),
};
