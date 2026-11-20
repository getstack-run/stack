// The single registry of CLI commands. `--help` (help.ts) and the command
// reference in README.md are both rendered from this data, and
// commands.test.ts fails when the router in index.ts, the README block or a
// usage string in any module drifts from it.
//
// Entries are plain data with no colour and no program name: the renderers add
// those. Inline `code` spans in summaries and notes render as highlighted
// text in `--help` and as code in the README.

export interface CommandEntry {
  /** The verb path followed by its arguments, for example `agent show <name|id>`. */
  readonly usage: string;
  readonly summary: string;
  /** Extra lines shown under the summary: flags and caveats. */
  readonly notes?: readonly string[];
}

export interface CommandGroup {
  readonly title: string;
  readonly entries: readonly CommandEntry[];
  /** Printed under the group in `--help` only. */
  readonly footnote?: string;
}

export const COMMAND_GROUPS: readonly CommandGroup[] = [
  {
    title: 'Get started',
    entries: [
      {
        usage: 'quickstart',
        summary:
          'Guided setup: register a safe bot, issue a passport, make one governed LLM call, print the audit row',
      },
      {
        usage: 'proxy serve --agent <name|id>',
        summary:
          "Run a localhost LLM gateway. Point any tool's baseURL at it (dummy key ok); STACK injects the real key. No key on the box.",
        notes: ['[--port 8788] [--provider anthropic|openai|openrouter] [--mission-ttl 3600]'],
      },
      {
        usage: 'setup [--clients claude,codex,cursor]',
        summary: 'Add STACK to one or several installed MCP clients',
        notes: ['Client names may be separated by commas or spaces.'],
      },
      {
        usage: 'register',
        summary: 'Print how to get started and the MCP install instructions',
      },
    ],
  },
  {
    title: 'Account',
    entries: [
      { usage: 'auth login', summary: 'Sign in via browser (Device flow, RFC 8628)' },
      { usage: 'auth status', summary: 'Show current sign-in state' },
      { usage: 'auth logout', summary: 'Revoke session and clear local credentials' },
      { usage: 'me', summary: 'Print your operator profile' },
    ],
  },
  {
    title: 'Usage & billing',
    entries: [
      { usage: 'usage', summary: 'Consumption vs plan + spend + earnings (billing period)' },
      {
        usage: 'usage --period <p>',
        summary: 'Scope to a window: today | yesterday | 7d | 30d | month | last-month | billing (default)',
      },
      {
        usage: 'usage --since <iso> --until <iso>',
        summary: 'Arbitrary range (ISO-8601 or unix-ms)',
        notes: ['`scan usage` and `llm usage` drill into those meters'],
      },
      {
        usage: 'billing subscriptions',
        summary: "Read the platform and controls subscription state and this month's account actions and control checks",
      },
      {
        usage: 'billing subscribe platform|controls',
        summary: 'Start the platform or hosted controls subscription; prints the Stripe Checkout URL and whether a free trial applies',
        notes: [
          '(controls need the platform subscription first; a 409 SUBSCRIPTION_CONFLICT means it is already on, or the account does not need one)',
        ],
      },
    ],
  },
  {
    title: 'Agents',
    entries: [
      { usage: 'agent list', summary: 'List all your agents' },
      { usage: 'agent show <name|id>', summary: 'Detail on one agent' },
      {
        usage: 'agent register <name>',
        summary: 'Register a new agent',
        notes: [
          '[--profile proxied-llm-bot]  <- safe default for a bot that just runs',
          '[--key-mode stack_managed|customer_managed|co_signed]',
          '[--llm-inject-system-prompt true|false]  <- no effect: accepted and ignored  [--llm-redact-pii true|false]',
          '[--accountability-mode logged|enforced|standard]  <- new agents start logged',
          '[--eval-traffic true|false]  <- test traffic: warnings arrive resolved, criticals stay live',
        ],
      },
      {
        usage: 'agent setup --from-file <setup.json>',
        summary: 'Register an agent, its first grants and the hosts its connections may reach, as one approval',
      },
      {
        usage: 'agent dismiss-warnings <name|id>',
        summary: "Resolve an agent's open warnings and hide new ones of the same kinds for a day; criticals stay open",
      },
      {
        usage: 'agent update <name|id>',
        summary: 'Update LLM-gateway toggles (redaction defaults true / fail-closed)',
        notes: [
          '[--llm-inject-system-prompt true|false]  <- no effect: accepted and ignored',
          '[--llm-redact-pii true|false]  <- false sends user PII to the provider unredacted',
        ],
      },
      {
        usage: 'agent enroll <name|id>',
        summary:
          "Enroll a customer-managed keypair (advanced; stack_managed agents and 'proxy serve' auto-enroll, no manual step)",
      },
      { usage: 'agent rotate <name|id>', summary: 'Rotate keypair (admin only)' },
      {
        usage: 'agent sign-claim <name|id>',
        summary: 'Sign a claim envelope locally (customer_managed mode)',
        notes: ['--envelope <file.json> [--out <file>]'],
      },
      { usage: 'agent suspend <name|id>', summary: 'Suspend an agent' },
      { usage: 'agent unsuspend <name|id>', summary: 'Re-activate a suspended agent' },
      {
        usage: 'agent unblock <name|id>',
        summary: 'Clear an auto-blocked agent so it can issue new passports',
      },
      { usage: 'agent delete <name|id>', summary: 'Delete an agent' },
    ],
  },
  {
    title: 'Passports',
    entries: [
      { usage: 'passport list', summary: 'List active passports' },
      {
        usage: 'passport issue --agent <name|id> --mission <ms_id> --intent "<summary>"',
        summary: 'Issue a passport for an agent under a Mission',
        notes: ['[--services slack,stripe] [--ttl <seconds>]', 'or: --from-file issue.json [--mission <ms_id>]'],
      },
      {
        usage: 'passport delegate --agent <child>',
        summary: 'Delegate a passport to a child agent (reads the parent token securely)',
        notes: ['[--services a,b] [--ttl 900]'],
      },
      { usage: 'passport verify', summary: 'Verify a passport JWT from stdin' },
      { usage: 'passport refresh <jti>', summary: 'Refresh a passport JWT from stdin' },
      { usage: 'passport revoke <jti>', summary: 'Revoke one passport' },
      { usage: 'passport revoke-agent <id>', summary: 'Revoke all passports for an agent' },
      { usage: 'passport revoke-session <id>', summary: 'Revoke all passports for a session' },
      { usage: 'passport revoke-all --yes', summary: 'Revoke every active passport' },
      { usage: 'passport report <jti>', summary: 'Show the report for one passport' },
    ],
  },
  {
    title: 'Missions',
    entries: [
      {
        usage: 'mission start --agent <name|id> --intent-summary "..."',
        summary: 'Open a Mission for an agent and issue its Passport',
        notes: [
          '[--services a,b] [--expires-in N] [--ttl N]',
          '[--recipients a@x.com,b@x.com] (Recipients: who this Mission may send to. A policy rule that leaves recipients to each Mission allows a send only to these.)',
          '[--pin <path>=<value>] (repeatable; a request field such as body.to, or * for every recipient field; a comma list means in)',
          '[--reply-to <message-id>] (Reply to a message: pins the Mission to the sender of this message, so the agent can answer that person and no one else.)',
        ],
      },
      { usage: 'mission start --file <path>', summary: 'Start a Mission under a fleet policy' },
      {
        usage: 'mission open --intent-summary "..."',
        summary: 'Open a Mission before issuing its Passport',
        notes: [
          '[--agent <name|id>] [--services a,b] [--expires-in N]',
          '[--recipients a@x.com,b@x.com] (Recipients: who this Mission may send to. A policy rule that leaves recipients to each Mission allows a send only to these.)',
          '[--pin <path>=<value>] (repeatable; a request field such as body.to, or * for every recipient field; a comma list means in)',
          '[--reply-to <message-id>] (Reply to a message: pins the Mission to the sender of this message, so the agent can answer that person and no one else.)',
        ],
      },
      { usage: 'mission open --file <path>', summary: 'Open a Mission from a request file' },
      {
        usage: 'mission add-recipients <id>',
        summary: 'Add who a running Mission may send to (the owner; nothing pinned is taken away)',
        notes: ['[--recipients a,b] [--pin <path>=<value>] [--reply-to <message-id>]'],
      },
      { usage: 'mission renew <id>', summary: 'Renew the Passport for an existing Mission' },
      { usage: 'mission list', summary: 'List Missions', notes: ['[--status active|completed|revoked|paused] (paused: the Missions a cap paused, waiting for your review)'] },
      {
        usage: 'mission review <id> --decision raise|continue|close',
        summary: 'Decide a Mission a cap paused; its agent is told',
        notes: ['[--limit N] (with raise: the new limit of the cap that paused it)'],
      },
      { usage: 'mission making-allowance <id> --cents N | --none', summary: "Pre-approve a Mission's print-on-demand orders up to an amount" },
      { usage: 'mission get <id>', summary: 'Show one Mission' },
      {
        usage: 'mission complete <id>',
        summary: 'Complete a Mission',
        notes: ['[--output-json <path>]'],
      },
      {
        usage: 'mission revoke <id> --reason <r>',
        summary: 'Revoke a Mission with reason adversarial or operator_initiated_clean',
        notes: ['[--notes "..."]'],
      },
      { usage: 'mission replay <id>', summary: 'Replay a Mission' },
      { usage: 'mission dossiers <id>', summary: "List a Mission's dossiers" },
      {
        usage: 'mission dossier <id> --narrative "..."',
        summary: 'Write a dossier for a Mission',
        notes: ['[--lessons "..."] [--classification false_positive|true_positive_handled|true_positive_escalated|inconclusive]'],
      },
    ],
  },
  {
    title: 'Fleets',
    entries: [
      { usage: 'fleet list [--page <number>] [--limit <number>]', summary: 'List fleet policies' },
      { usage: 'fleet get <id>', summary: 'Read one fleet policy and its shared usage' },
      { usage: 'fleet membership <agent>', summary: 'Read the fleet policy an agent belongs to' },
      {
        usage: 'fleet activate --file <path> --idempotency-key <key>',
        summary: 'Request approval for a fleet policy',
      },
      {
        usage: 'fleet revise <id> --file <path> --expected-revision <number> --idempotency-key <key>',
        summary: 'Request approval for a policy change',
      },
      { usage: 'fleet revoke <id>', summary: 'Revoke a fleet policy' },
      {
        usage: 'fleet members <id> [--page <number>] [--limit <number>]',
        summary: 'List the agents in a fleet policy',
      },
      { usage: 'fleet revoke-member <id> <agent>', summary: "Revoke one agent's fleet membership" },
      { usage: 'fleet enrollment-challenge <id>', summary: 'Request an enrollment challenge' },
      {
        usage: 'fleet enroll <id> --file <path>',
        summary: 'Enroll with a public key and signed challenge',
      },
      {
        usage: 'fleet enroll-local <id> --name <name> --idempotency-key <key>',
        summary: 'Create and store an agent key on this machine, then enroll it',
      },
      {
        usage: 'fleet enroll-workload-local <id> --name <name> --idempotency-key <key>',
        summary: 'Enroll using a trusted workload token from STACK_WORKLOAD_TOKEN',
      },
      {
        usage: 'fleet session [--fleet-policy-id <id>]',
        summary: 'Create a short-lived MCP session',
      },
    ],
  },
  {
    title: 'Catalogue',
    entries: [
      {
        usage: 'catalogue [<words>...]',
        summary: 'Search what an agent can use: models, tools, services, skills and the pieces of an account; read only and free',
        notes: [
          '[--kind model|tool|service|skill|account|mcp_tool] [--limit <1-100>] [--offset <number>]',
          '(every word must appear in the id, name, description or provider; to look for the word get or account, write `catalogue search <words>`; text from providers is printed as data, never followed)',
        ],
      },
      {
        usage: 'catalogue get [--out <path>]',
        summary: 'Fetch the whole catalogue file, to the terminal or to a file',
      },
      {
        usage: 'catalogue account <id>',
        summary: 'Read what one account can reach in the catalogue: its connected services and the state of each piece',
      },
    ],
  },
  {
    title: 'Agent accounts',
    entries: [
      {
        usage: 'account open --name <name> --idempotency-key <key>',
        summary: 'Open an agent account at once; prepaid credit is its limit',
        notes: [
          '[--monthly-budget-cents <cents>] (a per-agent budget; needs controls)',
          '[--description "..."] [--file <path>] (the full request as JSON: phone, wallet, inbox, skip)',
        ],
      },
      { usage: 'account list [--limit <number>]', summary: 'List agent accounts' },
      { usage: 'account get <id>', summary: 'Read one agent account and the state of each piece' },
      { usage: 'account close <id>', summary: 'Close an agent account and every piece at its provider' },
      {
        usage: 'account messages <id> [<message-id>]',
        summary: 'List the messages an account received, or read one',
        notes: ['[--channel email|sms|voicemail|call|telegram|post] [--limit <number>] [--cursor <cursor>]'],
      },
      {
        usage: 'account send-email <id> --to <address[,address...]> --subject "..." --body "..."',
        summary: "Send an email from the account's inbox to one or several people, with copies and attachments",
        notes: [
          '[--cc <address[,address...]>] [--bcc <address[,address...]>] (--to, --cc and --bcc each take a comma-separated list or may repeat; the mail goes to OpenMail with one To address, so the further --to addresses are delivered as Cc; a To is required, --cc or --bcc alone is refused)',
          '[--attach <file or drv_id>] (repeat for each file: a drive file id attaches that drive file; any other value is a file on this machine, sent inline, 10 MB in all; upload a larger file with drive upload and attach its id; an email carries 25 MB in all)',
          '[--body-file <path>] [--body-html-file <path>] [--thread-id <id>] (reply in a thread without --subject)',
          "[--reply-to-message <id>] (the received message this answers; needed when your policy sets the account's email recipients per mission, and then it goes only to whoever wrote that message)",
        ],
      },
      {
        usage: 'account reply-email <id> <message-id> --body "..."',
        summary: 'Reply to an email the account received, in its thread and quoting it, to the person who wrote it',
        notes: [
          '[--all] (reply to everyone the email went to as well) [--cc <addresses>] [--bcc <addresses>] [--subject "..."]',
          '[--no-quote] (leave the quote of the email being answered out)',
          '[--body-file <path>] [--body-html-file <path>] [--attach <file or drv_id>] (repeat for each file; see send-email)',
        ],
      },
      {
        usage: 'account forward-email <id> <message-id> --to <address[,address...]>',
        summary: 'Forward an email the account received, with the attachments that were kept, as a new email in no thread',
        notes: [
          '[--body "..."] [--body-file <path>] (your own note above the original) [--cc <addresses>] [--bcc <addresses>]',
          '[--no-attachments] (leave the original\'s files out) [--no-quote] (leave the original\'s text out) [--attach <file or drv_id>] (more files; see send-email)',
        ],
      },
      {
        usage: 'account send-sms <id> --to <+E.164> --body "..."',
        summary: "Send a text from the account's number to any country Twilio can reach",
        notes: [
          '[--body-file <path>]',
          "[--reply-to-message <id>] (the received message this answers; needed when your policy sets the account's text recipients per mission, and then it goes only to whoever wrote that message)",
        ],
      },
      {
        usage: 'account telegram-start <id>',
        summary: "Get the link the owner opens in Telegram to have the agent's bot made for them (no BotFather, no pasted token)",
        notes: ['[--name <suggested bot name>] (owner or admin; nothing is created until the owner confirms in Telegram; the link is single-use and lasts 10 minutes)'],
      },
      {
        usage: 'account telegram-connect <id>',
        summary: "Give the agent its own Telegram bot (made with BotFather); the bot token is read from stdin or a hidden prompt, never argv",
        notes: ['(owner or admin; an OAuth sign-in cannot connect a bot, use an API key)'],
      },
      { usage: 'account telegram <id>', summary: "Read the agent's Telegram bot" },
      { usage: 'account telegram-chats <id>', summary: 'List the chats that have written to the bot (a bot cannot message a chat first)' },
      { usage: 'account telegram-disconnect <id>', summary: "Take the agent's Telegram bot away and stop receiving" },
      {
        usage: 'account send-telegram <id> --chat-id <chat> --body "..."',
        summary: "Answer a chat on the agent's own Telegram bot (only that account's own agent, or the owner, sends from it)",
        notes: ['[--body-file <path>] [--passport-stdin] (send it as the account\'s agent)'],
      },
      {
        usage: 'account message-delete <id> <message-id>',
        summary: 'Delete one message the account received (owner or admin)',
      },
      {
        usage: 'account call <id> --to <+E.164>',
        summary: "Place a phone call from the account's number to any country Twilio can reach",
        notes: [
          '(you hold the call: STACK says nothing; it opens with --greeting or with silence, and you speak with account call-say; the command returns once the call is answered, with what the other side first says)',
          '[--greeting "..."] [--wait-seconds <number>] (0 to 60, default 30: how long to wait for the first sentence)',
          '[--on-behalf-of <name> --brief "..." | --brief-file <path>] (STACK holds the call with its own model instead, opening with its line that the other side is speaking with an AI on behalf of that name)',
          '[--max-seconds <number>] (30 to 14400, the default; the call is paid 10 minutes at a time) [--tts-provider Google|Amazon|ElevenLabs] [--voice <name>] [--language <BCP-47>]',
          "[--reply-to-message <id>] (the received message this answers; needed when your policy sets the account's call recipients per mission, and then it goes only to whoever wrote that message)",
          "[--passport-stdin] (place it as one of your agents; reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account answer-call <id> <call-id>',
        summary: "Answer a call that is ringing on the account's number, held by you or, with a brief, by STACK",
        notes: [
          '[--greeting "..."] [--wait-seconds <number>] | [--on-behalf-of <name> --brief "..." | --brief-file <path>] [--max-seconds <number>] [--tts-provider ...] [--voice ...] [--language ...]',
          "[--passport-stdin] (answer it as one of your agents; reads the Passport token from stdin or a hidden prompt)",
          '(a call rings for 30 seconds, then goes to voicemail)',
        ],
      },
      {
        usage: 'account call-say <id> <call-id> [--text "..."]',
        summary: 'Speak on a live call you hold, then wait for what the other side says next; prints the events since your last call action',
        notes: ['[--wait-seconds <number>] (0 to 60, default 30) [--passport-stdin]'],
      },
      {
        usage: 'account call-keys <id> <call-id> --digits <keys>',
        summary: 'Send keys to the other side of a live call as tones (0-9, *, #, w for a pause)',
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'account call-voice <id> <call-id> [--tts-provider ...] [--voice ...] [--language <BCP-47>]',
        summary: 'Change the voice or language of a live call for the rest of it',
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'account hang-up <id> <call-id>',
        summary: 'Hang up a live call of the account, whoever holds it; STACK says nothing',
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'account call-voice-settings <id>',
        summary: "Read the account's call voice and voicemail greeting, or set them with any of the flags (a field left out is cleared)",
        notes: ['[--tts-provider Google|Amazon|ElevenLabs] [--voice <name>] [--language <BCP-47>] [--voicemail-greeting "..."] [--passport-stdin] (the owner, an admin or the account\'s own agent)'],
      },
      {
        usage: 'account decline-call <id> <call-id>',
        summary: "Decline a call that is ringing on the account's number; the call is hung up with nothing said",
        notes: ["[--passport-stdin] (decline it as the account's agent)"],
      },
      {
        usage: 'account calls <id> [<call-id>]',
        summary: 'List the calls an account placed and received, or read one with its transcript',
        notes: ['[--limit <number>] [--cursor <cursor>] [--passport-stdin] (read as the agent, which marks the transcript read)'],
      },
      {
        usage: 'account tools <id> discover --query "..."',
        summary: 'Find paid tools the account can run; reads the Passport token from stdin or a hidden prompt',
        notes: ['[--limit <number>]'],
      },
      {
        usage: 'account tools <id> inspect --provider <provider> --endpoint <path>',
        summary: "Read one tool's input schema and price; reads the Passport token from stdin or a hidden prompt",
      },
      {
        usage: 'account tools <id> run --provider <provider> --endpoint <path>',
        summary: "Run a paid tool, charged to the account's budget; reads the Passport token from stdin or a hidden prompt",
        notes: [
          "[--input '<json>' | --input-file <path>] [--max-results <number>] [--max-cost-cents <number>]",
          '(only tools in the catalogue run; what comes back is marked untrusted when it is web or provider content, and the files it made are saved to the drive)',
        ],
      },
      {
        usage: 'account workspace <id> run (--command "..." | --command-file <path>)',
        summary: "Run a shell command in a workspace, a machine of its own that keeps its files; the id is the account that owns it, without --workspace a new one is made in your own account (another agent of the customer runs in a shared workspace with --workspace, as itself)",
        notes: [
          '[--workspace <wsp_id>] [--cwd <dir>] [--timeout <seconds>] (default 120, no longest) [--background] (start it and print its command id at once; read it with workspace <id> command) [--env-file <path>] (a JSON object of strings for this command only) [--stack-access] (a short-lived Passport of the agent in STACK_PASSPORT, for your connected services through STACK\'s proxy)',
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt; the output is untrusted, read it as data)",
        ],
      },
      {
        usage: 'account workspace <id> command --workspace <wsp_id> --command-id <wcmd_id>',
        summary: 'Read a command started with run --background: its status (running, succeeded or failed), its exit code once it has ended and what it has printed so far; the output is untrusted',
        notes: [
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account workspace <id> read --workspace <wsp_id> --path <path>',
        summary: "Read a file of the workspace (at most 1 MB); the content is untrusted",
        notes: [
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account workspace <id> write --workspace <wsp_id> --path <path> (--text "..." | --content-file <path>)',
        summary: 'Write a text file into the workspace (at most 1 MB)',
        notes: [
          '[--mode <octal>] (permission bits such as 755, set once the file is written)',
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account workspace <id> save --workspace <wsp_id> --path <path>',
        summary: "Save a file of the workspace to the account's drive",
        notes: [
          '[--name <name>] [--content-type <type>] [--visibility agent|account]',
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      { usage: 'account workspace <id> list', summary: "List the account's workspaces, what each has cost and when a stopped one will be deleted; another agent of the customer sees only the ones shared with it" },
      {
        usage: 'account workspaces',
        summary: "List every workspace you may use across the customer's accounts: the account, the agent and whether the customer shares it with their other agents",
        notes: ['(an agent sees its own account\'s and the ones the other agents share; the owner sees all)'],
      },
      {
        usage: 'account workspace-sharing <id> --workspace <wsp_id> (--on | --off)',
        summary: "Choose whether the customer's other agents may run commands and read and write files in one workspace (on by default); off keeps it to its own agent",
        notes: [
          '(<id> is the account that owns the workspace; the machine\'s time is charged to it either way)',
          '(owner or admin only: an agent cannot change it)',
        ],
      },
      {
        usage: 'account workspace-settings get [<id>]',
        summary: "Read the idle pause, the days a stopped workspace is kept and the number of workspaces, and what is in force: for one agent account, or without an id the customer's defaults",
        notes: ['(owner or admin only: an agent cannot read or change its own)'],
      },
      {
        usage: 'account workspace-settings set [<id>] [--idle-pause <minutes>|off|default] [--delete-after <days>|never|default] [--max-workspaces <n>|default]',
        summary: "Change them, for one agent account or without an id the customer's defaults: idle pause 5 minutes or more or off, days kept 1 or more or never, workspaces per agent account (any number from 1)",
        notes: [
          "(default gives the setting back; a running workspace takes a new idle pause now, and a stopped one kept longer than the new days is deleted by the next sweep)",
          "(a stopped workspace's disk storage is charged to the account until the workspace is deleted; the money held for a machine is not a setting)",
          '(owner or admin only)',
        ],
      },
      {
        usage: 'account workspace <id> stop --workspace <wsp_id> [--delete]',
        summary: 'Pause a workspace (its files stay), or with --delete delete it and its files',
        notes: ['(needs the accounts:write scope)'],
      },
      {
        usage: 'account signing-keys <id> [list | rotate]',
        summary: "Read or rotate the keys the account signs its outbound requests with (Web Bot Auth); rotate is for an owner or admin",
      },
      {
        usage: 'account identity <id> [get | show-name | hide-name | on | off]',
        summary: 'Read or change what STACK\'s public answer to "who is this agent" shows: the agent\'s name (hidden by default) and whether it answers at all (on by default)',
        notes: ['Owner or admin only. The answer never carries the owner\'s name, email, address or card, only whether STACK verified them and whether they are in good standing.'],
      },
      {
        usage: 'account tools <id> run-get <run-id>',
        summary: 'Read one tool run and its result',
        notes: ['[--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account making <id> upload <file>',
        summary: 'Upload a design file (any format; up to 20 MB, which is what one request carries); reads the Passport token from stdin or a hidden prompt',
        notes: ['[--description "..."]', '(for a larger file: put it on the drive, then give no file and use --drive-file <drive-file-id> [--name <file name>])'],
      },
      {
        usage: 'account making <id> designs [<design-id>]',
        summary: 'List the designs of an account, or read one',
        notes: ['[--limit <number>] [--passport-stdin]'],
      },
      {
        usage: 'account making <id> quote --design <design-id> --recipient-file <path>',
        summary: 'Ask the suppliers for quotes; which files and destinations a supplier takes is its own answer',
        notes: [
          '[--supplier afn|craftcloud|gelato|prodigi|printful|lulu] [--quantity <number>] [--spec-file <path>]',
          '[--process <p>] [--material <m>] [--finish <f>] [--color <c>] [--unit mm|cm|in] [--product <id>] [--placement <p>] [--page-count <number>] [--shipping cheapest|fastest]',
          '(the recipient file holds name, email, phone, address and a two-letter country as one JSON object; reads the Passport token from stdin or a hidden prompt)',
        ],
      },
      {
        usage: 'account making <id> quote-get <quote-id>',
        summary: 'Read one quote',
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'account making <id> order <quote-id>',
        summary: "Order a quote: a fabrication order ends in a checkout page to pay with the account's card, a print-on-demand order waits for your approval; reads the Passport token from stdin or a hidden prompt",
      },
      {
        usage: 'account making <id> orders [<order-id>]',
        summary: 'List the orders of an account, or read one (a read refreshes it from the supplier)',
        notes: ['[--limit <number>] [--passport-stdin]'],
      },
      {
        usage: 'account making <id> cancel <order-id>',
        summary: 'Stop an order while the supplier still can',
        notes: ['[--passport-stdin] (cancel it as the account\'s agent)'],
      },
      {
        usage: 'account making <id> approve <order-id>',
        summary: "Place a held print-on-demand order on your own supplier account; waits for human approval when the API asks for it",
      },
      {
        usage: 'account making <id> reject <order-id>',
        summary: 'Decline a held order',
      },
      {
        usage: 'account making-suppliers',
        summary: 'List the making suppliers, and whether your own account at each print-on-demand supplier is connected',
      },
      {
        usage: 'account making-connect-supplier gelato|prodigi|printful|lulu',
        summary: 'Connect your own account at a print-on-demand supplier; the key is read from MAKING_SUPPLIER_KEY, stdin or a hidden prompt, never from an argument',
        notes: [
          '(Lulu also needs MAKING_SUPPLIER_SECRET, or JSON with api_key and api_secret on stdin; the supplier charges its own account, STACK never pays one)',
          '(owner or admin)',
        ],
      },
      {
        usage: 'account making-connect-printful',
        summary: 'Connect your own Printful account by signing in at Printful: prints the address to open, sign in or up there and approve; STACK stores and renews the tokens',
        notes: ['(owner or admin)'],
      },
      {
        usage: 'account making-disconnect-supplier <supplier>',
        summary: 'Remove your account at a print-on-demand supplier',
        notes: ['(owner or admin)'],
      },
      {
        usage: 'account toll-free <id>',
        summary: "Read the toll-free text verification status of the account's number",
      },
      {
        usage: 'account toll-free <id> submit --file <path>',
        summary: 'Submit the business details for toll-free text verification; waits for human approval when the API asks for it',
        notes: [
          '(the file holds the details as one JSON object: business, address, contact, use case and opt-in)',
          '(needs an admin role)',
        ],
      },
      {
        usage: 'account mail-domains',
        summary: 'List your own mail domains for agent inboxes, each with the DNS records to publish and its status',
      },
      {
        usage: 'account mail-domain-connect --domain <name>',
        summary: 'Connect your own mail domain and print the DNS records to publish; needs the platform subscription',
        notes: [
          '(owner or admin; there is no remove command, an unverified claim on a name lapses on its own)',
        ],
      },
      {
        usage: 'account mail-domain-verify <mail-domain-id>',
        summary: "Ask the mail provider to check a domain's DNS records now",
      },
      {
        usage: 'account opt-outs',
        summary: 'List the numbers on your do-not-contact list: people who texted STOP and numbers added to it',
        notes: ['(an owner or admin, or the account agent, which reads it only; texts and calls to a listed number are refused)'],
      },
      {
        usage: 'account opt-out-add <+E.164>',
        summary: 'Add a number to the do-not-contact list, so texts and calls to it are refused',
        notes: ['(an owner or admin, or an account agent; a number already listed is returned as it is)'],
      },
      {
        usage: 'account opt-out-remove <opt-out-id>',
        summary: 'Take a number off the do-not-contact list, so texts and calls to it go through again',
        notes: ['(owner or admin)'],
      },
      {
        usage: 'account blocked-callers',
        summary: 'List the numbers on your blocked-callers list: an incoming call from one is turned away before it rings',
        notes: ['(an owner or admin, or the account agent, which reads it only)'],
      },
      {
        usage: 'account blocked-caller-add <+E.164>',
        summary: 'Add a number to the blocked-callers list, so its incoming calls are turned away before they ring',
        notes: ['(an owner or admin, or an account agent; a number already listed is returned as it is)'],
      },
      {
        usage: 'account blocked-caller-remove <blocked-caller-id>',
        summary: 'Take a number off the blocked-callers list, so its calls ring again',
        notes: ['(owner or admin)'],
      },
      {
        usage: 'account website <id> [get]',
        summary: "Read the account's website: addresses, the live deploy, prices and limits",
        notes: ['[--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account website <id> publish --dir <folder>',
        summary: "Publish a folder as the account's website; the scan runs first and a refusal names each finding",
        notes: [
          '[--server-file <path>] (one JavaScript module with small server code)',
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account website <id> deploys [<deploy-id>]',
        summary: "List the website's recent deploys, or read one with its file hashes",
        notes: ['[--limit <number>] [--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account website <id> hostnames',
        summary: "List the website's addresses and the DNS records to set for your own domain",
        notes: ['[--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account website <id> hostname-add --hostname <name>',
        summary: 'Serve the website on your own domain and print the DNS records to set',
        notes: [
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account website <id> hostname-check <hostname-id>',
        summary: "Check a domain's DNS and certificate now",
        notes: [
          '[--passport-stdin] (check as the agent)',
        ],
      },
      {
        usage: 'account website <id> hostname-remove <hostname-id>',
        summary: 'Stop serving the website on a domain and release the name',
        notes: [
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account website <id> prices',
        summary: 'List the website paths that cost USDC to read',
        notes: ['[--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account website <id> prices-set --file <path>',
        summary: 'Replace the priced paths; the file holds a list of path, price_usdc and an optional description',
        notes: [
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account website <id> suspend --reason "..."',
        summary: 'Take the website offline now (owner or admin; the agent cannot lift it)',
      },
      {
        usage: 'account website <id> resume',
        summary: 'Bring the website back after your own suspension; a suspension by STACK is not lifted this way',
      },
      {
        usage: 'account websites-suspend-all --reason "..."',
        summary: 'Take every website of your account offline at once',
      },
      {
        usage: 'account website-report --url <address> --category <category> --description "..."',
        summary: 'Report a page on a STACK-hosted website; needs no sign-in and sends no credential',
        notes: ['[--email <address>] (category: phishing, impersonation, malware, illegal_content, copyright, spam or other)'],
      },
      {
        usage: 'account payments <id> stripe',
        summary: "Start connecting your own Stripe and print the address of the page where the restricted key is pasted",
        notes: [
          '(the key is never a command argument; an agent gets the connection without the address)',
          '[--passport-stdin] (start as the agent)',
        ],
      },
      {
        usage: 'account payments <id> stripe-get',
        summary: 'Read the Stripe connection and the webhook address to add in Stripe',
        notes: ['[--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account payments <id> stripe-disconnect',
        summary: 'Erase the Stripe key and signing secret and turn off the active payment links (owner or admin)',
      },
      {
        usage: 'account payments <id> link-create --name "..." --amount-minor <number>',
        summary: 'Create a reusable payment link for one fixed price on your own Stripe',
        notes: [
          '[--currency <code>] [--item "..."] [--after-payment-url <address>] (usd when no currency is given; the address must be on the agent\'s own site)',
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account payments <id> checkout-create --name "..." --amount-minor <number> --success-url <address>',
        summary: 'Create a one-off checkout session for one fixed price on your own Stripe',
        notes: [
          '[--cancel-url <address>] [--currency <code>] [--item "..."] (both addresses must be on the agent\'s own site)',
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account payments <id> links',
        summary: 'List the payment links and checkout sessions',
        notes: ['[--limit <number>] [--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account payments <id> link-deactivate <link-id>',
        summary: 'Turn a payment link off so it can no longer be paid',
        notes: [
          "(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)",
        ],
      },
      {
        usage: 'account payments <id> [list]',
        summary: 'List the payments received, on card and in USDC',
        notes: ['[--rail stripe|x402] [--limit <number>] [--cursor <cursor>] [--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account payments <id> get <payment-id>',
        summary: 'Read one payment',
        notes: ['[--passport-stdin] (read as the agent)'],
      },
      {
        usage: 'account budget <id> <dollars|none>',
        summary: "Set or remove the account's monthly spend budget, in dollars (25 or 25.50); raising or removing waits for human approval",
        notes: ['(owner or admin; setting needs controls)'],
      },
      {
        usage: 'account resume <id> --piece inbox|phone',
        summary: 'Resume an automatically paused piece; waits for human approval when the API asks for it',
      },
    ],
  },
  {
    title: 'Post',
    entries: [
      {
        usage: 'post address [start|connect|refresh|pause|resume|close]',
        summary: "The customer's one US street address: read it, start it, hand over the supplier key (stdin), look again, pause, resume, disconnect",
        notes: [
          '(the owner signs up at the supplier, completes USPS Form 1583 there and creates an agent key there; STACK never sees the documents)',
          'connect reads the key from stdin or a hidden prompt, optionally followed by the webhook secret',
        ],
      },
      { usage: 'post items [--routing routed|pending|unassigned] [--limit <number>]', summary: 'Every item at the address, including those no agent has' },
      { usage: 'post items assign <item-id> --account <id>', summary: 'Give an item that no agent has taken to an account' },
      { usage: 'post <account-id> address', summary: "The agent's own line on the shared address, to print on a form" },
      { usage: 'post <account-id> items [<limit/cursor flags>]', summary: 'The items routed to an account' },
      {
        usage: 'post <account-id> scan|forward|shred <item-id>',
        summary: 'Ask the supplier to scan, forward or shred an item; the owner approves it there',
        notes: [
          'scan: [--capture document_pdf|contents_photos|both]; forward: --to-name "..." --to-line1 "..." --to-city "..." --to-state NV --to-postal-code 89501 (or --to-address-file) [--mail-class <class>]; shred: --confirm',
        ],
      },
      { usage: 'post <account-id> check --to-line1 "..." --to-city "..." --to-postal-code <code> [--to-state <st>] [--to-country <cc>]', summary: 'Whether an address is deliverable' },
      {
        usage: 'post <account-id> send --use-type operational|marketing --sender-name "..." --to-name "..." --to-line1 "..." --to-city "..." --to-state NV --to-postal-code 89501 (--text "..." | --text-file <path> | --pdf-file <path>)',
        summary: "Send a letter from text or a PDF, from the customer's own address, held and charged at cost",
        notes: [
          '--sender-name is the name printed as the sender (up to 40 characters)',
          "[--return-line1 \"...\" --return-city \"...\" --return-state NV --return-postal-code 89701 [--return-line2 \"...\"] [--return-company \"...\"] | --return-address-file <path>]: the sender address printed on the letter, a US address in the same form as --to-*; without it the account's street address is used; returned post goes to this address",
          '[--color] [--single-sided] [--mail-class first_class|standard] [--extra-service certified|certified_return_receipt] [--description "..."] [--idempotency-key <key>]',
          'a postcard: --kind postcard --front "..." --back "..." [--size 4x6|6x9] (text only)',
          "the account's agent adds --passport-stdin and pipes its Passport; the print provider's refusal is reported with nothing held",
        ],
      },
      { usage: 'post <account-id> letters [<limit/cursor flags>]', summary: "An account's letters and postcards, newest first" },
      { usage: 'post <account-id> letter <letter-id>', summary: 'One letter with its tracking events' },
    ],
  },
  {
    title: 'Control socket',
    entries: [
      {
        usage: 'control-socket get',
        summary: 'Read the control socket: who decides now, both addresses and their state, and the action kinds checked',
      },
      {
        usage: 'control-socket set-decision <url>',
        summary: 'Set the address of your own decision server and print its signing secret once; it decides nothing until verified; waits for human approval when the API asks for it',
        notes: [
          '[--timeout-ms <number>] (how long STACK waits for an answer, 300 to 2000; default 1500)',
          '(store the secret when it is printed: it is not shown again)',
        ],
      },
      {
        usage: 'control-socket set-events <url>',
        summary: "Set the address that receives your agents' record and print its signing secret once; waits for human approval when the API asks for it",
        notes: ['(store the secret when it is printed: it is not shown again)'],
      },
      {
        usage: 'control-socket clear decision|events',
        summary: 'Remove the decision or events address; waits for human approval when the API asks for it',
      },
      {
        usage: 'control-socket verify decision|events',
        summary: 'Run the setup check; when it passes the address is put into use; waits for human approval when that replaces hosted controls',
      },
      {
        usage: 'control-socket test decision|events',
        summary: 'One test exchange with the address; nothing changes',
      },
      {
        usage: 'control-socket rotate-secret decision|events',
        summary: 'Replace the signing secret and print the new one once; the old one works for 24 hours more; waits for human approval when the API asks for it',
        notes: ['(store the secret when it is printed: it is not shown again)'],
      },
      {
        usage: 'control-socket mode none|hosted',
        summary: "Use STACK's hosted controls, or none; turning controls off, or leaving your own server, waits for human approval",
        notes: ['(hosted needs controls on; your own server is switched on with verify)'],
      },
      {
        usage: 'control-socket on-unavailable [refuse|allow]',
        summary: 'Read or set what happens when your own decision server does not answer in time: refuse (default) or allow; allow waits for human approval',
      },
      {
        usage: 'control-socket checked-types [--all | <types...>]',
        summary: 'Read which action kinds are checked, or set them (--all checks every kind, including kinds added later); unchecking a kind waits for human approval',
        notes: ['(types are comma or space separated, e.g. email.send card.checkout wallet.payment)'],
      },
      {
        usage: 'control-socket decisions',
        summary: 'List the decisions made, newest first',
        notes: ['[--limit <number>] [--account <id>] [--verdict allow|deny|unavailable] [--before <iso>]'],
      },
      { usage: 'control-socket decision <id>', summary: 'Read one decision, with its request while it is kept' },
    ],
  },
  {
    title: 'STACK network',
    entries: [
      {
        usage: 'network install register <name>',
        summary: 'Register a self-hosted install, which can sign nothing until it has a key',
      },
      { usage: 'network install list', summary: 'List your installs with their keys' },
      { usage: 'network install show <install-id>', summary: 'Read one install and its keys' },
      {
        usage: 'network install key add <install-id> --key-file <path>',
        summary: 'Register a key for an install: writes a new private key to the file (readable by you only, never printed) or reuses the one there, and waits for a person to approve it in a browser',
        notes: ["[--rollover-seconds <number>] (how long the install's other keys keep working, up to a week; default one day)"],
      },
      {
        usage: 'network install key revoke <install-id> <key-id>',
        summary: 'Stop a key at once and publish it; every countersignature made under it stops being live',
        notes: ['[--reason key_compromise|owner_request|...]'],
      },
      {
        usage: 'network install revoke <install-id>',
        summary: 'Stop an install and all its keys at once and publish it',
        notes: ['[--reason key_compromise|owner_request|...]'],
      },
      {
        usage: 'network licence revoke [--licence-file <path>]',
        summary: 'Revoke a licence key STACK issued to your account before it expires; the network refuses it from the next call on',
        notes: [
          '[--reason key_compromise|owner_request|...]',
          '(the key is the proof it is yours and is never an argument: read from the file, or from standard input)',
        ],
      },
      { usage: 'network licence list', summary: 'List the licence keys your account revoked' },
      {
        usage: 'network revoke <passport|agent|key|install> <subject>',
        summary: "Publish a revocation across companies; with `--key-file` it is the install's own request, otherwise yours",
        notes: [
          '(--for-install <id> | --install <id> --key-file <path>) [--reason <reason>]',
          '(the subject is a passport digest, an agent id, a key thumbprint or an install id; every revocation names its install, and it appears on the public list)',
        ],
      },
      {
        usage: 'network subscription create <url>',
        summary: 'Have STACK post each new revocation, as a list signed by STACK, to an https address',
        notes: ['[--install <id>] (repeat to follow only some installs)', '(the signing secret for the requests is printed once)'],
      },
      { usage: 'network subscription list', summary: 'List your subscriptions and whether each is delivering' },
      { usage: 'network subscription delete <id>', summary: 'Remove a subscription' },
      { usage: 'network subscription rotate-secret <id>', summary: 'Issue a new signing secret (printed once); the old one keeps signing for 24 hours' },
      { usage: 'network subscription resume <id>', summary: 'Put a paused subscription back to work; it is sent what it missed' },
      {
        usage: 'network rules --install <id> --key-file <path>',
        summary: "Fetch STACK's signed detection rule set as an install and check it against STACK's keys",
        notes: [
          '[--held-revision <number>] (refuse an older set)',
          '(an install holds no account credential: it signs each request with its key; STACK_INSTALL_ID and STACK_INSTALL_KEY_FILE set the defaults)',
        ],
      },
      {
        usage: 'network classify <content|@file|-> --install <id> --key-file <path>',
        summary: "Send content to STACK's classifier as an install; the content leaves your machine and STACK keeps none of it",
        notes: ['[--context email|document|webpage|chat_log|api_response|calendar|other]'],
      },
      {
        usage: 'network intent-deviation <json|@file|-> --install <id> --key-file <path>',
        summary: 'Have STACK grade a checkout for intent deviation as an install: {"declared": {...}, "observed": {...}} in, a score and a flag out',
      },
      {
        usage: 'network countersign <passport|@file|-> --install <id> --key-file <path>',
        summary: "Have STACK countersign a passport your install issued; only the passport's digest is sent",
        notes: ['[--agent <id>] [--passport-id <id>] [--ttl-seconds <60 to 3600>]'],
      },
      {
        usage: 'network verify <countersignature|@file|-> [--passport <token|@file>]',
        summary: 'Check a countersignature now, revocation included, and with a passport that it is the one signed (no sign-in needed)',
      },
      {
        usage: 'network verified --passport-digest <digest> | --passport <token> | --install <id> --agent <id>',
        summary: "Read the signed STACK-verified statement for a passport or an install's agent (no sign-in needed)",
      },
      {
        usage: 'network revocations',
        summary: 'Read the signed list of revocations, checking its signature (no sign-in needed)',
        notes: ['[--after <cursor>] [--limit <number>] [--install <id>] (resume from `resume_from`)'],
      },
      { usage: 'network jwks', summary: "Print STACK's public keys for the network's signed objects (no sign-in needed)" },
    ],
  },
  {
    title: 'Who an agent is',
    entries: [
      {
        usage: 'agent-identity lookup --key-id <id> | --site <host> | --agent-id <id>',
        summary: "Ask STACK who an agent is: its id, whether it is active, suspended or closed, and three yes-or-no facts of its owner (no sign-in needed). The statement STACK signed is checked before it is printed",
        notes: ['[--no-verify] (print the answer without checking the signature)', '(an agent that is not found, closed or switched off by its owner is one and the same 404)'],
      },
      {
        usage: 'agent-identity urls <agent-id>',
        summary: "Print where an agent's lookup and machine files are on STACK's domain: its signed A2A card, MCP server card and key directory",
      },
    ],
  },
  {
    title: 'Policies',
    entries: [
      {
        usage: 'policies list',
        summary: 'List your policies and whether hosted controls are on; a policy only narrows what a connection grant allows, it never opens anything',
      },
      {
        usage: 'policies get default|<agent>',
        summary: "Read the default policy, or an agent's own policy and the one in force for it",
      },
      {
        usage: 'policies set default|<agent> --file <definition.json>',
        summary: 'Create or revise the default or an agent policy; tightening applies at once, loosening waits for human approval',
        notes: [
          '[--stdin] (read the definition from stdin instead of a file; the output of policies get works too)',
          '[--expected-revision <number>] (omit to create; pass the revision you read to revise)',
          '(Recipients set per job: put "recipients": "per_mission" on an allow rule, and each Mission names who it may send to when it opens)',
        ],
      },
      {
        usage: 'policies delete default|<agent>',
        summary: 'Delete the default or an agent policy; always waits for human approval',
        notes: ['[--expected-revision <number>] (the delete is refused if the policy moved on)'],
      },
      {
        usage: 'policies start <agent>',
        summary: "Create a policy equal to the agent's current connection access; it changes no outcome until you tighten it",
      },
      {
        usage: 'policies simulate --agent <agent> --action <type>',
        summary: 'Try one call against a policy; nothing is counted, held or sent',
        notes: [
          '[--amount-cents <number>] [--connection <scon_id>] [--target <json>] (the call, in the terms a decision request uses)',
          '[--mission <ms_id>] (try the call with the recipients that Mission pinned)',
          '[--definition <draft.json>] (try a draft instead of the stored policy; then --agent is optional)',
          '[--file <input.json> | --stdin] (the whole input, with the call under "call"; flags override it)',
        ],
      },
      {
        usage: 'policies revisions <policy-id>',
        summary: 'List the revisions of a policy: who made each, how it changed, and the approval behind a loosening',
      },
    ],
  },
  {
    title: 'Wake-ups',
    entries: [
      {
        usage: 'wake list <agent> [--status open|pending|delivered|acknowledged|refused|expired]',
        summary: "List an agent's wakes (any agent, with or without an account), newest first; --status open is the agent's queue, oldest first",
        notes: ['[--limit <number>] [--cursor <cursor>] [--passport-stdin] (run as the agent, with its Passport on stdin)'],
      },
      { usage: 'wake get <agent> <wake-id>', summary: 'Read one wake', notes: ['[--passport-stdin]'] },
      { usage: 'wake ack <agent> <wake-id>', summary: 'The agent has picked a delivered wake up', notes: ['[--passport-stdin]'] },
      {
        usage: 'wake settings get [<agent>]',
        summary: "Read one agent's wake settings and what is in force, or (without an agent) your defaults",
      },
      {
        usage: 'wake settings set [<agent>]',
        summary: 'Change wake settings for one agent or, without an agent, for all of them; a first webhook address prints its signing secret once',
        notes: [
          '[--file <settings.json>] [--time-zone <zone|none>] [--quiet <HH:MM-HH:MM|none>] [--quiet-mode hold|drop]',
          '[--rate-limit <number>] [--rate-window <seconds>] [--delivery <mcp,webhook,mission|default>] [--invite-lead <minutes>]',
          '[--webhook-url <https url|none>] [--enable | --disable] [--ring-incoming-calls | --no-ring-incoming-calls]',
          '(store the secret when it is printed: it is not shown again)',
        ],
      },
      { usage: 'wake rules [<agent>]', summary: "List one agent's wake rules or, without an agent, your default rules" },
      {
        usage: 'wake rule-add [<agent>] --name <name> --source <source>',
        summary: 'Add a rule: which event wakes the agent and with what task (mail, texts, Telegram messages, voicemail, calls and payments wake nobody without one)',
        notes: ['sources: email, sms, voicemail, call, incoming_call, payment, post, invite, schedule, handoff, decision, meeting, service_event, telegram', '[--task <text>] [--from <a@b.example,@domain.example,+15550100,telegram:name>] [--min-amount-cents <number>] [--disabled] [--file <rule.json>]'],
      },
      { usage: 'wake rule-update <rule-id> --name <name> --source <source>', summary: 'Replace a rule', notes: ['(same options as rule-add)'] },
      { usage: 'wake rule-delete <rule-id>', summary: 'Remove a rule' },
      { usage: 'wake schedules <agent>', summary: "List an agent's schedules, with their next fire" },
      {
        usage: 'wake schedule-add <agent> --name <name> --cron <expression> --task <text>',
        summary: "Wake the agent on a cron schedule, five fields, in its time zone; no more often than every 5 minutes",
        notes: ['[--time-zone <zone|none>] [--disabled] [--file <schedule.json>]'],
      },
      { usage: 'wake schedule-update <agent> <schedule-id> --name <name> --cron <expression> --task <text>', summary: 'Replace a schedule' },
      { usage: 'wake schedule-delete <agent> <schedule-id>', summary: 'Remove a schedule' },
      {
        usage: 'wake rotate-secret <agent>',
        summary: "Replace the agent's webhook signing secret and print the new one once; the old one works for 24 hours more",
        notes: ['(store the secret when it is printed: it is not shown again)'],
      },
      { usage: 'wake test-webhook <agent>', summary: "Send a signed test to the agent's webhook; nothing is waking the agent" },
    ],
  },
  {
    title: 'Calendar',
    entries: [
      {
        usage: 'calendar events <account> [--role organizer|attendee] [--response pending|accepted|tentative|declined]',
        summary: "List the events on an agent's calendar, soonest first: its own and the invites sent to its address",
        notes: ['[--limit <number>] [--cursor <cursor>] [--passport-stdin]'],
      },
      { usage: 'calendar get <account> <event-id>', summary: 'Read one event: its times, repeat rule, guests and their answers, proposals, meeting room', notes: ['[--passport-stdin]'] },
      {
        usage: 'calendar agenda <account> --from <date|time> --to <date|time> [--tz <zone>]',
        summary: 'Every occurrence in a range, repeats expanded, changed and cancelled occurrences applied',
        notes: ['[--limit <number>] [--cursor <cursor>] [--passport-stdin]'],
      },
      {
        usage: 'calendar create <account> --title <text> --start <time> [--end <time>] [--tz <zone>] [--repeat <rrule>] [--guests a@x,b@y]',
        summary: 'Make an event (one action); each guest is mailed the invite from the account\'s address',
        notes: ['[--except <times>] [--also <times>] [--location <text>] [--link <url>] [--description <text>] [--wake <minutes>] [--meeting] [--attend] [--max-seconds <n>] [--meeting-voice <name>] [--meeting-language <code>] [--passport-stdin]', '(--meeting makes a video room whose link goes in the invite; --attend has STACK\'s meeting worker join it as the agent at each start; the customer\'s controls are asked once, and a refusal makes the event without attend)'],
      },
      {
        usage: 'calendar update <account> <event-id> [--title ...] [--start ...] [--occurrence <time>] [--scope series|occurrence|following]',
        summary: 'Change an event, one occurrence of it, or it and the following (one action); the guests get the update',
        notes: ['[--end <time>|--no-end] [--tz <zone>] [--repeat <rrule>|--no-repeat] [--guests ...] [--meeting|--no-meeting] [--attend|--no-attend] [--meeting-voice <name>] [--meeting-language <code>] [--no-meeting-voice] [--counter <proposal-id>] [--passport-stdin]'],
      },
      {
        usage: 'calendar cancel <account> <event-id> [--occurrence <time>] [--scope series|occurrence|following]',
        summary: 'Cancel an event, one occurrence, or it and the following (one action); the guests are mailed the cancellation',
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'calendar respond <account> <event-id> accept|tentative|decline',
        summary: 'Answer an invite; it mails the organizer a calendar reply from the account\'s address (one action) unless --no-notify, and an accepted invite wakes the agent before each occurrence',
        notes: ['[--no-notify] [--passport-stdin]'],
      },
      {
        usage: 'calendar decline-proposal <account> <event-id> <proposal-id> [--comment <text>]',
        summary: "Turn down a guest's proposed other time; accept one by updating the event with --counter",
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'calendar feed <account> [--rotate | --revoke]',
        summary: 'Whether the private read-only calendar feed exists; --rotate makes it or gives it a new URL (shown once), --revoke ends it',
        notes: ['(whoever holds the URL sees every event and the guests\' addresses until it is rotated or ended)'],
      },
    ],
  },
  {
    title: 'Paying an x402 seller',
    entries: [
      {
        usage: 'pay <account> <url> --passport-stdin',
        summary: "Buy from an x402 seller in one step: asks the URL, pays the 402 from the account's wallet through STACK (the wallet's caps, the budget and your controls) and asks again; what was bought goes to stdout, the payment to stderr (one action)",
        notes: [
          '[--wallet-key-file <path>] [--max-cents <n>] [--method <m>] [--header "Name: value"]... [--data <text>] [--out <file>]',
          "(the agent's wallet key comes from --wallet-key-file or STACK_AGENT_WALLET_KEY, never argv, and is never printed; only USDC on Base with x402's exact scheme, over https)",
        ],
      },
    ],
  },
  {
    title: 'RentAHuman',
    entries: [
      {
        usage: 'rentahuman join <account> --country <country> --accept-terms',
        summary: "Step one of opening a RentAHuman account for the customer: asks RentAHuman what it costs and prints the payment for the agent's wallet to sign; nothing is taken (one action)",
        notes: ['[--city <city>] [--agent-name <name>] [--passport-stdin]', "(--accept-terms is the customer accepting RentAHuman's terms through its agent; the agent signs the payment with its own wallet key, which this command never holds)"],
      },
      {
        usage: 'rentahuman join-complete <account> <join-id> --signed <signature> --passport-stdin',
        summary: "Step two: sends the agent's signature; the payment goes through the wallet's caps and the customer's decider, and RentAHuman's key is kept in the vault and never shown",
      },
      {
        usage: 'rentahuman fund <account> <cents>',
        summary: "Step one of topping up the customer's RentAHuman wallet from the agent's wallet: prints the payment to sign (one action)",
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'rentahuman fund-complete <account> <fund-id> --signed <signature> --passport-stdin',
        summary: "Step two of a top-up: sends the agent's signature",
      },
      {
        usage: 'rentahuman get <account>',
        summary: "The customer's RentAHuman connection and whether its events are registered; it shows no key",
        notes: ['[--passport-stdin]'],
      },
    ],
  },
  {
    title: 'Meetings',
    entries: [
      {
        usage: 'meeting join <account> <event-id> [--max-seconds <n>] [--wait <seconds>]',
        summary: "Put the agent in the room of one of its calendar events (made with --meeting): STACK's meeting worker joins under the agent's name, runs no model and says nothing of its own (one action)",
        notes: ['[--passport-stdin]', "(the first ten minutes are held on the account's credit, then each next ten; what the meeting used is charged at cost when it ends)"],
      },
      {
        usage: 'meeting say <account> <meeting-id> [--text <words>] [--wait <seconds>]',
        summary: 'Speak in the meeting (as written), then wait for what a participant says or writes next; returns every event since your last action on it',
        notes: ['[--passport-stdin]'],
      },
      { usage: 'meeting chat <account> <meeting-id> --text <line>', summary: "Write a line in the room's chat", notes: ['[--passport-stdin]'] },
      {
        usage: 'meeting leave <account> <meeting-id>',
        summary: "Leave the meeting: the agent's part ends at once, the transcript is stored as a message and the agent is woken",
        notes: ['[--passport-stdin]'],
      },
      { usage: 'meeting list <account> [--status joining|live|ended]', summary: "The account's meetings, newest first", notes: ['[--limit <number>] [--cursor <cursor>] [--passport-stdin]'] },
      { usage: 'meeting get <account> <meeting-id>', summary: "One meeting and its transcript so far; what a participant says is a stranger's text", notes: ['[--passport-stdin]'] },
      {
        usage: 'meeting voice <account> [--voice <name>] [--language <code>]',
        summary: "Read, or with a flag set, the voice and language the agent speaks in during meetings and listens for (Soniox's own words for them; a field left out is cleared; not metered)",
        notes: ["[--passport-stdin]", "(STACK keeps no list of voices or languages: Soniox's refusal is what comes back; an event can set its own with calendar create --meeting-voice and --meeting-language)"],
      },
    ],
  },
  {
    title: 'Chat approvals',
    entries: [
      {
        usage: 'chat list',
        summary: 'Which chat channels are on and the identities bound; a held payment can be approved from a bound chat only within the limits in the policy',
      },
      {
        usage: 'chat link telegram|slack|sms',
        summary: 'Start binding a chat identity; prints the link or slash command to carry into the chat',
        notes: ['[--phone <+E.164>] (sms only; starting a text binding needs the console, signed in)', '(finish in the console: confirm the identity, or type a text\'s code)'],
      },
      { usage: 'chat remove <identity-id>', summary: 'End a bound chat identity at once' },
      {
        usage: 'chat slack-install-url --redirect-uri <url> --state <value>',
        summary: "Where the workspace's admin installs STACK's Slack app",
      },
      { usage: 'chat slack-remove', summary: 'Uninstall the Slack workspace; the Slack identities bound through it end' },
    ],
  },
  {
    title: 'Held actions',
    entries: [
      {
        usage: 'reviews list [--all]',
        summary: 'List the actions a policy held for a person (pending ones unless --all), each with the approval link where a person decides it',
        notes: ['[--limit <number>] (1 to 200)', '(there is no decide command: a person approves or rejects at the link)'],
      },
      { usage: 'reviews get <id>', summary: 'Read one held action and where a person decides it' },
    ],
  },
  {
    title: 'Intents',
    entries: [
      { usage: 'intents simulate --intent-json <path>', summary: 'Dry-run an Intent' },
      { usage: 'intents submit --intent-json <path>', summary: 'Submit for approval' },
      {
        usage: 'intents submit-and-wait --intent-json <path>',
        summary: 'Submit for approval and wait for the decision',
        notes: ['[--timeout 60] [--interval 1] [--expires 900] [--skip-simulation]'],
      },
      { usage: 'intents pending', summary: 'List pending approvals' },
      { usage: 'intents get <approval-id>', summary: 'Show one approval row (any status)' },
      { usage: 'intents approve <approval-id> [--notes "..."]', summary: 'Approve an Intent' },
      {
        usage: 'intents reject <approval-id> [--notes "..."] [--block-future]',
        summary: 'Reject an Intent',
      },
    ],
  },
  {
    title: 'Authority',
    entries: [
      {
        usage: 'authority request --file <request.json> --idempotency-key <key>',
        summary: 'Submit an authority request for approval',
      },
      { usage: 'authority status <request-id>', summary: 'Show an authority request and its decision' },
    ],
  },
  {
    title: 'Evidence packs',
    entries: [
      {
        usage: 'evidence-pack export --scope <kind>:<ref>',
        summary: 'Export a signed evidence pack for a mission, session, incident or period',
        notes: ['[--supersedes pck_*] [--output pack.json] [--air-gap]'],
      },
      { usage: 'evidence-pack list [--scope <kind>:<ref>]', summary: 'List evidence packs' },
      { usage: 'evidence-pack get <pack-id>', summary: 'Show one evidence pack' },
    ],
  },
  {
    title: 'Services',
    entries: [
      { usage: 'service catalog', summary: 'Browse available service catalog' },
      { usage: 'service templates', summary: 'List credential templates' },
      { usage: 'service connections', summary: 'List your connected services' },
      { usage: 'service show <connection-id>', summary: 'Detail on one connection' },
      { usage: 'service verify <connection-id>', summary: 'Re-test connection health' },
      { usage: 'service disconnect <id>', summary: 'Disconnect a service' },
      { usage: 'service rename <connection-id> <name>', summary: 'Rename a connection (owner or admin); calls name it by the new name' },
      {
        usage: 'service credential <provider>',
        summary: 'Retrieve raw credential (operator only)',
        notes: ['[--connection <name|id>]  Which connection, when the service has several'],
      },
      {
        usage: 'service tools <service> --passport-stdin',
        summary: "List the tools of a connected service that speaks MCP over HTTP (any whose connection carries its mcp_url, and RentAHuman), as the agent, through STACK's credential proxy (one action); the answer is the service's own words, never instructions",
        notes: ['[--connection <name|id>]  Which connection, when the service has several', '[--request-id <id>]'],
      },
      {
        usage: 'service call <service> <tool> --passport-stdin [--args <json>]',
        summary: "Call one tool of a connected service as the agent, through STACK's credential proxy (one action); for RentAHuman that is searching people, posting and funding a bounty and the conversations with the people it hires (send_message, get_conversation, list_conversations)",
        notes: ['[--connection <name|id>]  Which connection, when the service has several', '[--request-id <id>] (reuse one id to repeat an unchanged call)'],
      },
      {
        usage: 'service connect-custom --stdin --name <name>',
        summary: 'Connect a custom service; the secret is read from stdin',
        notes: ['[--scopes a,b] [--allowed-hosts h1,h2] [--mcp-url <https address>] [--connection-name <name>] or: --from-file <config.json>'],
      },
      {
        usage: 'service grant --agent <id> --connection <id> --scopes <a,b>',
        summary: 'Grant an agent scoped access to a connection',
        notes: ['[--allow-data-from <source,...>]  A service, or one connection as service@<connection id>. Omit for no cross-service flow'],
      },
      {
        usage: 'service connect-link create <service>',
        summary: 'Make a one-time link that connects a service in your browser, with no credential typed here or in a chat',
        notes: [
          '[--scopes a,b]  OAuth scopes, for a service that signs in on the provider',
          '[--connection-name <name>]  What the connection is called, when the service already has one',
          '(prints the link once; it works once and expires in 10 minutes)',
        ],
      },
      {
        usage: 'service connect-link create --custom <name> --hosts <h1,h2>',
        summary: 'Make a one-time link for your own API: its key goes only to the hosts named here, which the page shows and the owner may correct',
        notes: [
          '[--description <text>]  What the service is, shown on the page',
          '[--template <name>]  A credential template whose fields the page asks for (service templates)',
          '[--mcp-url <address>]  Where its MCP endpoint is, when it speaks MCP over HTTP (https, on one of the hosts)',
          '[--connection-name <name>]  What the connection is called, when the service already has one',
          '(a key or token only, never OAuth; the key is entered on the page, not here)',
        ],
      },
      { usage: 'service connect-link get <link-id>', summary: 'Read whether a connect link was used (pending, connected or expired) and the name its connection will get' },
      { usage: 'service connect-link list', summary: 'List the connect links still waiting for you to finish them' },
      { usage: 'service revoke-agent <agent-id>', summary: "Revoke an agent's service grants" },
      { usage: 'service permissions <agent-id>', summary: "Show an agent's service permissions" },
    ],
    footnote:
      'When a governance change needs human approval, the CLI prints and opens the dashboard\n' +
      'request, waits for that decision, and retries the exact command once if approved.',
  },
  {
    title: 'Approvals',
    entries: [
      {
        usage: 'approval show <approval-id>',
        summary: 'Read one governance approval: its status, the hash of the change it covers and its link',
        notes: ['(read only: a person decides in the dashboard)'],
      },
      {
        usage: 'approval list [--status <status>] [--json]',
        summary: 'List the account\'s governance approvals, newest first; status is pending, approved, rejected, consumed or expired',
        notes: ['(read only: a person decides in the dashboard)'],
      },
    ],
  },
  {
    title: 'Drive',
    entries: [
      {
        usage: 'drive upload <file>',
        summary: "Store a file in the account's drive; an agent's file is private to it unless --account",
        notes: [
          '[--name <name>] [--type <media-type>] (a label: taken from the extension, else application/octet-stream) [--account | --private] [--expires <seconds>] [--passport-stdin]',
          '(a file of any type, stored as it is; 1 GB at most, 10 MB for a file typed as text, Markdown, CSV or JSON; every file is untrusted content)',
          '(the file is streamed from disk as one request, with progress on stderr; the API refuses it while the wallet cannot pay for storage past the free amount, DRIVE_READ_ONLY, and while the account already has as many uploads running as it may, DRIVE_TOO_MANY_UPLOADS)',
        ],
      },
      { usage: 'drive list [--limit <number>] [--cursor <cursor>]', summary: 'List the files you may see, with the account\'s usage' },
      { usage: 'drive get <id>', summary: 'Read one file\'s facts' },
      { usage: 'drive read <id>', summary: 'Read a file of 256 KB or less inline (untrusted content)' },
      {
        usage: 'drive update <id>',
        summary: 'Change who sees a file or when it ends',
        notes: ['[--account | --private] [--expires <seconds> | --no-expiry]'],
      },
      {
        usage: 'drive copy <id>',
        summary: 'Copy a file into a new file of your own, which does not end',
        notes: ['[--name <name>] [--account | --private] [--expires <seconds>]'],
      },
      { usage: 'drive delete <id>', summary: 'Delete a file and its bytes' },
      {
        usage: 'drive share <id> [--ttl <seconds>] [--max-downloads <number>]',
        summary: 'Make a signed download link, shown once; 100 downloads unless you name another number',
      },
      { usage: 'drive links <id>', summary: 'List a file\'s links and their download counts' },
      { usage: 'drive unshare <id> <link-id>', summary: 'End a link at once' },
      {
        usage: 'drive <command> --passport-stdin',
        summary: "Act as the account's agent: pipe its Passport on stdin or type it at the hidden prompt",
        notes: ['(an agent\'s Passport is never taken from a flag)'],
      },
    ],
  },
  {
    title: 'Memory',
    entries: [
      {
        usage: 'memory add <text> --name <name>',
        summary: "Add an episode to the account's memory (metered): answers at once with its uuid and status queued; episodes shows when it is stored",
        notes: [
          '[--file <path> | --text <text>] [--source text|json|message] [--source-description <d>] [--uuid <uuid>] [--at <iso>]',
          '[--exclude-type <t>]... [--instructions <t>] [--previous <episode-uuid>]... [--saga <name>] [--saga-previous <episode-uuid>] [--passport-stdin]',
          '(flagged text is refused when controls are on; with controls off it is stored with its flag)',
        ],
      },
      {
        usage: 'memory triplet --source <name> --edge <name> --fact <text> --target <name>',
        summary: 'Write one fact directly, without extraction (metered)',
        notes: ['[--source-uuid <uuid>] [--target-uuid <uuid>] [--passport-stdin]'],
      },
      {
        usage: 'memory search-nodes <query>',
        summary: 'Search entities',
        notes: ['[--max <n>] [--type <entity-type>]... [--where <field>=<value>]... [--center <uuid>] [--passport-stdin]'],
      },
      {
        usage: 'memory search-facts <query>',
        summary: 'Search facts, with when each held',
        notes: ['[--max <n>] [--center <uuid>] [--edge-type <t>]... [--valid-after <iso>] [--valid-before <iso>] [--invalid-after <iso>] [--invalid-before <iso>] [--passport-stdin]'],
      },
      {
        usage: 'memory episodes',
        summary: 'Episodes, newest first, each with its status: stored, queued, processing or failed (with a reason)',
        notes: ['[--max <n>] [--passport-stdin]'],
      },
      { usage: 'memory fact <uuid>', summary: 'Read one fact', notes: ['[--passport-stdin]'] },
      { usage: 'memory episode-entities <episode-uuid>...', summary: 'The entities and facts the given episodes produced', notes: ['[--passport-stdin]'] },
      { usage: 'memory delete-episode <uuid>', summary: 'Delete an episode; what only it supports goes with it', notes: ['[--passport-stdin]'] },
      { usage: 'memory delete-fact <uuid>', summary: 'Delete one fact', notes: ['[--passport-stdin]'] },
      { usage: 'memory summarize-saga <name>', summary: 'Summarize a saga, the name given as --saga to memory add (metered)', notes: ['[--passport-stdin]'] },
      { usage: 'memory types', summary: "The entity types memory extracts: Graphiti's ten and the account's own", notes: ['[--passport-stdin]'] },
      {
        usage: 'memory type-add <name> --description <text>',
        summary: "Add an entity type of the account's own; later writes extract it beside the ten (free)",
        notes: ['[--field <name>:<kind>[:<word>,<word>]]... | [--fields-file <path>] [--passport-stdin]', '(kind is text, number, date, boolean or one_of)'],
      },
      {
        usage: 'memory type-change <name>',
        summary: 'Change one of the account\'s entity types; later writes use it (free)',
        notes: ['[--description <text>] [--field <name>:<kind>[:<word>,<word>]]... | [--fields-file <path>] [--passport-stdin]'],
      },
      { usage: 'memory type-retire <name>', summary: 'Retire a type: no longer extracted; its entities keep their label (free)', notes: ['[--passport-stdin]'] },
      { usage: 'memory history', summary: "One page of the account's writes, newest first, each with what it changed: before and after; next_cursor in the answer is the --cursor of the next page", notes: ['[--max <n>] [--cursor <next_cursor>] [--passport-stdin]'] },
      {
        usage: 'memory undo <write-id>',
        summary: 'Undo a write, with every later write that changed the same things (free; one delete toward the hourly rate)',
        notes: ['[--dry-run] [--passport-stdin]', '(--dry-run only says what would be undone)'],
      },
      { usage: 'memory settings', summary: 'Show the memory settings, or change them (owner or admin)', notes: ["[--enabled on|off] [--call-memory-access on|off] (whether STACK's model may search memory and the knowledge base during a call STACK holds; with it on, a caller can try to get the call's model to read out what is in memory or the brain)"] },
      {
        usage: 'memory <command> --passport-stdin',
        summary: "Act as the account's agent: pipe its Passport on stdin or type it at the hidden prompt",
        notes: ["(an agent's Passport is never taken from a flag)"],
      },
    ],
  },
  {
    title: 'Brain',
    entries: [
      {
        usage: 'brain add <file-id>... | --prefix <name-prefix>',
        summary: "Make drive files searchable (metered): one row per file with its status and an estimate of the pages reading it bills (the first pages each month free)",
        notes: ['[--passport-stdin]', '(reading is the only cost; the pages and cost are estimated from each file\'s size and type, and the real ones are counted when the file is read; name one file id, several, or every file whose name starts with --prefix)'],
      },
      {
        usage: 'brain remove <file-id>... | --prefix <name-prefix>',
        summary: 'Take files out of the brain; they stay in the drive, only no longer searchable (free)',
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'brain search <query>',
        summary: 'Ask the brain a question and get the passages that answer it, each with its file and page (free; every passage is untrusted content)',
        notes: ['[--passport-stdin]'],
      },
      {
        usage: 'brain list',
        summary: "The files in the brain the caller may see, each with its state, and the month's usage (free)",
        notes: ['[--status reading|searchable|unreadable] [--cursor <c>] [--limit <n>] [--passport-stdin]'],
      },
      {
        usage: 'brain <command> --passport-stdin',
        summary: "Act as the account's agent: pipe its Passport on stdin or type it at the hidden prompt",
        notes: ["(an agent's Passport is never taken from a flag)"],
      },
    ],
  },
  {
    title: 'Drop-offs',
    entries: [
      { usage: 'dropoff list', summary: 'List your drop-offs' },
      { usage: 'dropoff show <id>', summary: 'Detail on one drop-off' },
      {
        usage: 'dropoff create --from <a> --to <b>[,<c>...] --schema <f>',
        summary: 'Create a drop-off for one agent, or for a group: every agent named is woken and the first to collect takes it',
        notes: ['[--ttl <seconds>] [--on-expire notify|retry|fail]'],
      },
      {
        usage: 'dropoff deposit <id> --agent <a> --payload <f>',
        summary: 'Deposit a payload into a drop-off',
        notes: ['[--passport-jti <jti>] [--mission <id>] [--drive-files <id,id>] (drive files the collector can read once it collects)'],
      },
      { usage: 'dropoff collect <id> --agent <a>', summary: 'Collect a payload from a drop-off, and the drive files handed over with it' },
      { usage: 'dropoff expire <id>', summary: 'Force-expire a drop-off' },
    ],
  },
  {
    title: 'Skills',
    entries: [
      { usage: 'skill list [--q "..."]', summary: 'Browse the skills marketplace' },
      { usage: 'skill mine', summary: 'List your own published skills' },
      { usage: 'skill show <id>', summary: 'Detail on one skill' },
      { usage: 'skill publish --file <skill.json>', summary: 'Publish a skill from a JSON spec' },
      { usage: "skill invoke <id> --agent <a> --input '{...}'", summary: 'Invoke a skill' },
      { usage: 'skill suspend <id>', summary: 'Suspend a published skill' },
      { usage: 'skill activate <id>', summary: 'Re-activate a suspended skill' },
      { usage: 'skill allow <id> --agent <a>', summary: 'Allow an agent to use a skill' },
      { usage: 'skill disallow <id> --agent <a>', summary: 'Stop an agent from using a skill' },
      { usage: 'skill favorites', summary: 'List your favourite skills' },
      { usage: 'skill invocations', summary: 'List pending skill invocations' },
      { usage: 'skill check-invocation <id>', summary: 'Show one skill invocation' },
      {
        usage: 'skill complete <id> --output-file <result.json>',
        summary: 'Complete a skill invocation with its output',
      },
      { usage: 'skill check-trust <skill-id>', summary: 'Check the trust level of a skill' },
      { usage: 'skill requests', summary: 'List skill requests' },
      { usage: 'skill post-request "<desc>"', summary: 'Post a new skill request' },
      {
        usage: 'skill matches <request-id>',
        summary: 'Find skills matching a request',
        notes: ['or: --description "<what you want to do>"'],
      },
      {
        usage: 'skill suggest <request-id>',
        summary: 'Suggest a skill composition for a request',
        notes: ['or: --description "<what you want to do>"'],
      },
      { usage: 'skill pending-reviews', summary: 'List skills awaiting review (platform staff)' },
      { usage: 'skill approve <skill-id>', summary: 'Approve a skill (platform staff)' },
      { usage: 'skill reject <skill-id> [--reason "..."]', summary: 'Reject a skill (platform staff)' },
    ],
  },
  {
    title: 'Scan',
    entries: [
      {
        usage: 'scan "<content>" | --file <path>',
        summary: 'Scan content for prompt injection',
      },
      { usage: 'scan usage', summary: "This month's scan usage against the included actions" },
    ],
  },
  {
    title: 'LLM',
    entries: [
      {
        usage: 'llm usage list',
        summary: 'List per-call LLM usage records (cursor-paginated)',
        notes: ['[--limit] [--cursor] [--provider] [--passport-jti] [--mission-id] [--agent-id] [--since] [--until]'],
      },
      {
        usage: 'llm usage summary',
        summary: 'Group-by aggregate (provider [+ model] + day)',
        notes: ["same filters as 'list', plus [--no-group-by-model]"],
      },
      {
        usage: "llm anthropic messages '<body-json>' [--stream]",
        summary: 'Governed Anthropic call; reads the passport token from stdin or a hidden prompt',
      },
      {
        usage: "llm openai chat-completions '<body-json>' [--stream]",
        summary: 'Governed OpenAI call; reads the passport token from stdin or a hidden prompt',
      },
      {
        usage: "llm openrouter chat-completions '<body-json>' [--stream]",
        summary: 'Governed OpenRouter call; reads the passport token from stdin or a hidden prompt',
      },
      {
        usage: "llm openai images '<body-json>'",
        summary: 'An image on your own OpenAI key, through the same gates; files go to the agent drive, marked untrusted',
      },
    ],
  },
  {
    title: 'Identity',
    entries: [
      { usage: 'identity settings', summary: 'Get operator identity settings' },
      {
        usage: 'identity update-settings',
        summary: 'Update operator identity settings',
        notes: ['[--inheritance auto|opt_in] [--ttl 30d|90d|180d|1y] [--auto-revoke true|false]'],
      },
      { usage: 'identity providers', summary: 'List identity-verification providers' },
      { usage: 'identity claims', summary: 'List your verified identity claims' },
      { usage: 'identity session <session-id>', summary: 'Show one identity verification session: pending, completed, failed or expired' },
      { usage: 'identity revoke-claim <id>', summary: 'Revoke an identity claim' },
      {
        usage: 'identity oidc <status|create|update|test|delete>',
        summary: 'Manage the operator OIDC identity configuration',
      },
      {
        usage: 'identity sso-domains <list|add|verify|remove> [<domain>|<domain-id>]',
        summary: 'Prove an e-mail domain for single sign-on with a DNS TXT record, so addresses at it count as verified when your provider (Microsoft Entra ID, for one) does not say',
        notes: ['(add prints the record to publish; verify looks it up now; adding a domain is approved by a person in a browser; owner or admin only)'],
      },
      {
        usage: 'identity spiffe <list|get|create|update|delete>',
        summary: 'Manage SPIFFE trust domains',
      },
      {
        usage: 'identity wimse <list|get|create|update|delete>',
        summary: 'Manage WIMSE issuers',
      },
      {
        usage: 'identity requirements <list|create|replace|clear|delete> <service-id>',
        summary: 'Manage the identity requirements of a service',
      },
    ],
  },
  {
    title: 'Audit',
    entries: [
      { usage: 'audit list [--limit N] [--agent <id>]', summary: 'List audit entries' },
      {
        usage: 'audit export',
        summary: 'Export the audit log',
        notes: ['[--format json|ndjson|csv] [--from ...] [--to ...] [--out <file>]'],
      },
      { usage: 'audit chain-head', summary: 'Current audit-chain head hash' },
      { usage: 'audit verify-chain', summary: 'Verify your audit chain integrity' },
    ],
  },
  {
    title: 'PII redaction',
    entries: [
      { usage: 'pii show', summary: 'Threshold + country scope in force' },
      { usage: 'pii set --countries SE,NO,DK', summary: "Only run these countries' schemes" },
      {
        usage: 'pii set --threshold 0.2',
        summary: 'Confidence to redact (higher redacts less)',
      },
      { usage: 'pii reset', summary: 'Back to built-in defaults' },
    ],
  },
  {
    title: 'Detectors',
    entries: [
      { usage: 'detector list', summary: 'List detectors and their configuration' },
      { usage: 'detector show <detector-key>', summary: 'Show one detector configuration' },
      { usage: 'detector enable <detector-key>', summary: 'Enable a detector' },
      { usage: 'detector disable <detector-key>', summary: 'Disable a detector' },
      {
        usage: 'detector configure <detector-key> --from-file <config.json>',
        summary: 'Replace a detector configuration',
      },
      { usage: 'detector reset <detector-key>', summary: 'Back to the built-in defaults' },
    ],
  },
  {
    title: 'Trust',
    entries: [
      { usage: 'trust get [<agent>]', summary: "Whether the account's agents ask first or are trusted to act: the account's value, or one agent's over it" },
      {
        usage: 'trust set <ask_first|trust_agents> [<agent>]',
        summary: 'Ask first, or trust the agents (nothing waits for a person on card purchases, orders on your own supplier account and governance changes made with your own key); for the account or one agent',
        notes: ['(owner or admin)'],
      },
      { usage: 'trust clear <agent>', summary: "Remove an agent's own value so it follows the account again" },
    ],
  },
  {
    title: 'Message access',
    entries: [
      { usage: 'message-access get [<agent>]', summary: "What the account's agents may do with the customer's messages: the account's values, or one agent's over them" },
      {
        usage: 'message-access set [--read-teammates true|false] [--read-only true|false] [<agent>]',
        summary: 'Whether agents read the messages of every message account of the customer (read-teammates, default true) or only their own, and whether they may only read (read-only, default false: true means no sending, replying, forwarding, texting or posting from any account); for the account or one agent',
        notes: ['(owner or admin, an agent is refused; applies at once with no approval)'],
      },
      { usage: 'message-access clear <agent> <read-teammates|read-only>...', summary: 'Remove the values an agent set for itself so it follows the account again' },
    ],
  },
  {
    title: 'Messages',
    entries: [
      {
        usage: 'messages search',
        summary: "Search every message you may read across the customer's message accounts and channels, newest first, without the bodies (read one with account messages)",
        notes: [
          '[--agent <agent>] [--channel email|sms|voicemail|call|telegram|post|meeting] [--sender <address>] [--recipient <address>] [--thread <id>] [--q "<text>"] [--after <datetime>] [--before <datetime>] [--limit <1-50>] [--cursor <cursor>]',
          '(datetimes are ISO 8601 with an offset; the window is the last 30 days, and a search on --q, --sender, --recipient or --thread needs a window of at most 90 days)',
        ],
      },
      {
        usage: 'messages attachment <account> <message> <file>',
        summary: 'Read a file a message carries, through the message: 256 KB or less inline (untrusted content)',
      },
    ],
  },
  {
    title: 'Flagged content',
    entries: [
      { usage: 'flagged-content get', summary: 'What controls do with flagged content, per severity, and whether controls are on' },
      {
        usage: 'flagged-content set [--warning withhold|deliver] [--critical withhold|deliver]',
        summary: 'Withhold flagged content from the agent or deliver it with its flag; applies while controls are on',
        notes: ['(owner or admin)'],
      },
    ],
  },
  {
    title: 'Security events',
    entries: [
      { usage: 'event list [--agent <id>]', summary: 'List security events' },
      { usage: 'event show <id>', summary: 'Detail on one security event' },
      { usage: 'event resolve <id>', summary: 'Mark a security event resolved' },
    ],
  },
  {
    title: 'Notifications',
    entries: [
      { usage: 'notifications methods list', summary: 'List delivery methods' },
      {
        usage: 'notifications methods add --kind <k> --destination <addr>',
        summary: 'Add a delivery method (kind: email, sms or webhook)',
      },
      { usage: 'notifications methods test <id>', summary: 'Send a test notification' },
      { usage: 'notifications methods send-code <id>', summary: 'Send a verification code' },
      {
        usage: 'notifications methods verify <id> --code <code>',
        summary: 'Verify a delivery method with its code',
      },
      { usage: 'notifications methods delete <id>', summary: 'Delete a delivery method' },
      { usage: 'notifications rules list', summary: 'List notification rules' },
      {
        usage: 'notifications rules create --method <id> --events <e1,e2>',
        summary: 'Create a notification rule',
        notes: ['or: --methods <id1,id2> [--min-severity info|warning|critical]'],
      },
      {
        usage: 'notifications rules update <id>',
        summary: 'Update a notification rule',
        notes: ['[--events e1,e2] [--min-severity info|warning|critical] [--methods id1,id2]'],
      },
      { usage: 'notifications rules delete <id>', summary: 'Delete a notification rule' },
    ],
  },
  {
    title: 'Inbound webhooks',
    entries: [
      {
        usage: 'inbound-webhook create --provider <agentmail|generic> --agent <agt_*>',
        summary: 'Create an inbound webhook (returns the URL and the plaintext secret)',
        notes: ['[--forward-url <https://...>]  log-only if omitted'],
      },
      { usage: 'inbound-webhook list', summary: 'List all inbound webhooks' },
      { usage: 'inbound-webhook get --id <iwh_*>', summary: 'Show one inbound webhook' },
      { usage: 'inbound-webhook revoke --id <iwh_*>', summary: 'Revoke an inbound webhook' },
      { usage: 'inbound-webhook rotate-secret --id <iwh_*>', summary: 'Issue a new signing secret (printed once); the old one keeps signing for 24 hours' },
    ],
  },
  {
    title: 'Partners',
    entries: [
      {
        usage: 'partner account create --ref <your-reference> [--controls]',
        summary: 'Open an account for a customer under your own reference (paid from your wallet; idempotent); --controls switches its hosted controls on',
      },
      { usage: 'partner account list', summary: 'List your accounts with month-to-date usage', notes: ['[--ref <your-reference>]'] },
      { usage: 'partner account get <id>', summary: 'Show one account' },
      {
        usage: 'partner account revoke <id>',
        summary: 'Close an account, its webhooks and its passports',
      },
      { usage: 'partner account rotate-key <id>', summary: "Replace an account's API key (printed once)" },
      {
        usage: 'partner account invite <id> --email <email>',
        summary: 'Invite the customer to see the account, read-only',
        notes: ['[--name <name>]'],
      },
      {
        usage: 'partner account controls <id> --on|--off',
        summary: "Switch hosted controls on or off for one account (paid from your wallet while on)",
      },
      {
        usage: 'partner account release <id>',
        summary: 'Release the account to its customer: they are mailed a claim link',
        notes: ['[--email <email>]  defaults to the one customer invited', '[--cancel]  withdraw a release the customer has not claimed', '[--status]  where the release stands'],
      },
      { usage: 'partner releases', summary: 'List the releases you have a record of' },
      {
        usage: 'partner account webhook --account <op_*> --provider <p> --agent <agt_*>',
        summary: 'Provision an inbound webhook under an account',
        notes: ['[--forward-url <https://...>]'],
      },
      {
        usage: 'partner account issue-passport --account <op_*> --agent <agt_*> --mission <ms_*>',
        summary: 'Issue a passport for an agent under an account',
        notes: ['[--intent "<summary>"] [--services a,b] [--ttl 900]'],
      },
    ],
  },
  {
    title: 'Team',
    entries: [
      { usage: 'team list', summary: 'List team members' },
      {
        usage: 'team invite <email> --name "<full name>"',
        summary: 'Invite a team member',
        notes: ['[--role admin|standard|readonly] [--allowed-connections id1,id2]'],
      },
      {
        usage: 'team update <id>',
        summary: 'Change a team member',
        notes: ['[--role admin|standard|readonly] [--allowed-connections id1,id2] [--status ...]'],
      },
      { usage: 'team revoke <id>', summary: 'Remove a team member' },
      {
        usage: 'team sso-unbind (<id> | --issuer <url>)',
        summary: "Forget a member's single sign-on identity, or that of everyone who signed in through one provider, so they bind again after you change provider",
        notes: ['(a person approves it in a browser; owner or admin only)'],
      },
    ],
  },
  {
    title: 'Monitor',
    entries: [
      { usage: 'monitor', summary: 'Replay a scripted run (same as --demo)' },
      { usage: 'monitor --demo [--loop]', summary: 'Replay a real-shape mission (no auth needed)' },
      { usage: 'monitor --follow', summary: 'Tail your own audit log' },
      { usage: 'monitor --sandbox', summary: 'Tail the public sandbox feed' },
      { usage: 'monitor --challenge', summary: 'Tail the public email agent feed' },
    ],
  },
];

/**
 * Router aliases per top-level verb. index.ts dispatches on the verb and on
 * every alias listed here; commands.test.ts keeps the two in step.
 */
export const COMMAND_ALIASES: Readonly<Record<string, readonly string[]>> = {
  agent: ['agents'],
  passport: ['passports'],
  intents: ['intent'],
  mission: ['missions'],
  fleet: ['fleets'],
  account: ['accounts'],
  'evidence-pack': ['evidence-packs'],
  'inbound-webhook': ['inbound-webhooks'],
  quickstart: ['init'],
  service: ['services'],
  approval: ['approvals'],
  dropoff: ['dropoffs'],
  skill: ['skills'],
  event: ['events', 'security-event', 'security-events'],
  team: ['members', 'member'],
  me: ['whoami'],
  notifications: ['notification', 'notify'],
  detector: ['detectors'],
  policies: ['policy'],
  reviews: ['review'],
  wake: ['wakes'],
  calendar: ['cal'],
  meeting: ['meetings'],
};

export interface OptionEntry {
  readonly name: string;
  /** `{apiUrl}` is replaced with the API base URL. */
  readonly description: string;
}

export interface OptionSection {
  readonly title: string;
  readonly entries: readonly OptionEntry[];
}

export const OPTION_SECTIONS: readonly OptionSection[] = [
  {
    title: 'Global flags',
    entries: [
      { name: '--json', description: 'Emit raw JSON instead of formatted tables.' },
      {
        name: '--control-ref <ref>',
        description:
          'Retry an action the owner approved: the ref a CONTROL_DENIED refusal (reason review_required) named, sent as X-Control-Ref on the writes of the command. Run the same command again with it once the owner approved.',
      },
    ],
  },
  {
    title: 'Environment',
    entries: [
      {
        name: 'STACK_OAUTH_SCOPE',
        description:
          'Override the OAuth scope requested at `auth login`. Default covers routine runtime and inspection flows; account, secret, billing and security administration remain explicit opt-ins. Set an exact subset (e.g. "passports:read agents:read services:read audit:read") for monitoring-only sign-ins.',
      },
      {
        name: 'STACK_API_URL',
        description: 'Point the CLI at a non-prod API (self-host / dev). Defaults to https://api.getstack.run.',
      },
    ],
  },
  {
    title: 'monitor flags',
    entries: [
      {
        name: '--demo',
        description:
          'Replay a real-shape mission (no auth needed). Same row format as --follow, just scripted.',
      },
      {
        name: '--follow',
        description:
          "Tail your operator's actual audit_log. Polls every 1s. Uses your `auth login` session.",
      },
      { name: '--loop', description: 'Loop the demo until Ctrl-C (default is one run).' },
      { name: '--agent <agent_id>', description: '(--follow) Only show entries for this agent.' },
      { name: '--jti <passport_jti>', description: '(--follow) Only show entries for this passport.' },
      {
        name: '--sandbox',
        description:
          'Tail the public sandbox feed at {apiUrl}/v1/public/events. No API key needed; implies a live tail (no --follow required). Same stream visitors see on getstack.run.',
      },
      {
        name: '--challenge',
        description:
          'Tail the public email agent at agent@getstack.run ({apiUrl}/v1/public/events?feed=challenge). No API key needed; implies a live tail. Same stream the board on getstack.run/attack renders.',
      },
    ],
  },
];

export type ExampleStep = { readonly cli: string } | { readonly shell: string };

export interface Example {
  readonly comment: readonly string[];
  readonly steps: readonly ExampleStep[];
}

/** Worked examples printed by `--help`. `cli` steps get the invocation prefix. */
export const HELP_EXAMPLES: readonly Example[] = [
  {
    comment: ['enroll a freshly-registered agent so the SDK skips the dance'],
    steps: [{ cli: 'agent enroll research-pipeline' }],
  },
  {
    comment: ['replay a credential-exfiltration-caught-by-scope_drift mission'],
    steps: [{ cli: 'monitor --demo --loop' }],
  },
  {
    comment: ['tail the public sandbox (no signup, no key)'],
    steps: [{ cli: 'monitor --sandbox' }],
  },
  {
    comment: ['watch strangers attack our public email agent, live'],
    steps: [{ cli: 'monitor --challenge' }],
  },
  {
    comment: ['sign in once, then tail your real audit log (everything)'],
    steps: [{ cli: 'auth login' }, { cli: 'monitor --follow' }],
  },
  {
    comment: ['tail just one agent'],
    steps: [{ cli: 'monitor --follow --agent abc123' }],
  },
];

const ARGUMENT_START = /^[<[("'-]/;

/** The words of a usage string that name the command, before any argument. */
export function commandPath(usage: string): string {
  const words = usage.split(' ');
  const path: string[] = [];
  for (const word of words) {
    if (ARGUMENT_START.test(word)) break;
    path.push(word);
  }
  return path.join(' ');
}

/** The top-level verb of a usage string. */
export function commandVerb(usage: string): string {
  return commandPath(usage).split(' ')[0] ?? '';
}

/** Every top-level verb the registry documents, in registry order. */
export function registeredVerbs(): string[] {
  const verbs: string[] = [];
  for (const group of COMMAND_GROUPS) {
    for (const entry of group.entries) {
      const verb = commandVerb(entry.usage);
      if (!verbs.includes(verb)) verbs.push(verb);
    }
  }
  return verbs;
}

/** Every verb the router must accept: registry verbs plus their aliases. */
export function routedVerbs(): string[] {
  const verbs = new Set<string>(registeredVerbs());
  for (const aliases of Object.values(COMMAND_ALIASES)) for (const alias of aliases) verbs.add(alias);
  return [...verbs];
}
