# @getstackrun/cli

STACK from your terminal. The operator CLI mirrors nearly every STACK surface:
register agents, issue passports, connect services and grant scoped
credentials, manage your team, configure detectors and notifications, retrieve
credentials for scripts and CI, and tail the live audit log. Sign in once via
OAuth Device flow.

```sh
# Sign in (browser opens, RFC 8628 Device flow)
npx @getstackrun/cli auth login

# Fastest path: register a safe bot, make one governed LLM call, see the proof
npx @getstackrun/cli quickstart

# Run a localhost LLM gateway — point any tool's baseURL at it, no key on the box
npx @getstackrun/cli proxy serve --agent familybot

# Retrieve a credential for a script (operator-only, audited, revocable)
export SLACK_TOKEN=$(npx @getstackrun/cli service credential slack --json | jq -r .access_token)

# Tail your live audit log
npx @getstackrun/cli monitor --follow

# See everything
npx @getstackrun/cli --help
```

> Agents with the default `stack_managed` signing model need no enrollment —
> `quickstart` and `proxy serve` provision the on-box keypair automatically on
> first run. `agent enroll` is only for the advanced `customer_managed`
> bring-your-own-keypair path.

## Docs for agents

How-to guides for every STACK service and for controls are published as markdown. The list is at https://getstack.run/llms.txt, and one service's guide is at https://getstack.run/docs/account/<service>.md (for example https://getstack.run/docs/account/email.md).

## Which surface? CLI vs MCP vs SDK

STACK has three client surfaces. Pick by who is driving.

| Surface | Who drives it | When | What it's for |
| --- | --- | --- | --- |
| **MCP** (`mcp.getstack.run`) | an LLM assistant (Claude Code, Cursor) | dev and setup, in natural language | auto-discovered `stack_*` tools over OAuth |
| **SDK** (`@getstackrun/sdk`, `getstack`) | the agent's own code | the runtime hot path | offline passport verification, in-process |
| **CLI** (`npx @getstackrun/cli`) | a human operator in a terminal | ops, scripts, CI | routine operator actions + live audit tail; team, credential and administration commands require explicit OAuth scopes |

The three share one credential: `auth login` writes `~/.stack/credentials.json`,
and both SDKs read it. Sign in once, all three work.

The default CLI login is the same set a person gets signing in from an MCP
client. It does not grant team administration, raw credential retrieval,
payout writes, OAuth-app/CMEK changes, authority or identity mutation, skill
publishing, partner administration, or platform admin. For a deliberate
management session, set `STACK_OAUTH_SCOPE` to the exact scopes you
need and sign in again; refresh tokens preserve or narrow scope and cannot add
it later.

## Commands

`npx @getstackrun/cli --help` prints every command. The reference below is
generated from the same registry as `--help` (`src/commands.ts`), so the two
cannot drift. Prefix each command with `npx @getstackrun/cli`.

<!-- commands:begin (generated from src/commands.ts by help.ts; do not edit by hand) -->

#### Get started

| Command | What it does |
| --- | --- |
| `quickstart` | Guided setup: register a safe bot, issue a passport, make one governed LLM call, print the audit row |
| `proxy serve --agent <name\|id>` | Run a localhost LLM gateway. Point any tool's baseURL at it (dummy key ok); STACK injects the real key. No key on the box.<br>`[--port 8788] [--provider anthropic\|openai\|openrouter] [--mission-ttl 3600]` |
| `setup [--clients claude,codex,cursor]` | Add STACK to one or several installed MCP clients<br>`Client names may be separated by commas or spaces.` |
| `register` | Print how to get started and the MCP install instructions |

#### Account

| Command | What it does |
| --- | --- |
| `auth login` | Sign in via browser (Device flow, RFC 8628) |
| `auth status` | Show current sign-in state |
| `auth logout` | Revoke session and clear local credentials |
| `me` | Print your operator profile |

#### Usage & billing

| Command | What it does |
| --- | --- |
| `usage` | Consumption vs plan + spend + earnings (billing period) |
| `usage --period <p>` | Scope to a window: today \| yesterday \| 7d \| 30d \| month \| last-month \| billing (default) |
| `usage --since <iso> --until <iso>` | Arbitrary range (ISO-8601 or unix-ms)<br>``scan usage` and `llm usage` drill into those meters` |
| `billing subscriptions` | Read the platform and controls subscription state and this month's account actions and control checks |
| `billing subscribe platform\|controls` | Start the platform or hosted controls subscription; prints the Stripe Checkout URL and whether a free trial applies<br>`(controls need the platform subscription first; a 409 SUBSCRIPTION_CONFLICT means it is already on, or the account does not need one)` |

#### Agents

| Command | What it does |
| --- | --- |
| `agent list` | List all your agents |
| `agent show <name\|id>` | Detail on one agent |
| `agent register <name>` | Register a new agent<br>`[--profile proxied-llm-bot]  <- safe default for a bot that just runs`<br>`[--key-mode stack_managed\|customer_managed\|co_signed]`<br>`[--llm-inject-system-prompt true\|false]  <- no effect: accepted and ignored  [--llm-redact-pii true\|false]`<br>`[--accountability-mode logged\|enforced\|standard]  <- new agents start logged`<br>`[--eval-traffic true\|false]  <- test traffic: warnings arrive resolved, criticals stay live` |
| `agent setup --from-file <setup.json>` | Register an agent, its first grants and the hosts its connections may reach, as one approval |
| `agent dismiss-warnings <name\|id>` | Resolve an agent's open warnings and hide new ones of the same kinds for a day; criticals stay open |
| `agent update <name\|id>` | Update LLM-gateway toggles (redaction defaults true / fail-closed)<br>`[--llm-inject-system-prompt true\|false]  <- no effect: accepted and ignored`<br>`[--llm-redact-pii true\|false]  <- false sends user PII to the provider unredacted` |
| `agent enroll <name\|id>` | Enroll a customer-managed keypair (advanced; stack_managed agents and 'proxy serve' auto-enroll, no manual step) |
| `agent rotate <name\|id>` | Rotate keypair (admin only) |
| `agent sign-claim <name\|id>` | Sign a claim envelope locally (customer_managed mode)<br>`--envelope <file.json> [--out <file>]` |
| `agent suspend <name\|id>` | Suspend an agent |
| `agent unsuspend <name\|id>` | Re-activate a suspended agent |
| `agent unblock <name\|id>` | Clear an auto-blocked agent so it can issue new passports |
| `agent delete <name\|id>` | Delete an agent |

#### Passports

| Command | What it does |
| --- | --- |
| `passport list` | List active passports |
| `passport issue --agent <name\|id> --mission <ms_id> --intent "<summary>"` | Issue a passport for an agent under a Mission<br>`[--services slack,stripe] [--ttl <seconds>]`<br>`or: --from-file issue.json [--mission <ms_id>]` |
| `passport delegate --agent <child>` | Delegate a passport to a child agent (reads the parent token securely)<br>`[--services a,b] [--ttl 900]` |
| `passport verify` | Verify a passport JWT from stdin |
| `passport refresh <jti>` | Refresh a passport JWT from stdin |
| `passport revoke <jti>` | Revoke one passport |
| `passport revoke-agent <id>` | Revoke all passports for an agent |
| `passport revoke-session <id>` | Revoke all passports for a session |
| `passport revoke-all --yes` | Revoke every active passport |
| `passport report <jti>` | Show the report for one passport |

#### Missions

| Command | What it does |
| --- | --- |
| `mission start --agent <name\|id> --intent-summary "..."` | Open a Mission for an agent and issue its Passport<br>`[--services a,b] [--expires-in N] [--ttl N]`<br>`[--recipients a@x.com,b@x.com] (Recipients: who this Mission may send to. A policy rule that leaves recipients to each Mission allows a send only to these.)`<br>`[--pin <path>=<value>] (repeatable; a request field such as body.to, or * for every recipient field; a comma list means in)`<br>`[--reply-to <message-id>] (Reply to a message: pins the Mission to the sender of this message, so the agent can answer that person and no one else.)` |
| `mission start --file <path>` | Start a Mission under a fleet policy |
| `mission open --intent-summary "..."` | Open a Mission before issuing its Passport<br>`[--agent <name\|id>] [--services a,b] [--expires-in N]`<br>`[--recipients a@x.com,b@x.com] (Recipients: who this Mission may send to. A policy rule that leaves recipients to each Mission allows a send only to these.)`<br>`[--pin <path>=<value>] (repeatable; a request field such as body.to, or * for every recipient field; a comma list means in)`<br>`[--reply-to <message-id>] (Reply to a message: pins the Mission to the sender of this message, so the agent can answer that person and no one else.)` |
| `mission open --file <path>` | Open a Mission from a request file |
| `mission add-recipients <id>` | Add who a running Mission may send to (the owner; nothing pinned is taken away)<br>`[--recipients a,b] [--pin <path>=<value>] [--reply-to <message-id>]` |
| `mission renew <id>` | Renew the Passport for an existing Mission |
| `mission list` | List Missions<br>`[--status active\|completed\|revoked\|paused] (paused: the Missions a cap paused, waiting for your review)` |
| `mission review <id> --decision raise\|continue\|close` | Decide a Mission a cap paused; its agent is told<br>`[--limit N] (with raise: the new limit of the cap that paused it)` |
| `mission making-allowance <id> --cents N \| --none` | Pre-approve a Mission's print-on-demand orders up to an amount |
| `mission get <id>` | Show one Mission |
| `mission complete <id>` | Complete a Mission<br>`[--output-json <path>]` |
| `mission revoke <id> --reason <r>` | Revoke a Mission with reason adversarial or operator_initiated_clean<br>`[--notes "..."]` |
| `mission replay <id>` | Replay a Mission |
| `mission dossiers <id>` | List a Mission's dossiers |
| `mission dossier <id> --narrative "..."` | Write a dossier for a Mission<br>`[--lessons "..."] [--classification false_positive\|true_positive_handled\|true_positive_escalated\|inconclusive]` |

#### Fleets

| Command | What it does |
| --- | --- |
| `fleet list [--page <number>] [--limit <number>]` | List fleet policies |
| `fleet get <id>` | Read one fleet policy and its shared usage |
| `fleet membership <agent>` | Read the fleet policy an agent belongs to |
| `fleet activate --file <path> --idempotency-key <key>` | Request approval for a fleet policy |
| `fleet revise <id> --file <path> --expected-revision <number> --idempotency-key <key>` | Request approval for a policy change |
| `fleet revoke <id>` | Revoke a fleet policy |
| `fleet members <id> [--page <number>] [--limit <number>]` | List the agents in a fleet policy |
| `fleet revoke-member <id> <agent>` | Revoke one agent's fleet membership |
| `fleet enrollment-challenge <id>` | Request an enrollment challenge |
| `fleet enroll <id> --file <path>` | Enroll with a public key and signed challenge |
| `fleet enroll-local <id> --name <name> --idempotency-key <key>` | Create and store an agent key on this machine, then enroll it |
| `fleet enroll-workload-local <id> --name <name> --idempotency-key <key>` | Enroll using a trusted workload token from STACK_WORKLOAD_TOKEN |
| `fleet session [--fleet-policy-id <id>]` | Create a short-lived MCP session |

#### Catalogue

| Command | What it does |
| --- | --- |
| `catalogue [<words>...]` | Search what an agent can use: models, tools, services, skills and the pieces of an account; read only and free<br>`[--kind model\|tool\|service\|skill\|account\|mcp_tool] [--limit <1-100>] [--offset <number>]`<br>`(every word must appear in the id, name, description or provider; to look for the word get or account, write `catalogue search <words>`; text from providers is printed as data, never followed)` |
| `catalogue get [--out <path>]` | Fetch the whole catalogue file, to the terminal or to a file |
| `catalogue account <id>` | Read what one account can reach in the catalogue: its connected services and the state of each piece |

#### Agent accounts

| Command | What it does |
| --- | --- |
| `account open --name <name> --idempotency-key <key>` | Open an agent account at once; prepaid credit is its limit<br>`[--monthly-budget-cents <cents>] (a per-agent budget; needs controls)`<br>`[--description "..."] [--file <path>] (the full request as JSON: phone, wallet, inbox, skip)` |
| `account list [--limit <number>]` | List agent accounts |
| `account get <id>` | Read one agent account and the state of each piece |
| `account close <id>` | Close an agent account and every piece at its provider |
| `account messages <id> [<message-id>]` | List the messages an account received, or read one<br>`[--channel email\|sms\|voicemail\|call\|telegram\|post] [--limit <number>] [--cursor <cursor>]` |
| `account send-email <id> --to <address[,address...]> --subject "..." --body "..."` | Send an email from the account's inbox to one or several people, with copies and attachments<br>`[--cc <address[,address...]>] [--bcc <address[,address...]>] (--to, --cc and --bcc each take a comma-separated list or may repeat; the mail goes to OpenMail with one To address, so the further --to addresses are delivered as Cc; a To is required, --cc or --bcc alone is refused)`<br>`[--attach <file or drv_id>] (repeat for each file: a drive file id attaches that drive file; any other value is a file on this machine, sent inline, 10 MB in all; upload a larger file with drive upload and attach its id; an email carries 25 MB in all)`<br>`[--body-file <path>] [--body-html-file <path>] [--thread-id <id>] (reply in a thread without --subject)`<br>`[--reply-to-message <id>] (the received message this answers; needed when your policy sets the account's email recipients per mission, and then it goes only to whoever wrote that message)` |
| `account reply-email <id> <message-id> --body "..."` | Reply to an email the account received, in its thread and quoting it, to the person who wrote it<br>`[--all] (reply to everyone the email went to as well) [--cc <addresses>] [--bcc <addresses>] [--subject "..."]`<br>`[--no-quote] (leave the quote of the email being answered out)`<br>`[--body-file <path>] [--body-html-file <path>] [--attach <file or drv_id>] (repeat for each file; see send-email)` |
| `account forward-email <id> <message-id> --to <address[,address...]>` | Forward an email the account received, with the attachments that were kept, as a new email in no thread<br>`[--body "..."] [--body-file <path>] (your own note above the original) [--cc <addresses>] [--bcc <addresses>]`<br>`[--no-attachments] (leave the original's files out) [--no-quote] (leave the original's text out) [--attach <file or drv_id>] (more files; see send-email)` |
| `account send-sms <id> --to <+E.164> --body "..."` | Send a text from the account's number to any country Twilio can reach<br>`[--body-file <path>]`<br>`[--reply-to-message <id>] (the received message this answers; needed when your policy sets the account's text recipients per mission, and then it goes only to whoever wrote that message)` |
| `account telegram-start <id>` | Get the link the owner opens in Telegram to have the agent's bot made for them (no BotFather, no pasted token)<br>`[--name <suggested bot name>] (owner or admin; nothing is created until the owner confirms in Telegram; the link is single-use and lasts 10 minutes)` |
| `account telegram-connect <id>` | Give the agent its own Telegram bot (made with BotFather); the bot token is read from stdin or a hidden prompt, never argv<br>`(owner or admin; an OAuth sign-in cannot connect a bot, use an API key)` |
| `account telegram <id>` | Read the agent's Telegram bot |
| `account telegram-chats <id>` | List the chats that have written to the bot (a bot cannot message a chat first) |
| `account telegram-disconnect <id>` | Take the agent's Telegram bot away and stop receiving |
| `account send-telegram <id> --chat-id <chat> --body "..."` | Answer a chat on the agent's own Telegram bot (only that account's own agent, or the owner, sends from it)<br>`[--body-file <path>] [--passport-stdin] (send it as the account's agent)` |
| `account message-delete <id> <message-id>` | Delete one message the account received (owner or admin) |
| `account call <id> --to <+E.164>` | Place a phone call from the account's number to any country Twilio can reach<br>`(you hold the call: STACK says nothing; it opens with --greeting or with silence, and you speak with account call-say; the command returns once the call is answered, with what the other side first says)`<br>`[--greeting "..."] [--wait-seconds <number>] (0 to 60, default 30: how long to wait for the first sentence)`<br>`[--on-behalf-of <name> --brief "..." \| --brief-file <path>] (STACK holds the call with its own model instead, opening with its line that the other side is speaking with an AI on behalf of that name)`<br>`[--max-seconds <number>] (30 to 14400, the default; the call is paid 10 minutes at a time) [--tts-provider Google\|Amazon\|ElevenLabs] [--voice <name>] [--language <BCP-47>]`<br>`[--reply-to-message <id>] (the received message this answers; needed when your policy sets the account's call recipients per mission, and then it goes only to whoever wrote that message)`<br>`[--passport-stdin] (place it as one of your agents; reads the Passport token from stdin or a hidden prompt)` |
| `account answer-call <id> <call-id>` | Answer a call that is ringing on the account's number, held by you or, with a brief, by STACK<br>`[--greeting "..."] [--wait-seconds <number>] \| [--on-behalf-of <name> --brief "..." \| --brief-file <path>] [--max-seconds <number>] [--tts-provider ...] [--voice ...] [--language ...]`<br>`[--passport-stdin] (answer it as one of your agents; reads the Passport token from stdin or a hidden prompt)`<br>`(a call rings for 30 seconds, then goes to voicemail)` |
| `account call-say <id> <call-id> [--text "..."]` | Speak on a live call you hold, then wait for what the other side says next; prints the events since your last call action<br>`[--wait-seconds <number>] (0 to 60, default 30) [--passport-stdin]` |
| `account call-keys <id> <call-id> --digits <keys>` | Send keys to the other side of a live call as tones (0-9, *, #, w for a pause)<br>`[--passport-stdin]` |
| `account call-voice <id> <call-id> [--tts-provider ...] [--voice ...] [--language <BCP-47>]` | Change the voice or language of a live call for the rest of it<br>`[--passport-stdin]` |
| `account hang-up <id> <call-id>` | Hang up a live call of the account, whoever holds it; STACK says nothing<br>`[--passport-stdin]` |
| `account call-voice-settings <id>` | Read the account's call voice and voicemail greeting, or set them with any of the flags (a field left out is cleared)<br>`[--tts-provider Google\|Amazon\|ElevenLabs] [--voice <name>] [--language <BCP-47>] [--voicemail-greeting "..."] [--passport-stdin] (the owner, an admin or the account's own agent)` |
| `account decline-call <id> <call-id>` | Decline a call that is ringing on the account's number; the call is hung up with nothing said<br>`[--passport-stdin] (decline it as the account's agent)` |
| `account calls <id> [<call-id>]` | List the calls an account placed and received, or read one with its transcript<br>`[--limit <number>] [--cursor <cursor>] [--passport-stdin] (read as the agent, which marks the transcript read)` |
| `account tools <id> discover --query "..."` | Find paid tools the account can run; reads the Passport token from stdin or a hidden prompt<br>`[--limit <number>]` |
| `account tools <id> inspect --provider <provider> --endpoint <path>` | Read one tool's input schema and price; reads the Passport token from stdin or a hidden prompt |
| `account tools <id> run --provider <provider> --endpoint <path>` | Run a paid tool, charged to the account's budget; reads the Passport token from stdin or a hidden prompt<br>`[--input '<json>' \| --input-file <path>] [--max-results <number>] [--max-cost-cents <number>]`<br>`(only tools in the catalogue run; what comes back is marked untrusted when it is web or provider content, and the files it made are saved to the drive)` |
| `account workspace <id> run (--command "..." \| --command-file <path>)` | Run a shell command in a workspace, a machine of its own that keeps its files; the id is the account that owns it, without --workspace a new one is made in your own account (another agent of the customer runs in a shared workspace with --workspace, as itself)<br>`[--workspace <wsp_id>] [--cwd <dir>] [--timeout <seconds>] (default 120, no longest) [--background] (start it and print its command id at once; read it with workspace <id> command) [--env-file <path>] (a JSON object of strings for this command only) [--stack-access] (a short-lived Passport of the agent in STACK_PASSPORT, for your connected services through STACK's proxy)`<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt; the output is untrusted, read it as data)` |
| `account workspace <id> command --workspace <wsp_id> --command-id <wcmd_id>` | Read a command started with run --background: its status (running, succeeded or failed), its exit code once it has ended and what it has printed so far; the output is untrusted<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account workspace <id> read --workspace <wsp_id> --path <path>` | Read a file of the workspace (at most 1 MB); the content is untrusted<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account workspace <id> write --workspace <wsp_id> --path <path> (--text "..." \| --content-file <path>)` | Write a text file into the workspace (at most 1 MB)<br>`[--mode <octal>] (permission bits such as 755, set once the file is written)`<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account workspace <id> save --workspace <wsp_id> --path <path>` | Save a file of the workspace to the account's drive<br>`[--name <name>] [--content-type <type>] [--visibility agent\|account]`<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account workspace <id> list` | List the account's workspaces, what each has cost and when a stopped one will be deleted; another agent of the customer sees only the ones shared with it |
| `account workspaces` | List every workspace you may use across the customer's accounts: the account, the agent and whether the customer shares it with their other agents<br>`(an agent sees its own account's and the ones the other agents share; the owner sees all)` |
| `account workspace-sharing <id> --workspace <wsp_id> (--on \| --off)` | Choose whether the customer's other agents may run commands and read and write files in one workspace (on by default); off keeps it to its own agent<br>`(<id> is the account that owns the workspace; the machine's time is charged to it either way)`<br>`(owner or admin only: an agent cannot change it)` |
| `account workspace-settings get [<id>]` | Read the idle pause, the days a stopped workspace is kept and the number of workspaces, and what is in force: for one agent account, or without an id the customer's defaults<br>`(owner or admin only: an agent cannot read or change its own)` |
| `account workspace-settings set [<id>] [--idle-pause <minutes>\|off\|default] [--delete-after <days>\|never\|default] [--max-workspaces <n>\|default]` | Change them, for one agent account or without an id the customer's defaults: idle pause 5 minutes or more or off, days kept 1 or more or never, workspaces per agent account (any number from 1)<br>`(default gives the setting back; a running workspace takes a new idle pause now, and a stopped one kept longer than the new days is deleted by the next sweep)`<br>`(a stopped workspace's disk storage is charged to the account until the workspace is deleted; the money held for a machine is not a setting)`<br>`(owner or admin only)` |
| `account workspace <id> stop --workspace <wsp_id> [--delete]` | Pause a workspace (its files stay), or with --delete delete it and its files<br>`(needs the accounts:write scope)` |
| `account signing-keys <id> [list \| rotate]` | Read or rotate the keys the account signs its outbound requests with (Web Bot Auth); rotate is for an owner or admin |
| `account identity <id> [get \| show-name \| hide-name \| on \| off]` | Read or change what STACK's public answer to "who is this agent" shows: the agent's name (hidden by default) and whether it answers at all (on by default)<br>`Owner or admin only. The answer never carries the owner's name, email, address or card, only whether STACK verified them and whether they are in good standing.` |
| `account tools <id> run-get <run-id>` | Read one tool run and its result<br>`[--passport-stdin] (read as the agent)` |
| `account making <id> upload <file>` | Upload a design file (any format; up to 20 MB, which is what one request carries); reads the Passport token from stdin or a hidden prompt<br>`[--description "..."]`<br>`(for a larger file: put it on the drive, then give no file and use --drive-file <drive-file-id> [--name <file name>])` |
| `account making <id> designs [<design-id>]` | List the designs of an account, or read one<br>`[--limit <number>] [--passport-stdin]` |
| `account making <id> quote --design <design-id> --recipient-file <path>` | Ask the suppliers for quotes; which files and destinations a supplier takes is its own answer<br>`[--supplier afn\|craftcloud\|gelato\|prodigi\|printful\|lulu] [--quantity <number>] [--spec-file <path>]`<br>`[--process <p>] [--material <m>] [--finish <f>] [--color <c>] [--unit mm\|cm\|in] [--product <id>] [--placement <p>] [--page-count <number>] [--shipping cheapest\|fastest]`<br>`(the recipient file holds name, email, phone, address and a two-letter country as one JSON object; reads the Passport token from stdin or a hidden prompt)` |
| `account making <id> quote-get <quote-id>` | Read one quote<br>`[--passport-stdin]` |
| `account making <id> order <quote-id>` | Order a quote: a fabrication order ends in a checkout page to pay with the account's card, a print-on-demand order waits for your approval; reads the Passport token from stdin or a hidden prompt |
| `account making <id> orders [<order-id>]` | List the orders of an account, or read one (a read refreshes it from the supplier)<br>`[--limit <number>] [--passport-stdin]` |
| `account making <id> cancel <order-id>` | Stop an order while the supplier still can<br>`[--passport-stdin] (cancel it as the account's agent)` |
| `account making <id> approve <order-id>` | Place a held print-on-demand order on your own supplier account; waits for human approval when the API asks for it |
| `account making <id> reject <order-id>` | Decline a held order |
| `account making-suppliers` | List the making suppliers, and whether your own account at each print-on-demand supplier is connected |
| `account making-connect-supplier gelato\|prodigi\|printful\|lulu` | Connect your own account at a print-on-demand supplier; the key is read from MAKING_SUPPLIER_KEY, stdin or a hidden prompt, never from an argument<br>`(Lulu also needs MAKING_SUPPLIER_SECRET, or JSON with api_key and api_secret on stdin; the supplier charges its own account, STACK never pays one)`<br>`(owner or admin)` |
| `account making-connect-printful` | Connect your own Printful account by signing in at Printful: prints the address to open, sign in or up there and approve; STACK stores and renews the tokens<br>`(owner or admin)` |
| `account making-disconnect-supplier <supplier>` | Remove your account at a print-on-demand supplier<br>`(owner or admin)` |
| `account toll-free <id>` | Read the toll-free text verification status of the account's number |
| `account toll-free <id> submit --file <path>` | Submit the business details for toll-free text verification; waits for human approval when the API asks for it<br>`(the file holds the details as one JSON object: business, address, contact, use case and opt-in)`<br>`(needs an admin role)` |
| `account mail-domains` | List your own mail domains for agent inboxes, each with the DNS records to publish and its status |
| `account mail-domain-connect --domain <name>` | Connect your own mail domain and print the DNS records to publish; needs the platform subscription<br>`(owner or admin; there is no remove command, an unverified claim on a name lapses on its own)` |
| `account mail-domain-verify <mail-domain-id>` | Ask the mail provider to check a domain's DNS records now |
| `account opt-outs` | List the numbers on your do-not-contact list: people who texted STOP and numbers added to it<br>`(an owner or admin, or the account agent, which reads it only; texts and calls to a listed number are refused)` |
| `account opt-out-add <+E.164>` | Add a number to the do-not-contact list, so texts and calls to it are refused<br>`(an owner or admin, or an account agent; a number already listed is returned as it is)` |
| `account opt-out-remove <opt-out-id>` | Take a number off the do-not-contact list, so texts and calls to it go through again<br>`(owner or admin)` |
| `account blocked-callers` | List the numbers on your blocked-callers list: an incoming call from one is turned away before it rings<br>`(an owner or admin, or the account agent, which reads it only)` |
| `account blocked-caller-add <+E.164>` | Add a number to the blocked-callers list, so its incoming calls are turned away before they ring<br>`(an owner or admin, or an account agent; a number already listed is returned as it is)` |
| `account blocked-caller-remove <blocked-caller-id>` | Take a number off the blocked-callers list, so its calls ring again<br>`(owner or admin)` |
| `account website <id> [get]` | Read the account's website: addresses, the live deploy, prices and limits<br>`[--passport-stdin] (read as the agent)` |
| `account website <id> publish --dir <folder>` | Publish a folder as the account's website; the scan runs first and a refusal names each finding<br>`[--server-file <path>] (one JavaScript module with small server code)`<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account website <id> deploys [<deploy-id>]` | List the website's recent deploys, or read one with its file hashes<br>`[--limit <number>] [--passport-stdin] (read as the agent)` |
| `account website <id> hostnames` | List the website's addresses and the DNS records to set for your own domain<br>`[--passport-stdin] (read as the agent)` |
| `account website <id> hostname-add --hostname <name>` | Serve the website on your own domain and print the DNS records to set<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account website <id> hostname-check <hostname-id>` | Check a domain's DNS and certificate now<br>`[--passport-stdin] (check as the agent)` |
| `account website <id> hostname-remove <hostname-id>` | Stop serving the website on a domain and release the name<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account website <id> prices` | List the website paths that cost USDC to read<br>`[--passport-stdin] (read as the agent)` |
| `account website <id> prices-set --file <path>` | Replace the priced paths; the file holds a list of path, price_usdc and an optional description<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account website <id> suspend --reason "..."` | Take the website offline now (owner or admin; the agent cannot lift it) |
| `account website <id> resume` | Bring the website back after your own suspension; a suspension by STACK is not lifted this way |
| `account websites-suspend-all --reason "..."` | Take every website of your account offline at once |
| `account website-report --url <address> --category <category> --description "..."` | Report a page on a STACK-hosted website; needs no sign-in and sends no credential<br>`[--email <address>] (category: phishing, impersonation, malware, illegal_content, copyright, spam or other)` |
| `account payments <id> stripe` | Start connecting your own Stripe and print the address of the page where the restricted key is pasted<br>`(the key is never a command argument; an agent gets the connection without the address)`<br>`[--passport-stdin] (start as the agent)` |
| `account payments <id> stripe-get` | Read the Stripe connection and the webhook address to add in Stripe<br>`[--passport-stdin] (read as the agent)` |
| `account payments <id> stripe-disconnect` | Erase the Stripe key and signing secret and turn off the active payment links (owner or admin) |
| `account payments <id> link-create --name "..." --amount-minor <number>` | Create a reusable payment link for one fixed price on your own Stripe<br>`[--currency <code>] [--item "..."] [--after-payment-url <address>] (usd when no currency is given; the address must be on the agent's own site)`<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account payments <id> checkout-create --name "..." --amount-minor <number> --success-url <address>` | Create a one-off checkout session for one fixed price on your own Stripe<br>`[--cancel-url <address>] [--currency <code>] [--item "..."] (both addresses must be on the agent's own site)`<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account payments <id> links` | List the payment links and checkout sessions<br>`[--limit <number>] [--passport-stdin] (read as the agent)` |
| `account payments <id> link-deactivate <link-id>` | Turn a payment link off so it can no longer be paid<br>`(an action of the account's agent: reads the Passport token from stdin or a hidden prompt)` |
| `account payments <id> [list]` | List the payments received, on card and in USDC<br>`[--rail stripe\|x402] [--limit <number>] [--cursor <cursor>] [--passport-stdin] (read as the agent)` |
| `account payments <id> get <payment-id>` | Read one payment<br>`[--passport-stdin] (read as the agent)` |
| `account budget <id> <dollars\|none>` | Set or remove the account's monthly spend budget, in dollars (25 or 25.50); raising or removing waits for human approval<br>`(owner or admin; setting needs controls)` |
| `account resume <id> --piece inbox\|phone` | Resume an automatically paused piece; waits for human approval when the API asks for it |

#### Post

| Command | What it does |
| --- | --- |
| `post address [start\|connect\|refresh\|pause\|resume\|close]` | The customer's one US street address: read it, start it, hand over the supplier key (stdin), look again, pause, resume, disconnect<br>`(the owner signs up at the supplier, completes USPS Form 1583 there and creates an agent key there; STACK never sees the documents)`<br>`connect reads the key from stdin or a hidden prompt, optionally followed by the webhook secret` |
| `post items [--routing routed\|pending\|unassigned] [--limit <number>]` | Every item at the address, including those no agent has |
| `post items assign <item-id> --account <id>` | Give an item that no agent has taken to an account |
| `post <account-id> address` | The agent's own line on the shared address, to print on a form |
| `post <account-id> items [<limit/cursor flags>]` | The items routed to an account |
| `post <account-id> scan\|forward\|shred <item-id>` | Ask the supplier to scan, forward or shred an item; the owner approves it there<br>`scan: [--capture document_pdf\|contents_photos\|both]; forward: --to-name "..." --to-line1 "..." --to-city "..." --to-state NV --to-postal-code 89501 (or --to-address-file) [--mail-class <class>]; shred: --confirm` |
| `post <account-id> check --to-line1 "..." --to-city "..." --to-postal-code <code> [--to-state <st>] [--to-country <cc>]` | Whether an address is deliverable |
| `post <account-id> send --use-type operational\|marketing --sender-name "..." --to-name "..." --to-line1 "..." --to-city "..." --to-state NV --to-postal-code 89501 (--text "..." \| --text-file <path> \| --pdf-file <path>)` | Send a letter from text or a PDF, from the customer's own address, held and charged at cost<br>`--sender-name is the name printed as the sender (up to 40 characters)`<br>`[--return-line1 "..." --return-city "..." --return-state NV --return-postal-code 89701 [--return-line2 "..."] [--return-company "..."] \| --return-address-file <path>]: the sender address printed on the letter, a US address in the same form as --to-*; without it the account's street address is used; returned post goes to this address`<br>`[--color] [--single-sided] [--mail-class first_class\|standard] [--extra-service certified\|certified_return_receipt] [--description "..."] [--idempotency-key <key>]`<br>`a postcard: --kind postcard --front "..." --back "..." [--size 4x6\|6x9] (text only)`<br>`the account's agent adds --passport-stdin and pipes its Passport; the print provider's refusal is reported with nothing held` |
| `post <account-id> letters [<limit/cursor flags>]` | An account's letters and postcards, newest first |
| `post <account-id> letter <letter-id>` | One letter with its tracking events |

#### Control socket

| Command | What it does |
| --- | --- |
| `control-socket get` | Read the control socket: who decides now, both addresses and their state, and the action kinds checked |
| `control-socket set-decision <url>` | Set the address of your own decision server and print its signing secret once; it decides nothing until verified; waits for human approval when the API asks for it<br>`[--timeout-ms <number>] (how long STACK waits for an answer, 300 to 2000; default 1500)`<br>`(store the secret when it is printed: it is not shown again)` |
| `control-socket set-events <url>` | Set the address that receives your agents' record and print its signing secret once; waits for human approval when the API asks for it<br>`(store the secret when it is printed: it is not shown again)` |
| `control-socket clear decision\|events` | Remove the decision or events address; waits for human approval when the API asks for it |
| `control-socket verify decision\|events` | Run the setup check; when it passes the address is put into use; waits for human approval when that replaces hosted controls |
| `control-socket test decision\|events` | One test exchange with the address; nothing changes |
| `control-socket rotate-secret decision\|events` | Replace the signing secret and print the new one once; the old one works for 24 hours more; waits for human approval when the API asks for it<br>`(store the secret when it is printed: it is not shown again)` |
| `control-socket mode none\|hosted` | Use STACK's hosted controls, or none; turning controls off, or leaving your own server, waits for human approval<br>`(hosted needs controls on; your own server is switched on with verify)` |
| `control-socket on-unavailable [refuse\|allow]` | Read or set what happens when your own decision server does not answer in time: refuse (default) or allow; allow waits for human approval |
| `control-socket checked-types [--all \| <types...>]` | Read which action kinds are checked, or set them (--all checks every kind, including kinds added later); unchecking a kind waits for human approval<br>`(types are comma or space separated, e.g. email.send card.checkout wallet.payment)` |
| `control-socket decisions` | List the decisions made, newest first<br>`[--limit <number>] [--account <id>] [--verdict allow\|deny\|unavailable] [--before <iso>]` |
| `control-socket decision <id>` | Read one decision, with its request while it is kept |

#### STACK network

| Command | What it does |
| --- | --- |
| `network install register <name>` | Register a self-hosted install, which can sign nothing until it has a key |
| `network install list` | List your installs with their keys |
| `network install show <install-id>` | Read one install and its keys |
| `network install key add <install-id> --key-file <path>` | Register a key for an install: writes a new private key to the file (readable by you only, never printed) or reuses the one there, and waits for a person to approve it in a browser<br>`[--rollover-seconds <number>] (how long the install's other keys keep working, up to a week; default one day)` |
| `network install key revoke <install-id> <key-id>` | Stop a key at once and publish it; every countersignature made under it stops being live<br>`[--reason key_compromise\|owner_request\|...]` |
| `network install revoke <install-id>` | Stop an install and all its keys at once and publish it<br>`[--reason key_compromise\|owner_request\|...]` |
| `network licence revoke [--licence-file <path>]` | Revoke a licence key STACK issued to your account before it expires; the network refuses it from the next call on<br>`[--reason key_compromise\|owner_request\|...]`<br>`(the key is the proof it is yours and is never an argument: read from the file, or from standard input)` |
| `network licence list` | List the licence keys your account revoked |
| `network revoke <passport\|agent\|key\|install> <subject>` | Publish a revocation across companies; with `--key-file` it is the install's own request, otherwise yours<br>`(--for-install <id> \| --install <id> --key-file <path>) [--reason <reason>]`<br>`(the subject is a passport digest, an agent id, a key thumbprint or an install id; every revocation names its install, and it appears on the public list)` |
| `network subscription create <url>` | Have STACK post each new revocation, as a list signed by STACK, to an https address<br>`[--install <id>] (repeat to follow only some installs)`<br>`(the signing secret for the requests is printed once)` |
| `network subscription list` | List your subscriptions and whether each is delivering |
| `network subscription delete <id>` | Remove a subscription |
| `network subscription rotate-secret <id>` | Issue a new signing secret (printed once); the old one keeps signing for 24 hours |
| `network subscription resume <id>` | Put a paused subscription back to work; it is sent what it missed |
| `network rules --install <id> --key-file <path>` | Fetch STACK's signed detection rule set as an install and check it against STACK's keys<br>`[--held-revision <number>] (refuse an older set)`<br>`(an install holds no account credential: it signs each request with its key; STACK_INSTALL_ID and STACK_INSTALL_KEY_FILE set the defaults)` |
| `network classify <content\|@file\|-> --install <id> --key-file <path>` | Send content to STACK's classifier as an install; the content leaves your machine and STACK keeps none of it<br>`[--context email\|document\|webpage\|chat_log\|api_response\|calendar\|other]` |
| `network intent-deviation <json\|@file\|-> --install <id> --key-file <path>` | Have STACK grade a checkout for intent deviation as an install: {"declared": {...}, "observed": {...}} in, a score and a flag out |
| `network countersign <passport\|@file\|-> --install <id> --key-file <path>` | Have STACK countersign a passport your install issued; only the passport's digest is sent<br>`[--agent <id>] [--passport-id <id>] [--ttl-seconds <60 to 3600>]` |
| `network verify <countersignature\|@file\|-> [--passport <token\|@file>]` | Check a countersignature now, revocation included, and with a passport that it is the one signed (no sign-in needed) |
| `network verified --passport-digest <digest> \| --passport <token> \| --install <id> --agent <id>` | Read the signed STACK-verified statement for a passport or an install's agent (no sign-in needed) |
| `network revocations` | Read the signed list of revocations, checking its signature (no sign-in needed)<br>`[--after <cursor>] [--limit <number>] [--install <id>] (resume from `resume_from`)` |
| `network jwks` | Print STACK's public keys for the network's signed objects (no sign-in needed) |

#### Who an agent is

| Command | What it does |
| --- | --- |
| `agent-identity lookup --key-id <id> \| --site <host> \| --agent-id <id>` | Ask STACK who an agent is: its id, whether it is active, suspended or closed, and three yes-or-no facts of its owner (no sign-in needed). The statement STACK signed is checked before it is printed<br>`[--no-verify] (print the answer without checking the signature)`<br>`(an agent that is not found, closed or switched off by its owner is one and the same 404)` |
| `agent-identity urls <agent-id>` | Print where an agent's lookup and machine files are on STACK's domain: its signed A2A card, MCP server card and key directory |

#### Policies

| Command | What it does |
| --- | --- |
| `policies list` | List your policies and whether hosted controls are on; a policy only narrows what a connection grant allows, it never opens anything |
| `policies get default\|<agent>` | Read the default policy, or an agent's own policy and the one in force for it |
| `policies set default\|<agent> --file <definition.json>` | Create or revise the default or an agent policy; tightening applies at once, loosening waits for human approval<br>`[--stdin] (read the definition from stdin instead of a file; the output of policies get works too)`<br>`[--expected-revision <number>] (omit to create; pass the revision you read to revise)`<br>`(Recipients set per job: put "recipients": "per_mission" on an allow rule, and each Mission names who it may send to when it opens)` |
| `policies delete default\|<agent>` | Delete the default or an agent policy; always waits for human approval<br>`[--expected-revision <number>] (the delete is refused if the policy moved on)` |
| `policies start <agent>` | Create a policy equal to the agent's current connection access; it changes no outcome until you tighten it |
| `policies simulate --agent <agent> --action <type>` | Try one call against a policy; nothing is counted, held or sent<br>`[--amount-cents <number>] [--connection <scon_id>] [--target <json>] (the call, in the terms a decision request uses)`<br>`[--mission <ms_id>] (try the call with the recipients that Mission pinned)`<br>`[--definition <draft.json>] (try a draft instead of the stored policy; then --agent is optional)`<br>`[--file <input.json> \| --stdin] (the whole input, with the call under "call"; flags override it)` |
| `policies revisions <policy-id>` | List the revisions of a policy: who made each, how it changed, and the approval behind a loosening |

#### Wake-ups

| Command | What it does |
| --- | --- |
| `wake list <agent> [--status open\|pending\|delivered\|acknowledged\|refused\|expired]` | List an agent's wakes (any agent, with or without an account), newest first; --status open is the agent's queue, oldest first<br>`[--limit <number>] [--cursor <cursor>] [--passport-stdin] (run as the agent, with its Passport on stdin)` |
| `wake get <agent> <wake-id>` | Read one wake<br>`[--passport-stdin]` |
| `wake ack <agent> <wake-id>` | The agent has picked a delivered wake up<br>`[--passport-stdin]` |
| `wake settings get [<agent>]` | Read one agent's wake settings and what is in force, or (without an agent) your defaults |
| `wake settings set [<agent>]` | Change wake settings for one agent or, without an agent, for all of them; a first webhook address prints its signing secret once<br>`[--file <settings.json>] [--time-zone <zone\|none>] [--quiet <HH:MM-HH:MM\|none>] [--quiet-mode hold\|drop]`<br>`[--rate-limit <number>] [--rate-window <seconds>] [--delivery <mcp,webhook,mission\|default>] [--invite-lead <minutes>]`<br>`[--webhook-url <https url\|none>] [--enable \| --disable] [--ring-incoming-calls \| --no-ring-incoming-calls]`<br>`(store the secret when it is printed: it is not shown again)` |
| `wake rules [<agent>]` | List one agent's wake rules or, without an agent, your default rules |
| `wake rule-add [<agent>] --name <name> --source <source>` | Add a rule: which event wakes the agent and with what task (mail, texts, Telegram messages, voicemail, calls and payments wake nobody without one)<br>`sources: email, sms, voicemail, call, incoming_call, payment, post, invite, schedule, handoff, decision, meeting, service_event, telegram`<br>`[--task <text>] [--from <a@b.example,@domain.example,+15550100,telegram:name>] [--min-amount-cents <number>] [--disabled] [--file <rule.json>]` |
| `wake rule-update <rule-id> --name <name> --source <source>` | Replace a rule<br>`(same options as rule-add)` |
| `wake rule-delete <rule-id>` | Remove a rule |
| `wake schedules <agent>` | List an agent's schedules, with their next fire |
| `wake schedule-add <agent> --name <name> --cron <expression> --task <text>` | Wake the agent on a cron schedule, five fields, in its time zone; no more often than every 5 minutes<br>`[--time-zone <zone\|none>] [--disabled] [--file <schedule.json>]` |
| `wake schedule-update <agent> <schedule-id> --name <name> --cron <expression> --task <text>` | Replace a schedule |
| `wake schedule-delete <agent> <schedule-id>` | Remove a schedule |
| `wake rotate-secret <agent>` | Replace the agent's webhook signing secret and print the new one once; the old one works for 24 hours more<br>`(store the secret when it is printed: it is not shown again)` |
| `wake test-webhook <agent>` | Send a signed test to the agent's webhook; nothing is waking the agent |

#### Calendar

| Command | What it does |
| --- | --- |
| `calendar events <account> [--role organizer\|attendee] [--response pending\|accepted\|tentative\|declined]` | List the events on an agent's calendar, soonest first: its own and the invites sent to its address<br>`[--limit <number>] [--cursor <cursor>] [--passport-stdin]` |
| `calendar get <account> <event-id>` | Read one event: its times, repeat rule, guests and their answers, proposals, meeting room<br>`[--passport-stdin]` |
| `calendar agenda <account> --from <date\|time> --to <date\|time> [--tz <zone>]` | Every occurrence in a range, repeats expanded, changed and cancelled occurrences applied<br>`[--limit <number>] [--cursor <cursor>] [--passport-stdin]` |
| `calendar create <account> --title <text> --start <time> [--end <time>] [--tz <zone>] [--repeat <rrule>] [--guests a@x,b@y]` | Make an event (one action); each guest is mailed the invite from the account's address<br>`[--except <times>] [--also <times>] [--location <text>] [--link <url>] [--description <text>] [--wake <minutes>] [--meeting] [--attend] [--max-seconds <n>] [--meeting-voice <name>] [--meeting-language <code>] [--passport-stdin]`<br>`(--meeting makes a video room whose link goes in the invite; --attend has STACK's meeting worker join it as the agent at each start; the customer's controls are asked once, and a refusal makes the event without attend)` |
| `calendar update <account> <event-id> [--title ...] [--start ...] [--occurrence <time>] [--scope series\|occurrence\|following]` | Change an event, one occurrence of it, or it and the following (one action); the guests get the update<br>`[--end <time>\|--no-end] [--tz <zone>] [--repeat <rrule>\|--no-repeat] [--guests ...] [--meeting\|--no-meeting] [--attend\|--no-attend] [--meeting-voice <name>] [--meeting-language <code>] [--no-meeting-voice] [--counter <proposal-id>] [--passport-stdin]` |
| `calendar cancel <account> <event-id> [--occurrence <time>] [--scope series\|occurrence\|following]` | Cancel an event, one occurrence, or it and the following (one action); the guests are mailed the cancellation<br>`[--passport-stdin]` |
| `calendar respond <account> <event-id> accept\|tentative\|decline` | Answer an invite; it mails the organizer a calendar reply from the account's address (one action) unless --no-notify, and an accepted invite wakes the agent before each occurrence<br>`[--no-notify] [--passport-stdin]` |
| `calendar decline-proposal <account> <event-id> <proposal-id> [--comment <text>]` | Turn down a guest's proposed other time; accept one by updating the event with --counter<br>`[--passport-stdin]` |
| `calendar feed <account> [--rotate \| --revoke]` | Whether the private read-only calendar feed exists; --rotate makes it or gives it a new URL (shown once), --revoke ends it<br>`(whoever holds the URL sees every event and the guests' addresses until it is rotated or ended)` |

#### Paying an x402 seller

| Command | What it does |
| --- | --- |
| `pay <account> <url> --passport-stdin` | Buy from an x402 seller in one step: asks the URL, pays the 402 from the account's wallet through STACK (the wallet's caps, the budget and your controls) and asks again; what was bought goes to stdout, the payment to stderr (one action)<br>`[--wallet-key-file <path>] [--max-cents <n>] [--method <m>] [--header "Name: value"]... [--data <text>] [--out <file>]`<br>`(the agent's wallet key comes from --wallet-key-file or STACK_AGENT_WALLET_KEY, never argv, and is never printed; only USDC on Base with x402's exact scheme, over https)` |

#### RentAHuman

| Command | What it does |
| --- | --- |
| `rentahuman join <account> --country <country> --accept-terms` | Step one of opening a RentAHuman account for the customer: asks RentAHuman what it costs and prints the payment for the agent's wallet to sign; nothing is taken (one action)<br>`[--city <city>] [--agent-name <name>] [--passport-stdin]`<br>`(--accept-terms is the customer accepting RentAHuman's terms through its agent; the agent signs the payment with its own wallet key, which this command never holds)` |
| `rentahuman join-complete <account> <join-id> --signed <signature> --passport-stdin` | Step two: sends the agent's signature; the payment goes through the wallet's caps and the customer's decider, and RentAHuman's key is kept in the vault and never shown |
| `rentahuman fund <account> <cents>` | Step one of topping up the customer's RentAHuman wallet from the agent's wallet: prints the payment to sign (one action)<br>`[--passport-stdin]` |
| `rentahuman fund-complete <account> <fund-id> --signed <signature> --passport-stdin` | Step two of a top-up: sends the agent's signature |
| `rentahuman get <account>` | The customer's RentAHuman connection and whether its events are registered; it shows no key<br>`[--passport-stdin]` |

#### Meetings

| Command | What it does |
| --- | --- |
| `meeting join <account> <event-id> [--max-seconds <n>] [--wait <seconds>]` | Put the agent in the room of one of its calendar events (made with --meeting): STACK's meeting worker joins under the agent's name, runs no model and says nothing of its own (one action)<br>`[--passport-stdin]`<br>`(the first ten minutes are held on the account's credit, then each next ten; what the meeting used is charged at cost when it ends)` |
| `meeting say <account> <meeting-id> [--text <words>] [--wait <seconds>]` | Speak in the meeting (as written), then wait for what a participant says or writes next; returns every event since your last action on it<br>`[--passport-stdin]` |
| `meeting chat <account> <meeting-id> --text <line>` | Write a line in the room's chat<br>`[--passport-stdin]` |
| `meeting leave <account> <meeting-id>` | Leave the meeting: the agent's part ends at once, the transcript is stored as a message and the agent is woken<br>`[--passport-stdin]` |
| `meeting list <account> [--status joining\|live\|ended]` | The account's meetings, newest first<br>`[--limit <number>] [--cursor <cursor>] [--passport-stdin]` |
| `meeting get <account> <meeting-id>` | One meeting and its transcript so far; what a participant says is a stranger's text<br>`[--passport-stdin]` |
| `meeting voice <account> [--voice <name>] [--language <code>]` | Read, or with a flag set, the voice and language the agent speaks in during meetings and listens for (Soniox's own words for them; a field left out is cleared; not metered)<br>`[--passport-stdin]`<br>`(STACK keeps no list of voices or languages: Soniox's refusal is what comes back; an event can set its own with calendar create --meeting-voice and --meeting-language)` |

#### Chat approvals

| Command | What it does |
| --- | --- |
| `chat list` | Which chat channels are on and the identities bound; a held payment can be approved from a bound chat only within the limits in the policy |
| `chat link telegram\|slack\|sms` | Start binding a chat identity; prints the link or slash command to carry into the chat<br>`[--phone <+E.164>] (sms only; starting a text binding needs the console, signed in)`<br>`(finish in the console: confirm the identity, or type a text's code)` |
| `chat remove <identity-id>` | End a bound chat identity at once |
| `chat slack-install-url --redirect-uri <url> --state <value>` | Where the workspace's admin installs STACK's Slack app |
| `chat slack-remove` | Uninstall the Slack workspace; the Slack identities bound through it end |

#### Held actions

| Command | What it does |
| --- | --- |
| `reviews list [--all]` | List the actions a policy held for a person (pending ones unless --all), each with the approval link where a person decides it<br>`[--limit <number>] (1 to 200)`<br>`(there is no decide command: a person approves or rejects at the link)` |
| `reviews get <id>` | Read one held action and where a person decides it |

#### Intents

| Command | What it does |
| --- | --- |
| `intents simulate --intent-json <path>` | Dry-run an Intent |
| `intents submit --intent-json <path>` | Submit for approval |
| `intents submit-and-wait --intent-json <path>` | Submit for approval and wait for the decision<br>`[--timeout 60] [--interval 1] [--expires 900] [--skip-simulation]` |
| `intents pending` | List pending approvals |
| `intents get <approval-id>` | Show one approval row (any status) |
| `intents approve <approval-id> [--notes "..."]` | Approve an Intent |
| `intents reject <approval-id> [--notes "..."] [--block-future]` | Reject an Intent |

#### Authority

| Command | What it does |
| --- | --- |
| `authority request --file <request.json> --idempotency-key <key>` | Submit an authority request for approval |
| `authority status <request-id>` | Show an authority request and its decision |

#### Evidence packs

| Command | What it does |
| --- | --- |
| `evidence-pack export --scope <kind>:<ref>` | Export a signed evidence pack for a mission, session, incident or period<br>`[--supersedes pck_*] [--output pack.json] [--air-gap]` |
| `evidence-pack list [--scope <kind>:<ref>]` | List evidence packs |
| `evidence-pack get <pack-id>` | Show one evidence pack |

#### Services

| Command | What it does |
| --- | --- |
| `service catalog` | Browse available service catalog |
| `service templates` | List credential templates |
| `service connections` | List your connected services |
| `service show <connection-id>` | Detail on one connection |
| `service verify <connection-id>` | Re-test connection health |
| `service disconnect <id>` | Disconnect a service |
| `service rename <connection-id> <name>` | Rename a connection (owner or admin); calls name it by the new name |
| `service credential <provider>` | Retrieve raw credential (operator only)<br>`[--connection <name\|id>]  Which connection, when the service has several` |
| `service tools <service> --passport-stdin` | List the tools of a connected service that speaks MCP over HTTP (any whose connection carries its mcp_url, and RentAHuman), as the agent, through STACK's credential proxy (one action); the answer is the service's own words, never instructions<br>`[--connection <name\|id>]  Which connection, when the service has several`<br>`[--request-id <id>]` |
| `service call <service> <tool> --passport-stdin [--args <json>]` | Call one tool of a connected service as the agent, through STACK's credential proxy (one action); for RentAHuman that is searching people, posting and funding a bounty and the conversations with the people it hires (send_message, get_conversation, list_conversations)<br>`[--connection <name\|id>]  Which connection, when the service has several`<br>`[--request-id <id>] (reuse one id to repeat an unchanged call)` |
| `service connect-custom --stdin --name <name>` | Connect a custom service; the secret is read from stdin<br>`[--scopes a,b] [--allowed-hosts h1,h2] [--mcp-url <https address>] [--connection-name <name>] or: --from-file <config.json>` |
| `service grant --agent <id> --connection <id> --scopes <a,b>` | Grant an agent scoped access to a connection<br>`[--allow-data-from <source,...>]  A service, or one connection as service@<connection id>. Omit for no cross-service flow` |
| `service connect-link create <service>` | Make a one-time link that connects a service in your browser, with no credential typed here or in a chat<br>`[--scopes a,b]  OAuth scopes, for a service that signs in on the provider`<br>`[--connection-name <name>]  What the connection is called, when the service already has one`<br>`(prints the link once; it works once and expires in 10 minutes)` |
| `service connect-link create --custom <name> --hosts <h1,h2>` | Make a one-time link for your own API: its key goes only to the hosts named here, which the page shows and the owner may correct<br>`[--description <text>]  What the service is, shown on the page`<br>`[--template <name>]  A credential template whose fields the page asks for (service templates)`<br>`[--mcp-url <address>]  Where its MCP endpoint is, when it speaks MCP over HTTP (https, on one of the hosts)`<br>`[--connection-name <name>]  What the connection is called, when the service already has one`<br>`(a key or token only, never OAuth; the key is entered on the page, not here)` |
| `service connect-link get <link-id>` | Read whether a connect link was used (pending, connected or expired) and the name its connection will get |
| `service connect-link list` | List the connect links still waiting for you to finish them |
| `service revoke-agent <agent-id>` | Revoke an agent's service grants |
| `service permissions <agent-id>` | Show an agent's service permissions |

#### Approvals

| Command | What it does |
| --- | --- |
| `approval show <approval-id>` | Read one governance approval: its status, the hash of the change it covers and its link<br>`(read only: a person decides in the dashboard)` |
| `approval list [--status <status>] [--json]` | List the account's governance approvals, newest first; status is pending, approved, rejected, consumed or expired<br>`(read only: a person decides in the dashboard)` |

#### Drive

| Command | What it does |
| --- | --- |
| `drive upload <file>` | Store a file in the account's drive; an agent's file is private to it unless --account<br>`[--name <name>] [--type <media-type>] (a label: taken from the extension, else application/octet-stream) [--account \| --private] [--expires <seconds>] [--passport-stdin]`<br>`(a file of any type, stored as it is; 1 GB at most, 10 MB for a file typed as text, Markdown, CSV or JSON; every file is untrusted content)`<br>`(the file is streamed from disk as one request, with progress on stderr; the API refuses it while the wallet cannot pay for storage past the free amount, DRIVE_READ_ONLY, and while the account already has as many uploads running as it may, DRIVE_TOO_MANY_UPLOADS)` |
| `drive list [--limit <number>] [--cursor <cursor>]` | List the files you may see, with the account's usage |
| `drive get <id>` | Read one file's facts |
| `drive read <id>` | Read a file of 256 KB or less inline (untrusted content) |
| `drive update <id>` | Change who sees a file or when it ends<br>`[--account \| --private] [--expires <seconds> \| --no-expiry]` |
| `drive copy <id>` | Copy a file into a new file of your own, which does not end<br>`[--name <name>] [--account \| --private] [--expires <seconds>]` |
| `drive delete <id>` | Delete a file and its bytes |
| `drive share <id> [--ttl <seconds>] [--max-downloads <number>]` | Make a signed download link, shown once; 100 downloads unless you name another number |
| `drive links <id>` | List a file's links and their download counts |
| `drive unshare <id> <link-id>` | End a link at once |
| `drive <command> --passport-stdin` | Act as the account's agent: pipe its Passport on stdin or type it at the hidden prompt<br>`(an agent's Passport is never taken from a flag)` |

#### Memory

| Command | What it does |
| --- | --- |
| `memory add <text> --name <name>` | Add an episode to the account's memory (metered): answers at once with its uuid and status queued; episodes shows when it is stored<br>`[--file <path> \| --text <text>] [--source text\|json\|message] [--source-description <d>] [--uuid <uuid>] [--at <iso>]`<br>`[--exclude-type <t>]... [--instructions <t>] [--previous <episode-uuid>]... [--saga <name>] [--saga-previous <episode-uuid>] [--passport-stdin]`<br>`(flagged text is refused when controls are on; with controls off it is stored with its flag)` |
| `memory triplet --source <name> --edge <name> --fact <text> --target <name>` | Write one fact directly, without extraction (metered)<br>`[--source-uuid <uuid>] [--target-uuid <uuid>] [--passport-stdin]` |
| `memory search-nodes <query>` | Search entities<br>`[--max <n>] [--type <entity-type>]... [--where <field>=<value>]... [--center <uuid>] [--passport-stdin]` |
| `memory search-facts <query>` | Search facts, with when each held<br>`[--max <n>] [--center <uuid>] [--edge-type <t>]... [--valid-after <iso>] [--valid-before <iso>] [--invalid-after <iso>] [--invalid-before <iso>] [--passport-stdin]` |
| `memory episodes` | Episodes, newest first, each with its status: stored, queued, processing or failed (with a reason)<br>`[--max <n>] [--passport-stdin]` |
| `memory fact <uuid>` | Read one fact<br>`[--passport-stdin]` |
| `memory episode-entities <episode-uuid>...` | The entities and facts the given episodes produced<br>`[--passport-stdin]` |
| `memory delete-episode <uuid>` | Delete an episode; what only it supports goes with it<br>`[--passport-stdin]` |
| `memory delete-fact <uuid>` | Delete one fact<br>`[--passport-stdin]` |
| `memory summarize-saga <name>` | Summarize a saga, the name given as --saga to memory add (metered)<br>`[--passport-stdin]` |
| `memory types` | The entity types memory extracts: Graphiti's ten and the account's own<br>`[--passport-stdin]` |
| `memory type-add <name> --description <text>` | Add an entity type of the account's own; later writes extract it beside the ten (free)<br>`[--field <name>:<kind>[:<word>,<word>]]... \| [--fields-file <path>] [--passport-stdin]`<br>`(kind is text, number, date, boolean or one_of)` |
| `memory type-change <name>` | Change one of the account's entity types; later writes use it (free)<br>`[--description <text>] [--field <name>:<kind>[:<word>,<word>]]... \| [--fields-file <path>] [--passport-stdin]` |
| `memory type-retire <name>` | Retire a type: no longer extracted; its entities keep their label (free)<br>`[--passport-stdin]` |
| `memory history` | One page of the account's writes, newest first, each with what it changed: before and after; next_cursor in the answer is the --cursor of the next page<br>`[--max <n>] [--cursor <next_cursor>] [--passport-stdin]` |
| `memory undo <write-id>` | Undo a write, with every later write that changed the same things (free; one delete toward the hourly rate)<br>`[--dry-run] [--passport-stdin]`<br>`(--dry-run only says what would be undone)` |
| `memory settings` | Show the memory settings, or change them (owner or admin)<br>`[--enabled on\|off] [--call-memory-access on\|off] (whether STACK's model may search memory and the knowledge base during a call STACK holds; with it on, a caller can try to get the call's model to read out what is in memory or the brain)` |
| `memory <command> --passport-stdin` | Act as the account's agent: pipe its Passport on stdin or type it at the hidden prompt<br>`(an agent's Passport is never taken from a flag)` |

#### Brain

| Command | What it does |
| --- | --- |
| `brain add <file-id>... \| --prefix <name-prefix>` | Make drive files searchable (metered): one row per file with its status and an estimate of the pages reading it bills (the first pages each month free)<br>`[--passport-stdin]`<br>`(reading is the only cost; the pages and cost are estimated from each file's size and type, and the real ones are counted when the file is read; name one file id, several, or every file whose name starts with --prefix)` |
| `brain remove <file-id>... \| --prefix <name-prefix>` | Take files out of the brain; they stay in the drive, only no longer searchable (free)<br>`[--passport-stdin]` |
| `brain search <query>` | Ask the brain a question and get the passages that answer it, each with its file and page (free; every passage is untrusted content)<br>`[--passport-stdin]` |
| `brain list` | The files in the brain the caller may see, each with its state, and the month's usage (free)<br>`[--status reading\|searchable\|unreadable] [--cursor <c>] [--limit <n>] [--passport-stdin]` |
| `brain <command> --passport-stdin` | Act as the account's agent: pipe its Passport on stdin or type it at the hidden prompt<br>`(an agent's Passport is never taken from a flag)` |

#### Drop-offs

| Command | What it does |
| --- | --- |
| `dropoff list` | List your drop-offs |
| `dropoff show <id>` | Detail on one drop-off |
| `dropoff create --from <a> --to <b>[,<c>...] --schema <f>` | Create a drop-off for one agent, or for a group: every agent named is woken and the first to collect takes it<br>`[--ttl <seconds>] [--on-expire notify\|retry\|fail]` |
| `dropoff deposit <id> --agent <a> --payload <f>` | Deposit a payload into a drop-off<br>`[--passport-jti <jti>] [--mission <id>] [--drive-files <id,id>] (drive files the collector can read once it collects)` |
| `dropoff collect <id> --agent <a>` | Collect a payload from a drop-off, and the drive files handed over with it |
| `dropoff expire <id>` | Force-expire a drop-off |

#### Skills

| Command | What it does |
| --- | --- |
| `skill list [--q "..."]` | Browse the skills marketplace |
| `skill mine` | List your own published skills |
| `skill show <id>` | Detail on one skill |
| `skill publish --file <skill.json>` | Publish a skill from a JSON spec |
| `skill invoke <id> --agent <a> --input '{...}'` | Invoke a skill |
| `skill suspend <id>` | Suspend a published skill |
| `skill activate <id>` | Re-activate a suspended skill |
| `skill allow <id> --agent <a>` | Allow an agent to use a skill |
| `skill disallow <id> --agent <a>` | Stop an agent from using a skill |
| `skill favorites` | List your favourite skills |
| `skill invocations` | List pending skill invocations |
| `skill check-invocation <id>` | Show one skill invocation |
| `skill complete <id> --output-file <result.json>` | Complete a skill invocation with its output |
| `skill check-trust <skill-id>` | Check the trust level of a skill |
| `skill requests` | List skill requests |
| `skill post-request "<desc>"` | Post a new skill request |
| `skill matches <request-id>` | Find skills matching a request<br>`or: --description "<what you want to do>"` |
| `skill suggest <request-id>` | Suggest a skill composition for a request<br>`or: --description "<what you want to do>"` |
| `skill pending-reviews` | List skills awaiting review (platform staff) |
| `skill approve <skill-id>` | Approve a skill (platform staff) |
| `skill reject <skill-id> [--reason "..."]` | Reject a skill (platform staff) |

#### Scan

| Command | What it does |
| --- | --- |
| `scan "<content>" \| --file <path>` | Scan content for prompt injection |
| `scan usage` | This month's scan usage against the included actions |

#### LLM

| Command | What it does |
| --- | --- |
| `llm usage list` | List per-call LLM usage records (cursor-paginated)<br>`[--limit] [--cursor] [--provider] [--passport-jti] [--mission-id] [--agent-id] [--since] [--until]` |
| `llm usage summary` | Group-by aggregate (provider [+ model] + day)<br>`same filters as 'list', plus [--no-group-by-model]` |
| `llm anthropic messages '<body-json>' [--stream]` | Governed Anthropic call; reads the passport token from stdin or a hidden prompt |
| `llm openai chat-completions '<body-json>' [--stream]` | Governed OpenAI call; reads the passport token from stdin or a hidden prompt |
| `llm openrouter chat-completions '<body-json>' [--stream]` | Governed OpenRouter call; reads the passport token from stdin or a hidden prompt |
| `llm openai images '<body-json>'` | An image on your own OpenAI key, through the same gates; files go to the agent drive, marked untrusted |

#### Identity

| Command | What it does |
| --- | --- |
| `identity settings` | Get operator identity settings |
| `identity update-settings` | Update operator identity settings<br>`[--inheritance auto\|opt_in] [--ttl 30d\|90d\|180d\|1y] [--auto-revoke true\|false]` |
| `identity providers` | List identity-verification providers |
| `identity claims` | List your verified identity claims |
| `identity session <session-id>` | Show one identity verification session: pending, completed, failed or expired |
| `identity revoke-claim <id>` | Revoke an identity claim |
| `identity oidc <status\|create\|update\|test\|delete>` | Manage the operator OIDC identity configuration |
| `identity sso-domains <list\|add\|verify\|remove> [<domain>\|<domain-id>]` | Prove an e-mail domain for single sign-on with a DNS TXT record, so addresses at it count as verified when your provider (Microsoft Entra ID, for one) does not say<br>`(add prints the record to publish; verify looks it up now; adding a domain is approved by a person in a browser; owner or admin only)` |
| `identity spiffe <list\|get\|create\|update\|delete>` | Manage SPIFFE trust domains |
| `identity wimse <list\|get\|create\|update\|delete>` | Manage WIMSE issuers |
| `identity requirements <list\|create\|replace\|clear\|delete> <service-id>` | Manage the identity requirements of a service |

#### Audit

| Command | What it does |
| --- | --- |
| `audit list [--limit N] [--agent <id>]` | List audit entries |
| `audit export` | Export the audit log<br>`[--format json\|ndjson\|csv] [--from ...] [--to ...] [--out <file>]` |
| `audit chain-head` | Current audit-chain head hash |
| `audit verify-chain` | Verify your audit chain integrity |

#### PII redaction

| Command | What it does |
| --- | --- |
| `pii show` | Threshold + country scope in force |
| `pii set --countries SE,NO,DK` | Only run these countries' schemes |
| `pii set --threshold 0.2` | Confidence to redact (higher redacts less) |
| `pii reset` | Back to built-in defaults |

#### Detectors

| Command | What it does |
| --- | --- |
| `detector list` | List detectors and their configuration |
| `detector show <detector-key>` | Show one detector configuration |
| `detector enable <detector-key>` | Enable a detector |
| `detector disable <detector-key>` | Disable a detector |
| `detector configure <detector-key> --from-file <config.json>` | Replace a detector configuration |
| `detector reset <detector-key>` | Back to the built-in defaults |

#### Trust

| Command | What it does |
| --- | --- |
| `trust get [<agent>]` | Whether the account's agents ask first or are trusted to act: the account's value, or one agent's over it |
| `trust set <ask_first\|trust_agents> [<agent>]` | Ask first, or trust the agents (nothing waits for a person on card purchases, orders on your own supplier account and governance changes made with your own key); for the account or one agent<br>`(owner or admin)` |
| `trust clear <agent>` | Remove an agent's own value so it follows the account again |

#### Message access

| Command | What it does |
| --- | --- |
| `message-access get [<agent>]` | What the account's agents may do with the customer's messages: the account's values, or one agent's over them |
| `message-access set [--read-teammates true\|false] [--read-only true\|false] [<agent>]` | Whether agents read the messages of every message account of the customer (read-teammates, default true) or only their own, and whether they may only read (read-only, default false: true means no sending, replying, forwarding, texting or posting from any account); for the account or one agent<br>`(owner or admin, an agent is refused; applies at once with no approval)` |
| `message-access clear <agent> <read-teammates\|read-only>...` | Remove the values an agent set for itself so it follows the account again |

#### Messages

| Command | What it does |
| --- | --- |
| `messages search` | Search every message you may read across the customer's message accounts and channels, newest first, without the bodies (read one with account messages)<br>`[--agent <agent>] [--channel email\|sms\|voicemail\|call\|telegram\|post\|meeting] [--sender <address>] [--recipient <address>] [--thread <id>] [--q "<text>"] [--after <datetime>] [--before <datetime>] [--limit <1-50>] [--cursor <cursor>]`<br>`(datetimes are ISO 8601 with an offset; the window is the last 30 days, and a search on --q, --sender, --recipient or --thread needs a window of at most 90 days)` |
| `messages attachment <account> <message> <file>` | Read a file a message carries, through the message: 256 KB or less inline (untrusted content) |

#### Flagged content

| Command | What it does |
| --- | --- |
| `flagged-content get` | What controls do with flagged content, per severity, and whether controls are on |
| `flagged-content set [--warning withhold\|deliver] [--critical withhold\|deliver]` | Withhold flagged content from the agent or deliver it with its flag; applies while controls are on<br>`(owner or admin)` |

#### Security events

| Command | What it does |
| --- | --- |
| `event list [--agent <id>]` | List security events |
| `event show <id>` | Detail on one security event |
| `event resolve <id>` | Mark a security event resolved |

#### Notifications

| Command | What it does |
| --- | --- |
| `notifications methods list` | List delivery methods |
| `notifications methods add --kind <k> --destination <addr>` | Add a delivery method (kind: email, sms or webhook) |
| `notifications methods test <id>` | Send a test notification |
| `notifications methods send-code <id>` | Send a verification code |
| `notifications methods verify <id> --code <code>` | Verify a delivery method with its code |
| `notifications methods delete <id>` | Delete a delivery method |
| `notifications rules list` | List notification rules |
| `notifications rules create --method <id> --events <e1,e2>` | Create a notification rule<br>`or: --methods <id1,id2> [--min-severity info\|warning\|critical]` |
| `notifications rules update <id>` | Update a notification rule<br>`[--events e1,e2] [--min-severity info\|warning\|critical] [--methods id1,id2]` |
| `notifications rules delete <id>` | Delete a notification rule |

#### Inbound webhooks

| Command | What it does |
| --- | --- |
| `inbound-webhook create --provider <agentmail\|generic> --agent <agt_*>` | Create an inbound webhook (returns the URL and the plaintext secret)<br>`[--forward-url <https://...>]  log-only if omitted` |
| `inbound-webhook list` | List all inbound webhooks |
| `inbound-webhook get --id <iwh_*>` | Show one inbound webhook |
| `inbound-webhook revoke --id <iwh_*>` | Revoke an inbound webhook |
| `inbound-webhook rotate-secret --id <iwh_*>` | Issue a new signing secret (printed once); the old one keeps signing for 24 hours |

#### Partners

| Command | What it does |
| --- | --- |
| `partner account create --ref <your-reference> [--controls]` | Open an account for a customer under your own reference (paid from your wallet; idempotent); --controls switches its hosted controls on |
| `partner account list` | List your accounts with month-to-date usage<br>`[--ref <your-reference>]` |
| `partner account get <id>` | Show one account |
| `partner account revoke <id>` | Close an account, its webhooks and its passports |
| `partner account rotate-key <id>` | Replace an account's API key (printed once) |
| `partner account invite <id> --email <email>` | Invite the customer to see the account, read-only<br>`[--name <name>]` |
| `partner account controls <id> --on\|--off` | Switch hosted controls on or off for one account (paid from your wallet while on) |
| `partner account release <id>` | Release the account to its customer: they are mailed a claim link<br>`[--email <email>]  defaults to the one customer invited`<br>`[--cancel]  withdraw a release the customer has not claimed`<br>`[--status]  where the release stands` |
| `partner releases` | List the releases you have a record of |
| `partner account webhook --account <op_*> --provider <p> --agent <agt_*>` | Provision an inbound webhook under an account<br>`[--forward-url <https://...>]` |
| `partner account issue-passport --account <op_*> --agent <agt_*> --mission <ms_*>` | Issue a passport for an agent under an account<br>`[--intent "<summary>"] [--services a,b] [--ttl 900]` |

#### Team

| Command | What it does |
| --- | --- |
| `team list` | List team members |
| `team invite <email> --name "<full name>"` | Invite a team member<br>`[--role admin\|standard\|readonly] [--allowed-connections id1,id2]` |
| `team update <id>` | Change a team member<br>`[--role admin\|standard\|readonly] [--allowed-connections id1,id2] [--status ...]` |
| `team revoke <id>` | Remove a team member |
| `team sso-unbind (<id> \| --issuer <url>)` | Forget a member's single sign-on identity, or that of everyone who signed in through one provider, so they bind again after you change provider<br>`(a person approves it in a browser; owner or admin only)` |

#### Monitor

| Command | What it does |
| --- | --- |
| `monitor` | Replay a scripted run (same as --demo) |
| `monitor --demo [--loop]` | Replay a real-shape mission (no auth needed) |
| `monitor --follow` | Tail your own audit log |
| `monitor --sandbox` | Tail the public sandbox feed |
| `monitor --challenge` | Tail the public email agent feed |

#### Global flags

| Name | What it does |
| --- | --- |
| `--json` | Emit raw JSON instead of formatted tables. |
| `--control-ref <ref>` | Retry an action the owner approved: the ref a CONTROL_DENIED refusal (reason review_required) named, sent as X-Control-Ref on the writes of the command. Run the same command again with it once the owner approved. |

#### Environment

| Name | What it does |
| --- | --- |
| `STACK_OAUTH_SCOPE` | Override the OAuth scope requested at `auth login`. Default covers routine runtime and inspection flows; account, secret, billing and security administration remain explicit opt-ins. Set an exact subset (e.g. "passports:read agents:read services:read audit:read") for monitoring-only sign-ins. |
| `STACK_API_URL` | Point the CLI at a non-prod API (self-host / dev). Defaults to https://api.getstack.run. |

#### monitor flags

| Name | What it does |
| --- | --- |
| `--demo` | Replay a real-shape mission (no auth needed). Same row format as --follow, just scripted. |
| `--follow` | Tail your operator's actual audit_log. Polls every 1s. Uses your `auth login` session. |
| `--loop` | Loop the demo until Ctrl-C (default is one run). |
| `--agent <agent_id>` | (--follow) Only show entries for this agent. |
| `--jti <passport_jti>` | (--follow) Only show entries for this passport. |
| `--sandbox` | Tail the public sandbox feed at https://api.getstack.run/v1/public/events. No API key needed; implies a live tail (no --follow required). Same stream visitors see on getstack.run. |
| `--challenge` | Tail the public email agent at agent@getstack.run (https://api.getstack.run/v1/public/events?feed=challenge). No API key needed; implies a live tail. Same stream the board on getstack.run/attack renders. |

<!-- commands:end -->

### Monitor examples

```sh
# Tail one agent
npx @getstackrun/cli monitor --follow --agent agt_abc123

# Tail one passport (e.g. debugging a specific revoke chain)
npx @getstackrun/cli monitor --follow --jti pas_xyz789

# Tail the public sandbox (no signup, no key)
npx @getstackrun/cli monitor --follow --sandbox
```

### Control socket examples

Point your agents' actions at your own decision server. Every change that moves
or loosens a control prints a human-approval link and waits; approve it in a
signed-in browser and the command finishes by itself.

```sh
# Set the address. The signing secret is printed once: store it now, it is not shown again.
npx @getstackrun/cli control-socket set-decision https://control.example.com/decide --timeout-ms 1000

# Run the setup check; when it passes, your server decides every checked action
npx @getstackrun/cli control-socket verify decision

# Choose which action kinds are checked
npx @getstackrun/cli control-socket checked-types email.send card.checkout wallet.payment

# What was decided, and why
npx @getstackrun/cli control-socket decisions --verdict deny --limit 20
```

The secret is printed to the terminal only. The CLI never writes it to a file
or a log, so pipe the output into your secret store if you need it kept.

### Policy examples

A policy is the configuration behind hosted controls (they need the controls
subscription). It only narrows what an agent's connection grants already allow:
it refuses an action, holds it for a person, or limits it. Tightening applies
at once; loosening and deleting wait for a person to approve in a browser, and
the command prints the link and finishes by itself.

```sh
# Start from what the agent can already do (changes no outcome yet), then read it
npx @getstackrun/cli policies start my-agent
npx @getstackrun/cli policies get my-agent > policy.json

# Edit policy.json, then revise it with the revision you read
npx @getstackrun/cli policies set my-agent --file policy.json --expected-revision 1

# Try a call before it happens: nothing is counted, held or sent
npx @getstackrun/cli policies simulate --agent my-agent --action card.checkout --amount-cents 900

# Actions a policy held for a person; they decide at the printed link
npx @getstackrun/cli reviews list
```

## Authentication

`auth login` runs the OAuth 2.1 Device Authorization Grant against
`https://api.getstack.run`:

1. CLI dynamically registers itself as a public PKCE client (one client_id per install).
2. Server issues a `device_code` + a human-readable `user_code` (e.g. `WDJB-MJHT`).
3. CLI prints the URL + opens your browser to `https://getstack.run/cli/auth?code=...`.
4. You confirm the code and approve.
5. CLI persists the refresh token to `~/.stack/credentials.json` (mode 0600).

Refresh tokens auto-rotate on every use. The same file is also read by both SDKs
(`@getstackrun/sdk` for TS/JS, `getstack` for Python), so signing in once gives all
three surfaces a working credential.

For unattended workers without a browser, enroll an agent with `agent enroll`; the
worker signs with its own agent key, not your sign-in.

See [the auth model](https://getstack.run/docs/security/stack-auth) for
the full auth model.

## License

Apache-2.0
