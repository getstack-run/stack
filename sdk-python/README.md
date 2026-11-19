# getstack

Python SDK for [STACK](https://getstack.run) — trust infrastructure for AI agents.

## Docs for agents

How-to guides for every STACK service and for controls are published as markdown. The list is at https://getstack.run/llms.txt, and one service's guide is at https://getstack.run/docs/account/<service>.md (for example https://getstack.run/docs/account/email.md).

## Install

```bash
pip install getstack
```

## Quick start

Sign in once on your machine — the SDK reads credentials from `~/.stack/credentials.json` automatically:

```bash
npx -y @getstackrun/cli auth login
```

```python
import hashlib
import json
from getstack.errors import StackError


def run_fleet_mission_example(stack, request, provider_url="https://slack.com/api/chat.postMessage"):
    started = stack.missions.start(request)
    repeated = stack.missions.start(request)
    assert repeated["mission_id"] == started["mission_id"]
    operation_id = hashlib.sha256(json.dumps([started["mission_id"], "support-update"]).encode()).hexdigest()
    response = stack.proxy.request(
        "slack",
        provider_url,
        "POST",
        body={"channel": "C123", "text": "Support update"},
        passport_token=started["passport"]["token"],
        authority_request_id=operation_id,
    )
    assert response.status == 200
    try:
        stack.proxy.request(
            "slack",
            provider_url,
            "POST",
            body={"channel": "OTHER", "text": "Support update"},
            passport_token=started["passport"]["token"],
            authority_request_id=operation_id + "_denied",
        )
    except StackError as error:
        assert error.status_code == 403
    else:
        raise AssertionError("Expected channel restriction")
    before = stack.missions.get(started["mission_id"])
    renewed = stack.missions.renew(started["mission_id"])
    after = stack.missions.get(renewed["mission_id"])
    assert renewed["mission_id"] == started["mission_id"]
    assert after["fleet"]["limits"] == before["fleet"]["limits"]
    assert after["fleet"]["usage"] == before["fleet"]["usage"]
    completed = stack.missions.complete(started["mission_id"], output={"done": True})
    assert completed["terminal_state"] == "completed_successful"
    stopped = stack.missions.start({**request, "idempotency_key": request["idempotency_key"] + "-stop"})
    stack.missions.revoke(stopped["mission_id"], reason="operator_initiated_clean")
    try:
        stack.missions.renew(stopped["mission_id"])
    except StackError:
        pass
    else:
        raise AssertionError("Expected revoked Mission")
    return {"mission_id": started["mission_id"], "operation_id": operation_id, "completed": True, "revoked": True}
```

## Authentication

Four sources, resolved in priority order:

```python
# 1. Explicit auth strategy
stack = Stack.from_oauth(client_id="...", client_secret="", access_token="...", refresh_token="...")
stack = Stack.from_session(session_token="...")

# 2. agent_id (recommended for production runtimes)
stack = Stack(agent_id="agt_xxx")

# 3. ~/.stack/credentials.json (`stack-cli auth login` writes it)
stack = Stack()
```

See [the auth model](https://getstack.run/docs/security/stack-auth) for the full auth model and [the agent keys page](https://getstack.run/docs/security/agent-keys) for the per-agent keypair story.

## Renew a Mission's Passport

```python
renewed = stack.missions.renew(mission_id)
passport_token = renewed["passport"]["token"]
```

Renewal keeps the same Mission, permission and recorded usage. Its deadline and limits still apply. Start a new Mission for the next job.

## Services

```python
# Agents
stack.agents.register(name, description=None, accountability_mode=None, eval_traffic=None)  # a new agent starts "logged"
stack.agents.setup(agent, grants=None, allowed_hosts=None)  # register + first grants + hosts as one approval
stack.agents.dismiss_warnings(agent_id)  # resolve an agent's open warnings; criticals stay open
stack.agents.get(agent_id)
stack.agents.list()
stack.agents.update(agent_id, **fields)
stack.agents.unblock(agent_id)

# Missions (every passport is issued for exactly one Mission)
stack.missions.open(intent_summary, agent_id=None, intent_services=None, ...)
stack.missions.start(agent_id=agent_id, mission={"intent_summary": "..."}, passport=None)
stack.missions.complete(mission_id)  # also revokes the Mission's passports
stack.missions.revoke(mission_id, reason="operator_initiated_clean")

# Passports
stack.passports.issue(agent_id, mission_ids=[mission_id], intent=None, services=None, ...)
stack.passports.mission(agent_id, intent, services, ...)  # context manager: Mission + passport, closed on exit
stack.passports.verify(token)
stack.passports.revoke(jti, reason=None)
stack.passports.checkpoint(jti, services_used, actions_count, ...)
stack.passports.checkout(jti, services_used, actions_count, ...)
stack.passports.report(jti)

# Credentials
stack.credentials.get(provider)
stack.credentials.get_by_connection(connection_id)

# Services (a service can hold several named connections; a call that does not say which one is refused with
# ConnectionAmbiguousError, so pass connection=<id or name>: stack.proxy.post("slack", url, connection="Work", ...))
stack.services.list()
stack.services.connect_custom(name, credential, ..., connection_name="Work")  # a second connection of a service needs a name
stack.services.rename(connection_id, "Personal")  # owner or admin
stack.services.verify(connection_id)
stack.services.disconnect(connection_id)
stack.services.create_connect_link("github", scopes=None)  # one-time link: {"link_id", "status", "url", ...}
stack.services.get_connect_link(link_id)  # pending, connected (connection_id) or expired; never the url
stack.services.list_connect_links()  # the links still waiting, newest first

# Governance approvals (read only: a person decides in the dashboard)
stack.governance.get_approval(approval_id)  # {"approval", "payload_hash", "approval_url"}

# Reviews
stack.reviews.list(status="flagged")
stack.reviews.decide(checkout_id, decision, notes=None, block_future=False)

# Drop-offs
stack.dropoffs.create(from_agent_id, to_agent_id, schema, ..., passport_token=None)
stack.dropoffs.deposit(dropoff_id, data, agent_id, passport_token=None)
stack.dropoffs.collect(dropoff_id, agent_id, passport_token=None)

# Notifications
stack.notifications.list()
stack.notifications.create(channel_type, destination, ...)
stack.notifications.delete(channel_id)

# Audit
stack.audit.list(page=1, limit=50, action=None, agent_id=None)
```

## Agent accounts

`stack.accounts` opens an agent with its pieces (Passport, inbox, phone, models, tools, browser, card, wallet, making, workspace) at once, with no approval; prepaid credit is its limit, and an optional `monthly_budget_cents` needs controls. Calls the account's agent makes take its Passport as `passport_token`; the operator calls without one.

```python
account = stack.accounts.open(
    {"name": "Support", "skip": ["phone"]},
    idempotency_key="open-support-1",  # 8 to 128 characters
)
stack.accounts.get(account_id)
stack.accounts.list(limit=None)
stack.accounts.close(account_id)

stack.accounts.messages.list(account_id, limit=None, cursor=None, channel=None, passport_token=None)
# A received email's attachments are saved to the agent's drive: content.attachments[].file_id, or not_saved with the reason
# (the email is kept either way). A received file is deleted with its message: drive.copy keeps it
stack.accounts.messages.get(account_id, message_id, passport_token=None)
stack.accounts.messages.delete(account_id, message_id)

# Search every message the caller may read, across the customer's message accounts and channels, newest first. Each hit is
# a summary without its body (get reads one). The window is the last 30 days unless after and before (ISO 8601 with an
# offset) say otherwise; a search on q, sender, recipient or thread_id needs a window of at most 90 days. limit is 1 to 50.
stack.accounts.messages.search(
    agent_id=None,
    channel=None,
    sender=None,
    recipient=None,
    thread_id=None,
    after=None,
    before=None,
    q=None,
    limit=None,
    cursor=None,
    passport_token=None,
)
# A file a message carries, read through the message: the same answer as drive.read (untrusted content)
stack.accounts.messages.read_attachment(account_id, message_id, file_id, passport_token=None)

# Message access, owner or admin only (an agent is refused; a change applies at once, with no approval).
# read_teammates (default True): the agent reads the messages of every message account of the customer; False: only its own.
# messages_read_only (default False): True lets the agent read but not send, reply, forward, text or post from any account.
stack.message_access.get(agent_id=None)  # {agent_id, read_teammates, messages_read_only, effective, source}
stack.message_access.set(agent_id=None, read_teammates=None, messages_read_only=None)  # a value left out is not touched
stack.message_access.clear(agent_id, ["read_teammates", "messages_read_only"])  # the agent follows the account again

# The customer's do-not-contact list (list: owner, admin or the account's agent; remove: owner or admin): a number that
# texted STOP. Texts and calls to a listed number are refused with RecipientOptedOutError.
stack.accounts.opt_outs.add("+14155550123")  # the entry; a number already listed returns its entry
stack.accounts.opt_outs.list()  # {"opt_outs": [{"id": "aoo_...", "number": ..., "texts_blocked": ..., "calls_blocked": ..., ...}]}
stack.accounts.opt_outs.remove(opt_out_id)  # {"removed": True}
# The blocked-callers list (list and add: owner, admin or the account's agent; remove: owner or admin): an incoming call from a listed number is turned away before it rings
stack.accounts.blocked_callers.add("+14155550123")  # the entry; a number already listed returns its entry
stack.accounts.blocked_callers.list()  # {"blocked_callers": [{"id": "abk_...", "number": ..., "created_at": ...}]}
stack.accounts.blocked_callers.remove(blocked_caller_id)  # {"removed": True}
# to is one address or a list, with optional cc and bcc lists; OpenMail takes one To address, so further To addresses are delivered as Cc
# An attachment is a drive file ({"file_id": ...}) or an inline file ({"filename": ..., "content_type": ..., "content": <bytes>}, at most 10 MB in all)
stack.accounts.send_email(account_id, {"to": [...], "bcc": [...], "subject": ..., "body": ...}, passport_token=None)
# Answers in the thread of a received email, quoting it unless "include_quote": False, to the person who wrote it, or to everyone with "reply_all": True
stack.accounts.reply_email(account_id, message_id, {"body": ...}, passport_token=None)
# Sends a received email on as a new email in no thread, with its text unless "include_quote": False and its kept files unless "include_attachments": False
# An address left out (the account's own, or an entry that is not one plain address) is named in the answer's "dropped"
stack.accounts.forward_email(account_id, message_id, {"to": ..., "body": ...}, passport_token=None)
# "reply_to_message": "amsg_..." names the received message a send answers; the policy's "per_mission" recipients for email, texts and calls ask for it
stack.accounts.send_sms(account_id, {"to": "+14155550123", "body": ...}, passport_token=None)
stack.accounts.send_telegram(account_id, {"chat_id": "42", "text": ...}, passport_token=None)
stack.accounts.telegram.start(account_id)  # owner or admin; the link the owner opens in Telegram to have the bot made
stack.accounts.telegram.connect(account_id, bot_token)  # owner or admin; the token goes only to this call
stack.accounts.telegram.get(account_id)
stack.accounts.telegram.chats(account_id)
stack.accounts.telegram.disconnect(account_id)
stack.chat_channels.get()  # chat identities an owner approves small held payments from
stack.chat_channels.create_identity("telegram")  # or "slack", or "sms" with phone="+46..."
stack.chat_channels.remove_identity(identity_id)
stack.accounts.resume_piece(account_id, "inbox", governance_approval_id=None)
stack.accounts.set_budget(
    account_id, 2500, governance_approval_id=None
)  # None removes the budget; raising or removing needs approval
stack.accounts.toll_free_verification.submit(
    account_id, {"business_name": ..., "business_website": ..., "business_type": ...}, governance_approval_id=None
)
stack.accounts.toll_free_verification.get(account_id)

# A call you hold: STACK runs no model and says nothing of its own. "greeting" (optional) is spoken first;
# the answer is {"call": ..., "events": [...]} once the other side has said its first sentence (up to "wait_seconds").
turn = stack.accounts.calls.place(
    account_id,
    {"to": "+14155550123", "greeting": "Hi, this is Ada.", "voice": {"language": "en-US"}},
    passport_token=None,
)  # "reply_to_message" as for texts
stack.accounts.calls.say(account_id, call_id, "Is this Sam?", wait_seconds=None, passport_token=None)
stack.accounts.calls.press_keys(account_id, call_id, "1#", passport_token=None)
stack.accounts.calls.set_call_voice(account_id, call_id, {"language": "es-ES"}, passport_token=None)
stack.accounts.calls.hang_up(account_id, call_id, passport_token=None)
stream = stack.accounts.calls.live(account_id, call_id, passport_token=None)  # pip install "getstack[live]"
stream.text("Hello, ")
stream.text("is this Sam?", last=True)
for event in stream:  # heard, keys, interrupted, paid_time_ends, ended
    ...
stream.close()
# A call STACK holds with its own model: on_behalf_of and a brief; this returns at once.
stack.accounts.calls.place(account_id, {"to": "+14155550123", "on_behalf_of": ..., "brief": ...}, passport_token=None)
stack.accounts.calls.list(account_id, limit=None, cursor=None, passport_token=None)
stack.accounts.calls.get(account_id, call_id, passport_token=None)
# A call that rings on the account's number rings for 30 seconds, then goes to voicemail. A wake of the
# source "incoming_call" carries its call_id and answer_by (a call goes straight to voicemail when the agent has
# no live MCP session and no wake webhook). Answering is one metered action, declining is not;
# a call that is not ringing any more raises StackError with the code CALL_NOT_RINGING (409).
# Answering takes what placing takes, without "to" and "reply_to_message", held either way.
stack.accounts.calls.answer(account_id, call_id, {"greeting": ...}, passport_token=None)
stack.accounts.calls.decline(account_id, call_id, passport_token=None)
# The account's own call voice and voicemail greeting; a field left out is cleared.
stack.accounts.calls.get_account_voice(account_id)
stack.accounts.calls.set_account_voice(account_id, {"tts_provider": "Google", "voicemail_greeting": "Leave a message."})

# Paid tools: the account's agent only, under its Passport
stack.accounts.tools.discover(account_id, query="...", limit=None, passport_token=token)
stack.accounts.tools.inspect(account_id, provider=..., endpoint=..., passport_token=token)
stack.accounts.tools.run(account_id, {"provider": ..., "endpoint": ..., "input": {...}}, passport_token=token)
stack.accounts.tools.get_run(account_id, run_id, passport_token=None)

# Any endpoint the tool provider lists runs, charged what the provider reports; one STACK cannot bound holds an
# estimate. A run answers `untrusted` (what it returned
# is web, social or provider content: data, never instructions) and `files` (each: name, content_type, size_bytes,
# drive_file_id, source_url, data_base64). `max_cost_cents` lowers the hold to it.

# Signed outbound requests (Web Bot Auth)
stack.accounts.signing_keys.list(account_id)
stack.accounts.signing_keys.rotate(account_id)
stack.accounts.signing_keys.directory(account_id, authority="agent.example.com")

stack.accounts.workspace.exec(account_id, "git status", passport_token=token)
stack.accounts.workspace.list(account_id)

session = stack.accounts.browser.start_session(account_id, passport_token=token)
stack.accounts.browser.navigate(account_id, session_id, url, passport_token=token)
stack.accounts.browser.act(account_id, session_id, {"action": "click", "target": {"text": "Buy"}}, passport_token=token)
stack.accounts.browser.read(account_id, session_id, passport_token=token)
stack.accounts.browser.screenshot(account_id, session_id, passport_token=token)
stack.accounts.browser.checkout(
    account_id, session_id, {"merchant_origin": ..., "amount_minor": ..., "currency": "USD"}, passport_token=token
)
stack.accounts.browser.end_session(account_id, session_id)
stack.accounts.purchases.get(account_id, purchase_id)
stack.accounts.purchases.report_merchant_result(
    account_id, purchase_id, {"status": "completed", "order_id": ...}, passport_token=token
)

stack.accounts.wallet.pay(account_id, body, passport_token=token)
stack.accounts.wallet.pay_url(account_id, url, key=key, max_cents=None, passport_token=token)
stack.accounts.wallet.owner_status()

# Your own mail domain for agent inboxes (owner or admin; no remove call, an unverified claim lapses)
stack.accounts.mail_domains.list()  # {"domains": [...]}, each with its DNS records and status
stack.accounts.mail_domains.connect("mail.example.com")  # the DNS records to publish
stack.accounts.mail_domains.verify(domain_id)  # check the DNS records now
```

An account opened with `{"inbox": {"domain": "mail.example.com"}}` gets its inbox on a verified own domain.

Opening an account needs no approval. `set_budget` (raising or removing), `resume_piece` and `toll_free_verification.submit` wait for a human approval outside a dashboard session: retry the same request with `governance_approval_id` once it is approved.

Errors: `GovernanceApprovalRequiredError` (`approval_id`, `approval_url`; a `ForbiddenError`), `GovernanceApprovalStateError` (`approval_id`, `approval_status`: a retry named an approval that is still pending, rejected or expired; a `ForbiddenError`), `AccountPieceNotReadyError` (`account_id`, `piece`, `state`), `AgentBudgetExceededError` (`account_id`, `remaining_cents`), `ProviderCapacityUnavailableError` (`provider`), `AccountCallFailedError` (`reason`, `retryable`: when true the call may have been placed, so read the calls before retrying), `DestinationNotAvailableError` (texts and calls to this number are not available; `reason` `no_price` when Twilio has no price for the destination, `refused_by_twilio` when its geographic permissions or high-risk number blocking do not allow it; nothing was charged), `ToolPriceRefusedError` (`reason`, `provider`, `endpoint`: `max_results` out of range, or an input too deep), `ToolsUnavailableError` (`reason`), `ToolRunRejectedError` (`provider_status`), `BudgetNeedsControlsError` (a `ForbiddenError`), `PlatformSubscriptionRequiredError` (`subscription_status`), `RecipientOptedOutError` (`account_id`; a `ForbiddenError`: the number asked not to be contacted), `SharedMailDailyLimitError` (`limit`) `UnboundedSendRuleError` (`rules`: the policy rules that allow a send without naming its recipients, each with `unbound_paths`), `ControlDeniedError` (`decision_id`, `reason_code`, `rule`, `retry`; a `ForbiddenError`) and `ControlLimitExceededError` (`limit`, `remaining`, `max_per_action_cents`; a `ForbiddenError`). All are `StackError`s.

### Post

`stack.post` is the customer's one US street address that receives and scans post, and letters and postcards out. The address belongs to the customer: they sign up at the address supplier, complete USPS Form 1583 there (two IDs and a short notary video call; STACK never sees the documents), create an agent key there and give it to `connect_address`. Each agent has its own line on the shared address. A scan, forward or shred is only proposed: the owner approves it at the supplier, who bills the owner's own account. A letter or postcard is held and charged on the account's credit at the provider's cost.

```python
# The owner (owner or admin; no Passport)
stack.post.start_address()  # the supplier page for the identity step is in identity["url"]
stack.post.connect_address(
    supplier_key, webhook_secret=None
)  # a secret: read it from a vault or stdin, never a literal
stack.post.get_address()
stack.post.refresh_address()
stack.post.pause_address()
stack.post.resume_address()
stack.post.close_address()
stack.post.list_items(limit=None, cursor=None, routing=None)  # routed, pending or unassigned
stack.post.assign_item(item_id, account_id)

# An account's post; its agent passes passport_token
stack.post.account_address(account_id, passport_token=None)  # the agent's own line, to print on a form
stack.post.list_account_items(account_id, limit=None, cursor=None, passport_token=None)
stack.post.get_account_item(account_id, item_id, passport_token=None)
stack.post.scan_item(account_id, item_id, capture=None, idempotency_key=None, passport_token=None)
stack.post.forward_item(account_id, item_id, {"name": ..., "line1": ..., "city": ..., "state": ..., "postal_code": ...})
stack.post.shred_item(account_id, item_id)  # cannot be undone
stack.post.check_address(account_id, address)

letter = stack.post.send(
    account_id,
    {
        "to": address,
        "sender_name": "Acme Dental",
        "content": {"text": "Your order has shipped."},
        "use_type": "operational",
    },
    passport_token=token,
)  # or content {"pdf_base64": ...}; a postcard is {"kind": "postcard", "front": {"text": ...}, "back": {"text": ...}, ...}
stack.post.list_letters(account_id, limit=None, cursor=None, passport_token=None)
stack.post.get_letter(account_id, letter_id, passport_token=None)  # with its tracking events
```

`use_type` is required on a send: `operational`, or `marketing` for promotion. So is `sender_name`, the name on the return address above the agent's line (up to 40 characters). Errors: `PostRefusedError` (`reason`: `address_undeliverable`, `pdf_unreadable`, `too_many_pages` or `provider_refused`; nothing was charged), `PostUnavailableError` (`reason`; retry later) and `PostalAddressNotActiveError` (`address_status`: `none`, `pending_identity` or `suspended`).

### Wallet key

The agent's own key is the wallet's only signer; STACK holds no key to any wallet. Create it on the agent's machine, put the public half in the open request, and sign each payment with it. STACK checks the budget, the caps and your controls, then passes the signed request to the wallet provider unchanged, or refuses it. Every function refuses with `WalletKeyInSandboxError` when `STACK_SANDBOX` is set to anything other than empty or `0`.

```python
from getstack import WalletPaymentTarget, generate_agent_wallet_key, load_agent_wallet_key, sign_wallet_payment

key = generate_agent_wallet_key()
stored = key.export_private_key()  # "wallet-auth:..." for your own secret store
key = load_agent_wallet_key(stored)
wallet = {"agent_public_key": key.public_key, "per_payment_cap_usdc": 5, "daily_cap_usdc": 50}

details = next(p for p in account["pieces"] if p["kind"] == "wallet")["details"]
target = WalletPaymentTarget(app_id=details["privy_app_id"], wallet_id=details["wallet_id"], typed_data=typed_data)
stack.accounts.wallet.pay(account_id, sign_wallet_payment(key, target), passport_token=token)
```

To buy from an x402 seller, `pay_url` does the whole exchange: it asks the URL, pays the seller's 402 from the account's wallet (signed with your key here, then checked by STACK as `pay` is) and asks again. `result.response` is what was bought; an answer that is not a 402 comes back with `paid` False. Only USDC on Base with x402's `exact` scheme (versions 1 and 2), over https; any other ask, or a price over `max_cents`, raises `X402PaymentError` before STACK is asked.

```python
result = stack.accounts.wallet.pay_url(
    account_id, "https://seller.example/report", key=key, max_cents=100, passport_token=token
)
report = result.response.content
```

## Website and getting paid

An agent account can have a website, and it can be paid for what it sells. The account's agent publishes a bundle under its Passport; the publish scan checks it first and a refusal raises `WebsitePublishRejectedError` with each finding. STACK serves the agent card, the MCP server card, the key directory and the contact form on every site, and the agent cannot remove them. The customer suspends a site in one call.

```python
from getstack import site_files

files = site_files([{"path": "/index.html", "content": "<h1>Hello</h1>"}, {"path": "/logo.png", "content": png_bytes}])
stack.website.publish(account_id, files=files, passport_token=token)  # server={"source": "..."} adds small server code
stack.website.get(account_id)  # url, hostnames, live deploy, prices, limits, identity card addresses
stack.website.add_hostname(account_id, hostname="www.example.com", passport_token=token)  # then set the DNS it lists
stack.website.check_hostname(account_id, hostname_id)
stack.website.set_prices(account_id, prices=[{"path": "/reports/*", "price_usdc": "0.25"}], passport_token=token)
stack.website.suspend(account_id, reason="checking it")  # owner or admin; resume(account_id) brings it back
stack.website.report(
    "https://acme.example-sites.test/page", "phishing", "Asks visitors for a bank login."
)  # public, no credential
```

Card payments go to the customer's own Stripe. `start_stripe` returns a connect page where the customer pastes a restricted key (never a full secret key) and the webhook signing secret; the key is never an SDK argument. Priced site paths are paid in USDC to the agent's own wallet, and both kinds are listed together.

```python
connection = stack.payments.start_stripe(account_id)  # the owner gets connection["connect_url"]
link = stack.payments.create_link(account_id, name="Report", amount_minor=1200, passport_token=token)
session = stack.payments.create_checkout_session(
    account_id,
    name="Report",
    amount_minor=1200,
    success_url="https://acme.example-sites.test/thanks",
    passport_token=token,
)
stack.payments.list_payments(account_id, rail="x402")  # {"payments": [...], "next_cursor": ...}
stack.payments.disconnect_stripe(account_id)  # owner or admin: erases the key and turns off the links
```

## Subscriptions

The platform and hosted controls subscriptions of agent accounts are card subscriptions through Stripe Checkout, with a free trial the first time. Starting one returns a Checkout URL; the subscription is written from Stripe's events, so read it back with `subscriptions()`.

```python
stack.billing.subscriptions()  # {"platform": {status, active, contract}, "controls": {status}, "this_month": {...}}
stack.billing.subscribe_platform(governance_approval_id=None)  # {"checkout_url", "session_id", "trial"}
stack.billing.subscribe_controls(governance_approval_id=None)  # needs the platform subscription first
```

The two writes are owner or admin actions and wait for a human approval outside a dashboard session: retry the same call with `governance_approval_id` once it is approved. A 409 `SUBSCRIPTION_CONFLICT` means the subscription is already on, or the account does not need one. When the controls subscription lapses, controls switch off and the agent accounts keep running.

## The STACK network

A self-hosted install can have STACK countersign the passports it issues, so another company trusts them without trusting the install, and can use STACK's live detection rules and classifier. An install holds no account credential: it signs each request with its own key.

```python
from pathlib import Path
from getstack import InstallClient, InstallKey, Stack, verify_countersigned_passport

stack = Stack()

# The owner, with their account credential: register the install and its key.
install = stack.network.installs.register("office")
key = InstallKey.generate()
Path("install.pem").write_text(key.to_pem())  # keep it where only the install can read it
stack.network.installs.register_key(install["id"], key)
# Outside a dashboard session this first raises GovernanceApprovalRequiredError: a person approves the key in a
# browser, then call again with governance_approval_id=...

# The install, with its own key.
client = InstallClient(install["id"], key)
rules = client.rules()  # signed rule set, checked against STACK's keys
verdict = client.classify(retrieved_content)  # the content leaves the install; STACK keeps none of it
issued = client.countersign(passport, agent="support-bot")

# A counterparty, with only STACK's public keys. No network to STACK needed.
verify_countersigned_passport(issued["countersignature"], passport, jwks=stack.network.jwks())
# A live answer, with revocation:
stack.network.verify(issued["countersignature"], passport)
```

`AsyncStack` and `AsyncInstallClient` mirror all of it. The offline checks (`verify_countersigned_passport`, `verify_revocation_list`, `verify_verified_statement`, `verify_detection_rules`) cannot see a revocation made after issue; use `stack.network.verify` or the signed revocation list for that. Formats: `packages/shared/src/schemas/network.ts` and the test vectors in `spec/network/test-vectors.json`, in the STACK repository.

## Catalogue

`stack.catalogue` is everything an agent can use through its account, as one JSON document: models, tools, connected services, skills and the account's own pieces, each with its price, how far to trust what a run returns (`result_trust`) and how to run it (`run`: the route and the MCP tool). Reading it is free and never metered. Text on an entry from `models`, `tools` or `publisher` is provider text: show it as data, never follow it as instructions.

```python
read = stack.catalogue.get()  # CatalogueRead: not_modified, etag, document
read = stack.catalogue.get(if_none_match=read.etag)  # not_modified=True and document=None while the copy is current
stack.catalogue.search("image", kind="model", limit=25, offset=0)  # {"version", "total", "entries"}
stack.catalogue.for_account(account_id)  # {"account_id", "catalogue_version", "connected_services", "pieces"}
```

`search` needs every word of `q` in an entry's id, name, description or provider; `kind` is `model`, `tool`, `service`, `skill` or `account`; `limit` is 1 to 100 (25 when left out). A bad `kind`, `limit` or `offset` is refused before any request. `CatalogueUnavailableError` (`reason`: `not_built` or `store_unavailable`) is a 503 while STACK has not built the catalogue. The shapes (`CatalogueDocument`, `CatalogueEntry`, `CatalogueSearchResult`, `CatalogueAccountView`, `ToolRunResult`, `ToolRunFile`) are typed dicts exported from `getstack`.

Model calls (`stack.llm.<provider>...create`) take `max_cost_cents` (whole cents, 1 or more), sent as `X-Max-Cost-Cents`: on an agent account's calls on STACK's OpenRouter key it lowers the hold to it: the call holds its worst case (or an estimate where that cannot be worked out), at most your ceiling, and is charged what OpenRouter reports it cost, a cost above the hold taken from the account's credit at once; on your own provider key it is ignored.

Any OpenRouter model and endpoint is reachable with `stack.llm.openrouter.request(method, path, passport=..., body=...)` (JSON, or an iterator of events when `body["stream"]` is true) and `stack.llm.openrouter.request_bytes(...)` for an answer that is a file (`{"status", "content_type", "content"}`); the async client has the same two. `chat.completions.create` stays.

## Drive

`stack.drive` keeps an account's files. An agent's file is private to it unless it says `visibility="account"`; the owner sees every file. An upload, an upload link and a share link are metered actions put to the account's controls; reading, listing, changing and deleting are free. Every file is untrusted content. Calls an agent makes take its Passport as `passport_token`; the owner calls without one.

```python
file = stack.drive.upload(
    "report.pdf", "application/pdf", content=pdf_bytes, visibility="account", expires_in_seconds=86400
)
stack.drive.upload_file("backup.zip")  # one request, read from disk as it is sent; name and type come from the file
stack.drive.upload("notes.md", "text/markdown", content_text="# Notes", passport_token=None)
link = stack.drive.create_upload_link("backup.zip", "application/zip")  # a one-time URL, 30 minutes
stack.drive.upload_to_link(link, path="backup.zip")  # sends the bytes there with no credential
stack.drive.list(limit=None, cursor=None, passport_token=None)
stack.drive.get(file_id)
stack.drive.read(file_id)  # inline, 256 KB or less: {"file", "encoding", "content", "withheld", "flag"}
stack.drive.update(file_id, visibility=None, expires_in_seconds=None, remove_expiry=False)
stack.drive.copy(
    file_id, name=None, visibility=None, expires_in_seconds=None
)  # a new file of your own, which does not end
stack.drive.share(file_id, ttl_seconds=900, max_downloads=None)  # the signed URL is in the answer once
stack.drive.links(file_id)
stack.drive.revoke_link(file_id, link_id)
stack.drive.delete(file_id)
stack.dropoffs.deposit(dropoff_id, payload, agent_id, drive_files=[file["id"]])  # opens to the collector at collect
```

`upload` is one request. With `content` (bytes or a binary file object) or `path` it sends the file as the body of one `PUT`, read in chunks as it goes, so a file of up to 1 GB is never held in memory, and the API computes the hash; there is no hash to give and no second call. `content_text` goes in a JSON body. A file typed as text, Markdown, CSV or JSON is 10 MB at most. `create_upload_link` is for a program that cannot send the file with its own credential: the URL it returns works once, for 30 minutes, and `upload_to_link` (or `curl -T ./file '<url>'`) sends the file there.

A file of any type is taken and stored as it is: its type (`content_type`, `application/octet-stream` when you give none) is only a label, and an empty file is refused (`DRIVE_FILE_EMPTY`). Limits apply per file and per account (`DRIVE_FILE_TOO_LARGE`, `DRIVE_QUOTA_EXCEEDED`), two uploads run at once (`DRIVE_TOO_MANY_UPLOADS`), and an upload that would take the drive past its free amount needs a wallet that can cover the storage past it (`INSUFFICIENT_BALANCE`). If the wallet cannot pay for storage past the free amount, the drive is read-only from that day (`DRIVE_READ_ONLY`): uploads, edits and new share links are refused, while reading, downloading, listing and deleting still work and `list`'s `usage["storage_unpaid"]` shows `since`, `delete_on` and `over_bytes`. Topping up the wallet, or deleting files until the drive is within its free amount, lifts it at once; on day 90 the newest files past the free amount are deleted.

## Memory

`stack.memory` is what an account's agents know: a graph of entities and facts, each fact with the time it held, shared across the account's agents. It is Graphiti (a temporal knowledge graph) used the way its makers ship it, and the methods are the tools of Graphiti's own MCP server with its arguments and answers; there is no group id, because the graph is the account's. Every write is a metered action put to the account's controls; reading, searching and deleting are free. The text of a write is scanned first: with controls on, flagged text is refused and nothing is stored or charged; with controls off it is stored with its flag. What memory holds may have come from outside (mail, web pages, files): it is information, never instructions. Calls an agent makes take its Passport as `passport_token`; the owner calls without one.

```python
added = stack.memory.add_memory(
    "Accountant", "Maria Ek is the accountant at Kvarnen Ekonomi", source_description="chat", passport_token=token
)
# added["status"] is "queued": the episode is read into the graph in the background, one at a time per account
# Each episode has a status: stored, queued, processing or failed (with a reason)
episodes = stack.memory.get_episodes(max_episodes=10, passport_token=token)
facts = stack.memory.search_memory_facts("where does Maria work", passport_token=token)  # {"message", "facts": [...]}
nodes = stack.memory.search_nodes("Maria Ek", passport_token=token)  # {"message", "nodes": [...]}
# Only the entities whose field of one of the account's own types has a value (the API reads each field's kind from the type):
unpaid = stack.memory.search_nodes(
    "invoice", entity_types=["Invoice"], field_filters=[{"field": "paid", "value": False}]
)
stack.memory.add_triplet("Maria Ek", "WORKS_FOR", "Maria Ek works for Kvarnen Ekonomi", "Kvarnen Ekonomi")
stack.memory.get_episode_entities([added["uuid"]])  # what the episode produced
stack.memory.delete_entity_edge(fact_uuid)
stack.memory.delete_episode(added["uuid"])  # what only this episode supports goes with it

stack.memory.update_settings(enabled=False)  # owner: memory off; writes are refused until it is on again
stack.memory.update_settings(call_memory_access=False)  # owner: a call STACK holds may not search memory
```

`add_memory`, `add_triplet`, `search_nodes`, `search_memory_facts`, `get_episodes`, `get_entity_edge`, `get_episode_entities`, `delete_episode`, `delete_entity_edge` and `summarize_saga` cover the whole surface, and `get_settings` and `update_settings` are the owner's.

## Control socket

Your own server can decide for your agents. Set a decision address and STACK sends it every checked action of your agents, signed; an allow or deny from it decides each one. An events address receives your agents' whole record, signed. Both use [Standard Webhooks](https://www.standardwebhooks.com).

```python
change = stack.control_socket.set_decision_address("https://decide.example.com/stack", timeout_ms=1500)
change["secret"]  # "whsec_...", shown once; store it now
stack.control_socket.test("decision")  # one exchange, nothing changes
stack.control_socket.verify("decision")  # a passing check puts the address into use
stack.control_socket.get()  # who decides now, the addresses, the checked action kinds
stack.control_socket.set_events_address("https://events.example.com/in")
stack.control_socket.rotate_secret("decision")  # the old secret works 24 hours more
stack.control_socket.set_checked_types(["email.send", "card.checkout"])  # None checks every kind
stack.control_socket.set_mode("hosted")  # or "none"; clear("decision"), clear("events") remove an address
stack.control_socket.list_decisions(verdict="deny", limit=20)  # {"decisions": [...]}
stack.control_socket.get_decision(decision_id)
```

A new address, a rotation and anything that loosens (clearing an enforcing address, unchecking an action kind, turning controls off, switching to your own server) wait for a human approval outside a dashboard session: retry the same call with `governance_approval_id` once it is approved. Tightening applies at once. An agent can never change its own controls.

Every request STACK signs to your server (a wake-up, a notification delivery method, an inbound-webhook forward, a network revocation push, the control socket) is a Standard Webhooks message (`spec/webhooks/SPEC.md`), and `verify_webhook` checks all of them: the HMAC over the raw body, a five minute tolerance in either direction and any live secret. It returns the parsed body, or raises `WebhookSignatureError` with a `reason` (`stale`, `bad_signature`, `replayed` and so on). A `ReplayGuard` remembers the ids it has taken, so a repeat inside the tolerance is noticed; call `guard.forget(message_id)` when you could not handle a delivery. A secret from before the scheme (64 hexadecimal characters) works as it is.

```python
from getstack import ReplayGuard, WebhookSignatureError, verify_webhook

GUARD = ReplayGuard()
try:
    event = verify_webhook(request.headers, request.get_data(), SECRET, replay_guard=GUARD)
except WebhookSignatureError:
    return "", 401
```

On your side, `verify_control_request` checks what STACK sent and `sign_control_answer` signs your answer. The answer echoes `decision_id` and `request_digest`, and its `webhook-id` is the `decision_id`.

```python
from getstack import ControlSignatureError, sign_control_answer, verify_control_request


@app.post("/stack/decide")
def decide():
    try:
        decision = verify_control_request(request.headers, request.get_data(), SECRET)  # a list during a rotation
    except ControlSignatureError:
        return "", 401
    deny = decision["action"]["type"] == "card.checkout"
    answer = sign_control_answer(
        decision["decision_id"],
        decision["request_digest"],
        "deny" if deny else "allow",
        SECRET,
        reason={"code": "needs_review", "message": "Card checkouts need a person"} if deny else None,
    )
    return Response(answer.body, headers=answer.headers, content_type="application/json")
```

The timestamp must be within 5 minutes (`tolerance_seconds`) and the comparison is constant-time. Pass `retry={"ref": ..., "after_seconds": ...}` to hold an action for an approval; the agent sends `ref` back as `X-Control-Ref` on its retry.

## Control policies

Policies are the configuration behind hosted controls (writing one needs controls on). A policy narrows what a connection grant already allows: it refuses, holds an action for a person, or limits spend and volume. It never opens anything. Each agent can have its own policy and the customer has one default; STACK keeps them and never binds one into a Passport. An agent can never read or change its own controls.

```python
stack.control_policies.list()  # {"controls_enabled": True, "policies": [...]}
stack.control_policies.get("default")  # the default policy (NotFoundError when there is none)
stack.control_policies.get("agt_1")  # {"policy", "in_force": {"id", "revision", "source"}, "controls_enabled"}
current = stack.control_policies.start_from_current_access("agt_1")["policy"]  # equal to its grants
definition = {**current["definition"], "spend": {"max_per_action_cents": 500}, "review": {"over_cents": 200}}
stack.control_policies.set("agt_1", definition, expected_revision=current["revision"])  # {"change", "policy"}
stack.control_policies.set("default", definition)  # no expected_revision creates
# Try one call; nothing is counted, held or sent
stack.control_policies.simulate({"action": "card.checkout", "amount_cents": 900}, agent_id="agt_1")
stack.control_policies.revisions(current["id"])  # {"revisions": [...]}
stack.control_policies.delete("agt_1", expected_revision=2)
stack.control_reviews.list(status="pending", limit=50)  # actions a policy held for a person: {"reviews": [...]}
stack.control_reviews.get(review_id)
```

`set` creates when `expected_revision` is left out and revises when it is the revision you read; a stale one is refused. Tightening a policy applies at once. Loosening it, a revision that is not provably a tightening, and deleting it wait for a person in a browser: the API answers `GovernanceApprovalRequiredError` with `approval_url`; approve it there and retry the same call with `governance_approval_id`. `UnboundedSendRuleError` (`rules`) means the policy allows a send without naming who receives it (bind its recipient fields, set the rule's `recipients` to `"per_mission"`, or set it to review or deny), and a 409 `CONTROLS_NOT_ENABLED` means controls are off.

### Recipients set per job

Each Mission names who it may send to. A policy rule that leaves recipients to each Mission allows a send only to these. Set `"recipients": "per_mission"` on an `allow` rule that names a send intent with a recipient field. A Mission without the pin is refused (`reason_code` `recipients_not_pinned`); a send to someone it did not pin is refused (`recipient_not_allowed`). A delegated Passport carries the same Mission, so it carries the same recipients; the per-job rules of the agent the Mission was opened for apply to it too.

```python
stack.control_policies.set(
    "agt_1",
    {
        "name": "Support agent",
        "connections": {
            "mode": "listed",
            "rules": [
                {
                    "id": "mail-per-job",
                    "effect": "allow",
                    "recipients": "per_mission",
                    "access": {"connection_id": "scon_1", "intents": [{"name": "resend.send_email"}]},
                }
            ],
        },
    },
)
# Recipients: who this Mission may send to.
mission = stack.missions.open("Answer one customer", agent_id="agt_1", recipients=["ana@example.com"])
# Reply to a message: pins the Mission to the sender of this message, so the agent can answer that person and no one else.
stack.missions.start(agent_id="agt_1", mission={"intent_summary": "Answer the message", "reply_to_message": "msg_1"})
# Try a call with what a Mission pinned.
stack.control_policies.simulate(
    {"action": "email.send", "mission_id": mission["mission_id"], "target": {"to": "ana@example.com"}}, agent_id="agt_1"
)
```

The account's own `recipients.email`, `recipients.sms` and `recipients.call` in a policy take a list or `"per_mission"`. Under `"per_mission"` an email, text or call names the received message it answers with `reply_to_message` (`send_email`, `send_sms`, `calls.place`) and goes only to who wrote that message. A send that names no message is refused (`recipients_not_pinned`), a recipient other than the sender is refused (`recipient_not_allowed`), and an id that is not one of the account's received messages is a `NotFoundError`. `reply_email` needs no field: the message in the path is the pin. `forward_email` has none.

```python
stack.control_policies.set(
    "agt_1", {"name": "Support agent", "recipients": {"email": "per_mission", "sms": "per_mission"}}
)
stack.accounts.send_email(
    "acct_1", {"to": "ana@example.com", "subject": "Re: order", "body": "Done", "reply_to_message": "amsg_1"}
)
```

`recipients` lists exact addresses, numbers or ids (an address may be in any case). `recipient_pins` is `[{"path", "op": "eq" | "in", "value"}]` with one pin per path: `path` is `"*"` (every recipient field a send names, a recipient inside the URL included: the path or one of its segments) or a request field such as `body.to`, `derived.email.recipients` or `url.pathname`; up to 64 pins and 1,000 recipients a list. `reply_to_message` is the id of a message the agent's account received, or of an incoming call it answered or declined (a readable email, text, voicemail or call, else 404 `NOT_FOUND`); it combines with `recipients` into one list. The owner adds to a running Mission's pins with `missions.add_recipients(mission_id, recipients=..., recipient_pins=..., reply_to_message=...)`; `missions.get` returns them as `recipient_pins` (a list, or `None`).

A refused action raises `ControlDeniedError` (`decision_id`, `reason_code`, `rule`, `retry`; a `ForbiddenError`). `rule` names which rule refused: `policy_id`, `policy_revision`, `section`, `rule`, `code` and sometimes `detail` (the policy's own side of the comparison), never a value the call carried. An action held for a person carries `retry={"ref": ..., "after_seconds": ...}`: once the person approves it at the review's `approval_url`, retry the same call with header `X-Control-Ref: <ref>`. A spend limit reached while paying raises `ControlLimitExceededError` (`limit`, `remaining`, `max_per_action_cents`). The same `refusal` object (`policy_id`, `policy_revision`, `section`, `rule`, `code`) is on a refusal's event in the record streamed to your events address. A held action is decided through the ordinary approval page, so `control_reviews` only reads. This is separate from `stack.reviews`, which lists flagged checkouts.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src
python -m pytest -q
```

The package ships `py.typed`; `mypy src` runs in strict mode.

## Links

- [Documentation](https://getstack.run/docs/sdk)
- [Dashboard](https://getstack.run)
- [GitHub](https://github.com/getstack-run/stack/tree/main/sdk-python)
