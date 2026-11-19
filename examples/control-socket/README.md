# A self-hosted control server

STACK asks your server before each checked action of your agents runs, and streams your record to it afterwards. This is a small server that answers the questions and takes the stream in. The rules are in `POLICY` and `decide()` in `server.mjs`; change them to yours.

What it does:

- `POST /stack/decide`: verifies the signed request and that its `request_digest` matches its content (a request changed after STACK built it is refused with 400), applies the rules, and returns a signed allow or deny that echoes `decision_id` and `request_digest`. A retried request gets the same answer. A deny can name a reason and, for something a person must approve, a `retry.ref` the agent sends back as `X-Control-Ref`.
- `POST /stack/events`: verifies the signed batch, ignores events it has seen (delivery is at least once), and notes a gap in the sequence, a gap STACK announces, or a break in the hash chain.

The decision secret and the events secret are different, so a log receiver can never sign an allow.

## Run it

```bash
npm install @getstackrun/sdk
STACK_DECISION_SECRET=whsec_... STACK_EVENTS_SECRET=whsec_... node server.mjs
```

Put it on a public https address (near Stockholm or Frankfurt: it has two seconds), then point STACK at it. Each secret is shown once, when its address is set.

```bash
npx @getstackrun/cli control-socket set-decision https://your.host/stack/decide
npx @getstackrun/cli control-socket set-events https://your.host/stack/events
npx @getstackrun/cli control-socket verify decision    # a signed test exchange; success puts the address into use
npx @getstackrun/cli control-socket verify events
```

Setting or changing an address, and anything that loosens your controls, needs you to approve in the console in a browser. Decisions to your own server cost nothing.

## What STACK sends

The request names who, what and how much, never content: the action kind (`email.send`, `model.call`, `proxy.call`, `card.checkout`, ...), the recipients or host or amount, the account and agent, and who is acting (`agent`, `owner` or `member`). Reasons are `[a-z0-9_]` codes of up to 64 characters. Read the request body exactly as received before you verify it; re-serialised JSON does not match its signature.

If your server does not answer in time, answers an error, or signs wrongly, STACK refuses the action and hands it back to the agent to retry. It never allows on silence.

```bash
node --test examples/control-socket/server.test.mjs
```
