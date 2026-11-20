# Installing STACK in Cline

STACK is a remote MCP server. Nothing is installed or built on your machine, and no API key is needed: you sign in in the browser.

## 1. Add the server

In Cline, open **MCP Servers**, then the **Remote Servers** tab, and enter:

- Server Name: `stack`
- Server URL: `https://mcp.getstack.run/mcp`
- Transport Type: **Streamable HTTP**

Then click **Add Server**.

Or add it to `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "stack": {
      "type": "streamableHttp",
      "url": "https://mcp.getstack.run/mcp",
      "disabled": false
    }
  }
}
```

## 2. Sign in

Cline shows **Authentication required** for the server. Click **Authenticate**. Your browser opens STACK's sign-in: sign in and approve Cline.

You need a STACK account. Start one at https://getstack.run/get-started.

## 3. Check it works

Ask Cline: `List my STACK agents.`
