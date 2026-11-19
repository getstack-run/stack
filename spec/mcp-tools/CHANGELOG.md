# Changelog: STACK MCP Tool Definitions

This specification follows semantic versioning applied to the tool catalog (see section 9 of the specification). `tools.json` is regenerated from the code with every change; this file records what a client or integrator needs to know.

## 2.3.1 - 2026-11-11

A correction to descriptions. No tool or input changes.

- Changed: the descriptions of `allow_data_from` on `stack_grant_agent_access`, `stack_issue_passport` and `stack_setup_agent` say that an entry is a service, or one connection of a service written `service@<connection id>`, and that content read through one connection of a service needs such an entry before it may go out through another connection of the same service.

## 2.3.0 - 2026-11-10

An addition: a service can hold several connections, each with its own name. No tool is removed or renamed, and every new input is optional.

- Added: `stack_rename_connection`, the owner's call that renames one connection (`connection_id`, `connection_name`).
- Changed: `stack_proxy_request`, `stack_service_tools` and `stack_service_call_tool` take an optional `connection`, the name or id of the connection to use; it is needed only when the agent has more than one connection of the service. A call that needs it and does not carry it fails with `CONNECTION_AMBIGUOUS` and the names to choose from.
- Changed: `stack_connect_service` and `stack_create_connect_link` take an optional `connection_name`, and the connect link and the connections read back carry it. The directory profile's `stack_create_connect_link` keeps its reviewed shape.

## 2.2.0 - 2026-11-03

An addition, and a loosening of when a person has to say yes. No tool is removed or renamed.

- Added: `stack_add_mission_recipients`, the owner's call that adds recipients to a running Mission.
- Changed: `stack_register_agent`, `stack_dismiss_agent_warnings`, `stack_set_identity_settings` and `stack_set_service_requirement` ask for no approval; their `governance_approval_id` is deprecated and ignored.
- Changed: `stack_decide_intent` decides at once except for an intent that can move money, and accepts `governance_approval_id` on a rejection (ignored).
- Changed: `stack_create_connect_link`'s `custom` takes a name of up to 200 characters, a description of up to 2,000, up to 100 hosts and a `template`.
- Changed: `stack_audit_export` and `stack_download_signed_record` hand a result over 3 MB to the drive like any tool, and an agent's session lists `stack_download_signed_record`.
- Changed: the Mission tools' `recipients` and `recipient_pins` cover a recipient inside the URL, and `reply_to_message` may name an incoming call.

## 2.1.0 - 2026-10-31

A loosening of when a person has to say yes. No tool is added, removed or renamed and no input changes shape.

- Changed: `stack_register_agent` needs no approval, except when the registration starts the agent weaker than the defaults (`eval_traffic` or `is_synthetic` true, `llm_redact_pii` or `llm_inject_system_prompt` false, a lower `accountability_mode`, looser `credential_access`, a lower `twin_policy`), which a person approves. `stack_allow_skill` needs none, and neither does adding skills or widening `skill_access_mode` with `stack_update_agent` (every other widening still does). `governance_approval_id` stays an optional input of both: `stack_register_agent` forwards it for the registrations that ask, and `stack_allow_skill` ignores it (deprecated).
- Changed: `stack_place_making_order` is confirmed in the chat as well as on its approval page, and the confirmation names the supplier, product, quantity, destination city and country and amount.

## 2.0.0 - 2026-10-25

- Removed: `stack_partner_list_connections`, `stack_partner_get_connection` and `stack_partner_revoke_connection` (partner grants are gone).
- Renamed, with the tenants becoming partner-managed accounts: `stack_partner_create_tenant`, `stack_partner_list_tenants`, `stack_partner_get_tenant`, `stack_partner_revoke_tenant`, `stack_partner_create_tenant_webhook` and `stack_partner_issue_tenant_passport` are `stack_partner_create_account`, `stack_partner_list_accounts`, `stack_partner_get_account`, `stack_partner_revoke_account`, `stack_partner_create_account_webhook` and `stack_partner_issue_account_passport`. The parameter `tenant_id` is `account_id`; creating takes the required `external_ref` in place of `external_customer_id`.
- Added: `stack_clear_member_sso_binding`, which forgets the single sign-on link of one team member or of every member linked to one issuer; a person approves it in a browser. The directory profile withholds it.
- Added: `stack_partner_invite_customer`, `stack_partner_release_account`, `stack_partner_cancel_release`, `stack_partner_get_release` and `stack_partner_list_releases`. The directory profile serves the reads of accounts and releases and withholds everything that opens, closes, invites or releases.
- Added: `stack_list_sso_domains`, `stack_add_sso_domain`, `stack_verify_sso_domain` and `stack_remove_sso_domain`, the verified e-mail domains of single sign-on; a person approves adding one in a browser. The directory profile withholds all four.

## 1.1.1 - 2026-10-24

- Conformance (section 12): the `mcp-listing` suite of the conformance kit judges section 11. No tool, schema, annotation or rule changed.

## 1.1.0 - 2026-10-23

- Which tools a session lists (section 11): every tool in `tools.json` now says its `group`, who it is for (`audience`: `agent`, `owner` or `both`), the account `pieces` that list it and whether it is rarely used (`on_demand`). A server may list an agent only the tools that apply to who is connected and which pieces are on, sends `notifications/tools/list_changed` when that changes, and refuses a call to a tool the session does not list.
- The load-on-demand hint: a rarely used tool carries `_meta` `"anthropic/alwaysLoad": false` in the standard profile. The directory profile is unchanged.
- No tool was added, removed or renamed, and no input schema or annotation changed.

## 1.0.0 - 2026-10-21

Initial public release.

- The generated catalog of the standard profile and the directory profile, with titles, descriptions, input schemas and the three behaviour annotations for every tool.
- Naming, description, annotation and profile conventions.
- The governance-approval flow, the rule for secrets, and the result and error shapes.
- The generator and its drift check.
- Every tool says what answers its calls (`served_by`: `engine` or `network`).
