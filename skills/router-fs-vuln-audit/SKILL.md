---
name: router-fs-vuln-audit
description: Audit extracted router firmware filesystems and binaries loaded in IDA via IDA MCP. Use when a user asks to identify externally exposed services (for example HTTP/HTTPS), prioritize binaries for reverse engineering, hunt pre-auth RCE, auth bypass, and post-auth RCE chains, and output a defensible vulnerability report with a minimal verification PoC.
---

# Router Fs Vuln Audit

## Goal

Execute a repeatable three-step router-firmware vulnerability workflow:
1. Identify externally exposed services from the extracted filesystem and output a prioritized binary list for IDA loading.
2. Audit those binaries through IDA MCP and correlate findings with scripts/web assets in the filesystem.
3. Produce a report and a minimal reproducible PoC.

## Workflow

### Step 1: Identify Externally Exposed Services and Prioritize Binaries

Do not assume a fixed router filesystem layout. Different vendors place binaries, startup scripts, web roots, and configs in different paths.

Do not require the user to run bundled scripts. Prefer direct filesystem inspection and concise search commands as needed.

Focus on externally reachable attack surface first:
1. HTTP/HTTPS management plane (for example `httpd`, `uhttpd`, `lighttpd`, `boa`, `goahead`, `nginx`).
2. Other network-facing daemons (for example UPnP, DNS/DHCP, SSH/Telnet/FTP/TFTP, TR-069/CWMP, proprietary TCP/UDP services).
3. Helper processes that parse network/user-controlled data and invoke command execution, nvram, or restart hooks.

Find evidence from files rather than hardcoded paths:
1. Service startup and respawn logic (for example `rc`, init scripts, `inittab`, service launch scripts).
2. Daemon binaries and symlinks in executable directories.
3. Config files with listen ports, bind addresses, auth toggles, endpoint mappings, and CGI/handler directives.
4. Web root assets (`.cgi`, `.asp`, `.htm`, `.js`) and route/action strings from binaries.

Required Step 1 outputs:
1. Exposed service inventory with protocol, port (if known), and evidence file paths.
2. `ida-priority` list of absolute binary paths ordered by likely exploitability.
3. HTTP route/endpoint candidate list when web services are present.

IDA prioritization order:
1. HTTP request handlers and control-plane dispatchers.
2. WAN/LAN-reachable management daemons.
3. Data-parsing helpers that connect request input to sensitive sinks.

Deliver to user:
1. Absolute paths of priority binaries.
2. Brief reason per binary tied to external exposure.
3. Explicit “load these into IDA first” instruction.

### Step 2: Perform IDA MCP Vulnerability Audit

Use the playbook in `references/ida-audit-playbook.md`.

Always run this sequence:
1. `mcp__IDAMCP__check_connection`
2. `mcp__IDAMCP__list_instances`
3. `mcp__IDAMCP__select_instance`
4. Per target binary: `list_functions`, `decompile`, `xrefs_to`, `xrefs_from`, `strings`-guided function review.

Hunt targets:
1. Pre-auth RCE sinks: `system/popen/eval/doSystemCmd`-style wrappers reachable from HTTP/UPnP/UDP handlers.
2. Auth bypass: weak/optional `auth_check`, referrer-only checks, token/session logic inconsistencies, no-auth endpoint whitelists.
3. Post-auth RCE: config/apply handlers that pass user-controlled fields into command builders (`rc_service`, shell scripts, nvram hooks).

Correlate each binary finding with filesystem evidence:
1. Web forms and JS endpoints in discovered web roots.
2. Service startup/restart paths in discovered init/rc/service scripts.
3. Config templates in discovered config directories.

Require per-finding evidence:
1. Function name/address.
2. Data flow summary (source -> check -> sink).
3. Trigger endpoint/protocol.
4. Constraints and exploitability conditions.

### Step 3: Produce Report and Minimal Verification PoC

Use templates:
- `references/report-template.md`
- `references/poc-template.md`

PoC requirements:
1. Default to non-destructive verification payloads.
2. Include prerequisites, exact request, and expected observable result.
3. Avoid wormable, self-propagating, or destructive payload behavior.
4. Clearly separate “verified” vs “inferred” claims.

Report requirements:
1. Affected component and firmware build.
2. Root cause with code evidence.
3. Attack path (pre-auth / auth bypass + post-auth).
4. Reproduction steps and expected output.
5. Suggested fix and regression checks.

## Resource Index

### references/
- `references/ida-audit-playbook.md`: MCP command flow and vulnerability hunt checklist.
- `references/report-template.md`: vendor-report structure.
- `references/poc-template.md`: minimal reproducible PoC format.
