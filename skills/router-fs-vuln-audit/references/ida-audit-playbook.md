# IDA MCP Audit Playbook

## 1. Session Bring-Up

1. Check MCP connection.
2. List IDA instances and select the target one.
3. Confirm binary metadata (`arch`, `bits`, `input_file`).

Suggested MCP flow:
- `check_connection`
- `list_instances`
- `select_instance`
- `get_metadata`

## 2. Triage Per Binary

1. Enumerate functions and imports.
2. Grep critical symbols in names/strings:
   - auth/session: `auth_check`, `check_Auth`, `token`, `login`, `referer`
   - command sinks: `system`, `popen`, `exec`, `doSystemCmd`, shell wrappers
   - config commit paths: `nvram_set`, `apply`, `rc_service`, `action_mode`
3. Decompile candidate functions.
4. Build source->sink data flow with xrefs.

Suggested MCP flow:
- `list_functions`
- `list_imports`
- `decompile`
- `xrefs_to`
- `xrefs_from`
- `get_string`

## 3. Vulnerability Buckets

## 3.1 Pre-Auth RCE

Check:
1. Network entry handlers callable pre-login.
2. User input entering command builders.
3. Missing sanitization/quoting at sink boundary.

Evidence to record:
1. Entry function address.
2. Validation branch and bypass condition.
3. Command assembly statement.

## 3.2 Auth Bypass

Check:
1. No-auth endpoint tables/whitelists.
2. Referrer-only checks.
3. Session token trust bugs (predictable, not bound, absent on specific paths).

Evidence to record:
1. Endpoint match logic.
2. Session check behavior for failing case.
3. A request path that reaches privileged handler.

## 3.3 Post-Auth RCE

Check:
1. Apply/config handlers controlled by authenticated users.
2. Parameters copied into scripts, `rc_service`, or shell command strings.
3. Weak normalization before privilege boundary crossing.

Evidence to record:
1. Parameter origin and parser.
2. Trust transfer points.
3. Final execution primitive.

## 4. Filesystem Correlation

Map binary findings to:
1. Web endpoint usage in `www/*.asp`, `www/js/*.js`.
2. Service orchestration in `sbin/rc` and helper scripts.
3. Runtime config files under `etc/`, `rom/etc/`, `usr/lighttpd/`.

Always include both code-side and file-side evidence in final write-up.
