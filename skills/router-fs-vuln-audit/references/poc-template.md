# Minimal Verification PoC Template

## Objective

Validate vulnerability existence with minimal side effects and clear success criteria.

## Preconditions

1. Device model and firmware version.
2. Network location (LAN/WAN).
3. Auth state (unauthenticated/authenticated).
4. Safety guardrails (isolated lab, backup config).

## Request

### HTTP Example

```
METHOD /path HTTP/1.1
Host: <target>
Cookie: <if needed>
Content-Type: application/x-www-form-urlencoded

<parameters>
```

## Expected Observable Result

1. HTTP status/body marker, or
2. Deterministic log/state change that confirms code path reached.

## Non-Destructive Confirmation

Prefer:
1. Read-only state leak proof.
2. Benign command marker or harmless callback marker.
3. No persistent modification unless required to prove impact.

## Rollback

1. Clear temporary state files/logs.
2. Revert changed config.
3. Reboot/restart service if needed.
