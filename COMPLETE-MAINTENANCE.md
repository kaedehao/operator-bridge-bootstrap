# One-run completion of the existing maintenance node

This is a **candidate for the already-prepared Windows x64 machine**, not a fresh-machine bootstrap or production application installer. It does not access eBay or change Owner/Ops permissions. Do not run the old bootstrap again on the prepared machine.

## What it does

1. Validates the existing preparation receipt, exact SSH configuration, public-key hash, host-key ACL, service identity, account group, firewall profiles and narrow rule. Unexpected state stops before installation or activation.
2. With `-Apply`, checks machine-wide Node.js 24.19.0 and pnpm 11.19.0. Installs only missing components using fixed official downloads and pinned hashes (plus Node MSI signature validation). Existing different versions stop for inspection. No Git installation, reboot, account recreation, key rotation or password prompt.
3. With `-Apply -Activate`, shows the actual source/destination and asks the person at the terminal to type `ENABLE MAINTENANCE`. This explicitly approves automatic-start persistent SSH and removal of the temporary full block, retaining the narrow allow rule. No generic administrator/Ops SSH or password login is enabled.
4. Checks that the only port-22 listener belongs to sshd and binds only the configured Tailscale IPv4. Prints the public host fingerprint for independent Mac verification.
5. Writes a per-run `result.json` under `C:\ProgramData\OperatorBridgeMaintenance\run-<unique-id>`, accessible only to SYSTEM/Administrators. No secret-bearing transcripts. Activation failure attempts to stop/disable sshd and restore the inbound safety block. Incomplete rollback is explicitly reported.

Run from **64-bit administrator Windows PowerShell** after verifying the downloaded script hash:

```powershell
# Read-only first; no policy change is made by this script.
.\complete-maintenance.ps1 -SourceIp <approved-client-ip> -ListenIp <approved-node-ip>

# Complete runtime and request persistent restricted activation locally.
.\complete-maintenance.ps1 -SourceIp <approved-client-ip> -ListenIp <approved-node-ip> -Apply -Activate
```

If PowerShell policy blocks the file, do not use Bypass or an encoded command. A separately approved process-only RemoteSigned setting can be used; closing that shell removes it. Respect Group Policy.

## Reruns and limits

Healthy existing components are verified and reused. Drift, different versions, modified ACLs/configuration or partial installation errors stop for inspection rather than resetting anything. Do not run two copies concurrently or rerun while an installer remains active. This is deliberately not a general automatic repair of arbitrary partial installations. Installation may take minutes; no fixed completion time is promised.

`INFRASTRUCTURE_READY_NOT_BUSINESS_DEPLOYED` is **not** application readiness. External pinned-host-key login, denied-login and forwarding tests remain required. Verified eBay Owner grants, authoritative Team Access membership, authenticated operator sessions and the dedicated business execution service are separate unfinished work.

## Validation status

Local TypeScript tests check source-level safety invariants. The new combined PowerShell candidate has **not yet been executed on Windows**. The individual Node install and host-key repair/service-start steps were previously verified on the target. First use is infrastructure validation, not a tested production application release.

Download evidence: Node's official `https://nodejs.org/dist/v24.19.0/SHASUMS256.txt` and npm's `https://registry.npmjs.org/pnpm/11.19.0` integrity metadata, retrieved 2026-09-06. No site-specific addresses or keys are embedded in the distributable script.
