# Operator Bridge maintenance bootstrap

Infrastructure preparation candidate, not a production application release.
This public distribution contains no account credentials, business data, private keys,
machine addresses, or application source. Windows downloads from GitHub over HTTPS;
no inbound connection to a developer machine is required.

## Before running

This script has not yet passed installation and isolation acceptance on the target
Windows machine. Review the exact version before use. It requires an elevated
Windows PowerShell session, local account management, Windows Firewall and the
Microsoft OpenSSH Server optional capability. It refuses to overwrite an existing
SSH installation or maintenance account. Download from an immutable commit URL,
verify the SHA-256 against the separately supplied release record, then inspect it.
Never pipe a download directly into execution. Do not bypass organizational
execution policy or a security challenge.

## Locally supplied parameters

Pass `-SourceIp` (approved maintenance client's literal Tailscale IPv4), `-ListenIp`
(target's literal Tailscale IPv4) and `-PublicKey` (approved Ed25519 public key).
Never supply a private key. No actual site configuration belongs in this repository.

Preparation asks the machine owner to enter a new strong local password for
`BridgeMaint`. The account is an ordinary user, separate from operators, owners and
the eventual application service identity. SSH accepts public keys only.

Preparation keeps SSH disabled and TCP port 22 blocked. It prints the host-key
fingerprint, which must be verified over an existing trusted channel. Only then
run the same approved script with the same parameters and `-Activate`. Activation
checks the prepared hashes and narrow firewall rule before enabling the service.
Verify allowed key login and denied password, administrator, operator, forwarding
and unapproved-source access before treating the channel as operational.

## Recovery and revocation

On any partial failure, preserve the output for local inspection and do not blindly
rerun. The script attempts to leave SSH stopped and blocked. To revoke access, an
administrator can stop and disable the `sshd` service and disable the exact
`OperatorBridge-SSH-Maintenance-Only` rule. Confirm the listener is closed. Do not
delete pre-existing services, accounts or files as a generic rollback step.

This bootstrap does not install or activate the business application, expose a web
port, authorize an eBay account, grant access to owner browser profiles, or prove
production readiness. Those require a separate tested application release and
verified per-user/per-store permissions.
