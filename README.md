# BulkClearAriaOPSAlerts

Bulk cancels **all ACTIVE alerts** and then bulk deletes **all CANCELED (inactive) alerts** in VMware Aria Operations (Aria Ops / vROps) using the `/suite-api` REST API. [2](https://blogs.vmware.com/cloud-foundation/2016/09/06/use-hcibench-like-pro-part-1/)[3](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-16/vmware-aria-operations-api-programming-guide-8-16/getting-started-with-the-api/acquire-an-authentication-token.html)[4](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-18/vmware-aria-operations-configuration-guide-8-18/configuring-alerts-and-actions/notifications/notifications-user-scenario-create-a-webhook-alert-notification.html)

> **Important:** Aria Ops does **not** allow deleting **active** alerts. Active alerts must be **canceled** first; only **canceled** alerts can be deleted. [4](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-18/vmware-aria-operations-configuration-guide-8-18/configuring-alerts-and-actions/notifications/notifications-user-scenario-create-a-webhook-alert-notification.html)

---

## What this script does

1. Acquires an API token via:
   - `POST /suite-api/api/auth/token/acquire` [1](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-18/vmware-aria-operations-configuration-guide-8-18/configuring-alerts-and-actions/defining-alerts-best-practices.html)[5](https://ia800506.us.archive.org/34/items/vmware.com_flings_25.10.2023/software/vmw-tools/hcibench/HCIBench_User_Guide-2.8.1.pdf)
2. Retrieves alerts with paging via:
   - `GET /suite-api/api/alerts?page={n}&pageSize={n}` [2](https://blogs.vmware.com/cloud-foundation/2016/09/06/use-hcibench-like-pro-part-1/)
3. Bulk cancels all ACTIVE alerts via:
   - `POST /suite-api/api/alerts?action=cancel` (with a UUID list) 
4. Bulk deletes all canceled alerts via:
   - `DELETE /suite-api/api/alerts/bulk` (using an `alert-query` for `CANCELLED`) [3](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-16/vmware-aria-operations-api-programming-guide-8-16/getting-started-with-the-api/acquire-an-authentication-token.html)

The script attempts `CANCELLED` first, and if the API rejects it, retries once with `CANCELED`. [3](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-16/vmware-aria-operations-api-programming-guide-8-16/getting-started-with-the-api/acquire-an-authentication-token.html)[4](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-18/vmware-aria-operations-configuration-guide-8-18/configuring-alerts-and-actions/notifications/notifications-user-scenario-create-a-webhook-alert-notification.html)

---

## Requirements

- **PowerShell 7+** recommended (supports `Invoke-RestMethod -SkipCertificateCheck`).  
- **Windows PowerShell 5.1** supported (uses `ServerCertificateValidationCallback`).
- Network access from the system running the script to:
  - `https://<aria-ops>/suite-api/...` endpoints for token and alert operations [1](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-18/vmware-aria-operations-configuration-guide-8-18/configuring-alerts-and-actions/defining-alerts-best-practices.html)[2](https://blogs.vmware.com/cloud-foundation/2016/09/06/use-hcibench-like-pro-part-1/)
- An Aria Ops account with sufficient RBAC privileges to view and modify alerts. [2](https://blogs.vmware.com/cloud-foundation/2016/09/06/use-hcibench-like-pro-part-1/)

---

## Security and safety considerations

### TLS certificate validation is bypassed
This script **always bypasses TLS certificate validation** to work in environments with self-signed or untrusted certificates (e.g., `UntrustedRoot`). This is convenient for one-time cleanup, but is not a best practice long-term.

**Recommended long-term fix:** replace the Aria Ops certificate with a certificate issued by a trusted CA chain and remove TLS bypass.

### “Cancel” vs “Resolve”
Canceling an alert does **not** remove the underlying condition that generated it; alerts can re-trigger if the condition persists. [4](https://techdocs.broadcom.com/us/en/vmware-cis/aria/aria-operations/8-18/vmware-aria-operations-configuration-guide-8-18/configuring-alerts-and-actions/notifications/notifications-user-scenario-create-a-webhook-alert-notification.html)

### Highly destructive operation
This script is designed to “reset” alert state at scale. Use a change window, and consider disabling outbound notifications (email/ticket/webhook) to avoid storms.

---

## Usage

### Interactive (recommended)
Prompts for credentials via `Get-Credential` (prevents passwords in command history):

```powershell
.\BulkClearAriaOPSAlerts.ps1 `
  -AriaOpsFqdnOrIp pod01ops01.corp.achieve-1.com `
  -AuthSource LOCAL


