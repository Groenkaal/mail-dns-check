# mail-dns-check

Checks MX, SPF, DKIM and DMARC for a list of domains and writes an HTML report. Works with any mail provider, with extra checks for Microsoft 365, Google Workspace and other known services.

## Layout

| Path | Purpose |
|---|---|
| `domains.txt` | Domains to check, one per line. `#` starts a comment. Both scripts read this file. |
| `report-template.html` | Shared report template. Both scripts fill it, so the output looks the same. |
| `python/check_mail_dns.py` | Python version (needs `dnspython`). |
| `powershell/Check-MailDns.ps1` | PowerShell version (5.1 or 7+). |
| `docs/` | Browser version, served by GitHub Pages. `checks.js` holds the check logic. |

## Run in the browser

**https://groenkaal.github.io/mail-dns-check/**

Paste domains or load a `.txt` file. Lookups run in the browser over DNS-over-HTTPS (dns.google, falling back to Cloudflare). Link straight to a check with `?d=contoso.com,fabrikam.com` (add `&s=mycorp2024` for extra selectors). **Download report** saves the same HTML report the scripts produce.

Scripts, scheduled tasks, cron, GitHub Actions and reading report results: **https://groenkaal.github.io/mail-dns-check/automation.html**

## Run locally

Each script asks where to save the report. Press Enter to save it in the current folder with a timestamped name.

```sh
pip install -r python/requirements.txt
python python/check_mail_dns.py                      # prompts for output path
python python/check_mail_dns.py -o reports/mail.html -n 1.1.1.1
python python/check_mail_dns.py --domain contoso.com --selector mycorp2024
```

```powershell
.\powershell\Check-MailDns.ps1                       # prompts for output path
.\powershell\Check-MailDns.ps1 -Domains list.txt -Output report.html -NameServer 1.1.1.1
.\powershell\Check-MailDns.ps1 -Domain contoso.com,fabrikam.com -Selector mycorp2024 -Output report.html
```

### Run straight from GitHub (no clone)

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Groenkaal/mail-dns-check/main/powershell/Check-MailDns.ps1))) -Domains list.txt -Output domainreport.html
```

`list.txt` is read from, and the report written to, the folder you run it in. The script downloads `report-template.html` from the repo when it can't find it locally (override with `-TemplateUrl`). Replace `main` with a tag or commit hash in both URLs for a version that won't change under you.

Python takes the same options: `--domains list.txt`, `--domain a.com b.com`, `--selector s1 s2`, `--output report.html`.

On Windows PowerShell uses `Resolve-DnsName`. On Linux and macOS (PowerShell 7) it falls back to DNS over HTTPS through Cloudflare, and `-NameServer` is ignored.

## What is checked

- **MX**: at least one MX record. The provider is named when the MX matches a known one (Microsoft 365, Google Workspace, Zoho, Proton, Fastmail, iCloud, Yandex) or a security gateway (Mimecast, Proofpoint, Barracuda, Cisco). Null MX is reported as info.
- **SPF**: exactly one record, a safe `all` qualifier, at most 10 DNS lookups (counted recursively), and no broken includes. When the MX provider is known, SPF must include that provider (e.g. `spf.protection.outlook.com`, `_spf.google.com`).
- **DKIM**: DNS can't list selectors, so the checker looks for keys on 36 common selectors (Microsoft 365, Google, SendGrid, Mailchimp/Mailgun, Zoho, Proton, Fastmail, HubSpot, Zendesk, Klaviyo and generic names like `default`, `dkim`, `mail`). Any active key passes. Add your own with `--selector` / `-Selector` / the web page's selector field. On Microsoft 365, the `selector1`/`selector2` CNAMEs are checked in detail, and a standby selector between rotations is fine.
- **DMARC**: exactly one record, `p=quarantine` or `p=reject`, `sp` and `pct` not weakening it, and an `rua` reporting address.
- **Tenant**: the Microsoft Entra tenant ID and region for the domain, from `login.microsoftonline.com/<domain>/.well-known/openid-configuration`. Informational only.

When the system resolver returns an empty TXT answer, the scripts ask a public resolver (1.1.1.1) before reporting a record as missing. Some home routers and local resolvers drop large TXT answers. Passing `-n` / `-NameServer` turns this off.

A domain's overall status is the worst of SPF, DKIM and DMARC. MX only fails the domain when no MX exists.
