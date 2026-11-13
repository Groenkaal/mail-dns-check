# mail-dns-check

Checks SPF, DKIM and DMARC (plus MX) for a list of domains, tuned for Microsoft 365, and writes an HTML report.

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

Paste domains or load a `.txt` file. Lookups run in the browser over DNS-over-HTTPS (dns.google, falling back to Cloudflare). Link straight to a check with `?d=contoso.com,fabrikam.com`. **Download report** saves the same HTML report the scripts produce.

## Run locally

Each script asks where to save the report. Press Enter to save it in the current folder with a timestamped name.

```sh
pip install -r python/requirements.txt
python python/check_mail_dns.py                      # prompts for output path
python python/check_mail_dns.py -o reports/mail.html -n 1.1.1.1
```

```powershell
.\powershell\Check-MailDns.ps1                       # prompts for output path
.\powershell\Check-MailDns.ps1 -Domains list.txt -Output report.html -NameServer 1.1.1.1
.\powershell\Check-MailDns.ps1 -Domain contoso.com,fabrikam.com -Output report.html
```

### Run straight from GitHub (no clone)

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Groenkaal/mail-dns-check/main/powershell/Check-MailDns.ps1))) -Domains list.txt -Output domainreport.html
```

`list.txt` is read from, and the report written to, the folder you run it in. The script downloads `report-template.html` from the repo when it can't find it locally (override with `-TemplateUrl`). Replace `main` with a tag or commit hash in both URLs for a version that won't change under you.

Python takes the same options: `--domains list.txt`, `--domain a.com b.com`, `--output report.html`.

On Windows PowerShell uses `Resolve-DnsName`. On Linux and macOS (PowerShell 7) it falls back to DNS over HTTPS through Cloudflare, and `-NameServer` is ignored.

## What is checked

- **MX**: points at `*.mail.protection.outlook.com` or `*.mx.microsoft`. Null MX is reported as info.
- **SPF**: exactly one record, includes `spf.protection.outlook.com`, safe `all` qualifier, at most 10 DNS lookups (counted recursively), and broken includes.
- **DKIM**: CNAMEs at `selector1` and `selector2._domainkey` that point to Microsoft 365 (`*.onmicrosoft.com` or `*.dkim.mail.microsoft`) and resolve to a published key. A second selector with no key yet is treated as normal rotation standby.
- **DMARC**: exactly one record, `p=quarantine` or `p=reject`, `sp` and `pct` not weakening it, and an `rua` reporting address.

- **Tenant**: the Microsoft Entra tenant ID and region for the domain, from `login.microsoftonline.com/<domain>/.well-known/openid-configuration`. Informational only.

When the system resolver returns no TXT answer, the Python script asks 1.1.1.1 and 8.8.8.8 before reporting a record as missing. Some home routers and local resolvers drop large TXT answers. Passing `-n` turns this off.

A domain's overall status is the worst of SPF, DKIM and DMARC. MX only fails the domain when no MX exists.
