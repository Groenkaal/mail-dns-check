#!/usr/bin/env python3
"""Check MX, SPF, DKIM and DMARC for a list of domains and write an HTML report.

Works for any mail provider. Microsoft 365, Google Workspace and other known
providers get extra checks when the MX records point at them.

Reads ../domains.txt by default, asks where to write the HTML report,
and fills ../report-template.html with the results.

Usage:
    python check_mail_dns.py                 # prompts for the output path
    python check_mail_dns.py -o report.html  # no prompt
    python check_mail_dns.py --domains list.txt --output report.html -n 1.1.1.1
    python check_mail_dns.py --domain contoso.com fabrikam.com -o report.html
    python check_mail_dns.py --selector mycorp2024 s2025 -o report.html
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

try:
    import dns.exception
    import dns.resolver
except ImportError:
    sys.exit("dnspython is required: pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DOMAINS = ROOT / "domains.txt"
TEMPLATE = ROOT / "report-template.html"

# Keep PROVIDERS and COMMON_SELECTORS in step with docs/checks.js and powershell/Check-MailDns.ps1.
# Providers are matched on MX host suffix. "spf" lists includes that authorise the provider;
# an empty tuple means the provider is a gateway or its include can't be predicted.
PROVIDERS = [
    {"name": "Microsoft 365", "mx": (".mail.protection.outlook.com", ".mx.microsoft"),
     "spf": ("spf.protection.outlook.com",), "dkim": ("selector1", "selector2")},
    {"name": "Google Workspace", "mx": (".google.com", ".googlemail.com"),
     "spf": ("_spf.google.com",), "dkim": ("google",)},
    {"name": "Zoho Mail", "mx": (".zoho.com", ".zoho.eu", ".zoho.in", ".zoho.com.au", ".zohomail.com"),
     "spf": ("zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zohomail.com", "one.zoho.com", "one.zoho.eu"), "dkim": ("zoho", "zmail")},
    {"name": "Proton Mail", "mx": (".protonmail.ch",), "spf": ("_spf.protonmail.ch",),
     "dkim": ("protonmail", "protonmail2", "protonmail3")},
    {"name": "Fastmail", "mx": (".messagingengine.com",), "spf": ("spf.messagingengine.com",), "dkim": ("fm1", "fm2", "fm3")},
    {"name": "iCloud Mail", "mx": (".mail.icloud.com",), "spf": ("icloud.com",), "dkim": ("sig1",)},
    {"name": "Yandex Mail", "mx": (".yandex.net", ".yandex.ru"), "spf": ("_spf.yandex.net",), "dkim": ("mail",)},
    {"name": "Mimecast", "mx": (".mimecast.com", ".mimecast.co.za"), "spf": (), "dkim": (), "gateway": True},
    {"name": "Proofpoint", "mx": (".pphosted.com", ".ppe-hosted.com"), "spf": (), "dkim": (), "gateway": True},
    {"name": "Barracuda", "mx": (".barracudanetworks.com",), "spf": (), "dkim": (), "gateway": True},
    {"name": "Cisco Secure Email", "mx": (".iphmx.com",), "spf": (), "dkim": (), "gateway": True},
]
MS_DKIM_SELECTORS = ("selector1", "selector2")
MS_DKIM_SUFFIXES = (".onmicrosoft.com", ".dkim.mail.microsoft")
COMMON_SELECTORS = (
    "selector1", "selector2",                        # Microsoft 365
    "google",                                        # Google Workspace
    "default", "dkim", "mail", "email", "smtp", "mx", "key1", "key2", "dk",
    "k1", "k2", "k3",                                # Mailchimp, Mailgun
    "s1", "s2",                                      # SendGrid
    "zoho", "zmail",                                 # Zoho
    "protonmail", "protonmail2", "protonmail3",      # Proton
    "fm1", "fm2", "fm3",                             # Fastmail
    "sig1",                                          # iCloud
    "hs1", "hs2",                                    # HubSpot
    "mandrill", "mxvault", "everlytickey1", "everlytickey2",
    "zendesk1", "zendesk2", "kl", "kl2",             # Zendesk, Klaviyo
)
SPF_LOOKUP_LIMIT = 10
SEVERITY = {"pass": 0, "info": 0, "warn": 1, "fail": 2}

resolver = dns.resolver.Resolver()
resolver.lifetime = 6.0
# Some local resolvers (home routers, systemd-resolved) silently drop large TXT
# answers. When the system resolver returns an empty TXT answer, ask a public one.
public_resolver = dns.resolver.Resolver(configure=False)
public_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
public_resolver.lifetime = 6.0
use_public_fallback = True


# --------------------------------------------------------------------------- DNS

def query(name: str, rtype: str) -> list[str]:
    """Return record strings, [] when the name or type does not exist."""
    answer = None
    resolvers = [resolver, public_resolver] if rtype == "TXT" and use_public_fallback else [resolver]
    for r in resolvers:
        try:
            answer = r.resolve(name, rtype)
            break
        except dns.resolver.NXDOMAIN:
            return []
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            if r is resolver:
                raise RuntimeError(f"DNS timeout looking up {rtype} {name}")
    if answer is None:
        return []
    out = []
    for r in answer:
        if rtype == "TXT":
            out.append(b"".join(r.strings).decode("utf-8", "replace"))
        elif rtype == "MX":
            out.append(f"{r.preference} {str(r.exchange).rstrip('.')}")
        else:
            out.append(r.to_text().rstrip("."))
    return out


def cname(name: str) -> str | None:
    """CNAME target of name itself (not following the chain)."""
    try:
        answer = resolver.resolve(name, "CNAME")
        return str(answer[0].target).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None


def worst(*statuses: str) -> str:
    return max(statuses, key=lambda s: SEVERITY.get(s, 0))


def finding(level: str, text: str) -> dict:
    return {"level": level, "text": text}


def name_list(items: list[str], limit: int = 6) -> str:
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


# --------------------------------------------------------------------------- MX

def mx_records(domain: str) -> list[str]:
    return sorted(query(domain, "MX"), key=lambda r: (int(r.split()[0]), r.split(" ", 1)[1].lower()))


def detect_provider(mx: list[str]) -> dict | None:
    for r in mx:
        host = r.split(" ", 1)[1].lower() if " " in r else ""
        for p in PROVIDERS:
            if host.endswith(p["mx"]):
                return p
    return None


def check_mx(domain: str, mx: list[str], provider: dict | None) -> dict:
    findings = []
    if not mx:
        return {"status": "fail", "summary": "No MX records. The domain cannot receive mail.",
                "records": [], "findings": findings}
    hosts = [r.split(" ", 1)[1].lower() for r in mx]
    if hosts == [""]:
        return {"status": "info", "summary": "Null MX (RFC 7505). The domain states it accepts no mail.",
                "records": ["0 ."], "findings": findings}
    if provider and provider.get("gateway"):
        summary = f"Mail goes through {provider['name']} (security gateway)."
        findings.append(finding("info", "The mailbox provider behind the gateway can't be seen from DNS."))
    elif provider:
        summary = f"Mail is handled by {provider['name']}."
    else:
        summary = f"Mail is handled by {hosts[0]}."
    if "" in hosts:
        findings.append(finding("warn", "A null MX (.) is mixed with real MX hosts. Remove one or the other."))
    return {"status": "warn" if "" in hosts else "pass", "summary": summary, "records": mx, "findings": findings}


# --------------------------------------------------------------------------- SPF

def spf_records(domain: str) -> list[str]:
    return [t for t in query(domain, "TXT") if t.lower().startswith("v=spf1")]


def count_spf_lookups(domain: str, seen: set[str] | None = None, depth: int = 0) -> tuple[int, list[str]]:
    """Count DNS-querying mechanisms recursively (RFC 7208 limit is 10)."""
    seen = seen if seen is not None else set()
    problems: list[str] = []
    if domain in seen or depth > 10:
        return 0, [f"SPF include loop at {domain}"]
    seen.add(domain)
    recs = spf_records(domain)
    if len(recs) != 1:
        if depth:
            problems.append(f"Included domain {domain} has no SPF record. Receivers return permerror when they reach it."
                            if not recs else f"Included domain {domain} has {len(recs)} SPF records.")
        return 0, problems
    count = 0
    for term in recs[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:") or t.startswith("redirect="):
            target = t.split(":", 1)[1] if t.startswith("include:") else t.split("=", 1)[1]
            count += 1
            sub, p = count_spf_lookups(target, seen, depth + 1)
            count += sub
            problems += p
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            count += 1
    return count, problems


def check_spf(domain: str, provider: dict | None) -> dict:
    recs = spf_records(domain)
    findings = []
    if not recs:
        example = f"v=spf1 include:{provider['spf'][0]} -all" if provider and provider["spf"] else "v=spf1 mx -all"
        return {"status": "fail", "summary": "No SPF record. Receivers cannot verify who may send for this domain.",
                "records": [], "findings": [finding("fail", f"Add a TXT record such as: {example}")]}
    if len(recs) > 1:
        return {"status": "fail", "summary": f"{len(recs)} SPF records. SPF fails when more than one exists.",
                "records": recs, "findings": [finding("fail", "Merge them into a single v=spf1 record.")]}

    rec = recs[0]
    terms = [t.lower() for t in rec.split()[1:]]
    statuses = []

    if provider and provider["spf"]:
        hit = next((inc for inc in provider["spf"] if f"include:{inc}" in terms), None)
        if hit:
            findings.append(finding("pass", f"Includes {hit} ({provider['name']})."))
        else:
            findings.append(finding("warn", f"MX points to {provider['name']}, but SPF does not include "
                                    f"{provider['spf'][0]}. Mail sent from {provider['name']} will fail SPF."))
            statuses.append("warn")

    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    redirect = next((t for t in terms if t.startswith("redirect=")), None)
    if all_term == "-all":
        findings.append(finding("pass", "Ends in -all (hard fail for unlisted senders)."))
    elif all_term == "~all":
        findings.append(finding("pass", "Ends in ~all (soft fail). Fine with DMARC enforcement; -all is stricter."))
    elif all_term == "?all":
        findings.append(finding("warn", "Ends in ?all (neutral). Unlisted senders are not rejected."))
        statuses.append("warn")
    elif all_term in ("all", "+all"):
        findings.append(finding("fail", "Ends in +all. Anyone may send as this domain."))
        statuses.append("fail")
    elif redirect:
        findings.append(finding("info", f"Policy delegated with {redirect}."))
    else:
        findings.append(finding("warn", "No all mechanism. Add -all or ~all at the end."))
        statuses.append("warn")

    try:
        lookups, problems = count_spf_lookups(domain)
    except RuntimeError as e:
        lookups, problems = -1, [str(e)]
    if lookups > SPF_LOOKUP_LIMIT:
        findings.append(finding("fail", f"{lookups} DNS lookups. The limit is {SPF_LOOKUP_LIMIT}, so SPF returns permerror."))
        statuses.append("fail")
    elif lookups >= 0:
        level = "warn" if lookups >= 8 else "pass"
        findings.append(finding(level, f"{lookups} of {SPF_LOOKUP_LIMIT} DNS lookups used."))
        if level == "warn":
            statuses.append("warn")
    for p in problems:
        findings.append(finding("warn", p))
        statuses.append("warn")

    status = worst("pass", *statuses)
    summary = {"pass": "Valid SPF record.", "warn": "SPF exists but needs attention.",
               "fail": "SPF record is broken or unsafe."}[status]
    return {"status": status, "summary": summary, "records": [rec], "findings": findings}


# --------------------------------------------------------------------------- DKIM

def dkim_key(domain: str, sel: str) -> str | None:
    """The DKIM record at a selector (any record with a p= tag), or None."""
    txt = [t for t in query(f"{sel}._domainkey.{domain}", "TXT") if "p=" in t.replace(" ", "")]
    return txt[0] if txt else None


def check_dkim(domain: str, provider: dict | None, extra: tuple[str, ...] = (), accepts_mail: bool = True) -> dict:
    selectors = list(dict.fromkeys([*COMMON_SELECTORS, *(provider["dkim"] if provider else ()), *extra]))
    with ThreadPoolExecutor(max_workers=12) as pool:
        keys = list(pool.map(lambda s: dkim_key(domain, s), selectors))
        ms_targets = list(pool.map(lambda s: cname(f"{s}._domainkey.{domain}"), MS_DKIM_SELECTORS))

    active, revoked = [], []
    for sel, key in zip(selectors, keys):
        if key is None:
            continue
        m = re.search(r"(?:^|;)p=([^;]*)", key.replace(" ", ""))
        (active if m and m.group(1) else revoked).append((sel, key))

    findings, records = [], []
    ms_cnames = dict(zip(MS_DKIM_SELECTORS, ms_targets))
    active_names = [s for s, _ in active]
    is_ms = bool(provider and provider["name"] == "Microsoft 365")

    for sel, key in active:
        target = ms_cnames.get(sel)
        if target:
            records.append({"host": f"{sel}._domainkey.{domain} CNAME", "value": target})
        else:
            records.append({"host": f"{sel}._domainkey.{domain} TXT",
                            "value": key[:120] + ("…" if len(key) > 120 else "")})
        findings.append(finding("pass", f"{sel}: public key published."))

    # Microsoft 365 publishes DKIM as CNAMEs at selector1/selector2. One can sit without a key between rotations.
    standby = [s for s in MS_DKIM_SELECTORS if ms_cnames[s] and s not in active_names]
    ms_active = [s for s in MS_DKIM_SELECTORS if s in active_names]
    expected = domain.replace(".", "-")
    for sel in MS_DKIM_SELECTORS:
        target = ms_cnames[sel]
        if not target or not (is_ms or target.lower().endswith(MS_DKIM_SUFFIXES)):
            continue
        if sel in standby:
            records.append({"host": f"{sel}._domainkey.{domain} CNAME", "value": target})
        if is_ms and not target.lower().endswith(MS_DKIM_SUFFIXES):
            findings.append(finding("warn", f"{sel} points outside Microsoft 365 ({target})."))
        elif target.lower().endswith(MS_DKIM_SUFFIXES) and not target.lower().startswith(f"{sel}-{expected}"):
            findings.append(finding("info", f"{sel} target name does not match {sel}-{expected}."))
    for sel in standby:
        if ms_active:
            findings.append(finding("info", f"{sel}: standby selector, no key yet. Normal between rotations."))
        else:
            findings.append(finding("warn", f"{sel}: CNAME exists but the target has no key. "
                                    "Enable DKIM signing for this domain in the Microsoft Defender portal."))
    if is_ms and not ms_active and not standby:
        findings.append(finding("warn", "Microsoft 365 DKIM is not set up (no selector1/selector2). Microsoft 365 then "
                                "signs with your onmicrosoft.com domain, which does not align for DMARC."))
    if provider and provider["name"] == "Google Workspace" and "google" not in active_names:
        findings.append(finding("info", "Google Workspace's default selector (google) has no key. "
                                "A custom selector may be in use."))
    if revoked:
        findings.append(finding("info", f"Empty (revoked) key at: {name_list([s for s, _ in revoked])}."))

    if active:
        status = "pass"
        summary = f"DKIM key found at {len(active)} selector{'s' if len(active) > 1 else ''}: {name_list(active_names)}."
        if any(f["level"] in ("warn", "fail") for f in findings):
            status = "warn"
    elif standby:
        status, summary = "warn", "DKIM CNAMEs exist but no key is published. Signing is not enabled yet."
    elif revoked and not accepts_mail:
        status, summary = "info", "Only empty (revoked) keys found. Typical for a domain that sends no mail."
    elif revoked:
        status, summary = "warn", "Only empty (revoked) keys found. Active keys may be under a selector not checked here."
    else:
        status = "warn"
        summary = f"No DKIM key found on the {len(selectors)} common selectors checked."
        findings.append(finding("warn", "DKIM may still be set up under a custom selector. "
                                "Add it to the selector list to check it."))
    return {"status": status, "summary": summary, "records": records, "findings": findings}


# --------------------------------------------------------------------------- DMARC

def parse_tags(rec: str) -> dict[str, str]:
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(domain: str) -> dict:
    name = f"_dmarc.{domain}"
    recs = [t for t in query(name, "TXT") if t.lower().replace(" ", "").startswith("v=dmarc1")]
    findings = []
    if not recs:
        return {"status": "fail", "summary": "No DMARC record. Spoofed mail from this domain is not blocked.",
                "records": [], "findings": [finding("fail", f"Add TXT at {name}: v=DMARC1; p=none; rua=mailto:dmarc@{domain}, "
                                                           "then move to quarantine or reject.")]}
    if len(recs) > 1:
        return {"status": "fail", "summary": f"{len(recs)} DMARC records. Receivers ignore DMARC when there is more than one.",
                "records": recs, "findings": [finding("fail", "Keep exactly one record at _dmarc.")]}

    rec = recs[0]
    tags = parse_tags(rec)
    statuses = []
    policy = tags.get("p", "").lower()
    if policy == "reject":
        findings.append(finding("pass", "p=reject: failing mail is rejected."))
    elif policy == "quarantine":
        findings.append(finding("pass", "p=quarantine: failing mail goes to junk."))
    elif policy == "none":
        findings.append(finding("warn", "p=none: monitoring only, spoofed mail is still delivered."))
        statuses.append("warn")
    else:
        findings.append(finding("fail", f"Invalid or missing p= tag ({policy or 'empty'})."))
        statuses.append("fail")

    sp = tags.get("sp", "").lower()
    if sp == "none" and policy in ("quarantine", "reject"):
        findings.append(finding("warn", "sp=none: subdomains are not protected."))
        statuses.append("warn")

    pct = tags.get("pct")
    if pct and pct != "100":
        findings.append(finding("warn", f"pct={pct}: policy applies to only part of failing mail."))
        statuses.append("warn")

    if tags.get("rua"):
        findings.append(finding("pass", f"Aggregate reports go to {tags['rua']}."))
    else:
        findings.append(finding("info", "No rua= tag, so you receive no aggregate reports."))

    status = worst("pass", *statuses)
    summary = {"pass": f"Enforcing DMARC policy ({policy}).", "warn": "DMARC exists but does not fully protect the domain.",
               "fail": "DMARC record is invalid."}[status]
    return {"status": status, "summary": summary, "records": [rec], "findings": findings}


# --------------------------------------------------------------------------- Run

def safe(fn, *args) -> dict:
    try:
        return fn(*args)
    except Exception as e:  # keep going for the other domains
        return {"status": "fail", "summary": "Lookup error.", "records": [], "findings": [finding("fail", str(e))]}


def lookup_tenant(domain: str) -> dict | None:
    """Microsoft Entra tenant behind the domain, from the public OpenID configuration."""
    url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        return {"found": False} if e.code == 400 else None
    except Exception:
        return None
    m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", data.get("issuer", ""), re.I)
    return {"found": True, "id": m.group(0), "region": data.get("tenant_region_scope", "")} if m else {"found": False}


def check_domain(domain: str, extra_selectors: tuple[str, ...] = ()) -> dict:
    mx: list[str] = []
    try:
        mx = mx_records(domain)
        provider = detect_provider(mx)
        mx_check = check_mx(domain, mx, provider)
    except Exception as e:
        provider = None
        mx_check = {"status": "fail", "summary": "Lookup error.", "records": [], "findings": [finding("fail", str(e))]}
    checks = {"mx": mx_check, "spf": safe(check_spf, domain, provider),
              "dkim": safe(check_dkim, domain, provider, extra_selectors, any(r.split(" ", 1)[1] for r in mx)), "dmarc": safe(check_dmarc, domain)}
    overall = worst(checks["spf"]["status"], checks["dkim"]["status"], checks["dmarc"]["status"],
                    "fail" if checks["mx"]["status"] == "fail" else "pass")
    result = {"domain": domain, "overall": overall, "provider": provider["name"] if provider else None, "checks": checks}
    tenant = lookup_tenant(domain)
    if tenant:
        result["tenant"] = tenant
    return result


def read_domains(path: Path) -> list[str]:
    seen, out = set(), []
    for line in path.read_text(encoding="utf-8").splitlines():
        d = line.split("#", 1)[0].strip().lower().rstrip(".")
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def ask_output_path() -> Path:
    default = Path.cwd() / f"mail-dns-report-{datetime.now():%Y%m%d-%H%M}.html"
    answer = input(f"Where should the HTML report be saved? [{default}]: ").strip().strip('"')
    path = Path(answer).expanduser() if answer else default
    if path.is_dir():
        path = path / default.name
    return path


def split_args(values: list[str] | None) -> list[str]:
    return list(dict.fromkeys(v.strip().lower().rstrip(".") for arg in values or [] for v in arg.split(",") if v.strip()))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--domains", type=Path, default=DEFAULT_DOMAINS, help="domain list (default: ../domains.txt)")
    ap.add_argument("-D", "--domain", nargs="+", metavar="DOMAIN", help="check these domains instead of a file")
    ap.add_argument("-s", "--selector", nargs="+", metavar="SELECTOR", help="extra DKIM selectors to check")
    ap.add_argument("-o", "--output", type=Path, help="HTML report path (prompted if omitted)")
    ap.add_argument("-n", "--nameserver", help="DNS server to query instead of the system resolver")
    args = ap.parse_args()

    global use_public_fallback
    if args.nameserver:
        resolver.nameservers = [args.nameserver]
        use_public_fallback = False
    if args.domain:
        domains = split_args(args.domain)
        source = "command line"
    else:
        if not args.domains.exists():
            sys.exit(f"Domain list not found: {args.domains}")
        domains = read_domains(args.domains)
        source = args.domains.name
    if not domains:
        sys.exit(f"No domains found in {source}")
    selectors = tuple(split_args(args.selector))

    out = args.output.expanduser() if args.output else ask_output_path()
    out.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for d in domains:
        print(f"Checking {d} ...", end=" ", flush=True)
        r = check_domain(d, selectors)
        print(r["overall"].upper())
        results.append(r)

    report = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "Python",
        "source": source,
        "resolver": ", ".join(resolver.nameservers),
        "domains": results,
    }
    payload = json.dumps(report, ensure_ascii=False).replace("</", "<\\/")
    html = TEMPLATE.read_text(encoding="utf-8").replace("__REPORT_DATA__", payload)
    out.write_text(html, encoding="utf-8")
    print(f"\nReport written to {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
