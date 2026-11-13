#!/usr/bin/env python3
"""Check SPF, DKIM, DMARC (and MX) for a list of domains, tuned for Microsoft 365.

Reads ../domains.txt by default, asks where to write the HTML report,
and fills ../report-template.html with the results.

Usage:
    python check_mail_dns.py                 # prompts for the output path
    python check_mail_dns.py -o report.html  # no prompt
    python check_mail_dns.py --domains list.txt --output report.html -n 1.1.1.1
    python check_mail_dns.py --domain contoso.com fabrikam.com -o report.html
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
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

MS_SPF_INCLUDE = "spf.protection.outlook.com"
MS_MX_SUFFIXES = (".mail.protection.outlook.com", ".mx.microsoft")
MS_DKIM_SUFFIXES = (".onmicrosoft.com", ".dkim.mail.microsoft")
DKIM_SELECTORS = ("selector1", "selector2")
SPF_LOOKUP_LIMIT = 10
SEVERITY = {"pass": 0, "info": 0, "warn": 1, "fail": 2}

resolver = dns.resolver.Resolver()
resolver.lifetime = 6.0
# Some local resolvers (home routers, systemd-resolved) silently drop large TXT
# answers. When the system resolver returns no TXT, ask a public one to be sure.
public_resolver = dns.resolver.Resolver(configure=False)
public_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
public_resolver.lifetime = 6.0
use_public_fallback = True


# --------------------------------------------------------------------------- DNS

def query(name: str, rtype: str) -> list[str]:
    """Return record strings, [] when the name or type does not exist."""
    answer = None
    for r in ([resolver, public_resolver] if rtype == "TXT" and use_public_fallback else [resolver]):
        try:
            answer = r.resolve(name, rtype)
            break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
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


# --------------------------------------------------------------------------- MX

def check_mx(domain: str) -> dict:
    mx = sorted(query(domain, "MX"), key=lambda r: int(r.split()[0]))
    findings = []
    if not mx:
        return {"status": "fail", "summary": "No MX records. The domain cannot receive mail.",
                "records": [], "findings": findings}
    hosts = [r.split(" ", 1)[1].lower() for r in mx]
    if hosts == [""]:
        return {"status": "info", "summary": "Null MX (RFC 7505). The domain states it accepts no mail.",
                "records": ["0 ."], "findings": findings}
    if any(h.endswith(MS_MX_SUFFIXES) for h in hosts):
        status, summary = "pass", "Mail is routed to Exchange Online."
        if len(mx) > 1:
            findings.append(finding("info", f"{len(mx)} MX records. Microsoft 365 normally needs only one."))
    else:
        status, summary = "info", "Mail is not routed to Microsoft 365."
        findings.append(finding("info", "MX points elsewhere, e.g. a third-party gateway or another provider."))
    return {"status": status, "summary": summary, "records": mx, "findings": findings}


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


def check_spf(domain: str) -> dict:
    recs = spf_records(domain)
    findings = []
    if not recs:
        return {"status": "fail", "summary": "No SPF record. Receivers cannot verify who may send for this domain.",
                "records": [], "findings": [finding("fail", f"Add TXT: v=spf1 include:{MS_SPF_INCLUDE} -all")]}
    if len(recs) > 1:
        return {"status": "fail", "summary": f"{len(recs)} SPF records. SPF fails when more than one exists.",
                "records": recs, "findings": [finding("fail", "Merge them into a single v=spf1 record.")]}

    rec = recs[0]
    terms = [t.lower() for t in rec.split()[1:]]
    statuses = []

    if f"include:{MS_SPF_INCLUDE}" in terms:
        findings.append(finding("pass", f"Includes {MS_SPF_INCLUDE} (Microsoft 365)."))
    else:
        findings.append(finding("warn", f"Does not include {MS_SPF_INCLUDE}. Microsoft 365 mail will fail SPF."))
        statuses.append("warn")

    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    redirect = next((t for t in terms if t.startswith("redirect=")), None)
    if all_term in ("-all",):
        findings.append(finding("pass", "Ends in -all (hard fail for unlisted senders)."))
    elif all_term == "~all":
        findings.append(finding("pass", "Ends in ~all (soft fail). Fine with DMARC enforcement; -all is stricter."))
    elif all_term in ("?all",):
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

def check_dkim(domain: str) -> dict:
    findings, records = [], []
    good = 0
    expected_prefix = domain.replace(".", "-")
    for sel in DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        target = cname(name)
        txt = [t for t in query(name, "TXT") if "p=" in t.replace(" ", "")]
        if target:
            records.append({"host": f"{name} CNAME", "value": target})
            if not target.lower().endswith(MS_DKIM_SUFFIXES):
                findings.append(finding("warn", f"{sel} points outside Microsoft 365 ({target})."))
            elif not target.lower().startswith(f"{sel}-{expected_prefix}".lower()):
                findings.append(finding("info", f"{sel} target name does not match {sel}-{expected_prefix}."))
        if txt:
            key = txt[0]
            m = re.search(r"\bp=([^;\s]*)", key.replace(" ", ""))
            if m and m.group(1):
                good += 1
                if not target:
                    records.append({"host": f"{name} TXT", "value": key[:120] + ("…" if len(key) > 120 else "")})
                findings.append(finding("pass", f"{sel}: public key published."))
            else:
                findings.append(finding("fail", f"{sel}: key is empty (p=), so the key is revoked."))
        elif target:
            findings.append(finding("warn", f"{sel}: CNAME exists but the target has no key. "
                                    "Enable DKIM signing for this domain in the Microsoft Defender portal."))
        else:
            findings.append(finding("fail", f"{sel}: no record at {name}."))

    standby = sum(1 for f in findings if f["text"].endswith("Microsoft Defender portal."))
    if good == len(DKIM_SELECTORS):
        status, summary = "pass", "Both Microsoft 365 DKIM selectors are published."
    elif good and standby:
        status, summary = "pass", "DKIM signing is active. The other selector is on standby for key rotation."
        for f in findings:
            if f["text"].endswith("Microsoft Defender portal."):
                f["level"], f["text"] = "info", f["text"].split(":", 1)[0] + ": standby selector, no key yet. Normal between rotations."
    elif good:
        status, summary = "warn", "Only one DKIM selector is published. Key rotation will break signing."
    elif standby:
        status, summary = "warn", "DKIM CNAMEs exist but no key is published. Signing is not enabled yet."
    else:
        status, summary = "fail", "No Microsoft 365 DKIM key found."
    if status == "pass" and any(f["level"] in ("warn", "fail") for f in findings):
        status = "warn"
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

def safe(fn, domain: str) -> dict:
    try:
        return fn(domain)
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


def check_domain(domain: str) -> dict:
    checks = {"mx": safe(check_mx, domain), "spf": safe(check_spf, domain),
              "dkim": safe(check_dkim, domain), "dmarc": safe(check_dmarc, domain)}
    overall = worst(checks["spf"]["status"], checks["dkim"]["status"], checks["dmarc"]["status"],
                    "fail" if checks["mx"]["status"] == "fail" else "pass")
    result = {"domain": domain, "overall": overall, "checks": checks}
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--domains", type=Path, default=DEFAULT_DOMAINS, help="domain list (default: ../domains.txt)")
    ap.add_argument("-D", "--domain", nargs="+", metavar="DOMAIN", help="check these domains instead of a file")
    ap.add_argument("-o", "--output", type=Path, help="HTML report path (prompted if omitted)")
    ap.add_argument("-n", "--nameserver", help="DNS server to query instead of the system resolver")
    args = ap.parse_args()

    global use_public_fallback
    if args.nameserver:
        resolver.nameservers = [args.nameserver]
        use_public_fallback = False
    if args.domain:
        domains = list(dict.fromkeys(d.strip().lower().rstrip(".") for arg in args.domain for d in arg.split(",") if d.strip()))
        source = "command line"
    else:
        if not args.domains.exists():
            sys.exit(f"Domain list not found: {args.domains}")
        domains = read_domains(args.domains)
        source = args.domains.name
    if not domains:
        sys.exit(f"No domains found in {source}")

    out = args.output.expanduser() if args.output else ask_output_path()
    out.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for d in domains:
        print(f"Checking {d} ...", end=" ", flush=True)
        r = check_domain(d)
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
