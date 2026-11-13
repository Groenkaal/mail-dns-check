/* Mail DNS checks for the browser (and node, for testing).
 * Mirrors python/check_mail_dns.py and powershell/Check-MailDns.ps1.
 * Lookups go over DNS-over-HTTPS: Google first, Cloudflare as fallback.
 */
(function (root) {
  "use strict";

  var MS_SPF_INCLUDE = "spf.protection.outlook.com";
  var MS_MX_SUFFIXES = [".mail.protection.outlook.com", ".mx.microsoft"];
  var MS_DKIM_SUFFIXES = [".onmicrosoft.com", ".dkim.mail.microsoft"];
  var DKIM_SELECTORS = ["selector1", "selector2"];
  var SPF_LOOKUP_LIMIT = 10;
  var SEVERITY = { pass: 0, info: 0, warn: 1, fail: 2 };
  var TYPE_NUM = { TXT: 16, MX: 15, CNAME: 5 };
  var STANDBY_TAIL = "Microsoft Defender portal.";

  var PROVIDERS = [
    { name: "dns.google", url: function (n, t) { return "https://dns.google/resolve?name=" + encodeURIComponent(n) + "&type=" + t; } },
    { name: "cloudflare-dns.com", url: function (n, t) { return "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(n) + "&type=" + t; } }
  ];

  function endsWithAny(v, list) { v = v.toLowerCase(); return list.some(function (s) { return v.endsWith(s); }); }
  function worst() {
    var w = "pass";
    for (var i = 0; i < arguments.length; i++) if ((SEVERITY[arguments[i]] || 0) > SEVERITY[w]) w = arguments[i];
    return w;
  }
  function finding(level, text) { return { level: level, text: text }; }
  function stripDot(s) { return s.replace(/\.$/, ""); }

  function parseTxt(data) {
    if (data.charAt(0) !== '"') return data;
    var parts = [], re = /"((?:[^"\\]|\\.)*)"/g, m;
    while ((m = re.exec(data))) parts.push(m[1].replace(/\\(.)/g, "$1"));
    return parts.join("");
  }

  /* Resolver with a per-run cache. Returns record strings, [] when nothing exists. */
  function createResolver(fetchImpl) {
    var f = fetchImpl || (typeof fetch !== "undefined" ? fetch.bind(root) : null);
    var cache = new Map();
    var used = null;

    async function raw(name, type) {
      var lastErr;
      for (var i = 0; i < PROVIDERS.length; i++) {
        var p = PROVIDERS[i];
        try {
          var res = await f(p.url(name, type), { headers: { accept: "application/dns-json" } });
          if (!res.ok) throw new Error("HTTP " + res.status + " from " + p.name);
          var j = await res.json();
          used = used || p.name;
          if (j.Status !== 0 || !j.Answer) return [];
          return j.Answer.filter(function (a) { return a.type === TYPE_NUM[type]; }).map(function (a) {
            if (type === "TXT") return parseTxt(a.data);
            if (type === "MX") { var s = a.data.split(/\s+/); return s[0] + " " + stripDot(s[1] || ""); }
            return stripDot(a.data);
          });
        } catch (e) { lastErr = e; }
      }
      throw new Error("DNS lookup failed for " + type + " " + name + " (" + (lastErr && lastErr.message) + ")");
    }

    function query(name, type) {
      var key = type + " " + name.toLowerCase();
      if (!cache.has(key)) cache.set(key, raw(name, type));
      return cache.get(key);
    }
    query.provider = function () { return used || PROVIDERS[0].name; };
    return query;
  }

  // ------------------------------------------------------------------ MX
  async function checkMx(q, domain) {
    var mx = (await q(domain, "MX")).slice().sort(function (a, b) { return parseInt(a) - parseInt(b); });
    var findings = [];
    if (!mx.length) return { status: "fail", summary: "No MX records. The domain cannot receive mail.", records: [], findings: findings };
    var hosts = mx.map(function (r) { return (r.split(" ")[1] || "").toLowerCase(); });
    if (hosts.length === 1 && hosts[0] === "")
      return { status: "info", summary: "Null MX (RFC 7505). The domain states it accepts no mail.", records: ["0 ."], findings: findings };
    var status, summary;
    if (hosts.some(function (h) { return endsWithAny(h, MS_MX_SUFFIXES); })) {
      status = "pass"; summary = "Mail is routed to Exchange Online.";
      if (mx.length > 1) findings.push(finding("info", mx.length + " MX records. Microsoft 365 normally needs only one."));
    } else {
      status = "info"; summary = "Mail is not routed to Microsoft 365.";
      findings.push(finding("info", "MX points elsewhere, e.g. a third-party gateway or another provider."));
    }
    return { status: status, summary: summary, records: mx, findings: findings };
  }

  // ------------------------------------------------------------------ SPF
  async function spfRecords(q, domain) {
    return (await q(domain, "TXT")).filter(function (t) { return t.toLowerCase().startsWith("v=spf1"); });
  }

  async function countSpfLookups(q, domain, seen, depth) {
    var problems = [];
    if (seen.has(domain) || depth > 10) return { count: 0, problems: ["SPF include loop at " + domain] };
    seen.add(domain);
    var recs = await spfRecords(q, domain);
    if (recs.length !== 1) {
      if (depth) problems.push(recs.length
        ? "Included domain " + domain + " has " + recs.length + " SPF records."
        : "Included domain " + domain + " has no SPF record. Receivers return permerror when they reach it.");
      return { count: 0, problems: problems };
    }
    var count = 0;
    var terms = recs[0].split(/\s+/).slice(1);
    for (var i = 0; i < terms.length; i++) {
      var t = terms[i].replace(/^[+\-~?]/, "").toLowerCase();
      if (t.startsWith("include:") || t.startsWith("redirect=")) {
        count++;
        var sub = await countSpfLookups(q, t.split(/[:=]/).slice(1).join(":"), seen, depth + 1);
        count += sub.count;
        problems = problems.concat(sub.problems);
      } else if (t === "a" || t === "mx" || t === "ptr" || /^(a[:/]|mx[:/]|ptr:|exists:)/.test(t)) {
        count++;
      }
    }
    return { count: count, problems: problems };
  }

  async function checkSpf(q, domain) {
    var recs = await spfRecords(q, domain);
    if (!recs.length) return { status: "fail", summary: "No SPF record. Receivers cannot verify who may send for this domain.",
      records: [], findings: [finding("fail", "Add TXT: v=spf1 include:" + MS_SPF_INCLUDE + " -all")] };
    if (recs.length > 1) return { status: "fail", summary: recs.length + " SPF records. SPF fails when more than one exists.",
      records: recs, findings: [finding("fail", "Merge them into a single v=spf1 record.")] };

    var rec = recs[0];
    var terms = rec.split(/\s+/).slice(1).map(function (t) { return t.toLowerCase(); });
    var findings = [], statuses = ["pass"];

    if (terms.indexOf("include:" + MS_SPF_INCLUDE) >= 0) findings.push(finding("pass", "Includes " + MS_SPF_INCLUDE + " (Microsoft 365)."));
    else { findings.push(finding("warn", "Does not include " + MS_SPF_INCLUDE + ". Microsoft 365 mail will fail SPF.")); statuses.push("warn"); }

    var allTerm = terms.find(function (t) { return t.replace(/^[+\-~?]/, "") === "all"; });
    var redirect = terms.find(function (t) { return t.startsWith("redirect="); });
    if (allTerm === "-all") findings.push(finding("pass", "Ends in -all (hard fail for unlisted senders)."));
    else if (allTerm === "~all") findings.push(finding("pass", "Ends in ~all (soft fail). Fine with DMARC enforcement; -all is stricter."));
    else if (allTerm === "?all") { findings.push(finding("warn", "Ends in ?all (neutral). Unlisted senders are not rejected.")); statuses.push("warn"); }
    else if (allTerm === "all" || allTerm === "+all") { findings.push(finding("fail", "Ends in +all. Anyone may send as this domain.")); statuses.push("fail"); }
    else if (redirect) findings.push(finding("info", "Policy delegated with " + redirect + "."));
    else { findings.push(finding("warn", "No all mechanism. Add -all or ~all at the end.")); statuses.push("warn"); }

    var m;
    try { m = await countSpfLookups(q, domain, new Set(), 0); }
    catch (e) { m = { count: -1, problems: [e.message] }; }
    if (m.count > SPF_LOOKUP_LIMIT) {
      findings.push(finding("fail", m.count + " DNS lookups. The limit is " + SPF_LOOKUP_LIMIT + ", so SPF returns permerror.")); statuses.push("fail");
    } else if (m.count >= 0) {
      var level = m.count >= 8 ? "warn" : "pass";
      findings.push(finding(level, m.count + " of " + SPF_LOOKUP_LIMIT + " DNS lookups used.")); statuses.push(level);
    }
    m.problems.forEach(function (p) { findings.push(finding("warn", p)); statuses.push("warn"); });

    var status = worst.apply(null, statuses);
    var summary = { pass: "Valid SPF record.", warn: "SPF exists but needs attention.", fail: "SPF record is broken or unsafe." }[status];
    return { status: status, summary: summary, records: [rec], findings: findings };
  }

  // ------------------------------------------------------------------ DKIM
  async function checkDkim(q, domain) {
    var findings = [], records = [], good = 0, standby = 0;
    var prefix = domain.replace(/\./g, "-");
    for (var i = 0; i < DKIM_SELECTORS.length; i++) {
      var sel = DKIM_SELECTORS[i];
      var name = sel + "._domainkey." + domain;
      var cn = await q(name, "CNAME");
      var target = cn[0] || null;
      var txt = (await q(name, "TXT")).filter(function (t) { return t.replace(/\s/g, "").indexOf("p=") >= 0; });
      if (target) {
        records.push({ host: name + " CNAME", value: target });
        if (!endsWithAny(target, MS_DKIM_SUFFIXES)) findings.push(finding("warn", sel + " points outside Microsoft 365 (" + target + ")."));
        else if (!target.toLowerCase().startsWith((sel + "-" + prefix).toLowerCase())) findings.push(finding("info", sel + " target name does not match " + sel + "-" + prefix + "."));
      }
      if (txt.length) {
        var key = txt[0];
        var mm = /(?:^|;)p=([^;]*)/.exec(key.replace(/\s/g, ""));
        if (mm && mm[1]) {
          good++;
          if (!target) records.push({ host: name + " TXT", value: key.length > 120 ? key.slice(0, 120) + "…" : key });
          findings.push(finding("pass", sel + ": public key published."));
        } else findings.push(finding("fail", sel + ": key is empty (p=), so the key is revoked."));
      } else if (target) {
        standby++;
        findings.push(finding("warn", sel + ": CNAME exists but the target has no key. Enable DKIM signing for this domain in the " + STANDBY_TAIL));
      } else findings.push(finding("fail", sel + ": no record at " + name + "."));
    }

    var status, summary;
    if (good === DKIM_SELECTORS.length) { status = "pass"; summary = "Both Microsoft 365 DKIM selectors are published."; }
    else if (good && standby) {
      status = "pass"; summary = "DKIM signing is active. The other selector is on standby for key rotation.";
      findings.forEach(function (f) {
        if (f.text.endsWith(STANDBY_TAIL)) { f.level = "info"; f.text = f.text.split(":")[0] + ": standby selector, no key yet. Normal between rotations."; }
      });
    }
    else if (good) { status = "warn"; summary = "Only one DKIM selector is published. Key rotation will break signing."; }
    else if (standby) { status = "warn"; summary = "DKIM CNAMEs exist but no key is published. Signing is not enabled yet."; }
    else { status = "fail"; summary = "No Microsoft 365 DKIM key found."; }
    if (status === "pass" && findings.some(function (f) { return f.level === "warn" || f.level === "fail"; })) status = "warn";
    return { status: status, summary: summary, records: records, findings: findings };
  }

  // ------------------------------------------------------------------ DMARC
  function parseTags(rec) {
    var tags = {};
    rec.split(";").forEach(function (part) {
      var i = part.indexOf("=");
      if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
    });
    return tags;
  }

  async function checkDmarc(q, domain) {
    var name = "_dmarc." + domain;
    var recs = (await q(name, "TXT")).filter(function (t) { return t.replace(/\s/g, "").toLowerCase().startsWith("v=dmarc1"); });
    if (!recs.length) return { status: "fail", summary: "No DMARC record. Spoofed mail from this domain is not blocked.", records: [],
      findings: [finding("fail", "Add TXT at " + name + ": v=DMARC1; p=none; rua=mailto:dmarc@" + domain + ", then move to quarantine or reject.")] };
    if (recs.length > 1) return { status: "fail", summary: recs.length + " DMARC records. Receivers ignore DMARC when there is more than one.",
      records: recs, findings: [finding("fail", "Keep exactly one record at _dmarc.")] };

    var rec = recs[0], tags = parseTags(rec), findings = [], statuses = ["pass"];
    var policy = (tags.p || "").toLowerCase();
    if (policy === "reject") findings.push(finding("pass", "p=reject: failing mail is rejected."));
    else if (policy === "quarantine") findings.push(finding("pass", "p=quarantine: failing mail goes to junk."));
    else if (policy === "none") { findings.push(finding("warn", "p=none: monitoring only, spoofed mail is still delivered.")); statuses.push("warn"); }
    else { findings.push(finding("fail", "Invalid or missing p= tag (" + (policy || "empty") + ").")); statuses.push("fail"); }

    if ((tags.sp || "").toLowerCase() === "none" && (policy === "quarantine" || policy === "reject")) {
      findings.push(finding("warn", "sp=none: subdomains are not protected.")); statuses.push("warn");
    }
    if (tags.pct && tags.pct !== "100") { findings.push(finding("warn", "pct=" + tags.pct + ": policy applies to only part of failing mail.")); statuses.push("warn"); }
    if (tags.rua) findings.push(finding("pass", "Aggregate reports go to " + tags.rua + "."));
    else findings.push(finding("info", "No rua= tag, so you receive no aggregate reports."));

    var status = worst.apply(null, statuses);
    var summary = { pass: "Enforcing DMARC policy (" + policy + ").", warn: "DMARC exists but does not fully protect the domain.", fail: "DMARC record is invalid." }[status];
    return { status: status, summary: summary, records: [rec], findings: findings };
  }

  // ------------------------------------------------------------------ Tenant
  /* Microsoft Entra tenant behind the domain, from the public OpenID configuration. */
  async function lookupTenant(domain, fetchImpl) {
    var f = fetchImpl || fetch.bind(root);
    try {
      var res = await f("https://login.microsoftonline.com/" + encodeURIComponent(domain) + "/.well-known/openid-configuration");
      if (res.status === 400) return { found: false };
      if (!res.ok) return null;
      var j = await res.json();
      var m = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i.exec(j.issuer || "");
      return m ? { found: true, id: m[1], region: j.tenant_region_scope || "" } : { found: false };
    } catch (e) { return null; }
  }

  // ------------------------------------------------------------------ Run
  async function safe(fn, q, domain) {
    try { return await fn(q, domain); }
    catch (e) { return { status: "fail", summary: "Lookup error.", records: [], findings: [finding("fail", e.message)] }; }
  }

  async function checkDomain(q, domain, fetchImpl) {
    var r = await Promise.all([safe(checkMx, q, domain), safe(checkSpf, q, domain), safe(checkDkim, q, domain),
      safe(checkDmarc, q, domain), lookupTenant(domain, fetchImpl)]);
    var checks = { mx: r[0], spf: r[1], dkim: r[2], dmarc: r[3] };
    var overall = worst(checks.spf.status, checks.dkim.status, checks.dmarc.status, checks.mx.status === "fail" ? "fail" : "pass");
    var out = { domain: domain, overall: overall, checks: checks };
    if (r[4]) out.tenant = r[4];
    return out;
  }

  function parseDomainList(text) {
    var seen = new Set(), out = [];
    text.split(/\r?\n/).forEach(function (line) {
      line.split("#")[0].split(/[,;\s]+/).forEach(function (d) {
        d = d.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^[^@]*@/, "").replace(/\/.*$/, "").replace(/\.$/, "");
        if (d && /^[a-z0-9.-]+\.[a-z0-9-]+$/.test(d) && !seen.has(d)) { seen.add(d); out.push(d); }
      });
    });
    return out;
  }

  var api = { createResolver: createResolver, checkDomain: checkDomain, parseDomainList: parseDomainList, lookupTenant: lookupTenant };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.MailDnsChecks = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
