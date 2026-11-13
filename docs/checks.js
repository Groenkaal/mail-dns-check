/* Mail DNS checks for the browser (and node, for testing).
 * Works for any mail provider. Mirrors python/check_mail_dns.py and powershell/Check-MailDns.ps1.
 * Lookups go over DNS-over-HTTPS: Google first, Cloudflare as fallback.
 */
(function (root) {
  "use strict";

  // Keep PROVIDERS and COMMON_SELECTORS in step with python/check_mail_dns.py and powershell/Check-MailDns.ps1.
  var MAIL_PROVIDERS = [
    { name: "Microsoft 365", mx: [".mail.protection.outlook.com", ".mx.microsoft"], spf: ["spf.protection.outlook.com"], dkim: ["selector1", "selector2"] },
    { name: "Google Workspace", mx: [".google.com", ".googlemail.com"], spf: ["_spf.google.com"], dkim: ["google"] },
    { name: "Zoho Mail", mx: [".zoho.com", ".zoho.eu", ".zoho.in", ".zoho.com.au", ".zohomail.com"],
      spf: ["zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zohomail.com", "one.zoho.com", "one.zoho.eu"], dkim: ["zoho", "zmail"] },
    { name: "Proton Mail", mx: [".protonmail.ch"], spf: ["_spf.protonmail.ch"], dkim: ["protonmail", "protonmail2", "protonmail3"] },
    { name: "Fastmail", mx: [".messagingengine.com"], spf: ["spf.messagingengine.com"], dkim: ["fm1", "fm2", "fm3"] },
    { name: "iCloud Mail", mx: [".mail.icloud.com"], spf: ["icloud.com"], dkim: ["sig1"] },
    { name: "Yandex Mail", mx: [".yandex.net", ".yandex.ru"], spf: ["_spf.yandex.net"], dkim: ["mail"] },
    { name: "Mimecast", mx: [".mimecast.com", ".mimecast.co.za"], spf: [], dkim: [], gateway: true },
    { name: "Proofpoint", mx: [".pphosted.com", ".ppe-hosted.com"], spf: [], dkim: [], gateway: true },
    { name: "Barracuda", mx: [".barracudanetworks.com"], spf: [], dkim: [], gateway: true },
    { name: "Cisco Secure Email", mx: [".iphmx.com"], spf: [], dkim: [], gateway: true }
  ];
  var MS_DKIM_SELECTORS = ["selector1", "selector2"];
  var MS_DKIM_SUFFIXES = [".onmicrosoft.com", ".dkim.mail.microsoft"];
  // Common selectors in check order, with who typically uses them.
  var SELECTOR_INFO = [
    ["selector1", "Microsoft 365", "Primary key. Published as a CNAME to Microsoft."],
    ["selector2", "Microsoft 365", "Rotation key. Can sit without a key between rotations."],
    ["google", "Google Workspace", "Default selector when DKIM is turned on in the Admin console."],
    ["default", "Generic", "Default on many web hosts and control panels (cPanel, Plesk)."],
    ["dkim", "Generic", "Common name on self-hosted mail servers."],
    ["mail", "Generic / Yandex", "Yandex default; also common on self-hosted servers."],
    ["email", "Generic", "Common custom name."],
    ["smtp", "Generic / Mailgun", "Older Mailgun setups and self-hosted relays."],
    ["mx", "Mailgun", "Mailgun's default selector for many domains."],
    ["key1", "Generic", "Numbered keys used by some hosts and ESPs."],
    ["key2", "Generic", "Second numbered key for rotation."],
    ["dk", "Generic", "Short name, often left over from DomainKeys."],
    ["k1", "Mailchimp", "Mailchimp's main selector."],
    ["k2", "Mailchimp / Mandrill", "Additional Mailchimp key."],
    ["k3", "Mailchimp / Mandrill", "Additional Mailchimp key."],
    ["s1", "SendGrid", "SendGrid domain authentication, first key."],
    ["s2", "SendGrid", "SendGrid domain authentication, second key."],
    ["zoho", "Zoho Mail", "Zoho Mail default."],
    ["zmail", "Zoho Mail", "Alternative Zoho selector."],
    ["protonmail", "Proton Mail", "Proton custom-domain key 1."],
    ["protonmail2", "Proton Mail", "Proton custom-domain key 2."],
    ["protonmail3", "Proton Mail", "Proton custom-domain key 3."],
    ["fm1", "Fastmail", "Fastmail key 1."],
    ["fm2", "Fastmail", "Fastmail key 2."],
    ["fm3", "Fastmail", "Fastmail key 3."],
    ["sig1", "iCloud Mail", "iCloud+ custom email domains."],
    ["hs1", "HubSpot", "HubSpot email sending domain, key 1."],
    ["hs2", "HubSpot", "HubSpot email sending domain, key 2."],
    ["mandrill", "Mandrill", "Mailchimp Transactional (Mandrill)."],
    ["mxvault", "Hosted mail", "Used by some hosted mail services."],
    ["everlytickey1", "Everlytic", "Everlytic key 1."],
    ["everlytickey2", "Everlytic", "Everlytic key 2."],
    ["zendesk1", "Zendesk", "Zendesk support mail, key 1."],
    ["zendesk2", "Zendesk", "Zendesk support mail, key 2."],
    ["kl", "Klaviyo", "Klaviyo dedicated sending domain, key 1."],
    ["kl2", "Klaviyo", "Klaviyo dedicated sending domain, key 2."]
  ];
  var COMMON_SELECTORS = SELECTOR_INFO.map(function (x) { return x[0]; });
  var SPF_LOOKUP_LIMIT = 10;
  var SEVERITY = { pass: 0, info: 0, warn: 1, fail: 2 };
  var TYPE_NUM = { TXT: 16, MX: 15, CNAME: 5 };

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
  function unique(list) { return list.filter(function (v, i) { return list.indexOf(v) === i; }); }
  function nameList(items, limit) {
    limit = limit || 6;
    return items.length <= limit ? items.join(", ") : items.slice(0, limit).join(", ") + " and " + (items.length - limit) + " more";
  }

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
  async function mxRecords(q, domain) {
    return (await q(domain, "MX")).slice().sort(function (a, b) {
      var d = parseInt(a) - parseInt(b), ha = a.split(" ")[1].toLowerCase(), hb = b.split(" ")[1].toLowerCase();
      return d || (ha < hb ? -1 : ha > hb ? 1 : 0);
    });
  }

  function detectProvider(mx) {
    for (var i = 0; i < mx.length; i++) {
      var host = (mx[i].split(" ")[1] || "").toLowerCase();
      for (var j = 0; j < MAIL_PROVIDERS.length; j++) if (endsWithAny(host, MAIL_PROVIDERS[j].mx)) return MAIL_PROVIDERS[j];
    }
    return null;
  }

  function checkMx(domain, mx, provider) {
    var findings = [];
    if (!mx.length) return { status: "fail", summary: "No MX records. The domain cannot receive mail.", records: [], findings: findings };
    var hosts = mx.map(function (r) { return (r.split(" ")[1] || "").toLowerCase(); });
    if (hosts.length === 1 && hosts[0] === "")
      return { status: "info", summary: "Null MX (RFC 7505). The domain states it accepts no mail.", records: ["0 ."], findings: findings };
    var summary;
    if (provider && provider.gateway) {
      summary = "Mail goes through " + provider.name + " (security gateway).";
      findings.push(finding("info", "The mailbox provider behind the gateway can't be seen from DNS."));
    } else if (provider) summary = "Mail is handled by " + provider.name + ".";
    else summary = "Mail is handled by " + hosts[0] + ".";
    var mixed = hosts.indexOf("") >= 0;
    if (mixed) findings.push(finding("warn", "A null MX (.) is mixed with real MX hosts. Remove one or the other."));
    return { status: mixed ? "warn" : "pass", summary: summary, records: mx, findings: findings };
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

  async function checkSpf(q, domain, provider) {
    var recs = await spfRecords(q, domain);
    if (!recs.length) {
      var example = provider && provider.spf.length ? "v=spf1 include:" + provider.spf[0] + " -all" : "v=spf1 mx -all";
      return { status: "fail", summary: "No SPF record. Receivers cannot verify who may send for this domain.",
        records: [], findings: [finding("fail", "Add a TXT record such as: " + example)] };
    }
    if (recs.length > 1) return { status: "fail", summary: recs.length + " SPF records. SPF fails when more than one exists.",
      records: recs, findings: [finding("fail", "Merge them into a single v=spf1 record.")] };

    var rec = recs[0];
    var terms = rec.split(/\s+/).slice(1).map(function (t) { return t.toLowerCase(); });
    var findings = [], statuses = ["pass"];

    if (provider && provider.spf.length) {
      var hit = provider.spf.find(function (inc) { return terms.indexOf("include:" + inc) >= 0; });
      if (hit) findings.push(finding("pass", "Includes " + hit + " (" + provider.name + ")."));
      else {
        findings.push(finding("warn", "MX points to " + provider.name + ", but SPF does not include " + provider.spf[0] +
          ". Mail sent from " + provider.name + " will fail SPF."));
        statuses.push("warn");
      }
    }

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
  async function dkimKey(q, domain, sel) {
    var txt = (await q(sel + "._domainkey." + domain, "TXT")).filter(function (t) { return t.replace(/ /g, "").indexOf("p=") >= 0; });
    return txt.length ? txt[0] : null;
  }

  async function checkDkim(q, domain, provider, extra, acceptsMail) {
    var selectors = unique(COMMON_SELECTORS.concat(provider ? provider.dkim : [], extra || []));
    var keys = await Promise.all(selectors.map(function (s) { return dkimKey(q, domain, s); }));
    var msTargets = await Promise.all(MS_DKIM_SELECTORS.map(function (s) {
      return q(s + "._domainkey." + domain, "CNAME").then(function (r) { return r[0] || null; });
    }));
    var msCnames = {};
    MS_DKIM_SELECTORS.forEach(function (s, i) { msCnames[s] = msTargets[i]; });

    var active = [], revoked = [];
    selectors.forEach(function (sel, i) {
      var key = keys[i];
      if (key == null) return;
      var m = /(?:^|;)p=([^;]*)/.exec(key.replace(/ /g, ""));
      (m && m[1] ? active : revoked).push([sel, key]);
    });

    var findings = [], records = [];
    var activeNames = active.map(function (a) { return a[0]; });
    var isMs = !!(provider && provider.name === "Microsoft 365");

    active.forEach(function (a) {
      var sel = a[0], key = a[1], target = msCnames[sel];
      if (target) records.push({ host: sel + "._domainkey." + domain + " CNAME", value: target });
      else records.push({ host: sel + "._domainkey." + domain + " TXT", value: key.length > 120 ? key.slice(0, 120) + "…" : key });
      findings.push(finding("pass", sel + ": public key published."));
    });

    // Microsoft 365 publishes DKIM as CNAMEs at selector1/selector2. One can sit without a key between rotations.
    var standby = MS_DKIM_SELECTORS.filter(function (s) { return msCnames[s] && activeNames.indexOf(s) < 0; });
    var msActive = MS_DKIM_SELECTORS.filter(function (s) { return activeNames.indexOf(s) >= 0; });
    var expected = domain.replace(/\./g, "-");
    MS_DKIM_SELECTORS.forEach(function (sel) {
      var target = msCnames[sel];
      if (!target || !(isMs || endsWithAny(target, MS_DKIM_SUFFIXES))) return;
      if (standby.indexOf(sel) >= 0) records.push({ host: sel + "._domainkey." + domain + " CNAME", value: target });
      if (isMs && !endsWithAny(target, MS_DKIM_SUFFIXES)) findings.push(finding("warn", sel + " points outside Microsoft 365 (" + target + ")."));
      else if (endsWithAny(target, MS_DKIM_SUFFIXES) && !target.toLowerCase().startsWith(sel + "-" + expected))
        findings.push(finding("info", sel + " target name does not match " + sel + "-" + expected + "."));
    });
    standby.forEach(function (sel) {
      if (msActive.length) findings.push(finding("info", sel + ": standby selector, no key yet. Normal between rotations."));
      else findings.push(finding("warn", sel + ": CNAME exists but the target has no key. Enable DKIM signing for this domain in the Microsoft Defender portal."));
    });
    if (isMs && !msActive.length && !standby.length)
      findings.push(finding("warn", "Microsoft 365 DKIM is not set up (no selector1/selector2). Microsoft 365 then signs with your onmicrosoft.com domain, which does not align for DMARC."));
    if (provider && provider.name === "Google Workspace" && activeNames.indexOf("google") < 0)
      findings.push(finding("info", "Google Workspace's default selector (google) has no key. A custom selector may be in use."));
    if (revoked.length) findings.push(finding("info", "Empty (revoked) key at: " + nameList(revoked.map(function (r) { return r[0]; })) + "."));

    var status, summary;
    if (active.length) {
      status = "pass";
      summary = "DKIM key found at " + active.length + " selector" + (active.length > 1 ? "s" : "") + ": " + nameList(activeNames) + ".";
      if (findings.some(function (f) { return f.level === "warn" || f.level === "fail"; })) status = "warn";
    } else if (standby.length) { status = "warn"; summary = "DKIM CNAMEs exist but no key is published. Signing is not enabled yet."; }
    else if (revoked.length && !acceptsMail) { status = "info"; summary = "Only empty (revoked) keys found. Typical for a domain that sends no mail."; }
    else if (revoked.length) { status = "warn"; summary = "Only empty (revoked) keys found. Active keys may be under a selector not checked here."; }
    else {
      status = "warn"; summary = "No DKIM key found on the " + selectors.length + " common selectors checked.";
      findings.push(finding("warn", "DKIM may still be set up under a custom selector. Add it to the selector list to check it."));
    }
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
  function errorCheck(e) { return { status: "fail", summary: "Lookup error.", records: [], findings: [finding("fail", e.message)] }; }

  async function checkDomain(q, domain, opts) {
    opts = opts || {};
    var provider = null, mxCheck, mx = [];
    try {
      mx = await mxRecords(q, domain);
      provider = detectProvider(mx);
      mxCheck = checkMx(domain, mx, provider);
    } catch (e) { mxCheck = errorCheck(e); }
    var r = await Promise.all([
      checkSpf(q, domain, provider).catch(errorCheck),
      checkDkim(q, domain, provider, opts.selectors, mx.some(function (r) { return !!r.split(" ")[1]; })).catch(errorCheck),
      checkDmarc(q, domain).catch(errorCheck),
      lookupTenant(domain, opts.fetch)
    ]);
    var checks = { mx: mxCheck, spf: r[0], dkim: r[1], dmarc: r[2] };
    var overall = worst(checks.spf.status, checks.dkim.status, checks.dmarc.status, checks.mx.status === "fail" ? "fail" : "pass");
    var out = { domain: domain, overall: overall, provider: provider ? provider.name : null, checks: checks };
    if (r[3]) out.tenant = r[3];
    return out;
  }

  function parseSelectorList(text) {
    return unique((text || "").toLowerCase().split(/[,;\s]+/).map(function (s) { return s.replace(/\._domainkey.*$/, "").trim(); })
      .filter(function (s) { return /^[a-z0-9._-]+$/.test(s); }));
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

  var api = { createResolver: createResolver, checkDomain: checkDomain, parseDomainList: parseDomainList,
    parseSelectorList: parseSelectorList, lookupTenant: lookupTenant, commonSelectorCount: COMMON_SELECTORS.length,
    selectorInfo: SELECTOR_INFO.map(function (x) { return { name: x[0], usedBy: x[1], note: x[2] }; }) };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.MailDnsChecks = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
