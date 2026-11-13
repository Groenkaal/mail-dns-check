<#
.SYNOPSIS
    Check MX, SPF, DKIM and DMARC for a list of domains and write an HTML report.

.DESCRIPTION
    Works for any mail provider. Microsoft 365, Google Workspace and other known
    providers get extra checks when the MX records point at them.

    Reads ..\domains.txt by default, asks where to write the HTML report, and fills
    ..\report-template.html with the results.

    It can also run straight from GitHub without cloning. In that case it downloads
    the report template from the repo, and you pass -Domains or -Domain.

    On Windows it uses Resolve-DnsName. Where that cmdlet is missing (PowerShell 7 on
    Linux/macOS) it falls back to DNS-over-HTTPS via Google (dns.google).

.EXAMPLE
    .\Check-MailDns.ps1
.EXAMPLE
    .\Check-MailDns.ps1 -Domains list.txt -Output report.html -NameServer 1.1.1.1
.EXAMPLE
    .\Check-MailDns.ps1 -Domain contoso.com,fabrikam.com -Selector mycorp2024 -Output report.html
.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Groenkaal/mail-dns-check/main/powershell/Check-MailDns.ps1))) -Domains list.txt -Output report.html
#>
[CmdletBinding()]
param(
    [Alias('Domains')]
    [string]$DomainsFile,
    [string[]]$Domain,
    [Alias('Selectors')]
    [string[]]$Selector,
    [Alias('Output')]
    [string]$OutputPath,
    [string]$NameServer,
    [string]$TemplateUrl = 'https://raw.githubusercontent.com/Groenkaal/mail-dns-check/main/report-template.html'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 can default to TLS 1.0, which GitHub and Google refuse.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# $PSScriptRoot is empty when the script runs from memory (irm | scriptblock).
$Root     = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { $null }
$Template = if ($Root) { Join-Path $Root 'report-template.html' } else { $null }

# Keep these in step with python/check_mail_dns.py and docs/checks.js.
# Providers are matched on MX host suffix. 'spf' lists includes that authorise the provider;
# an empty list means the provider is a gateway or its include can't be predicted.
$Providers = @(
    @{ name = 'Microsoft 365';      gateway = $false; mx = @('.mail.protection.outlook.com', '.mx.microsoft'); spf = @('spf.protection.outlook.com'); dkim = @('selector1', 'selector2') }
    @{ name = 'Google Workspace';   gateway = $false; mx = @('.google.com', '.googlemail.com'); spf = @('_spf.google.com'); dkim = @('google') }
    @{ name = 'Zoho Mail';          gateway = $false; mx = @('.zoho.com', '.zoho.eu', '.zoho.in', '.zoho.com.au', '.zohomail.com')
       spf = @('zoho.com', 'zoho.eu', 'zoho.in', 'zoho.com.au', 'zohomail.com', 'one.zoho.com', 'one.zoho.eu'); dkim = @('zoho', 'zmail') }
    @{ name = 'Proton Mail';        gateway = $false; mx = @('.protonmail.ch'); spf = @('_spf.protonmail.ch'); dkim = @('protonmail', 'protonmail2', 'protonmail3') }
    @{ name = 'Fastmail';           gateway = $false; mx = @('.messagingengine.com'); spf = @('spf.messagingengine.com'); dkim = @('fm1', 'fm2', 'fm3') }
    @{ name = 'iCloud Mail';        gateway = $false; mx = @('.mail.icloud.com'); spf = @('icloud.com'); dkim = @('sig1') }
    @{ name = 'Yandex Mail';        gateway = $false; mx = @('.yandex.net', '.yandex.ru'); spf = @('_spf.yandex.net'); dkim = @('mail') }
    @{ name = 'Mimecast';           gateway = $true;  mx = @('.mimecast.com', '.mimecast.co.za'); spf = @(); dkim = @() }
    @{ name = 'Proofpoint';         gateway = $true;  mx = @('.pphosted.com', '.ppe-hosted.com'); spf = @(); dkim = @() }
    @{ name = 'Barracuda';          gateway = $true;  mx = @('.barracudanetworks.com'); spf = @(); dkim = @() }
    @{ name = 'Cisco Secure Email'; gateway = $true;  mx = @('.iphmx.com'); spf = @(); dkim = @() }
)
$MsDkimSelectors = @('selector1', 'selector2')
$MsDkimSuffixes  = @('.onmicrosoft.com', '.dkim.mail.microsoft')
$CommonSelectors = @(
    'selector1', 'selector2', 'google',
    'default', 'dkim', 'mail', 'email', 'smtp', 'mx', 'key1', 'key2', 'dk',
    'k1', 'k2', 'k3', 's1', 's2', 'zoho', 'zmail',
    'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3', 'sig1',
    'hs1', 'hs2', 'mandrill', 'mxvault', 'everlytickey1', 'everlytickey2',
    'zendesk1', 'zendesk2', 'kl', 'kl2'
)
$SpfLookupLimit = 10
$Severity       = @{ pass = 0; info = 0; warn = 1; fail = 2 }
$UseNative      = [bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)

# ----------------------------------------------------------------------------- DNS

function Invoke-DohQuery([string]$Name, [string]$Type) {
    $uri = "https://dns.google/resolve?name=$([uri]::EscapeDataString($Name))&type=$Type"
    $resp = Invoke-RestMethod -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 10
    $typeNum = @{ TXT = 16; MX = 15; CNAME = 5 }[$Type]
    if (-not ($resp.PSObject.Properties.Name -contains 'Answer')) { return @() }
    return @($resp.Answer | Where-Object { $_.type -eq $typeNum } | ForEach-Object { $_.data })
}

function Invoke-NativeQuery([string]$Name, [string]$Type, [string]$Server) {
    # Returns @{ Missing = <name does not exist>; Records = <matching records> }.
    $params = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'Stop' }
    if ($Server) { $params.Server = $Server }
    try { $answers = @(Resolve-DnsName @params) }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'timeout') { throw "DNS timeout looking up $Type $Name" }
        return @{ Missing = ($msg -match 'does not exist'); Records = @() }
    }
    return @{ Missing = $false; Records = @($answers | Where-Object { [string]$_.Type -eq $Type }) }
}

function Get-Dns([string]$Name, [string]$Type) {
    # Returns record strings; empty when the name or type does not exist.
    $out = New-Object System.Collections.Generic.List[string]
    if ($UseNative) {
        $res = Invoke-NativeQuery $Name $Type $NameServer
        # Some local resolvers silently drop large TXT answers. Ask a public resolver before
        # reporting a TXT record as missing (skipped when -NameServer is given).
        if ($Type -eq 'TXT' -and -not $NameServer -and -not $res.Missing -and -not $res.Records.Count) {
            try { $res = Invoke-NativeQuery $Name $Type '1.1.1.1' } catch { }
        }
        foreach ($r in $res.Records) {
            switch ($Type) {
                'TXT'   { $out.Add(($r.Strings -join '')) }
                'MX'    { $out.Add(('{0} {1}' -f $r.Preference, ([string]$r.NameExchange).TrimEnd('.'))) }
                'CNAME' { $out.Add(([string]$r.NameHost).TrimEnd('.')) }
            }
        }
    }
    else {
        foreach ($d in (Invoke-DohQuery $Name $Type)) {
            switch ($Type) {
                'TXT' {
                    if ($d.StartsWith('"')) {
                        $parts = @([regex]::Matches($d, '"((?:[^"\\]|\\.)*)"') | ForEach-Object { $_.Groups[1].Value -replace '\\(.)', '$1' })
                        $out.Add(($parts -join ''))
                    }
                    else { $out.Add($d) }
                }
                'MX' {
                    $p = $d -split '\s+', 2
                    $out.Add(('{0} {1}' -f $p[0], $p[1].TrimEnd('.')))
                }
                'CNAME' { $out.Add($d.TrimEnd('.')) }
            }
        }
    }
    return $out.ToArray()
}

function Get-Cname([string]$Name) {
    # CNAME target of the name itself, or $null.
    $r = @(Get-Dns $Name 'CNAME')
    if ($r.Count) { return $r[0] } else { return $null }
}

function Get-Worst([string[]]$Statuses) {
    $w = 'pass'
    foreach ($s in $Statuses) { if ($Severity[$s] -gt $Severity[$w]) { $w = $s } }
    return $w
}

function New-Finding([string]$Level, [string]$Text) { [ordered]@{ level = $Level; text = $Text } }

function New-Check([string]$Status, [string]$Summary, $Records, $Findings) {
    [ordered]@{ status = $Status; summary = $Summary; records = @($Records); findings = @($Findings) }
}

function Test-EndsWithAny([string]$Value, [string[]]$Suffixes) {
    foreach ($s in $Suffixes) { if ($Value.ToLower().EndsWith($s)) { return $true } }
    return $false
}

function Format-NameList([string[]]$Items, [int]$Limit = 6) {
    if ($Items.Count -le $Limit) { return ($Items -join ', ') }
    return (($Items[0..($Limit - 1)] -join ', ') + " and $($Items.Count - $Limit) more")
}

function Get-UniqueList([string[]]$Items) {
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($i in $Items) { if ($i -and -not $list.Contains($i)) { $list.Add($i) } }
    return , $list.ToArray()
}

# ----------------------------------------------------------------------------- MX

function Get-MxRecords([string]$Domain) {
    @(Get-Dns $Domain 'MX' | Sort-Object { [int]($_ -split ' ')[0] }, { (($_ -split ' ', 2)[1]).ToLower() })
}

function Find-Provider([string[]]$Mx) {
    foreach ($r in $Mx) {
        $mxHost = (($r -split ' ', 2)[1]).ToLower()
        foreach ($p in $Providers) { if (Test-EndsWithAny $mxHost $p.mx) { return $p } }
    }
    return $null
}

function Test-Mx([string]$Domain, [string[]]$Mx, $Provider) {
    $findings = @()
    if (-not $Mx.Count) { return New-Check 'fail' 'No MX records. The domain cannot receive mail.' @() @() }
    $hosts = @($Mx | ForEach-Object { (($_ -split ' ', 2)[1]).ToLower() })
    if ($hosts.Count -eq 1 -and $hosts[0] -eq '') {
        return New-Check 'info' 'Null MX (RFC 7505). The domain states it accepts no mail.' @('0 .') @()
    }
    if ($Provider -and $Provider.gateway) {
        $summary = "Mail goes through $($Provider.name) (security gateway)."
        $findings += New-Finding 'info' "The mailbox provider behind the gateway can't be seen from DNS."
    }
    elseif ($Provider) { $summary = "Mail is handled by $($Provider.name)." }
    else { $summary = "Mail is handled by $($hosts[0])." }
    $mixed = $hosts -contains ''
    if ($mixed) { $findings += New-Finding 'warn' 'A null MX (.) is mixed with real MX hosts. Remove one or the other.' }
    $status = if ($mixed) { 'warn' } else { 'pass' }
    return New-Check $status $summary $Mx $findings
}

# ----------------------------------------------------------------------------- SPF

function Get-SpfRecords([string]$Domain) {
    @(Get-Dns $Domain 'TXT' | Where-Object { $_.ToLower().StartsWith('v=spf1') })
}

function Measure-SpfLookups([string]$Domain, [hashtable]$Seen, [int]$Depth = 0) {
    # Counts DNS-querying mechanisms recursively (RFC 7208 limit is 10).
    $problems = @()
    if ($Seen.ContainsKey($Domain) -or $Depth -gt 10) {
        return @{ Count = 0; Problems = @("SPF include loop at $Domain") }
    }
    $Seen[$Domain] = $true
    $recs = @(Get-SpfRecords $Domain)
    if ($recs.Count -ne 1) {
        if ($Depth) {
            if (-not $recs.Count) { $problems += "Included domain $Domain has no SPF record. Receivers return permerror when they reach it." }
            else { $problems += "Included domain $Domain has $($recs.Count) SPF records." }
        }
        return @{ Count = 0; Problems = $problems }
    }
    $count = 0
    foreach ($term in ($recs[0] -split '\s+' | Select-Object -Skip 1)) {
        $t = $term.TrimStart('+', '-', '~', '?').ToLower()
        if ($t.StartsWith('include:') -or $t.StartsWith('redirect=')) {
            $target = ($t -split '[:=]', 2)[1]
            $count++
            $sub = Measure-SpfLookups $target $Seen ($Depth + 1)
            $count += $sub.Count
            $problems += $sub.Problems
        }
        elseif ($t -in @('a', 'mx', 'ptr') -or $t -match '^(a[:/]|mx[:/]|ptr:|exists:)') {
            $count++
        }
    }
    return @{ Count = $count; Problems = $problems }
}

function Test-Spf([string]$Domain, $Provider) {
    $recs = @(Get-SpfRecords $Domain)
    if (-not $recs.Count) {
        $example = if ($Provider -and $Provider.spf.Count) { "v=spf1 include:$($Provider.spf[0]) -all" } else { 'v=spf1 mx -all' }
        return New-Check 'fail' 'No SPF record. Receivers cannot verify who may send for this domain.' @() `
            @(New-Finding 'fail' "Add a TXT record such as: $example")
    }
    if ($recs.Count -gt 1) {
        return New-Check 'fail' "$($recs.Count) SPF records. SPF fails when more than one exists." $recs `
            @(New-Finding 'fail' 'Merge them into a single v=spf1 record.')
    }

    $rec = $recs[0]
    $terms = @($rec -split '\s+' | Select-Object -Skip 1 | ForEach-Object { $_.ToLower() })
    $findings = @(); $statuses = @('pass')

    if ($Provider -and $Provider.spf.Count) {
        $hit = $Provider.spf | Where-Object { $terms -contains "include:$_" } | Select-Object -First 1
        if ($hit) { $findings += New-Finding 'pass' "Includes $hit ($($Provider.name))." }
        else {
            $findings += New-Finding 'warn' ("MX points to $($Provider.name), but SPF does not include $($Provider.spf[0]). " +
                "Mail sent from $($Provider.name) will fail SPF.")
            $statuses += 'warn'
        }
    }

    $allTerm  = $terms | Where-Object { $_.TrimStart('+', '-', '~', '?') -eq 'all' } | Select-Object -First 1
    $redirect = $terms | Where-Object { $_.StartsWith('redirect=') } | Select-Object -First 1
    if ($allTerm -eq '-all') { $findings += New-Finding 'pass' 'Ends in -all (hard fail for unlisted senders).' }
    elseif ($allTerm -eq '~all') { $findings += New-Finding 'pass' 'Ends in ~all (soft fail). Fine with DMARC enforcement; -all is stricter.' }
    elseif ($allTerm -eq '?all') { $findings += New-Finding 'warn' 'Ends in ?all (neutral). Unlisted senders are not rejected.'; $statuses += 'warn' }
    elseif ($allTerm -in @('all', '+all')) { $findings += New-Finding 'fail' 'Ends in +all. Anyone may send as this domain.'; $statuses += 'fail' }
    elseif ($redirect) { $findings += New-Finding 'info' "Policy delegated with $redirect." }
    else { $findings += New-Finding 'warn' 'No all mechanism. Add -all or ~all at the end.'; $statuses += 'warn' }

    try { $m = Measure-SpfLookups $Domain @{} }
    catch { $m = @{ Count = -1; Problems = @("$_") } }
    if ($m.Count -gt $SpfLookupLimit) {
        $findings += New-Finding 'fail' "$($m.Count) DNS lookups. The limit is $SpfLookupLimit, so SPF returns permerror."
        $statuses += 'fail'
    }
    elseif ($m.Count -ge 0) {
        $level = if ($m.Count -ge 8) { 'warn' } else { 'pass' }
        $findings += New-Finding $level "$($m.Count) of $SpfLookupLimit DNS lookups used."
        $statuses += $level
    }
    foreach ($p in $m.Problems) { $findings += New-Finding 'warn' $p; $statuses += 'warn' }

    $status = Get-Worst $statuses
    $summary = @{ pass = 'Valid SPF record.'; warn = 'SPF exists but needs attention.'; fail = 'SPF record is broken or unsafe.' }[$status]
    return New-Check $status $summary @($rec) $findings
}

# ----------------------------------------------------------------------------- DKIM

function Get-DkimKey([string]$Domain, [string]$Sel) {
    # The DKIM record at a selector (any record with a p= tag), or $null.
    $txt = @(Get-Dns "$Sel._domainkey.$Domain" 'TXT' | Where-Object { ($_ -replace ' ', '') -match 'p=' })
    if ($txt.Count) { return $txt[0] } else { return $null }
}

function Test-Dkim([string]$Domain, $Provider, [string[]]$Extra, [bool]$AcceptsMail = $true) {
    $providerSelectors = if ($Provider) { $Provider.dkim } else { @() }
    $selectors = Get-UniqueList (@($CommonSelectors) + @($providerSelectors) + @($Extra))
    $msCnames = @{}
    foreach ($s in $MsDkimSelectors) { $msCnames[$s] = Get-Cname "$s._domainkey.$Domain" }

    $active = @(); $revoked = @()
    foreach ($sel in $selectors) {
        $key = Get-DkimKey $Domain $sel
        if ($null -eq $key) { continue }
        if (($key -replace ' ', '') -match '(?:^|;)p=([^;]*)' -and $Matches[1]) { $active += , @($sel, $key) }
        else { $revoked += $sel }
    }

    $findings = @(); $records = @()
    $activeNames = @($active | ForEach-Object { $_[0] })
    $isMs = [bool]($Provider -and $Provider.name -eq 'Microsoft 365')

    foreach ($a in $active) {
        $sel = $a[0]; $key = $a[1]; $target = $msCnames[$sel]
        if ($target) { $records += [ordered]@{ host = "$sel._domainkey.$Domain CNAME"; value = $target } }
        else {
            $short = if ($key.Length -gt 120) { $key.Substring(0, 120) + [char]0x2026 } else { $key }
            $records += [ordered]@{ host = "$sel._domainkey.$Domain TXT"; value = $short }
        }
        $findings += New-Finding 'pass' "${sel}: public key published."
    }

    # Microsoft 365 publishes DKIM as CNAMEs at selector1/selector2. One can sit without a key between rotations.
    $standby  = @($MsDkimSelectors | Where-Object { $msCnames[$_] -and $activeNames -notcontains $_ })
    $msActive = @($MsDkimSelectors | Where-Object { $activeNames -contains $_ })
    $expected = $Domain.Replace('.', '-')
    foreach ($sel in $MsDkimSelectors) {
        $target = $msCnames[$sel]
        if (-not $target) { continue }
        $isMsTarget = Test-EndsWithAny $target $MsDkimSuffixes
        if (-not ($isMs -or $isMsTarget)) { continue }
        if ($standby -contains $sel) { $records += [ordered]@{ host = "$sel._domainkey.$Domain CNAME"; value = $target } }
        if ($isMs -and -not $isMsTarget) { $findings += New-Finding 'warn' "$sel points outside Microsoft 365 ($target)." }
        elseif ($isMsTarget -and -not $target.ToLower().StartsWith("$sel-$expected")) {
            $findings += New-Finding 'info' "$sel target name does not match $sel-$expected."
        }
    }
    foreach ($sel in $standby) {
        if ($msActive.Count) { $findings += New-Finding 'info' "${sel}: standby selector, no key yet. Normal between rotations." }
        else {
            $findings += New-Finding 'warn' ("${sel}: CNAME exists but the target has no key. " +
                'Enable DKIM signing for this domain in the Microsoft Defender portal.')
        }
    }
    if ($isMs -and -not $msActive.Count -and -not $standby.Count) {
        $findings += New-Finding 'warn' ('Microsoft 365 DKIM is not set up (no selector1/selector2). Microsoft 365 then ' +
            'signs with your onmicrosoft.com domain, which does not align for DMARC.')
    }
    if ($Provider -and $Provider.name -eq 'Google Workspace' -and $activeNames -notcontains 'google') {
        $findings += New-Finding 'info' "Google Workspace's default selector (google) has no key. A custom selector may be in use."
    }
    if ($revoked.Count) { $findings += New-Finding 'info' "Empty (revoked) key at: $(Format-NameList $revoked)." }

    if ($active.Count) {
        $status = 'pass'
        $plural = if ($active.Count -gt 1) { 's' } else { '' }
        $summary = "DKIM key found at $($active.Count) selector${plural}: $(Format-NameList $activeNames)."
        if (@($findings | Where-Object { $_.level -in @('warn', 'fail') }).Count) { $status = 'warn' }
    }
    elseif ($standby.Count) { $status = 'warn'; $summary = 'DKIM CNAMEs exist but no key is published. Signing is not enabled yet.' }
    elseif ($revoked.Count -and -not $AcceptsMail) { $status = 'info'; $summary = 'Only empty (revoked) keys found. Typical for a domain that sends no mail.' }
    elseif ($revoked.Count) { $status = 'warn'; $summary = 'Only empty (revoked) keys found. Active keys may be under a selector not checked here.' }
    else {
        $status = 'warn'
        $summary = "No DKIM key found on the $($selectors.Count) common selectors checked."
        $findings += New-Finding 'warn' 'DKIM may still be set up under a custom selector. Add it to the selector list to check it.'
    }
    return New-Check $status $summary $records $findings
}

# ----------------------------------------------------------------------------- DMARC

function ConvertFrom-TagList([string]$Record) {
    $tags = @{}
    foreach ($part in $Record -split ';') {
        if ($part -match '=') {
            $kv = $part -split '=', 2
            $tags[$kv[0].Trim().ToLower()] = $kv[1].Trim()
        }
    }
    return $tags
}

function Test-Dmarc([string]$Domain) {
    $name = "_dmarc.$Domain"
    $recs = @(Get-Dns $name 'TXT' | Where-Object { ($_ -replace '\s', '').ToLower().StartsWith('v=dmarc1') })
    if (-not $recs.Count) {
        return New-Check 'fail' 'No DMARC record. Spoofed mail from this domain is not blocked.' @() `
            @(New-Finding 'fail' "Add TXT at ${name}: v=DMARC1; p=none; rua=mailto:dmarc@$Domain, then move to quarantine or reject.")
    }
    if ($recs.Count -gt 1) {
        return New-Check 'fail' "$($recs.Count) DMARC records. Receivers ignore DMARC when there is more than one." $recs `
            @(New-Finding 'fail' 'Keep exactly one record at _dmarc.')
    }

    $rec = $recs[0]
    $tags = ConvertFrom-TagList $rec
    $findings = @(); $statuses = @('pass')
    $policy = if ($tags.ContainsKey('p')) { $tags['p'].ToLower() } else { '' }

    switch ($policy) {
        'reject'     { $findings += New-Finding 'pass' 'p=reject: failing mail is rejected.' }
        'quarantine' { $findings += New-Finding 'pass' 'p=quarantine: failing mail goes to junk.' }
        'none'       { $findings += New-Finding 'warn' 'p=none: monitoring only, spoofed mail is still delivered.'; $statuses += 'warn' }
        default {
            $shown = if ($policy) { $policy } else { 'empty' }
            $findings += New-Finding 'fail' "Invalid or missing p= tag ($shown)."; $statuses += 'fail'
        }
    }
    if ($tags.ContainsKey('sp') -and $tags['sp'].ToLower() -eq 'none' -and $policy -in @('quarantine', 'reject')) {
        $findings += New-Finding 'warn' 'sp=none: subdomains are not protected.'; $statuses += 'warn'
    }
    if ($tags.ContainsKey('pct') -and $tags['pct'] -ne '100') {
        $findings += New-Finding 'warn' "pct=$($tags['pct']): policy applies to only part of failing mail."; $statuses += 'warn'
    }
    if ($tags.ContainsKey('rua') -and $tags['rua']) {
        $findings += New-Finding 'pass' "Aggregate reports go to $($tags['rua'])."
    }
    else {
        $findings += New-Finding 'info' 'No rua= tag, so you receive no aggregate reports.'
    }

    $status = Get-Worst $statuses
    $summary = @{ pass = "Enforcing DMARC policy ($policy)."; warn = 'DMARC exists but does not fully protect the domain.'; fail = 'DMARC record is invalid.' }[$status]
    return New-Check $status $summary @($rec) $findings
}

# ----------------------------------------------------------------------------- Run

function New-ErrorCheck($Err) { New-Check 'fail' 'Lookup error.' @() @(New-Finding 'fail' "$Err") }

function Get-Tenant([string]$Domain) {
    # Microsoft Entra tenant behind the domain, from the public OpenID configuration.
    try {
        $cfg = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration" -TimeoutSec 8
    }
    catch {
        $code = $null
        if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -eq 400) { return [ordered]@{ found = $false } } else { return $null }
    }
    if ($cfg.issuer -match '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}') {
        $region = if ($cfg.PSObject.Properties.Name -contains 'tenant_region_scope') { [string]$cfg.tenant_region_scope } else { '' }
        return [ordered]@{ found = $true; id = $Matches[0]; region = $region }
    }
    return [ordered]@{ found = $false }
}

function Test-Domain([string]$Domain, [string[]]$ExtraSelectors) {
    $provider = $null; $mx = @()
    try {
        $mx = @(Get-MxRecords $Domain)
        $provider = Find-Provider $mx
        $mxCheck = Test-Mx $Domain $mx $provider
    }
    catch { $mxCheck = New-ErrorCheck $_ }
    $checks = [ordered]@{ mx = $mxCheck }
    try { $checks.spf = Test-Spf $Domain $provider } catch { $checks.spf = New-ErrorCheck $_ }
    $acceptsMail = [bool](@($mx | Where-Object { ($_ -split ' ', 2)[1] }).Count)
    try { $checks.dkim = Test-Dkim $Domain $provider $ExtraSelectors $acceptsMail } catch { $checks.dkim = New-ErrorCheck $_ }
    try { $checks.dmarc = Test-Dmarc $Domain } catch { $checks.dmarc = New-ErrorCheck $_ }

    $mxPart = if ($checks.mx.status -eq 'fail') { 'fail' } else { 'pass' }
    $overall = Get-Worst @($checks.spf.status, $checks.dkim.status, $checks.dmarc.status, $mxPart)
    $providerName = if ($provider) { $provider.name } else { $null }
    $result = [ordered]@{ domain = $Domain; overall = $overall; provider = $providerName; checks = $checks }
    $tenant = Get-Tenant $Domain
    if ($tenant) { $result.tenant = $tenant }
    return $result
}

function Split-ArgList([string[]]$Values) {
    Get-UniqueList @($Values | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower().TrimEnd('.') })
}

# Domains: -Domain wins, then -Domains <file>, then domains.txt in the repo root.
if ($Domain) {
    $lines = @($Domain | ForEach-Object { $_ -split ',' })
    $source = 'command line'
}
else {
    if (-not $DomainsFile) {
        if (-not $Root) { throw 'Running from GitHub: pass -Domains <file> or -Domain contoso.com,fabrikam.com.' }
        $DomainsFile = Join-Path $Root 'domains.txt'
    }
    if (-not (Test-Path -LiteralPath $DomainsFile)) { throw "Domain list not found: $DomainsFile" }
    $lines = @(Get-Content -LiteralPath $DomainsFile -Encoding UTF8)
    $source = Split-Path $DomainsFile -Leaf
}
$domains = @($lines |
    ForEach-Object { ($_ -split '#', 2)[0].Trim().ToLower().TrimEnd('.') } |
    Where-Object { $_ } | Select-Object -Unique)
if (-not $domains.Count) { throw "No domains found in $source" }
$extraSelectors = if ($Selector) { @(Split-ArgList $Selector) } else { @() }

# Template: local copy when the repo is on disk, otherwise download it.
if ($Template -and (Test-Path -LiteralPath $Template)) {
    $templateHtml = [IO.File]::ReadAllText($Template)
}
else {
    try { $templateHtml = (Invoke-WebRequest -Uri $TemplateUrl -UseBasicParsing -TimeoutSec 20).Content }
    catch { throw "Could not download the report template from ${TemplateUrl}: $($_.Exception.Message)" }
    if ($templateHtml -isnot [string]) { $templateHtml = [Text.Encoding]::UTF8.GetString($templateHtml) }
    if ($templateHtml -notmatch '__REPORT_DATA__') { throw "The file at $TemplateUrl is not a report template." }
}

if (-not $OutputPath) {
    $defaultName = 'mail-dns-report-{0:yyyyMMdd-HHmm}.html' -f (Get-Date)
    $default = Join-Path (Get-Location).Path $defaultName
    $answer = (Read-Host "Where should the HTML report be saved? [$default]").Trim().Trim('"')
    $OutputPath = if ($answer) { $answer } else { $default }
    if (Test-Path -LiteralPath $OutputPath -PathType Container) { $OutputPath = Join-Path $OutputPath $defaultName }
}
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$outDir = Split-Path $OutputPath -Parent
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$results = @()
foreach ($d in $domains) {
    Write-Host "Checking $d ... " -NoNewline
    $r = Test-Domain $d $extraSelectors
    $color = @{ pass = 'Green'; warn = 'Yellow'; fail = 'Red' }[$r.overall]
    Write-Host $r.overall.ToUpper() -ForegroundColor $color
    $results += $r
}

$resolverName = if ($NameServer -and $UseNative) { $NameServer } elseif ($UseNative) { 'system' } else { 'dns.google (DNS over HTTPS)' }
$report = [ordered]@{
    generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    tool      = "PowerShell $($PSVersionTable.PSVersion)"
    source    = $source
    resolver  = $resolverName
    domains   = @($results)
}
$json = (ConvertTo-Json -InputObject $report -Depth 10 -Compress).Replace('</', '<\/')
$html = $templateHtml.Replace('__REPORT_DATA__', $json)
[IO.File]::WriteAllText($OutputPath, $html, (New-Object System.Text.UTF8Encoding $false))
Write-Host "`nReport written to $OutputPath"
