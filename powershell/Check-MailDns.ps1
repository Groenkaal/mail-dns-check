<#
.SYNOPSIS
    Check SPF, DKIM, DMARC (and MX) for a list of domains, tuned for Microsoft 365.

.DESCRIPTION
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
    .\Check-MailDns.ps1 -Domain contoso.com,fabrikam.com -Output report.html
.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Groenkaal/mail-dns-check/main/powershell/Check-MailDns.ps1))) -Domains list.txt -Output report.html
#>
[CmdletBinding()]
param(
    [Alias('Domains')]
    [string]$DomainsFile,
    [string[]]$Domain,
    [Alias('Output')]
    [string]$OutputPath,
    [string]$NameServer,
    [string]$TemplateUrl = 'https://raw.githubusercontent.com/Groenkaal/mail-dns-check/main/report-template.html'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 can default to TLS 1.0, which GitHub and Cloudflare refuse.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# $PSScriptRoot is empty when the script runs from memory (irm | scriptblock).
$Root           = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { $null }
$Template       = if ($Root) { Join-Path $Root 'report-template.html' } else { $null }
$MsSpfInclude   = 'spf.protection.outlook.com'
$MsMxSuffixes   = @('.mail.protection.outlook.com', '.mx.microsoft')
$MsDkimSuffixes = @('.onmicrosoft.com', '.dkim.mail.microsoft')
$DkimSelectors  = @('selector1', 'selector2')
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

function Get-Dns([string]$Name, [string]$Type) {
    # Returns record strings; empty when the name or type does not exist.
    $out = New-Object System.Collections.Generic.List[string]
    if ($UseNative) {
        $params = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'Stop' }
        if ($NameServer) { $params.Server = $NameServer }
        try { $answers = @(Resolve-DnsName @params) }
        catch {
            if ($_.Exception.Message -match 'timeout') { throw "DNS timeout looking up $Type $Name" }
            return @()
        }
        foreach ($r in $answers) {
            if ([string]$r.Type -ne $Type) { continue }
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
                    $parts = [regex]::Matches($d, '"((?:[^"\\]|\\.)*)"') | ForEach-Object { $_.Groups[1].Value -replace '\\(.)', '$1' }
                    if ($parts) { $out.Add((@($parts) -join '')) } else { $out.Add($d) }
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

# ----------------------------------------------------------------------------- MX

function Test-Mx([string]$Domain) {
    $mx = @(Get-Dns $Domain 'MX' | Sort-Object { [int]($_ -split ' ')[0] })
    $findings = @()
    if (-not $mx.Count) {
        return New-Check 'fail' 'No MX records. The domain cannot receive mail.' @() @()
    }
    $hosts = @($mx | ForEach-Object { (($_ -split ' ', 2)[1]).ToLower() })
    if ($hosts.Count -eq 1 -and $hosts[0] -eq '') {
        return New-Check 'info' 'Null MX (RFC 7505). The domain states it accepts no mail.' @('0 .') @()
    }
    if (@($hosts | Where-Object { Test-EndsWithAny $_ $MsMxSuffixes }).Count) {
        $status = 'pass'; $summary = 'Mail is routed to Exchange Online.'
        if ($mx.Count -gt 1) { $findings += New-Finding 'info' "$($mx.Count) MX records. Microsoft 365 normally needs only one." }
    }
    else {
        $status = 'info'; $summary = 'Mail is not routed to Microsoft 365.'
        $findings += New-Finding 'info' 'MX points elsewhere, e.g. a third-party gateway or another provider.'
    }
    return New-Check $status $summary $mx $findings
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

function Test-Spf([string]$Domain) {
    $recs = @(Get-SpfRecords $Domain)
    if (-not $recs.Count) {
        return New-Check 'fail' 'No SPF record. Receivers cannot verify who may send for this domain.' @() `
            @(New-Finding 'fail' "Add TXT: v=spf1 include:$MsSpfInclude -all")
    }
    if ($recs.Count -gt 1) {
        return New-Check 'fail' "$($recs.Count) SPF records. SPF fails when more than one exists." $recs `
            @(New-Finding 'fail' 'Merge them into a single v=spf1 record.')
    }

    $rec = $recs[0]
    $terms = @($rec -split '\s+' | Select-Object -Skip 1 | ForEach-Object { $_.ToLower() })
    $findings = @(); $statuses = @('pass')

    if ($terms -contains "include:$MsSpfInclude") {
        $findings += New-Finding 'pass' "Includes $MsSpfInclude (Microsoft 365)."
    }
    else {
        $findings += New-Finding 'warn' "Does not include $MsSpfInclude. Microsoft 365 mail will fail SPF."
        $statuses += 'warn'
    }

    $allTerm  = $terms | Where-Object { $_.TrimStart('+', '-', '~', '?') -eq 'all' } | Select-Object -First 1
    $redirect = $terms | Where-Object { $_.StartsWith('redirect=') } | Select-Object -First 1
    switch ($allTerm) {
        '-all'  { $findings += New-Finding 'pass' 'Ends in -all (hard fail for unlisted senders).' }
        '~all'  { $findings += New-Finding 'pass' 'Ends in ~all (soft fail). Fine with DMARC enforcement; -all is stricter.' }
        '?all'  { $findings += New-Finding 'warn' 'Ends in ?all (neutral). Unlisted senders are not rejected.'; $statuses += 'warn' }
        { $_ -in @('all', '+all') } { $findings += New-Finding 'fail' 'Ends in +all. Anyone may send as this domain.'; $statuses += 'fail' }
        default {
            if ($redirect) { $findings += New-Finding 'info' "Policy delegated with $redirect." }
            elseif (-not $allTerm) { $findings += New-Finding 'warn' 'No all mechanism. Add -all or ~all at the end.'; $statuses += 'warn' }
        }
    }

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

function Test-Dkim([string]$Domain) {
    $findings = @(); $records = @()
    $good = 0; $standby = @()
    $expectedPrefix = $Domain.Replace('.', '-')

    foreach ($sel in $DkimSelectors) {
        $name   = "$sel._domainkey.$Domain"
        $target = Get-Cname $name
        $txt    = @(Get-Dns $name 'TXT' | Where-Object { ($_ -replace '\s', '') -match 'p=' })

        if ($target) {
            $records += [ordered]@{ host = "$name CNAME"; value = $target }
            if (-not (Test-EndsWithAny $target $MsDkimSuffixes)) {
                $findings += New-Finding 'warn' "$sel points outside Microsoft 365 ($target)."
            }
            elseif (-not $target.ToLower().StartsWith("$sel-$expectedPrefix".ToLower())) {
                $findings += New-Finding 'info' "$sel target name does not match $sel-$expectedPrefix."
            }
        }
        if ($txt.Count) {
            $key = $txt[0]
            if (($key -replace '\s', '') -match '(?:^|;)p=([^;]+)') {
                $good++
                if (-not $target) {
                    $short = if ($key.Length -gt 120) { $key.Substring(0, 120) + [char]0x2026 } else { $key }
                    $records += [ordered]@{ host = "$name TXT"; value = $short }
                }
                $findings += New-Finding 'pass' "${sel}: public key published."
            }
            else {
                $findings += New-Finding 'fail' "${sel}: key is empty (p=), so the key is revoked."
            }
        }
        elseif ($target) {
            $standby += $sel
            $findings += New-Finding 'warn' ("${sel}: CNAME exists but the target has no key. " +
                'Enable DKIM signing for this domain in the Microsoft Defender portal.')
        }
        else {
            $findings += New-Finding 'fail' "${sel}: no record at $name."
        }
    }

    if ($good -eq $DkimSelectors.Count) {
        $status = 'pass'; $summary = 'Both Microsoft 365 DKIM selectors are published.'
    }
    elseif ($good -and $standby.Count) {
        $status = 'pass'; $summary = 'DKIM signing is active. The other selector is on standby for key rotation.'
        foreach ($f in $findings) {
            if ($f.text.EndsWith('Microsoft Defender portal.')) {
                $f.level = 'info'
                $f.text = ($f.text -split ':', 2)[0] + ': standby selector, no key yet. Normal between rotations.'
            }
        }
    }
    elseif ($good) {
        $status = 'warn'; $summary = 'Only one DKIM selector is published. Key rotation will break signing.'
    }
    elseif ($standby.Count) {
        $status = 'warn'; $summary = 'DKIM CNAMEs exist but no key is published. Signing is not enabled yet.'
    }
    else {
        $status = 'fail'; $summary = 'No Microsoft 365 DKIM key found.'
    }
    if ($status -eq 'pass' -and @($findings | Where-Object { $_.level -in @('warn', 'fail') }).Count) { $status = 'warn' }
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

function Invoke-Safe([scriptblock]$Check, [string]$Domain) {
    try { & $Check $Domain }
    catch { New-Check 'fail' 'Lookup error.' @() @(New-Finding 'fail' "$_") }
}

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

function Test-Domain([string]$Domain) {
    $checks = [ordered]@{
        mx    = Invoke-Safe ${function:Test-Mx}    $Domain
        spf   = Invoke-Safe ${function:Test-Spf}   $Domain
        dkim  = Invoke-Safe ${function:Test-Dkim}  $Domain
        dmarc = Invoke-Safe ${function:Test-Dmarc} $Domain
    }
    $mxPart = if ($checks.mx.status -eq 'fail') { 'fail' } else { 'pass' }
    $overall = Get-Worst @($checks.spf.status, $checks.dkim.status, $checks.dmarc.status, $mxPart)
    $result = [ordered]@{ domain = $Domain; overall = $overall; checks = $checks }
    $tenant = Get-Tenant $Domain
    if ($tenant) { $result.tenant = $tenant }
    return $result
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
    $r = Test-Domain $d
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
