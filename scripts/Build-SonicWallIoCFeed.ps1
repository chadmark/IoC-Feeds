#Requires -Version 7.0
<#
.SYNOPSIS
    Aggregates public IoC IP feeds, vets them, and publishes clean SonicWall SonicOS 8 IoC files.

.DESCRIPTION
    Pulls the sources defined in config/feed-config.json, then:
      - Strips comments, headers, ports and extra columns; keeps single IPv4 addresses only
      - Drops IPv6, CIDR ranges (other than /32), malformed lines, and private/reserved/bogon space
      - Falls back to the last good cached copy if a feed fails or returns suspiciously few entries
      - Removes anything in the allowlist (config/allowlist.txt + live Microsoft 365 IPv4 ranges)
      - Ranks inbound IPs by how many sources agree, then trims to the SonicWall model budgets
      - Refuses to publish if a list shrinks drastically versus the last run (poisoned/broken feed guard)
      - Writes UTF-8 (no BOM), LF, one-IP-per-line files plus a manifest for auditing

    Outputs (feeds/):
      c2.txt            Outbound C2 list (apply to LAN->WAN rules)
      inbound-tz.txt    Inbound list sized so c2 + inbound fits TZ/NSv (25,000 IP device limit)
      inbound-nsa.txt   Inbound list sized so c2 + inbound fits NSa (50,000 IP device limit)
      manifest.json     Per-source stats, allowlist hits, output counts, generation time
      allowlist-hits.txt  IPs the feeds wanted to block but the allowlist protected

.PARAMETER RepoRoot
    Root of the IoC-Feeds repo. Defaults to the parent of this script's folder.

.PARAMETER TzBudget
    Total IPs allowed across c2 + inbound for TZ/NSv. Default 24000 (headroom under 25,000).

.PARAMETER NsaBudget
    Total IPs allowed across c2 + inbound for NSa. Default 49000 (headroom under 50,000).

.PARAMETER CacheMaxAgeHours
    Oldest cached feed copy that may be reused when a live download fails. Default 72.

.PARAMETER MaxShrinkRatio
    Abort publishing if an inbound list falls below this fraction of its previous size. Default 0.5.

.PARAMETER CanaryIP
    Harmless TEST-NET address appended to every output file so you can verify each file loaded
    with the SonicWall Diagnostics "Check IoC IP Addresses" tool. Set to '' to disable.

.PARAMETER DryRun
    Build and report everything, but write nothing (no feeds, no cache, no state).

.PARAMETER Force
    Publish even if the shrink guard trips.

.NOTES
    Author:       Chad Markley - Markley Technologies
    Last Edit:    10-30-2026
    GitHub:       github.com/chadmark/IoC-Feeds/scripts/Build-SonicWallIoCFeed.ps1
    Environment:  PowerShell 7+ (GitHub Actions ubuntu-latest runner, or Windows/macOS for local testing)
    Requires:     Outbound HTTPS to the feed URLs and endpoints.office.com
    Version:      1.0

.CHANGELOG
    1.0 - 10-30-2026 - Initial release

.LINK
    https://www.sonicwall.com/support/technical-documentation/docs/sonicos8-rules_policies_classic/Content/IoC/introduction.htm
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [int]$TzBudget = 24000,
    [int]$NsaBudget = 49000,
    [int]$CacheMaxAgeHours = 72,
    [double]$MaxShrinkRatio = 0.5,
    [string]$CanaryIP = '192.0.2.1',
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ScriptVersion = '1.0'
$UserAgent = "MarkleyTech-IoC-Feed-Builder/$ScriptVersion (+https://markleytech.com)"

#region Helpers

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Host "[$ts] [$Level] $Message"
    # Surface warnings/errors as annotations in the GitHub Actions UI
    if ($env:GITHUB_ACTIONS -eq 'true' -and $Level -ne 'INFO') {
        Write-Host "::$($Level.ToLower() -replace 'warn','warning')::$Message"
    }
}

function ConvertTo-IPv4Number {
    param([string]$Ip)
    $o = $Ip.Split('.')
    return ([uint64]$o[0] * 16777216) + ([uint64]$o[1] * 65536) + ([uint64]$o[2] * 256) + [uint64]$o[3]
}

function Test-IPv4String {
    # Returns a normalized dotted-quad string, or $null if not a valid IPv4 address
    param([string]$Value)
    if ($Value -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { return $null }
    $octets = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    foreach ($o in $octets) { if ($o -gt 255) { return $null } }
    return ($octets -join '.')
}

function ConvertTo-IPv4Range {
    # Accepts "a.b.c.d" or "a.b.c.d/nn"; returns @{Start;End} as uint64, or $null if invalid
    param([string]$Cidr)
    $parts = $Cidr.Trim().Split('/')
    $ip = Test-IPv4String $parts[0]
    if (-not $ip) { return $null }
    $bits = 32
    if ($parts.Count -gt 1) {
        if ($parts[1] -notmatch '^\d{1,2}$' -or [int]$parts[1] -gt 32) { return $null }
        $bits = [int]$parts[1]
    }
    $size = [uint64]1 -shl (32 - $bits)
    $start = [uint64]([math]::Floor((ConvertTo-IPv4Number $ip) / $size) * $size)
    return [pscustomobject]@{ Start = $start; End = $start + $size - 1 }
}

function New-RangeSet {
    # Merges overlapping ranges and returns sorted arrays for binary search
    param([object[]]$Ranges)
    $merged = [System.Collections.Generic.List[object]]::new()
    if ($Ranges -and $Ranges.Count -gt 0) {
        foreach ($r in ($Ranges | Sort-Object Start)) {
            if ($merged.Count -gt 0 -and $r.Start -le ($merged[$merged.Count - 1].End + 1)) {
                if ($r.End -gt $merged[$merged.Count - 1].End) { $merged[$merged.Count - 1].End = $r.End }
            }
            else {
                $merged.Add([pscustomobject]@{ Start = [uint64]$r.Start; End = [uint64]$r.End })
            }
        }
    }
    $starts = [uint64[]]::new($merged.Count)
    $ends = [uint64[]]::new($merged.Count)
    for ($i = 0; $i -lt $merged.Count; $i++) { $starts[$i] = $merged[$i].Start; $ends[$i] = $merged[$i].End }
    return [pscustomobject]@{ Starts = $starts; Ends = $ends; Count = $merged.Count }
}

function Test-InRangeSet {
    param([uint64]$Value, $Set)
    $lo = 0; $hi = $Set.Count - 1
    while ($lo -le $hi) {
        $mid = [int][math]::Floor(($lo + $hi) / 2)
        if ($Value -lt $Set.Starts[$mid]) { $hi = $mid - 1 }
        elseif ($Value -gt $Set.Ends[$mid]) { $lo = $mid + 1 }
        else { return $true }
    }
    return $false
}

function Read-ListFile {
    # Reads an IP/CIDR list file, ignoring blank lines and # comments
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @() }
    return @(Get-Content -Path $Path | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
}

function Get-WebText {
    param([string]$Uri)
    $resp = Invoke-WebRequest -Uri $Uri -TimeoutSec 60 -UserAgent $UserAgent -MaximumRetryCount 2 -RetryIntervalSec 5
    if ($resp.Content -is [byte[]]) { return [System.Text.Encoding]::UTF8.GetString($resp.Content) }
    return [string]$resp.Content
}

function ConvertFrom-FeedText {
    # Parses raw feed text into clean, deduped public IPv4 addresses plus parse statistics
    param([string]$Text, $BogonSet)
    $stats = [ordered]@{ lines = 0; valid = 0; cidrSkipped = 0; ipv6Skipped = 0; bogonDropped = 0; invalid = 0 }
    $ips = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($rawLine in ($Text -split "`r?`n")) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#') -or $line.StartsWith(';') -or $line.StartsWith('//')) { continue }
        $stats.lines++
        # First token only: handles "ip<TAB>count", "ip,extra", "ip # comment"
        $token = ($line -split '[\s,;#]+')[0]
        if ($token -match ':' -and $token -notmatch '^\d{1,3}(\.\d{1,3}){3}:\d+$') { $stats.ipv6Skipped++; continue }
        $token = $token -replace ':\d+$', ''   # strip ip:port
        if ($token -match '/') {
            if ($token -match '/32$') { $token = $token -replace '/32$', '' }
            else { $stats.cidrSkipped++; continue }
        }
        $ip = Test-IPv4String $token
        if (-not $ip) { $stats.invalid++; continue }
        if (Test-InRangeSet -Value (ConvertTo-IPv4Number $ip) -Set $BogonSet) { $stats.bogonDropped++; continue }
        [void]$ips.Add($ip)
    }
    $stats.valid = $ips.Count
    return [pscustomobject]@{ IPs = @($ips); Stats = $stats }
}

function Write-FeedFile {
    # UTF-8 without BOM, LF line endings, one entry per line, trailing newline
    param([string]$Path, [string[]]$Lines)
    $enc = [System.Text.UTF8Encoding]::new($false)
    $text = if ($Lines -and $Lines.Count -gt 0) { ($Lines -join "`n") + "`n" } else { '' }
    [System.IO.File]::WriteAllText($Path, $text, $enc)
}

function Get-PreviousCount {
    param([string]$Path, [string]$Canary)
    if (-not (Test-Path $Path)) { return 0 }
    return @(Get-Content -Path $Path | Where-Object { $_ -and $_ -ne $Canary }).Count
}

function Get-M365IPv4Ranges {
    # Only re-downloads endpoints when Microsoft publishes a new version (per Microsoft guidance)
    param([string]$ClientRequestId, [string]$StateDir, [switch]$NoWrite)
    $verFile = Join-Path $StateDir 'm365-version.txt'
    $ipFile = Join-Path $StateDir 'm365-ipv4.txt'
    $cachedVer = if (Test-Path $verFile) { (Get-Content -Raw $verFile).Trim() } else { '' }
    try {
        $ver = Invoke-RestMethod -Uri "https://endpoints.office.com/version/Worldwide?ClientRequestId=$ClientRequestId" -TimeoutSec 60
        $latest = [string]$ver.latest
        if ($latest -eq $cachedVer -and (Test-Path $ipFile)) {
            Write-Log "M365 endpoints unchanged (version $latest), using cached ranges"
            return [pscustomobject]@{ Version = $latest; Ranges = @(Read-ListFile $ipFile); Source = 'cache' }
        }
        $eps = Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/Worldwide?ClientRequestId=$ClientRequestId" -TimeoutSec 60
        $v4 = @($eps | Where-Object { $_.PSObject.Properties.Name -contains 'ips' } |
            ForEach-Object { $_.ips } | Where-Object { $_ -notmatch ':' } | Sort-Object -Unique)
        if ($v4.Count -eq 0) { throw 'Microsoft endpoints returned no IPv4 ranges' }
        if (-not $NoWrite) {
            Write-FeedFile -Path $ipFile -Lines $v4
            Write-FeedFile -Path $verFile -Lines @($latest)
        }
        Write-Log "M365 endpoints updated to version $latest ($($v4.Count) IPv4 ranges)"
        return [pscustomobject]@{ Version = $latest; Ranges = $v4; Source = 'live' }
    }
    catch {
        if (Test-Path $ipFile) {
            Write-Log "M365 endpoint lookup failed ($($_.Exception.Message)); using cached ranges" -Level WARN
            return [pscustomobject]@{ Version = $cachedVer; Ranges = @(Read-ListFile $ipFile); Source = 'cache-fallback' }
        }
        # Fail closed: never publish without the M365 allowlist in place
        throw "M365 endpoint lookup failed and no cached copy exists: $($_.Exception.Message)"
    }
}

#endregion Helpers

try {
    $configPath = Join-Path $RepoRoot 'config/feed-config.json'
    $allowPath = Join-Path $RepoRoot 'config/allowlist.txt'
    $feedDir = Join-Path $RepoRoot 'feeds'
    $stateDir = Join-Path $RepoRoot 'state'
    $cacheDir = Join-Path $stateDir 'cache'
    foreach ($d in @($feedDir, $stateDir, $cacheDir)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }

    Write-Log "IoC feed build v$ScriptVersion starting (DryRun=$DryRun, Force=$Force)"
    $config = Get-Content -Raw -Path $configPath | ConvertFrom-Json

    # --- Bogon / special-purpose IPv4 space (never valid IoCs) ---
    $bogonCidrs = @('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
        '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4')
    $bogonSet = New-RangeSet -Ranges @($bogonCidrs | ForEach-Object { ConvertTo-IPv4Range $_ })

    # --- Allowlist: custom file + Microsoft 365 ---
    $allowEntries = @(Read-ListFile $allowPath)
    $allowRanges = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $allowEntries) {
        $r = ConvertTo-IPv4Range $a
        if ($r) { $allowRanges.Add($r) } else { Write-Log "Ignoring invalid allowlist entry: $a" -Level WARN }
    }
    $m365 = $null
    if ($config.m365.enabled) {
        $guid = [guid]::Empty
        if (-not [guid]::TryParse([string]$config.m365.clientRequestId, [ref]$guid)) { throw 'config m365.clientRequestId is not a valid GUID' }
        $m365 = Get-M365IPv4Ranges -ClientRequestId $guid -StateDir $stateDir -NoWrite:$DryRun
        foreach ($c in $m365.Ranges) { $r = ConvertTo-IPv4Range $c; if ($r) { $allowRanges.Add($r) } }
    }
    $allowSet = New-RangeSet -Ranges $allowRanges.ToArray()
    Write-Log "Allowlist loaded: $($allowEntries.Count) custom entries, $(if ($m365) { $m365.Ranges.Count } else { 0 }) M365 ranges"

    # --- Pull and parse each source ---
    $table = [System.Collections.Generic.Dictionary[string, object]]::new()
    $sourceStats = [System.Collections.Generic.List[object]]::new()
    $cutoff = (Get-Date).ToUniversalTime().AddHours(-$CacheMaxAgeHours)

    foreach ($src in @($config.sources | Where-Object { $_.enabled })) {
        if ($src.role -notin @('c2', 'inbound')) { throw "Source '$($src.name)' has invalid role '$($src.role)' (use c2 or inbound)" }
        $cacheFile = Join-Path $cacheDir "$($src.name).txt"
        $result = $null; $status = ''; $err = ''
        try {
            $parsed = ConvertFrom-FeedText -Text (Get-WebText -Uri $src.url) -BogonSet $bogonSet
            if ($parsed.IPs.Count -lt [int]$src.minEntries) {
                throw "returned $($parsed.IPs.Count) valid IPs, below minEntries $($src.minEntries)"
            }
            $result = $parsed; $status = 'live'
            if (-not $DryRun) {
                $stamp = "# cachedUtc=$((Get-Date).ToUniversalTime().ToString('o'))"
                Write-FeedFile -Path $cacheFile -Lines (@($stamp) + @($parsed.IPs | Sort-Object { ConvertTo-IPv4Number $_ }))
            }
        }
        catch {
            $err = $_.Exception.Message
            # Fall back to last good copy if it is fresh enough. Timestamp lives inside the file
            # because file mtimes reset on every git checkout.
            $cachedAt = $null
            if (Test-Path $cacheFile) {
                $first = Get-Content -Path $cacheFile -TotalCount 1
                if ($first -match '^# cachedUtc=(.+)$') { $cachedAt = [datetime]::Parse($Matches[1]).ToUniversalTime() }
            }
            if ($cachedAt -and $cachedAt -ge $cutoff) {
                $ips = @(Read-ListFile $cacheFile)
                $result = [pscustomobject]@{ IPs = $ips; Stats = [ordered]@{ lines = $ips.Count; valid = $ips.Count; cidrSkipped = 0; ipv6Skipped = 0; bogonDropped = 0; invalid = 0 } }
                $status = "cache ($($cachedAt.ToString('yyyy-MM-ddTHH:mmZ')))"
                Write-Log "Source '$($src.name)' failed ($err); using cached copy from $status" -Level WARN
            }
            else {
                $status = 'skipped'
                Write-Log "Source '$($src.name)' failed ($err) and no usable cache; skipping this run" -Level WARN
            }
        }

        $stat = [ordered]@{ name = $src.name; role = $src.role; url = $src.url; status = $status; error = $err }
        if ($result) {
            foreach ($k in $result.Stats.Keys) { $stat[$k] = $result.Stats[$k] }
            foreach ($ip in $result.IPs) {
                if (-not $table.ContainsKey($ip)) {
                    $table[$ip] = [pscustomobject]@{
                        IP      = $ip
                        Num     = ConvertTo-IPv4Number $ip
                        Sources = [System.Collections.Generic.HashSet[string]]::new()
                        Roles   = [System.Collections.Generic.HashSet[string]]::new()
                    }
                }
                [void]$table[$ip].Sources.Add($src.name)
                [void]$table[$ip].Roles.Add($src.role)
            }
        }
        $sourceStats.Add([pscustomobject]$stat)
        Write-Log ("Source {0,-20} {1,-28} valid={2}" -f $src.name, $status, $(if ($result) { $result.Stats.valid } else { 0 }))
    }

    # --- Apply allowlist ---
    $allowHits = [System.Collections.Generic.List[string]]::new()
    foreach ($key in @($table.Keys)) {
        if (Test-InRangeSet -Value $table[$key].Num -Set $allowSet) {
            $allowHits.Add("$key`t$(@($table[$key].Sources) -join ',')")
            [void]$table.Remove($key)
        }
    }
    if ($allowHits.Count -gt 0) { Write-Log "Allowlist protected $($allowHits.Count) IP(s) that feeds wanted to block - review allowlist-hits.txt" -Level WARN }

    # --- Build outputs ---
    $entries = @($table.Values)
    $c2 = @($entries | Where-Object { $_.Roles.Contains('c2') } | Sort-Object Num | ForEach-Object IP)
    # Inbound excludes anything already in c2 so the same IP is not counted twice against the device limit.
    # Ranked by number of agreeing sources (higher confidence first), then numeric order for stable output.
    $inboundRanked = @($entries | Where-Object { $_.Roles.Contains('inbound') -and -not $_.Roles.Contains('c2') } |
        Sort-Object @{ Expression = { $_.Sources.Count }; Descending = $true }, @{ Expression = 'Num'; Descending = $false })

    $canary = @()
    if ($CanaryIP) { $canary = @($CanaryIP) }
    $perFileCanary = $canary.Count
    # Both files are enforced together on a firewall, so both canaries count toward the budget
    $tzCap = [math]::Max(0, $TzBudget - $c2.Count - (2 * $perFileCanary))
    $nsaCap = [math]::Max(0, $NsaBudget - $c2.Count - (2 * $perFileCanary))
    $inboundTz = @($inboundRanked | Select-Object -First $tzCap | Sort-Object Num | ForEach-Object IP)
    $inboundNsa = @($inboundRanked | Select-Object -First $nsaCap | Sort-Object Num | ForEach-Object IP)

    Write-Log "Outputs: c2=$($c2.Count), inbound candidates=$($inboundRanked.Count), inbound-tz=$($inboundTz.Count), inbound-nsa=$($inboundNsa.Count)"

    # --- Safety gates ---
    if ($inboundRanked.Count -eq 0) { throw 'No inbound IPs collected from any source; refusing to publish an empty list' }
    foreach ($check in @(
            @{ File = 'inbound-tz.txt'; New = $inboundTz.Count },
            @{ File = 'inbound-nsa.txt'; New = $inboundNsa.Count })) {
        $prev = Get-PreviousCount -Path (Join-Path $feedDir $check.File) -Canary $CanaryIP
        if ($prev -ge 1000 -and $check.New -lt ($prev * $MaxShrinkRatio)) {
            $msg = "$($check.File) would shrink from $prev to $($check.New) (below $([int]($MaxShrinkRatio*100))% guard)"
            if ($Force) { Write-Log "$msg - publishing anyway due to -Force" -Level WARN }
            else { throw "$msg - not publishing. Investigate the sources, or rerun with -Force." }
        }
    }

    # --- Manifest ---
    $manifest = [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        builder      = "Build-SonicWallIoCFeed.ps1 v$ScriptVersion"
        canaryIP     = $CanaryIP
        budgets      = [ordered]@{ tz = $TzBudget; nsa = $NsaBudget }
        outputs      = [ordered]@{
            c2                = $c2.Count
            inboundCandidates = $inboundRanked.Count
            inboundTz         = $inboundTz.Count
            inboundNsa        = $inboundNsa.Count
            droppedForTzCap   = [math]::Max(0, $inboundRanked.Count - $inboundTz.Count)
            droppedForNsaCap  = [math]::Max(0, $inboundRanked.Count - $inboundNsa.Count)
        }
        allowlist    = [ordered]@{
            customEntries = $allowEntries.Count
            m365Version   = if ($m365) { $m365.Version } else { $null }
            m365Ranges    = if ($m365) { $m365.Ranges.Count } else { 0 }
            m365Source    = if ($m365) { $m365.Source } else { 'disabled' }
            ipsProtected  = $allowHits.Count
        }
        sources      = $sourceStats
    }

    if ($DryRun) {
        Write-Log 'DryRun: nothing written. Manifest preview follows.'
        $manifest | ConvertTo-Json -Depth 6 | Write-Host
    }
    else {
        Write-FeedFile -Path (Join-Path $feedDir 'c2.txt') -Lines (@($c2) + $canary)
        Write-FeedFile -Path (Join-Path $feedDir 'inbound-tz.txt') -Lines (@($inboundTz) + $canary)
        Write-FeedFile -Path (Join-Path $feedDir 'inbound-nsa.txt') -Lines (@($inboundNsa) + $canary)
        Write-FeedFile -Path (Join-Path $feedDir 'allowlist-hits.txt') -Lines @($allowHits)
        Write-FeedFile -Path (Join-Path $feedDir 'manifest.json') -Lines @($manifest | ConvertTo-Json -Depth 6)
        Write-Log "Feeds written to $feedDir"
    }

    # --- GitHub Actions run summary ---
    if ($env:GITHUB_STEP_SUMMARY) {
        $md = @("## IoC feed build $($manifest.generatedUtc)", '',
            '| Source | Role | Status | Valid IPs |', '|---|---|---|---|')
        foreach ($s in $sourceStats) { $md += "| $($s.name) | $($s.role) | $($s.status) | $(if ($s.PSObject.Properties.Name -contains 'valid') { $s.valid } else { 0 }) |" }
        $md += '', "c2: **$($c2.Count)** | inbound-tz: **$($inboundTz.Count)** | inbound-nsa: **$($inboundNsa.Count)** | allowlist protected: **$($allowHits.Count)**"
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value ($md -join "`n")
    }

    Write-Log 'Build complete'
    exit 0
}
catch {
    Write-Log "Build failed: $($_.Exception.Message)" -Level ERROR
    Write-Log "At: $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR
    exit 1
}
