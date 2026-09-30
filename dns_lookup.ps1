<#
Bulk DNS lookup: A, PTR (of each A record) and NS for a list of domains.
No install needed - uses the built-in Resolve-DnsName (Windows PowerShell 5.1 or PowerShell 7 on Windows).

Usage:
  .\dns_lookup.ps1 -InputFile domains.txt
  .\dns_lookup.ps1 -InputFile domains.txt -OutputFile out.csv -Server 8.8.8.8

Input file = one entry per line. Each line can be a domain OR an email address
(user@example.com or "Name <user@example.com>"); the domain is extracted automatically.
Duplicates are removed. Blank lines and # comments are ignored.

Also returns registrar + abuse contact (email/phone) and ICANN domain status
(e.g. clientTransferProhibited, ok, pendingDelete) via RDAP, the modern WHOIS.
Queries the registry's own RDAP server first (found via IANA's bootstrap list),
falling back to rdap.org if that fails. A whois_note column explains any n/a
(no RDAP server for that TLD, registry returned nothing, no abuse contact published, etc).
Use -NoWhois to skip WHOIS and run DNS-only.
Also saves a row/column-aligned plain-text table (dns_results.txt by default,
override with -TextOutputFile) for viewing outside Excel — e.g. in Notepad
or pasted into a ticket/email.
#>
param(
    [Parameter(Mandatory)][string]$InputFile,
    [string]$OutputFile = "dns_results.csv",
    [string]$Server,           # optional resolver, e.g. 1.1.1.1
    [switch]$NoWhois,          # skip registrar/abuse lookup (faster)
    [string]$TextOutputFile = "dns_results.txt"   # aligned plain-text table, readable outside Excel
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-Dns($Name, $Type) {
    $p = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'SilentlyContinue' }
    if ($Server) { $p.Server = $Server }
    Resolve-DnsName @p
}

# ---- WHOIS via RDAP (built-in HTTPS/JSON, no install needed) ----
function Get-VcardValue($entity, $field) {
    if (-not $entity -or -not $entity.vcardArray) { return $null }
    foreach ($item in $entity.vcardArray[1]) {
        if ($item[0] -eq $field) { return [string]$item[3] }
    }
}

function Find-Entity($entities, $role) {
    foreach ($e in @($entities)) {
        if ($e.roles -contains $role) { return $e }
        if ($e.entities) {
            $found = Find-Entity $e.entities $role
            if ($found) { return $found }
        }
    }
}

$script:RdapBootstrap = $null
function Get-RdapBase($tld) {
    if (-not $script:RdapBootstrap) {
        try {
            $script:RdapBootstrap = Invoke-RestMethod "https://data.iana.org/rdap/dns.json" -TimeoutSec 15
        } catch { $script:RdapBootstrap = $false }
    }
    if (-not $script:RdapBootstrap) { return $null }
    foreach ($svc in $script:RdapBootstrap.services) {
        if ($svc[0] -contains $tld) { return ($svc[1][0]).TrimEnd('/') }
    }
}

function Get-Whois($domain) {
    $out = [pscustomobject]@{ registrar = 'n/a'; abuse_email = 'n/a'; abuse_phone = 'n/a'; domain_status = 'n/a'; whois_note = '' }
    $tld = ($domain -split '\.')[-1]

    $urls = @()
    $base = Get-RdapBase $tld
    if ($base) { $urls += "$base/domain/$domain" }
    $urls += "https://rdap.org/domain/$domain"   # fallback / catch-all

    $r = $null
    $lastErr = $null
    foreach ($u in $urls) {
        try { $r = Invoke-RestMethod $u -TimeoutSec 15 -ErrorAction Stop; break }
        catch {
            $lastErr = $_.Exception.Response.StatusCode
            if (-not $lastErr) { $lastErr = 'timeout/unreachable' }
        }
    }

    if (-not $r) {
        $out.whois_note = if (-not $base) { "no RDAP server for .$tld" } else { "lookup failed ($lastErr)" }
        return $out
    }

    $reg = Find-Entity $r.entities 'registrar'
    $abuse = $null
    if ($reg) { $abuse = Find-Entity $reg.entities 'abuse' }
    if (-not $abuse) { $abuse = Find-Entity $r.entities 'abuse' }

    if ($r.status) { $out.domain_status = (@($r.status) -join ';') }

    $name  = Get-VcardValue $reg 'fn'
    $email = Get-VcardValue $abuse 'email'
    $phone = Get-VcardValue $abuse 'tel'
    if ($name)  { $out.registrar   = $name }
    if ($email) { $out.abuse_email = $email }
    if ($phone) { $out.abuse_phone = $phone -replace '^tel:', '' }

    if (-not $reg -and -not $abuse) { $out.whois_note = "registry returned no entities (privacy/thin registry)" }
    elseif (-not $abuse)            { $out.whois_note = "no abuse contact published" }

    $out
}

$domains = Get-Content $InputFile |
    ForEach-Object { $_.Trim().ToLower() } |
    Where-Object { $_ -and -not $_.StartsWith('#') } |
    ForEach-Object {
        # Email (plain or "Name <user@domain>") -> keep only the part after the last @
        if ($_ -match '@([^@\s<>;,"'']+)[>\s]*$') { $Matches[1].TrimEnd('.') } else { $_.TrimEnd('.') }
    } |
    Select-Object -Unique

$results = foreach ($d in $domains) {
    Write-Host "Checking $d"

    $a  = @(Get-Dns $d 'A'  | Where-Object Type -eq 'A'  | ForEach-Object IPAddress)
    $ns = @(Get-Dns $d 'NS' | Where-Object Type -eq 'NS' | ForEach-Object NameHost)

    $ptr = foreach ($ip in $a) {
        $h = @(Get-Dns $ip 'PTR' | Where-Object Type -eq 'PTR' | ForEach-Object NameHost)
        "$ip=" + $(if ($h) { $h -join '|' } else { 'no-ptr' })
    }

    $w = if ($NoWhois) {
        [pscustomobject]@{ registrar = ''; abuse_email = ''; abuse_phone = ''; domain_status = ''; whois_note = '' }
    } else {
        Start-Sleep -Milliseconds 300   # be gentle with RDAP servers
        Get-Whois $d
    }

    [pscustomobject]@{
        domain        = $d
        status        = if ($a) { 'OK' } else { 'NO_A' }
        a_records     = $a   -join ';'
        ptr_records   = $ptr -join ';'
        ns_records    = $ns  -join ';'
        registrar     = $w.registrar
        abuse_email   = $w.abuse_email
        abuse_phone   = $w.abuse_phone
        domain_status = $w.domain_status
        whois_note    = $w.whois_note
    }
}

$results | Export-Csv $OutputFile -NoTypeInformation

$results | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content $TextOutputFile

$results | Format-Table -AutoSize
Write-Host "Saved $($results.Count) rows to $OutputFile"
Write-Host "Saved aligned text table to $TextOutputFile"
