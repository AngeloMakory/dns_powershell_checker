<#
Bulk DNS lookup: A, PTR (of each A record) and NS for a list of domains.
No install needed - uses the built-in Resolve-DnsName (Windows PowerShell 5.1 or PowerShell 7 on Windows).

Usage:
  .\dns_lookup.ps1 -InputFile domains.txt
  .\dns_lookup.ps1 -InputFile domains.txt -OutputFile out.csv -Server 8.8.8.8

Input file = one entry per line. Each line can be a domain OR an email address
(user@example.com or "Name <user@example.com>"); the domain is extracted automatically.
Duplicates are removed. Blank lines and # comments are ignored.

Also returns registrar + abuse contact (email/phone) via RDAP, the modern WHOIS.
Use -NoWhois to skip that and run DNS-only.
#>
param(
    [Parameter(Mandatory)][string]$InputFile,
    [string]$OutputFile = "dns_results.csv",
    [string]$Server,           # optional resolver, e.g. 1.1.1.1
    [switch]$NoWhois           # skip registrar/abuse lookup (faster)
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

function Get-Whois($domain) {
    $out = [pscustomobject]@{ registrar = 'n/a'; abuse_email = 'n/a'; abuse_phone = 'n/a' }
    try {
        $r = Invoke-RestMethod "https://rdap.org/domain/$domain" -TimeoutSec 15 -ErrorAction Stop
    } catch { return $out }

    $reg = Find-Entity $r.entities 'registrar'
    $abuse = $null
    if ($reg) { $abuse = Find-Entity $reg.entities 'abuse' }
    if (-not $abuse) { $abuse = Find-Entity $r.entities 'abuse' }

    $name  = Get-VcardValue $reg 'fn'
    $email = Get-VcardValue $abuse 'email'
    $phone = Get-VcardValue $abuse 'tel'
    if ($name)  { $out.registrar   = $name }
    if ($email) { $out.abuse_email = $email }
    if ($phone) { $out.abuse_phone = $phone -replace '^tel:', '' }
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
        [pscustomobject]@{ registrar = ''; abuse_email = ''; abuse_phone = '' }
    } else {
        Start-Sleep -Milliseconds 300   # be gentle with RDAP servers
        Get-Whois $d
    }

    [pscustomobject]@{
        domain      = $d
        status      = if ($a) { 'OK' } else { 'NO_A' }
        a_records   = $a   -join ';'
        ptr_records = $ptr -join ';'
        ns_records  = $ns  -join ';'
        registrar   = $w.registrar
        abuse_email = $w.abuse_email
        abuse_phone = $w.abuse_phone
    }
}

$results | Export-Csv $OutputFile -NoTypeInformation
$results | Format-Table -AutoSize
Write-Host "Saved $($results.Count) rows to $OutputFile"