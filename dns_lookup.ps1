<#
Bulk DNS lookup: A, PTR (of each A record) and NS for a list of domains.
No install needed - uses the built-in Resolve-DnsName (Windows PowerShell 5.1 or PowerShell 7 on Windows).

Usage:
  .\dns_lookup.ps1 -InputFile domains.txt
  .\dns_lookup.ps1 -Domain example.com
  .\dns_lookup.ps1 -Domain example.com,user@other.com
  .\dns_lookup.ps1 -Domain example.com -InputFile domains.txt   (combines both)
  .\dns_lookup.ps1 -InputFile domains.txt -OutputFile out.csv -Server 8.8.8.8

Provide -InputFile, -Domain, or both. Each entry (from the file or typed on the
command line) can be a domain OR an email address (user@example.com or
"Name <user@example.com>"); the domain is extracted automatically.
Defanged/obfuscated forms are also accepted and cleaned up automatically, e.g.
example[.]co[.]ke, example.[co.ke], example.co.[ke], example(dot)com, user[at]example[.]com.
Duplicates are removed. Blank lines and # comments in the file are ignored.

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
# ============================================================================
# PARAMETERS — neither InputFile nor Domain is marked [Parameter(Mandatory)]
# because either one alone is enough; the check just below enforces that at
# least one was actually given.
# ============================================================================
param(
    [string]$InputFile,        # path to a text file of domains/emails, one per line (optional if -Domain is used)
    [string[]]$Domain,         # one or more domains/emails typed directly, e.g. -Domain example.com,user@other.com
    [string]$OutputFile = "dns_results.csv",
    [string]$Server,           # optional resolver, e.g. 1.1.1.1 — defaults to the machine's configured DNS server
    [switch]$NoWhois,          # skip registrar/abuse lookup (faster, DNS-only)
    [string]$TextOutputFile = "dns_results.txt"   # aligned plain-text table, readable outside Excel
)

# Bail out early with a usage hint rather than failing later with a confusing error.
if (-not $InputFile -and -not $Domain) {
    Write-Host "Provide at least one of -InputFile or -Domain. Examples:"
    Write-Host "  .\dns_lookup.ps1 -InputFile domains.txt"
    Write-Host "  .\dns_lookup.ps1 -Domain example.com"
    Write-Host "  .\dns_lookup.ps1 -Domain example.com,user@other.com -InputFile domains.txt"
    exit 1
}

# Older Windows/.NET defaults can refuse modern TLS, which breaks the
# HTTPS calls to IANA/RDAP below. Force TLS 1.2 explicitly to avoid that.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================================
# DNS HELPER
# Thin wrapper around Resolve-DnsName so every lookup in the script shares
# the same settings (optional custom server, silent on failure instead of
# throwing, and DNS-only so it doesn't fall back to the local hosts file).
# ============================================================================
function Get-Dns($Name, $Type) {
    $p = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'SilentlyContinue' }
    if ($Server) { $p.Server = $Server }   # $Server comes from the script's own -Server parameter
    Resolve-DnsName @p
}

# ============================================================================
# WHOIS VIA RDAP
# RDAP (Registration Data Access Protocol) is the modern, JSON-over-HTTPS
# replacement for legacy WHOIS. Windows has no built-in `whois` command,
# but RDAP needs nothing beyond Invoke-RestMethod, which ships with
# PowerShell — so no extra install is required.
# ============================================================================

# RDAP contact details (registrar name, abuse email/phone) are returned as
# "vcard" arrays — a generic contact-card format, not simple key/value pairs.
# This pulls one named field (e.g. 'fn' for full name, 'email', 'tel') out
# of an entity's vcardArray. Returns $null if the entity or field is absent.
function Get-VcardValue($entity, $field) {
    if (-not $entity -or -not $entity.vcardArray) { return $null }
    foreach ($item in $entity.vcardArray[1]) {
        if ($item[0] -eq $field) { return [string]$item[3] }
    }
}

# An RDAP response lists one or more "entities" (registrar, registrant,
# abuse contact, etc.), each tagged with a role, and entities can be
# nested inside other entities (e.g. the abuse contact often sits inside
# the registrar entity). This searches recursively for the first entity
# matching the given role ('registrar' or 'abuse').
function Find-Entity($entities, $role) {
    foreach ($e in @($entities)) {
        if ($e.roles -contains $role) { return $e }
        if ($e.entities) {
            $found = Find-Entity $e.entities $role
            if ($found) { return $found }
        }
    }
}

# IANA publishes a bootstrap file mapping each TLD to its authoritative
# RDAP server. Fetching this once per script run (cached in $script:RdapBootstrap)
# and querying the registry directly is more reliable than always going through
# the public rdap.org aggregator, which can be slower or rate-limited.
$script:RdapBootstrap = $null
function Get-RdapBase($tld) {
    if (-not $script:RdapBootstrap) {
        try {
            $script:RdapBootstrap = Invoke-RestMethod "https://data.iana.org/rdap/dns.json" -TimeoutSec 15
        } catch { $script:RdapBootstrap = $false }   # $false = "already tried, don't retry" (distinct from $null = "not tried yet")
    }
    if (-not $script:RdapBootstrap) { return $null }
    foreach ($svc in $script:RdapBootstrap.services) {
        if ($svc[0] -contains $tld) { return ($svc[1][0]).TrimEnd('/') }
    }
    # No match found -> falls through and returns $null, signalling "no direct RDAP server for this TLD"
}

# Looks up registrar, abuse contact and ICANN/EPP domain status for one
# domain. Always returns a result object (never throws) — on any failure
# the relevant fields stay 'n/a' and whois_note explains why.
function Get-Whois($domain) {
    $out = [pscustomobject]@{ registrar = 'n/a'; abuse_email = 'n/a'; abuse_phone = 'n/a'; domain_status = 'n/a'; whois_note = '' }
    $tld = ($domain -split '\.')[-1]

    # Build a list of URLs to try in order: the registry's own RDAP server
    # first (most accurate/complete), then rdap.org as a catch-all fallback
    # for TLDs IANA's bootstrap doesn't cover directly.
    $urls = @()
    $base = Get-RdapBase $tld
    if ($base) { $urls += "$base/domain/$domain" }
    $urls += "https://rdap.org/domain/$domain"   # fallback / catch-all

    $r = $null
    $lastErr = $null
    foreach ($u in $urls) {
        try { $r = Invoke-RestMethod $u -TimeoutSec 15 -ErrorAction Stop; break }   # stop at the first URL that works
        catch {
            $lastErr = $_.Exception.Response.StatusCode
            if (-not $lastErr) { $lastErr = 'timeout/unreachable' }
        }
    }

    # Both URLs failed (or there was no direct RDAP server at all) — record why and bail.
    if (-not $r) {
        $out.whois_note = if (-not $base) { "no RDAP server for .$tld" } else { "lookup failed ($lastErr)" }
        return $out
    }

    # The abuse contact is usually nested inside the registrar entity, but
    # some registries list it as a separate top-level entity instead —
    # check both places.
    $reg = Find-Entity $r.entities 'registrar'
    $abuse = $null
    if ($reg) { $abuse = Find-Entity $reg.entities 'abuse' }
    if (-not $abuse) { $abuse = Find-Entity $r.entities 'abuse' }

    # RDAP's top-level "status" array holds the EPP/ICANN status codes
    # (e.g. clientTransferProhibited, ok, pendingDelete).
    if ($r.status) { $out.domain_status = (@($r.status) -join ';') }

    $name  = Get-VcardValue $reg 'fn'
    $email = Get-VcardValue $abuse 'email'
    $phone = Get-VcardValue $abuse 'tel'
    if ($name)  { $out.registrar   = $name }
    if ($email) { $out.abuse_email = $email }
    if ($phone) { $out.abuse_phone = $phone -replace '^tel:', '' }   # RDAP phone numbers are prefixed "tel:" per the vcard spec

    # Explain any remaining n/a fields so the whois_note column is self-documenting.
    if (-not $reg -and -not $abuse) { $out.whois_note = "registry returned no entities (privacy/thin registry)" }
    elseif (-not $abuse)            { $out.whois_note = "no abuse contact published" }

    $out
}

# Un-defang common obfuscation styles seen in abuse/threat-intel reports:
#   example[.]co[.]ke  example.[co.ke]  example.co.[ke]  example(dot)com  user[at]example[.]com
function Remove-Defang($s) {
    $s = $s -replace '\(dot\)', '.' -replace '\[dot\]', '.' -replace '\{dot\}', '.'
    $s = $s -replace '\(at\)',  '@' -replace '\[at\]',  '@' -replace '\{at\}',  '@'
    $s = $s -replace '[\[\]\(\)\{\}]', ''   # strip any remaining brackets, e.g. [.] -> . once "at/dot" text is gone
    return $s
}

# ============================================================================
# BUILD THE FINAL DOMAIN LIST
# Combine file entries and command-line entries into one list, then run
# every entry through the same cleanup pipeline: trim/lowercase -> drop
# blanks/comments -> un-defang -> extract domain from email if needed ->
# drop duplicates.
# ============================================================================
$rawEntries = @()
if ($InputFile) { $rawEntries += Get-Content $InputFile }
if ($Domain)    { $rawEntries += $Domain }

$domains = $rawEntries |
    ForEach-Object { $_.Trim().ToLower() } |
    Where-Object { $_ -and -not $_.StartsWith('#') } |
    ForEach-Object { Remove-Defang $_ } |
    ForEach-Object {
        # Email (plain or "Name <user@domain>") -> keep only the part after the last @
        if ($_ -match '@([^@\s<>;,"'']+)[>\s]*$') { $Matches[1].TrimEnd('.') } else { $_.TrimEnd('.') }
    } |
    Select-Object -Unique

# ============================================================================
# MAIN LOOP — one pass per domain, building one result row each
# ============================================================================
$results = foreach ($d in $domains) {
    Write-Host "Checking $d"

    # A records -> the IP(s) the domain resolves to.
    $a  = @(Get-Dns $d 'A'  | Where-Object Type -eq 'A'  | ForEach-Object IPAddress)
    # NS records -> the authoritative nameservers for the domain.
    $ns = @(Get-Dns $d 'NS' | Where-Object Type -eq 'NS' | ForEach-Object NameHost)

    # PTR = reverse DNS. For each IP the domain resolved to, look up what
    # hostname that IP claims to be — useful for spotting shared/suspicious
    # hosting or confirming which server is actually behind an A record.
    $ptr = foreach ($ip in $a) {
        $h = @(Get-Dns $ip 'PTR' | Where-Object Type -eq 'PTR' | ForEach-Object NameHost)
        "$ip=" + $(if ($h) { $h -join '|' } else { 'no-ptr' })
    }

    # Skip the RDAP/WHOIS call entirely when -NoWhois was passed (faster for big lists).
    $w = if ($NoWhois) {
        [pscustomobject]@{ registrar = ''; abuse_email = ''; abuse_phone = ''; domain_status = ''; whois_note = '' }
    } else {
        Start-Sleep -Milliseconds 300   # small delay between lookups so we don't hammer RDAP servers
        Get-Whois $d
    }

    # Assemble one output row. Multi-value fields (A/PTR/NS, domain_status)
    # are joined with ';' so the whole thing still fits one CSV cell per column.
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

# ============================================================================
# OUTPUT — write both a CSV (for Excel/further processing) and an aligned
# plain-text table (readable in Notepad without opening a spreadsheet app).
# ============================================================================
$results | Export-Csv $OutputFile -NoTypeInformation

# -Width 4096 stops PowerShell wrapping/truncating long rows to the console's
# default width when writing to the text file.
$results | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content $TextOutputFile

$results | Format-Table -AutoSize   # also show the table in the terminal
Write-Host "Saved $($results.Count) rows to $OutputFile"
Write-Host "Saved aligned text table to $TextOutputFile"
