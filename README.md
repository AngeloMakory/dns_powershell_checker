# DNS & WHOIS Bulk Lookup (PowerShell)

Bulk-resolves **A**, **PTR** and **NS** records for a list of domains (or email
addresses), and enriches each result with **registrar** and **abuse contact**
details via RDAP (the modern replacement for WHOIS). Built for quick triage
during abuse investigations, spoofing/phishing checks, and general
infrastructure recon.

## Prerequisites

- Windows 8 / Windows Server 2012 or newer.
- PowerShell 5.1 (ships with Windows) or PowerShell 7 on Windows.
  **Does not work on PowerShell on Linux/macOS** — it relies on the
  Windows-only `Resolve-DnsName` cmdlet.
- Outbound **DNS (UDP/TCP 53)** allowed from the host, for the DNS lookups.
- Outbound **HTTPS (443)** allowed, for the RDAP/WHOIS lookups.
- No third-party modules or installs required — everything used
  (`Resolve-DnsName`, `Invoke-RestMethod`) is built into Windows PowerShell.

## Files

| File            | Purpose                                              |
|-----------------|-------------------------------------------------------|
| `dns_lookup.ps1`| The script                                            |
| `domains.txt`   | Your input list — one domain or email per line (example below) |

## Input format

One entry per line in `domains.txt`. Each line can be:
- a plain domain: `example.com`
- an email address: `user@example.com`
- a display-name email: `Some Name <user@example.com>`

The script extracts the domain automatically and de-duplicates the list.
Blank lines and lines starting with `#` are ignored.

**Defanged/obfuscated domains are also accepted** (common in abuse reports and
threat-intel feeds, used so links don't render as clickable). These are
automatically cleaned up before lookup:

| Obfuscated form              | Cleaned to       |
|-------------------------------|------------------|
| `example[.]co[.]ke`          | `example.co.ke`  |
| `example.[co.ke]`            | `example.co.ke`  |
| `example.co.[ke]`            | `example.co.ke`  |
| `example(dot)com`            | `example.com`    |
| `user[at]example[.]com`      | `user@example.com` |

```
example.com
alice@example.org
Bob Smith <bob@example.net>
example[.]co[.]ke
user[at]example(dot)com
# this line is a comment and is skipped
```

## Usage

1. Put `dns_lookup.ps1` (and `domains.txt`, if using a file) in the same folder.
2. Open PowerShell in that folder (Shift+Right-click the folder →
   *Open PowerShell window here*, or `cd` to it manually).
3. Allow script execution for this session only (does not change any
   system-wide policy, and reverts when the window is closed):
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   ```
   If the script file shows as "blocked" (common for downloaded files):
   ```powershell
   Unblock-File .\dns_lookup.ps1
   ```
4. Run it, either from a file, typed directly, or both:
   ```powershell
   .\dns_lookup.ps1 -InputFile domains.txt
   .\dns_lookup.ps1 -Domain example.com
   ```

### Parameters

| Parameter     | Required | Description                                                        |
|---------------|----------|----------------------------------------------------------------------|
| `-InputFile`  | One of `-InputFile` / `-Domain` is required | Path to your domain/email list. |
| `-Domain`     | One of `-InputFile` / `-Domain` is required | One or more domains/emails typed directly, comma-separated for multiple. Can be combined with `-InputFile`. |
| `-OutputFile` | No       | Output CSV path. Defaults to `dns_results.csv`.                     |
| `-Server`     | No       | Use a specific DNS resolver (e.g. `8.8.8.8`) instead of the host's default. |
| `-NoWhois`    | No       | Skip the RDAP/WHOIS lookup and only return DNS data (faster).       |
| `-TextOutputFile` | No   | Aligned plain-text table path. Defaults to `dns_results.txt`.       |

### Examples

```powershell
# From a file
.\dns_lookup.ps1 -InputFile domains.txt

# One domain typed directly - no file needed
.\dns_lookup.ps1 -Domain example.com

# Several domains/emails typed directly
.\dns_lookup.ps1 -Domain example.com,alice@other.org

# Combine a file with extra ad-hoc domains
.\dns_lookup.ps1 -InputFile domains.txt -Domain justcameup.com

# Custom output file, use Google's resolver
.\dns_lookup.ps1 -InputFile domains.txt -OutputFile results.csv -Server 8.8.8.8

# DNS-only, skip WHOIS/RDAP (fast, for large lists)
.\dns_lookup.ps1 -InputFile domains.txt -NoWhois
```

## Output

Results print to the terminal as a table and are saved to two files:

- **`dns_results.csv`** — comma-separated, for Excel or further processing.
- **`dns_results.txt`** — the same data as a row/column-aligned plain-text
  table (like the terminal output), readable in Notepad or pasted directly
  into a ticket/email without opening Excel. Override the path with
  `-TextOutputFile`.

Columns:

| Column        | Description                                                          |
|---------------|-----------------------------------------------------------------------|
| `domain`      | The resolved domain (extracted from email if applicable)             |
| `status`      | `OK` if an A record was found, `NO_A` if not                         |
| `a_records`   | A record IP(s), `;`-separated                                        |
| `ptr_records` | Reverse DNS for each A record, as `ip=hostname`, `;`-separated. `no-ptr` if none |
| `ns_records`  | Authoritative nameservers, `;`-separated                             |
| `registrar`   | Registrar name from RDAP                                             |
| `abuse_email` | Registrar/registry abuse contact email                               |
| `abuse_phone` | Registrar/registry abuse contact phone                               |
| `domain_status` | ICANN/EPP domain status code(s) (e.g. `clientTransferProhibited`, `ok`, `pendingDelete`), `;`-separated |
| `whois_note`  | Explains an `n/a` result (see below) — blank when data was found     |

## Viewing the output

```powershell
# Open the CSV in Excel (or your default spreadsheet app)
Invoke-Item .\dns_results.csv

# Open the aligned plain-text table in Notepad
notepad .\dns_results.txt
```

## How WHOIS/RDAP works here

Windows has no built-in `whois` command, so the script uses **RDAP**
(Registration Data Access Protocol) — the modern, structured, HTTPS/JSON
replacement for legacy WHOIS that most registries now support. For each
domain it:

1. Looks up the correct registry RDAP server via IANA's bootstrap list.
2. Falls back to the public aggregator `rdap.org` if that fails or the TLD
   has no direct entry.

### Interpreting `whois_note`

| Note                                             | Meaning                                                              |
|---------------------------------------------------|-----------------------------------------------------------------------|
| *(blank)*                                        | Registrar/abuse data was found                                       |
| `no RDAP server for .xx`                         | That TLD's registry doesn't run RDAP — common for some ccTLDs. Legacy port-43 WHOIS would be needed instead, which this script doesn't do |
| `lookup failed (...)`                            | Network/timeout issue, or the registry rate-limited/blocked the request |
| `registry returned no entities (privacy/thin registry)` | Record exists but publishes no contact data (privacy protection or thin registry) |
| `no abuse contact published`                     | Registrar name was found, but no abuse-role contact was listed        |

## Known limitations

- Subdomains (e.g. `mail.example.com`) won't return WHOIS/RDAP data — only
  registered (second-level) domains are covered by RDAP.
- Some ccTLDs (`.ke` among others) have partial or no RDAP support; expect
  more `n/a` results there.
- Sequential DNS/RDAP resolution (not parallelized) — a list of several
  hundred domains with WHOIS enabled will take a while. Use `-NoWhois` for
  a quick DNS-only pass on large lists.
- Each RDAP lookup has a short built-in delay to avoid rate-limiting
  registry servers.

## Troubleshooting

| Symptom                                                        | Fix                                                                 |
|-----------------------------------------------------------------|----------------------------------------------------------------------|
| `cannot be loaded because running scripts is disabled`         | Re-run the `Set-ExecutionPolicy` command above in the same window   |
| `Cannot find path ... domains.txt`                              | Confirm you're in the right folder (`dir`, then `cd`)                |
| Everything shows `NO_A` even for domains you know are live      | Outbound DNS may be blocked — try `-Server 8.8.8.8`                  |
| All `registrar`/`abuse_email` columns are `n/a`                | Outbound HTTPS (443) may be blocked, or check the `whois_note` column for the specific reason |

## Disclaimer

For legitimate operational use (abuse handling, security investigations,
infrastructure triage). Be considerate of registry rate limits — avoid
running this against very large domain lists in short succession.
