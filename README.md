# package-json-scanner

Scans all `package.json` files on a system to detect compromised or suspicious npm dependencies. Useful for identifying supply chain attacks where a malicious version of a package has been installed.

## How it works

1. **Discovery** -- Automatically finds all `package.json` files across all available drives/filesystems.
2. **Scanning** -- Searches each file for exact dependency version strings that are known to be compromised.
3. **Reporting** -- Outputs a report listing every infected file and which terms matched.

## Scripts

| Script | Platform | Parallel |
|---|---|---|
| `find_lib.ps1` | Windows (PowerShell 5.1+) | Yes (Runspace pool) |
| `find_lib.sh` | Linux / macOS (Bash 4+) | No (sequential with progress) |

Both scripts produce identical output.

## Usage

### Windows

```powershell
.\find_lib.ps1
```

### Linux / macOS

```bash
chmod +x find_lib.sh
./find_lib.sh
```

## Configuration

Edit the search terms at the top of either script:

**PowerShell:**
```powershell
$SearchStrings = @(
    '"axios": "0.30.4"'
    '"axios": "1.14.1"'
)
```

**Bash:**
```bash
SEARCH_STRINGS=(
    '"axios": "0.30.4"'
    '"axios": "1.14.1"'
)
```

The PowerShell script auto-detects all filesystem drives via `Get-PSDrive`. The Bash script auto-detects mounted filesystems via `findmnt`, falling back to `/`.

## Output

Results are saved to `Infected_Files_Report.txt` in the script directory:

```
C:\projects\myapp\package.json | Matched: "axios": "0.30.4"
C:\projects\other\package.json | Matched: "axios": "0.30.4", "axios": "1.14.1"
```

## Requirements

- **Windows:** PowerShell 5.1 or later (built into Windows 10/11)
- **Linux/macOS:** Bash 4+, standard coreutils (`find`, `wc`, `cat`)

## License

MIT
