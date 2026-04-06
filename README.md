# Cybersecurity-search

Search for multiple terms simultaneously across any file on your device. Available as both a PowerShell script (Windows) and a Bash script (Linux/macOS), these tools automatically discover all target files across every drive and filesystem, then scan them in parallel for any number of user-defined search strings.

Originally built to detect compromised npm packages in `package.json` files, but easily adaptable to search for any content in any file type.

## Process Diagram

```
┌─────────────────────────────────────────────────────────┐
│                        START                            │
└────────────────────────┬────────────────────────────────┘
                         │
                         v
┌─────────────────────────────────────────────────────────┐
│              Auto-Detect All Drives                     │
│                                                         │
│  PowerShell: Get-PSDrive -PSProvider FileSystem          │
│  Bash:       findmnt / fallback to "/"                  │
└────────────────────────┬────────────────────────────────┘
                         │
                         v
┌─────────────────────────────────────────────────────────┐
│          Recursively Find Target Files                  │
│                                                         │
│  Searches every detected drive for files matching       │
│  the target filename (e.g. "package.json")              │
│                                                         │
│  Output: package_json.txt (list of file paths)          │
└────────────────────────┬────────────────────────────────┘
                         │
                         v
┌─────────────────────────────────────────────────────────┐
│        Scan Each File for All Search Terms              │
│                                                         │
│  ┌───────────────┐   ┌──────────────────────────────┐   │
│  │ Search Terms  │   │  For each file:              │   │
│  │               │   │    Read contents              │   │
│  │  "axios": ... │──>│    Check against ALL terms    │   │
│  │  "lodash": ...|   │    Collect matches            │   │
│  │  ...          │   │                              │   │
│  └───────────────┘   └──────────────┬───────────────┘   │
│                                     │                   │
│  PowerShell: Parallel (Runspace pool, 1 thread/core)    │
│  Bash:       Sequential with live progress bar          │
└────────────────────────┬────────────────────────────────┘
                         │
                         v
┌─────────────────────────────────────────────────────────┐
│                  Generate Report                        │
│                                                         │
│  Infected_Files_Report.txt                              │
│  ┌─────────────────────────────────────────────────┐    │
│  │ /path/to/file | Matched: "term1", "term2"      │    │
│  │ /path/to/other | Matched: "term1"               │    │
│  └─────────────────────────────────────────────────┘    │
└────────────────────────┬────────────────────────────────┘
                         │
                         v
┌─────────────────────────────────────────────────────────┐
│                        DONE                             │
└─────────────────────────────────────────────────────────┘
```

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

Edit the search terms at the top of either script. You can add as many terms as needed:

**PowerShell:**
```powershell
$SearchStrings = @(
    '"axios": "0.30.4"'
    '"axios": "1.14.1"'
    '"lodash": "4.17.99"'
)
```

**Bash:**
```bash
SEARCH_STRINGS=(
    '"axios": "0.30.4"'
    '"axios": "1.14.1"'
    '"lodash": "4.17.99"'
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
