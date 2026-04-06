# Works on Windows PowerShell 5.1
$SearchRoots    = (Get-PSDrive -PSProvider FileSystem).Root
$ExportFilePath = "C:\projects\json_corruption\package_json.txt"
$SearchStrings  = @(
    '"axios": "0.30.4"'
    '"axios": "1.14.1"'
)
$OutputReport   = "C:\projects\json_corruption\Infected_Files_Report.txt"

# Step 1: Discover all package.json files
Write-Host "Searching for package.json files in: $($SearchRoots -join ', ')..." -ForegroundColor Cyan
$FilePaths = @()
foreach ($Root in $SearchRoots) {
    $FilePaths += Get-ChildItem -Path $Root -Filter "package.json" -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
}
$FilePaths | Out-File -FilePath $ExportFilePath
Write-Host "Found $($FilePaths.Count) package.json files. List saved to $ExportFilePath" -ForegroundColor Green

# Step 2: Scan files for search terms
$Threads = [Environment]::ProcessorCount

Write-Host "Starting Runspace pool with $Threads threads to scan $($FilePaths.Count) files for $($SearchStrings.Count) search terms..." -ForegroundColor Cyan

# Create and open the Runspace Pool
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$RunspacePool.Open()
$Jobs = @()

# Dispatch jobs to the pool
foreach ($File in $FilePaths) {
    $PowerShell = [powershell]::Create().AddScript({
        param($Path, $Patterns)
        if (Test-Path $Path -PathType Leaf) {
            $Content = Get-Content -Path $Path -Raw
            $Matched = @()
            foreach ($Pattern in $Patterns) {
                if ($Content.Contains($Pattern)) {
                    $Matched += $Pattern
                }
            }
            if ($Matched.Count -gt 0) {
                return [PSCustomObject]@{
                    Path     = $Path
                    Matches  = $Matched
                }
            }
        }
    }).AddArgument($File).AddArgument($SearchStrings)

    $PowerShell.RunspacePool = $RunspacePool

    $Jobs += [PSCustomObject]@{
        Pipe   = $PowerShell
        Result = $PowerShell.BeginInvoke()
    }
}

# Collect results
$InfectedFiles = @()
foreach ($Job in $Jobs) {
    $Found = $Job.Pipe.EndInvoke($Job.Result)
    if ($Found) { $InfectedFiles += $Found }
    $Job.Pipe.Dispose()
}

# Cleanup Runspaces
$RunspacePool.Close()
$RunspacePool.Dispose()

# Save and display results
$Report = @()
foreach ($Entry in $InfectedFiles) {
    $Report += "$($Entry.Path) | Matched: $($Entry.Matches -join ', ')"
}
$Report | Out-File -FilePath $OutputReport
Write-Host "Search complete. Found $($InfectedFiles.Count) infected files. Results saved to $OutputReport" -ForegroundColor Green