Write-Host "=== Cleaning JJWT dependencies from .m2 repository ==="

# 1. Close Java/IDE processes that may lock the .m2 folder
$processes = "java", "javaw", "maven", "idea64", "eclipse"
foreach ($p in $processes) {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# 2. Remove old JJWT versions
$repoPath = "$env:USERPROFILE\.m2\repository\io\jsonwebtoken"
if (Test-Path $repoPath) {
    Write-Host "Deleting $repoPath ..."
    try {
        Remove-Item -Recurse -Force $repoPath -ErrorAction Stop
        Write-Host "Old JJWT versions removed successfully."
    } catch {
        Write-Host "Could not delete, renaming instead..."
        $backup = "$repoPath.old_" + (Get-Date -Format "yyyyMMddHHmmss")
        Rename-Item $repoPath $backup -ErrorAction SilentlyContinue
        Write-Host "Renamed to: $backup"
    }
} else {
    Write-Host "No existing jsonwebtoken folder found."
}

# 3. Reinstall latest version
Write-Host "Running Maven clean install..."
mvn clean install -U -DskipTests

# 4. Verify installed versions
Write-Host "Verifying JJWT version..."
mvn dependency:tree | Select-String "io.jsonwebtoken"

Write-Host "=== Done. If you see only version 0.12.5, everything is clean. ==="
