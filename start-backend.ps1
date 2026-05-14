# backend/start-backend.ps1
# Wrapper so you can run the root start script while inside the `backend` folder.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

$parent = Join-Path $ScriptDir '..\start-backend.ps1'
if (Test-Path $parent) {
    Write-Host "Found parent script at $parent - invoking it."
    & $parent
} else {
    Write-Host "Parent start-backend.ps1 not found at $parent. Try running the root script from project root."
}
