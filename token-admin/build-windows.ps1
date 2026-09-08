param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
& $Python -c "import PyInstaller, cryptography, tkinter"
if ($LASTEXITCODE -ne 0) { throw "Python prerequisites missing. No packages were installed." }
& $Python -m PyInstaller --noconfirm --clean --onefile --windowed `
  --name RDP-Token-Manager --icon assets/token_access.ico `
  --version-file windows-version.txt `
  --add-data "assets;assets" token_admin.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }
Write-Host "Built dist\RDP-Token-Manager.exe (vendor runtimes must be provided separately)."
