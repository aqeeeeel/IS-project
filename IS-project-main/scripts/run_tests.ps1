param(
    [string]$VenvPath = ".venv"
)

$python = "$VenvPath\Scripts\python.exe"
if (-Not (Test-Path $python)) {
    Write-Error "Virtual environment not found at $VenvPath"
    exit 1
}

& $python -m pytest
