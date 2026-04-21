param(
    [string]$VenvPath = ".venv"
)

python -m venv $VenvPath
& "$VenvPath\Scripts\python.exe" -m pip install --upgrade pip
& "$VenvPath\Scripts\python.exe" -m pip install -e .[dev]
