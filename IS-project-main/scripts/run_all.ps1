param(
    [switch]$WithDemo,
    [switch]$WithAttack,
    [switch]$SkipTests,
    [int]$AttackTrials = 8,
    [int]$AttackChallengeBits = 16,
    [string]$VenvPath = ".venv"
)

$python = "$VenvPath\Scripts\python.exe"
if (-Not (Test-Path $python)) {
    Write-Error "Virtual environment not found at $VenvPath"
    exit 1
}

$args = @("scripts/run_all.py")
if ($WithDemo) { $args += "--with-demo" }
if ($WithAttack) { $args += "--with-attack" }
if ($SkipTests) { $args += "--skip-tests" }
$args += @("--attack-trials", "$AttackTrials", "--attack-challenge-bits", "$AttackChallengeBits")

& $python $args
