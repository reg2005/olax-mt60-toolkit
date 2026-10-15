# Pass arguments directly to Python; no Invoke-Expression, no stored credentials.
$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if ($args.Count -gt 0 -and $args[0] -eq 'setup') {
    $extra = @($args | Select-Object -Skip 1)
    & py -3.12 (Join-Path $PSScriptRoot 'setup.py') @extra
    exit $LASTEXITCODE
}
if (-not (Test-Path $python)) {
    Write-Error 'Сначала выполните .\olax.ps1 setup'
    exit 1
}
& $python (Join-Path $PSScriptRoot 'olax.py') @args
exit $LASTEXITCODE
