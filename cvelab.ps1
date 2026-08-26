[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $candidate = Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"
    if (Test-Path -LiteralPath $candidate) {
        $python = $candidate
    } else {
        throw "Python 3.11+ was not found."
    }
}

& $python -m cvelab @Arguments
exit $LASTEXITCODE
