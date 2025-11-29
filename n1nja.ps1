param(
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$Arguments
)

$scriptPath = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "n1nja_cli_minimal.py"
python $scriptPath @Arguments