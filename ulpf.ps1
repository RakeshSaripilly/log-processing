param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgsList
)
python -m core.cli @ArgsList
