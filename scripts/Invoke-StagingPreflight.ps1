param(
 [Parameter(Mandatory=$true)][ValidateSet('plan-bootstrap','inspect-bootstrap')][string]$Phase,
 [Parameter(Mandatory=$true)][string]$Config,
 [string]$Output
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$resolved = (Resolve-Path -LiteralPath $Config).Path
$arguments = @((Join-Path $PSScriptRoot 'staging-preflight-cli.mjs'), $Phase, $resolved)
if ($Phase -eq 'plan-bootstrap') {
 if (-not $Output) { throw 'Specify a new local bootstrap configuration path in the repository root.' }
 $target = [IO.Path]::GetFullPath($Output)
 if ([IO.Path]::GetDirectoryName($target) -ne $root -or [IO.Path]::GetFileName($target) -ne 'wrangler.bootstrap.local.jsonc') { throw 'Use wrangler.bootstrap.local.jsonc in the repository root.' }
 $arguments += $target
}
& node @arguments
if ($LASTEXITCODE -ne 0) { throw "Staging preflight failed with exit code $LASTEXITCODE." }
