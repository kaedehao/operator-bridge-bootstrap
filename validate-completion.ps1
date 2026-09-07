# Pure parser/function tests. Never execute the finalizer's top-level statements.
param([string]$Path = (Join-Path $PSScriptRoot 'complete-maintenance.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }
foreach ($name in @('Assert-True', 'Assert-Address')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if (-not $definition) { throw "Missing function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
foreach ($address in @('100.64.0.1', '100.127.255.254')) { Assert-Address $address }
foreach ($address in @('127.0.0.1', '100.63.255.255', '100.128.0.0', '100.64.0.1/32', '100.64.0.01', '::1', 'example.test', '')) {
    $rejected = $false
    try { Assert-Address $address } catch { $rejected = $true }
    if (-not $rejected) { throw "Invalid address accepted: $address" }
}
Write-Output 'PASS: PowerShell syntax and isolated address-validation tests. No installations or service mutations executed.'
