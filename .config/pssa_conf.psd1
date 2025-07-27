# https://github.com/PowerShell/vscode-powershell/blob/main/examples/PSScriptAnalyzerSettings.psd1
@{
  ExcludeRules = @(
    'PSAvoidUsingInvokeExpression',
    'PSAvoidUsingWriteHost',
    'PSUseApprovedVerbs',
    'PSUseShouldProcessForStateChangingFunctions'
  )
}
