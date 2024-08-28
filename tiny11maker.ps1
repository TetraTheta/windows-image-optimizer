param(
  [switch] $CopyBin = $false,
  [switch] $CopyTweak = $false,
  [switch] $Debug = $false,
  [switch] $RemoveEdge = $false,
  [System.IO.FileInfo] $ScratchDisk = $env:SystemDrive
)

$ScriptVersion = '2024-08-28'

$packageRemovePrefix = @(
  'Clipchamp.Clipchamp_'
  'Microsoft.549981C3F5F10_'
  'Microsoft.BingNews_'
  'Microsoft.BingWeather_'
  'Microsoft.GamingApp_'
  'Microsoft.GetHelp_'
  'Microsoft.Getstarted_'
  'Microsoft.MicrosoftOfficeHub_'
  'Microsoft.MicrosoftSolitaireCollection_'
  'Microsoft.People_'
  'Microsoft.PowerAutomateDesktop_'
  'Microsoft.Todos_'
  'Microsoft.WindowsAlarms_'
  'microsoft.windowscommunicationsapps_'
  'Microsoft.WindowsFeedbackHub_'
  'Microsoft.WindowsMaps_'
  'Microsoft.WindowsSoundRecorder_'
  'Microsoft.Xbox.TCUI_'
  'Microsoft.XboxGameOverlay_'
  'Microsoft.XboxGamingOverlay_'
  'Microsoft.XboxSpeechToTextOverlay_'
  'Microsoft.YourPhone_'
  'Microsoft.ZuneMusic_'
  'Microsoft.ZuneVideo_'
  'MicrosoftCorporationII.MicrosoftFamily_'
  'MicrosoftCorporationII.QuickAssist_'
  'MicrosoftTeams_'
)

#region Helper Function
###################
# Helper Function #
###################
function ConvertTo-Boolean {
  param([string] $Value)
  $Value = $Value.ToLower()
  switch ($Value) {
    '0' { return $false }
    '1' { return $true }
    'false' { return $false }
    'n' { return $false }
    'no' { return $false }
    'ok' { return $true }
    'true' { return $true }
    'y' { return $true }
    'yes' { return $true }
    default { throw 'Invalid input. Must be "yes", "no", "y", "n", "true", "false", "1", "0", or "ok".' }
  }
}
function Enable-Privilege {
  # this function allows PowerShell to take ownership of the Scheduled Tasks registry key from TrustedInstaller. Based on Jose Espitia's script.
  param(
    [string]
    [ValidateSet('SeAssignPrimaryTokenPrivilege', 'SeAuditPrivilege', 'SeBackupPrivilege', 'SeChangeNotifyPrivilege', 'SeCreateGlobalPrivilege', 'SeCreatePagefilePrivilege', 'SeCreatePermanentPrivilege', 'SeCreateSymbolicLinkPrivilege', 'SeCreateTokenPrivilege', 'SeDebugPrivilege', 'SeEnableDelegationPrivilege', 'SeImpersonatePrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeIncreaseQuotaPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeLoadDriverPrivilege', 'SeLockMemoryPrivilege', 'SeMachineAccountPrivilege', 'SeManageVolumePrivilege', 'SeProfileSingleProcessPrivilege', 'SeRelabelPrivilege', 'SeRemoteShutdownPrivilege', 'SeRestorePrivilege', 'SeSecurityPrivilege', 'SeShutdownPrivilege', 'SeSyncAgentPrivilege', 'SeSystemEnvironmentPrivilege', 'SeSystemProfilePrivilege', 'SeSystemtimePrivilege', 'SeTakeOwnershipPrivilege', 'SeTcbPrivilege', 'SeTimeZonePrivilege', 'SeTrustedCredManAccessPrivilege', 'SeUndockPrivilege', 'SeUnsolicitedInputPrivilege')]
    $Privilege,
    $ProcessId = $PID, # The process on which to adjust the privilege. Defaults to the current process.
    [Switch] $Disable # Switch to disable the privilege, rather than enable it.
  )
  $definition = @'
using System;
using System.Runtime.InteropServices;
  
public class AdjPriv {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege (long processHandle, string privilege, bool disable) {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = new IntPtr(processHandle);
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    if (disable) { tp.Attr = SE_PRIVILEGE_DISABLED; }
    else { tp.Attr = SE_PRIVILEGE_ENABLED; }
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
  }
}
'@
  $processHandle = (Get-Process -Id $ProcessId).Handle
  $type = Add-Type $definition -PassThru
  $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

function Get-Ownership {
  param(
    [string] $Path,
    [switch] $Directory
  )
  if ($Directory) {
    Start-Process -NoNewWindow -Wait -FilePath 'takeown' -ArgumentList "/F $Path /R" | Out-Null
    Start-Process -NoNewWindow -Wait -FilePath 'icacls' -ArgumentList "`"$Path`" /grant Administrators:F /T /C" | Out-Null
  } else {
    Start-Process -NoNewWindow -Wait -FilePath 'takeown' -ArgumentList "/F $Path" | Out-Null
    Start-Process -NoNewWindow -Wait -FilePath 'icacls' -ArgumentList "`"$Path`" /grant Administrators:F" | Out-Null
  }
}
function Format-Path {
  param([string] $Path)
  $Path = $Path.Replace('/', '\').TrimEnd('\')
  if ($Path.Length -eq 1) {
    $Path += ':'
  }
  return $Path
}
function Add-Reg {
  param(
    [string] $Path,
    [string] $Key,
    [string][ValidateSet('REG_SZ', 'REG_MULTI_SZ', 'REG_EXPAND_SZ', 'REG_DWORD', 'REG_QWORD', 'REG_BINARY', 'REG_NONE')] $Type,
    [string] $Value,
    [switch] $Verbose = $false
  )
  if ($Verbose) {
    Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "add `"$Path`" /v `"$Key`" /t `"$Type`" /d `"$Value`" /f"
  } else {
    Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "add `"$Path`" /v `"$Key`" /t `"$Type`" /d `"$Value`" /f" | Out-Null
  }
}
function Remove-Reg {
  param(
    [string] $Path,
    [string] $Key = '',
    [switch] $Verbose = $false
  )
  if ($Key -eq '') {
    if ($Verbose) {
      Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "delete `"$Path`" /f"
    } else {
      Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "delete `"$Path`" /f" | Out-Null
    }
  } else {
    if ($Verbose) {
      Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "delete `"$Path`" /v `"$Key`" /f"
    } else {
      Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "delete `"$Path`" /v `"$Key`" /f" | Out-Null
    }
  }
}
function Write-Header {
  param(
    [string] $Object,
    [string] $Color = 'Green',
    [string] $Header = 'INFO',
    [switch] $NoNewline = $false
  )
  Write-Host -NoNewline -ForegroundColor $Color "$Header "
  if ($NoNewline) {
    Write-Host $Object -NoNewline
  } else {
    Write-Host $Object
  }
}
function Write-HInfo {
  param([string] $Object)
  Write-Header -Color 'Green' -Header 'INFO' $Object
}
function Write-HWarn {
  param([string] $Object)
  Write-Header -Color 'Yellow' -Header 'WARN' $Object
}
function Write-HError {
  param([string] $Object)
  Write-Header -Color 'Red' -Header 'ERROR' $Object
}
#######################
# Helper Function END #
#######################
#endregion Helper Function

# Enable debugging
if ($Debug) {
  Set-PSDebug -Trace 1
}

# Check validity of $ScratchDisk
try {
  $ScratchDisk = New-Object System.IO.FileInfo $ScratchDisk
  $ScratchDisk = Format-Path -Path $ScratchDisk
} catch {
  Write-HError "Invalid path provided for ScratchDisk: $ScratchDisk"
  exit 1
}

# Check if PowerShell execution is restricted
if ((Get-ExecutionPolicy) -eq 'Restricted') {
  Write-HWarn 'Your current PowerShell Execution Policy is set to Restricted, which prevents scripts from running.'
  $response = Read-Host 'Do you want to change it to RemoteSigned? >'
  try {
    $response = ConvertTo-Boolean -Value $response
    if ($response) {
      Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    } else {
      Write-HError 'User refused to change PowerShell Execution Policy. Exiting...'
      exit 1
    }
  } catch {
    Write-HError 'Cannot parse input to boolean value. Exiting...'
    exit 1
  }
}

# Check and run the script as admin if required
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-HInfo 'Restarting Tiny11 image creator as admin in a new window, you can close this one.'
  $newProcess = New-Object System.Diagnostics.ProcessStartInfo 'PowerShell';
  $newProcess.Arguments = $myInvocation.MyCommand.Definition;
  $newProcess.Verb = 'runas';
  [System.Diagnostics.Process]::Start($newProcess);
  exit
}

# Start logging
Start-Transcript -Path "$PSScriptRoot\tiny11.log" 

# Configure window title
$Host.UI.RawUI.WindowTitle = 'Tiny11 Image Creator'
Clear-Host

Write-HInfo "Welcome to the tiny11 image creator! Release: $ScriptVersion"

# Get $MediaDrive for copying Windows 11 image
New-Item -ItemType Directory -Force -Path "$ScratchDisk\tiny11\sources" | Out-Null
$MediaDrive = Read-Host 'Please enter the drive letter for the Windows 11 image >'
$MediaDrive = Format-Path -Path $MediaDrive

# Copy install.esd or install.wim (no boot.wim modification)
$_isESDPresent = Test-Path "$MediaDrive\sources\install.esd"
$_isWIMPresent = Test-Path "$MediaDrive\sources\install.wim"
$wimFilePath = "$ScratchDisk\tiny11\sources\install.wim"
if ($_isWIMPresent -and $_isESDPresent) {
  Write-HWarn 'Both install.wim and install.esd are detected. Copying install.wim only...'
  Copy-Item -Path "$MediaDrive\install.wim" -Destination "$ScratchDisk\tiny11\sources" -Recurse -Force | Out-Null
} elseif ($_isESDPresent) {
  Write-HInfo 'Found install.esd, converting to install.wim...'
  Start-Process -NoNewWindow -Wait -FilePath 'dism' -ArgumentList "/English /Get-ImageInfo /ImageFile:$MediaDrive\sources\install.esd"
  $index = $null # temporary value
    do {
      $index = Read-Host 'Please enter the image index to extract (default: 1) >'
      if ($index -eq "") {
        $index = 1
      }
      $_isValid = [int]::TryParse($index, [ref]$parsedIndex)
      if (-not $_isValid -or $parsedIndex -lt 0) {
        Write-HError 'Invalid input. Please enter a valid number >= 0.'
      }
    } until ($_isValid -and $parsedIndex -ge 0)
    $index = $parsedIndex
  Write-HInfo 'Converting install.esd to install.wim. This may take a while...'
  Start-Process -NoNewWindow -Wait -FilePath 'dism' -ArgumentList "/Export-Image /SourceImageFile:`"$MediaDrive\sources\install.esd`" /SourceIndex:$index /DestinationImageFile:`"$wimFilePath`" /Compress:max /CheckIntegrity"
} elseif ($_isWIMPresent) {
  Write-HWarn 'Found install.wim. Copying...'
  Copy-Item -Path "$MediaDrive\install.wim" -Destination "$ScratchDisk\tiny11\sources" -Recurse -Force | Out-Null
} else {
  Write-HError 'Failed to find Windows OS installation files in the specified Drive Letter.'
  Write-HError 'Please enter the correct DVD Drive Letter.'
  exit
}

Write-HInfo 'Copy complete!'
Start-Sleep -Seconds 2
Clear-Host

# Mount install.wim
$MountDir = "$MountDir"
Write-HInfo 'Getting image information:'
Start-Process -NoNewWindow -Wait -FilePath 'dism' -ArgumentList "/English /Get-ImageInfo /ImageFile:$wimFilePath"
$index = $null # temporary value
do {
  $index = Read-Host 'Please enter the image index (default: 1) '
  if ($index -eq '') {
    $index = 1
  }
  $_isValid = [int]::TryParse($index, [ref]$parsedIndex)
  if (-not $_isValid -or $parsedIndex -lt 0) {
    Write-HError 'Invalid input. Please enter a valid number >= 0.'
  }
} until ($_isValid -and $parsedIndex -ge 0)
Write-HInfo 'Mounting Windows image. This may take a while.'
Get-Ownership -Path $wimFilePath
try {
  Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false
}
catch {
  Write-HError 'Failed to make install.wim not read-only. Aborting...'
  exit 1
}
New-Item -ItemType Directory -Path $MountDir | Out-Null
Start-Process -NoNewWindow -Wait -FilePath 'dism' -ArgumentList "/English /Mount-Image /ImageFile:$wimFilePath /Index:$index /MountDir:$MountDir"

# Get image information
$imageIntl = Invoke-Expression -Command "dism /English /Get-Intl /Image:$MountDir"
$languageLine = $imageIntl -split '\r?\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }
if ($languageLine) {
  $languageCode = $Matches[1]
  Write-HInfo "Image System UI Language Code: $languageCode"
}
else {
  Write-HInfo 'Image System UI Language Code not found.'
}
$imageInfo = Invoke-Expression -Command "dism /English /Get-ImageInfo /ImageFile:$wimFilePath /Index:$index"
$arch = $null # temporary value
$imageInfo -split '\r?\n' | ForEach-Object {
  if ($_ -like '*Architecture : *') {
    $arch = $_ -replace 'Architecture : ', ''
    if ($arch -eq 'x64') {
      $arch = 'amd64'
    }
    break
  }
}
if ($arch) {
  Write-HInfo "Image Architecture: $arch"
} else {
  Write-HError 'Image Architecture information not found.'
}

# Remove packages
Write-HInfo 'Mounting complete! Performing removal of applications...'
$installedPackages = Invoke-Expression -Command "dism /English /Get-ProvisionedAppxPackages /Image:$MountDir" | ForEach-Object {
  if ($_ -match 'PackageName : (.*)') {
    $Matches.1
  }
}
$installedPackages | Where-Object {
  $_name = $_
  $packageRemovePrefix -contains ($packageRemovePrefix | Where-Object { $_name -like "$_*" })
} | ForEach-Object {
  Write-HInfo "Removing $_"
  Start-Process -NoNewWindow -Wait -FilePath 'dism' -ArgumentList "/English /Image:$MountDir /Remove-ProvisionedAppxPackage /PackageName:$_"
}

# Remove Edge
if ($RemoveEdge) {
  Write-HInfo 'Removing Edge...'
  # Edge & EdgeUpdate & EdgeCore
  Remove-Item -Path "$MountDir\Program Files (x86)\Microsoft\Edge" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-Item -Path "$MountDir\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-Item -Path "$MountDir\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
  # Edge WebView (This will break few program that relies on this)
  $_edgeWBPath = Get-ChildItem -Path "$MountDir\Windows\WinSxS" -Filter "$arch`_microsoft-edge-webview_31bf3856ad364e35*" -Directory | Select-Object -ExpandProperty FullName
  if ($_edgeWBPath) {
    Get-Ownership -Path $_edgeWBPath -Directory
    Remove-Item -Path $_edgeWBPath -Recurse -Force | Out-Null
  } else {
    Write-HWarn "Failed to located Edge Webview for $arch"
  }
  Get-Ownership -Path "$MountDir\Windows\System32\Microsoft-Edge-Webview" -Directory
  Remove-Item -Path "$MountDir\Windows\System32\Microsoft-Edge-Webview" -Recurse -Force | Out-Null
}

# Remove OneDrive
Write-HInfo 'Removing OneDrive...'
Get-Ownership -Path "$MountDir\Windows\System32\OneDriveSetup.exe"
Remove-Item -Path "$MountDir\Windows\System32\OneDriveSetup.exe" -Force | Out-Null

Write-HInfo 'Removing file complete!'
Start-Sleep -Seconds 2
Clear-Host

# Mount registry hive
Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "load HKLM\zDEFAULT `"$MountDir\Windows\System32\config\default`"" | Out-Null
Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "load HKLM\zNTUSER `"$MountDir\Users\Default\ntuser.dat`"" | Out-Null
Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "load HKLM\zSOFTWARE `"$MountDir\Windows\System32\config\SOFTWARE`"" | Out-Null
Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "load HKLM\zSYSTEM `"$MountDir\Windows\System32\config\SYSTEM`"" | Out-Null

# Bypass system requirements
Write-HInfo 'Bypass system requirements'
Add-Reg -Path 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' -Key 'SV1' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' -Key 'SV2' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' -Key 'SV1' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' -Key 'SV2' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zSYSTEM\Setup\LabConfig' -Key 'BypassCPUCheck' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSYSTEM\Setup\LabConfig' -Key 'BypassRAMCheck' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSYSTEM\Setup\LabConfig' -Key 'BypassSecureBootCheck' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSYSTEM\Setup\LabConfig' -Key 'BypassStorageCheck' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSYSTEM\Setup\LabConfig' -Key 'BypassTPMCheck' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSYSTEM\Setup\MoSetup' -Key 'AllowUpgradesWithUnsupportedTPMOrCPU' -Type 'REG_DWORD' -Value '1'

# Disable sponsored apps
Write-HInfo 'Disable sponsored apps'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'FeatureManagementEnabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'OemPreInstalledAppsEnabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'PreInstalledAppsEnabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'PreInstalledAppsEverEnabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SilentInstalledAppsEnabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SoftLandingEnabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-310093Enabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-338388Enabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-338389Enabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-338393Enabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-353694Enabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-353696Enabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SystemPaneSuggestionsEnabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' -Key 'ConfigureStartPins' -Type 'REG_SZ' -Value '{"pinnedList": [{}]}'
Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' -Key 'DontOfferThroughWUAU' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' -Key 'DisablePushToInstall' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' -Key 'DisableCloudOptimizedContent' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' -Key 'DisableConsumerAccountStateContent' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' -Key 'DisableWindowsConsumerFeatures' -Type 'REG_DWORD' -Value '1'
Remove-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
Remove-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'

# Allow local account on OOBE
Write-HInfo 'Allow local account on OOBE'
Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' -Key 'BypassNRO' -Type 'REG_DWORD' -Value '1'
#Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$MountDir\Windows\System32\Sysprep\autounattend.xml" -Force | Out-Null

# Remove Chat icon from task bar
Write-HInfo 'Remove Chat icon from task bar'
Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' -Key 'ChatIcon' -Type 'REG_DWORD' -Value '3'
Add-Reg -Path 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Key 'TaskbarMn' -Type 'REG_DWORD' -Value '0'

# Remove Edge (Registry)
Write-HInfo 'Remove Edge (Registry)'
Remove-Reg -Path 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge'
Remove-Reg -Path 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update'

# Disable OneDrive backup
Write-HInfo 'Disable OneDrive backup'
Add-Reg -Path "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" -Key 'DisableFileSyncNGSC' -Type 'REG_DWORD' -Value '1'

# Disable telemetry
Write-HInfo 'Disabling telemetry'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' -Key 'RestrictImplicitInkCollection' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' -Key 'RestrictImplicitTextCollection' -Type 'REG_DWORD' -Value '1'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' -Key 'HarvestContacts' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' -Key 'Enabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' -Key 'AcceptedPrivacyPolicy' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' -Key 'HasAccepted' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Key 'Enabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' -Key 'TailoredExperiencesWithDiagnosticDataEnabled' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' -Key 'AllowTelemetry' -Type 'REG_DWORD' -Value '0'
Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' -Key 'Start' -Type 'REG_DWORD' -Value '4'

# Update permission for registry key protected by TrustedInstaller
Write-HInfo 'Disable task protected by TrustedInstaller'
Enable-Privilege 'SeTakeOwnershipPrivilege'
$adminGroup = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount])
$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
$regACL = $regKey.GetAccessControl()
$regACL.SetOwner($adminGroup)
$regKey.SetAccessControl($regACL)
$regKey.Close()
Write-HInfo "Owner of `"HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`" changed to Administrators."
$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
$regACL = $regKey.GetAccessControl()
$regRule = New-Object System.Security.AccessControl.RegistryAccessRule ($adminGroup, 'FullControl', 'ContainerInherit', 'None', 'Allow')
$regACL.SetAccessRule($regRule)
$regKey.SetAccessControl($regACL)
$regKey.Close()
Write-HInfo "Permissions of `"HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`" modified for Administrators."

#TODO
Write-HInfo 'Deleting Application Compatibility Appraiser'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /f >null
Write-HInfo 'Deleting Customer Experience Improvement Program'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /f >null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /f >null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /f >null
Write-HInfo 'Deleting Program Data Updater'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /f >null
Write-HInfo 'Deleting autochk proxy'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}" /f >null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}" /f >null
Write-HInfo 'Deleting QueueReporting'
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /f >null
Write-HInfo "Tweaking complete!"
Write-HInfo "Unmounting Registry..."
$regKey.Close()
reg unload HKLM\zCOMPONENTS >null
reg unload HKLM\zDRIVERS >null
reg unload HKLM\zDEFAULT >null
reg unload HKLM\zNTUSER >null
reg unload HKLM\zSCHEMA >null
reg unload HKLM\zSOFTWARE
reg unload HKLM\zSYSTEM >null
Write-HInfo "Cleaning up image..."
& 'dism' '/English' "/image:$MountDir" '/Cleanup-Image' '/StartComponentCleanup' '/ResetBase' >null
Write-HInfo "Cleanup complete."
Write-HInfo ' '
Write-HInfo "Unmounting image..."
& 'dism' '/English' '/unmount-image' "/mountdir:$MountDir" '/commit'
Write-HInfo "Exporting image..."
& 'dism' '/English' '/Export-Image' "/SourceImageFile:$ScratchDisk\tiny11\sources\install.wim" "/SourceIndex:$index" "/DestinationImageFile:$ScratchDisk\tiny11\sources\install2.wim" '/compress:recovery'
Remove-Item -Path "$ScratchDisk\tiny11\sources\install.wim" -Force >null
Rename-Item -Path "$ScratchDisk\tiny11\sources\install2.wim" -NewName "install.wim" >null



# Finishing up
Write-HInfo "Creation completed! Press any key to exit the script..."
Read-Host "Press Enter to continue"
Write-HInfo "Performing Cleanup..."
Remove-Item -Path "$ScratchDisk\tiny11" -Recurse -Force >null
Remove-Item -Path "$MountDir" -Recurse -Force >null

# Stop the transcript
Stop-Transcript

exit
