param(
  [System.IO.DirectoryInfo][Parameter(Mandatory, Position = 0)] $MountDir # Directory where install.wim is mounted.
)

$ScriptVersion = '250727'

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
  'Microsoft.OutlookForWindows_'
  'Microsoft.People_'
  'Microsoft.PowerAutomateDesktop_'
  'Microsoft.Todos_'
  'Microsoft.Windows.DevHome_' # DevHome will be deprecated
  'Microsoft.WindowsAlarms_'
  'Microsoft.WindowsCamera_'
  'microsoft.windowscommunicationsapps_'
  'Microsoft.WindowsFeedbackHub_'
  'Microsoft.WindowsMaps_'
  'Microsoft.WindowsSoundRecorder_'
  'Microsoft.WindowsTerminal_'
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

#########################
# Console Output Helper #
#########################
function Write-HeaderMessage {
  [CmdletBinding()]
  param(
    [System.Object[]][Alias('Msg', 'Message')][Parameter(ValueFromPipeline, Position = 0)] $Object,
    [string] $Header,
    [System.ConsoleColor] $HeaderColor = [System.ConsoleColor]::Green
  )
  process {
    Write-Host -NoNewline -ForegroundColor $HeaderColor -Object "$Header"
    Write-Host -NoNewLine -Object ' '
    Write-Host -Object $Object
  }
}

function Write-HError {
  [CmdletBinding()]
  param(
    [System.Object[]][Alias('Msg', 'Message')][Parameter(ValueFromPipeline, Position = 0)] $Object,
    [string] $Header = 'ERROR',
    [System.ConsoleColor] $HeaderColor = [System.ConsoleColor]::Red
  )
  process { Write-HeaderMessage -Header $Header -HeaderColor $HeaderColor -Object $Object }
}

function Write-HInfo {
  [CmdletBinding()]
  param(
    [System.Object[]][Alias('Msg', 'Message')][Parameter(ValueFromPipeline, Position = 0)] $Object,
    [string] $Header = 'INFO ',
    [System.ConsoleColor] $HeaderColor = [System.ConsoleColor]::Green
  )
  process { Write-HeaderMessage -Header $Header -HeaderColor $HeaderColor -Object $Object }
}

#####################
# Permission Helper #
#####################
function Check-Admin {
  if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-HInfo 'Restarting the script as admin in a new window, you can close this one.'
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo 'PowerShell';
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = 'runas';
    [System.Diagnostics.Process]::Start($newProcess);
    exit 0
  }
}

function Get-Privilege {
  # This will only get 'SeTakeOwnershipPrivilege' privilege.
  $def = @'
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
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable) {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = new IntPtr(processHandle);
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    if(disable) { tp.Attr = SE_PRIVILEGE_DISABLED; } else { tp.Attr = SE_PRIVILEGE_ENABLED; }
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
  }
}
'@
  $pHandle = (Get-Process -Id $PID).Handle
  $type = Add-Type $def -PassThru
  $type[0]::EnablePrivilege($pHandle, 'SeTakeOwnershipPrivilege', $false)
}

###################
# Registry Helper #
###################
function Add-Reg {
  param(
    [string] $Path,
    [string] $Key,
    [string][ValidateSet('REG_SZ', 'REG_MULTI_SZ', 'REG_EXPAND_SZ', 'REG_DWORD', 'REG_QWORD', 'REG_BINARY', 'REG_NONE')] $Type,
    [string] $Value,
    [switch] $Verbose
  )
  if ($Verbose) {
    Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "add `"$Path`" /v `"$Key`" /t `"$Type`" /d `"$Value`" /f"
  }
  else {
    Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "add `"$Path`" /v `"$Key`" /t `"$Type`" /d `"$Value`" /f" | Out-Null
  }
}

function Remove-Reg {
  param(
    [string] $Path,
    [string] $Key = '',
    [switch] $Verbose
  )
  if ($Key -eq '') {
    if ($Verbose) {
      Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "delete `"$Path`" /f"
    }
    else {
      Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "delete `"$Path`" /f" | Out-Null
    }
  }
  else {
    if ($Verbose) {
      Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "delete `"$Path`" /v `"$Key`" /f"
    }
    else {
      Start-Process -NoNewWindow -Wait -FilePath 'reg' -ArgumentList "delete `"$Path`" /v `"$Key`" /f" | Out-Null
    }
  }
}

###############
# Script Body #
###############
function Main {
  param(
    [System.IO.DirectoryInfo] $MountDir
  )

  # Check MountDir
  if ((Get-Item $MountDir) -isnot [System.IO.DirectoryInfo]) {
    Write-HError "'$MountDir' is not a directory"
    exit 1
  }
  if ((Join-Path -Path $MountDir -ChildPath "Windows") -isnot [System.IO.DirectoryInfo]) {
    Write-HError "'$MountDir' is not WIM mounted directory"
    exit 1
  }

  # Check admin (restart script if needed)
  Check-Admin

  # Configure Console Window
  $Host.UI.RawUI.WindowTitle = "WindowsImageOptimizer r$ScriptVersion"
  Clear-Host

  # Remove Package
  $installedPackages = Invoke-Expression -Command "dism /English /Image:`"$MountDir`" /Get-ProvisionedAppxPackages" | ForEach-Object {
    if ($_ -match 'PackageName : (.*)') {
      $Matches[1]
    }
  }
  $packagesToRemove = $installedPackages | Where-Object {
    $packageName = $_
    $packageRemovePrefix -contains ($packageRemovePrefix | Where-Object { $packageName -like "$_*" })
  }
  foreach ($package in $packagesToRemove) {
    Write-HInfo "Removing '$package'"
    Invoke-Expression -Command "dism /English /Image:`"$MountDir`" /Remove-ProvisionedAppxPackage /PackageName:$package"
  }

  # TODO: Remove MS Edge only (Leave WebView)

  # Mount Registry Files
  Invoke-Expression -Command "reg load HKLM\zCOMPONENTS `"$MountDir\Windows\System32\config\COMPONENTS`"" | Out-Null
  Invoke-Expression -Command "reg load HKLM\zDEFAULT `"$MountDir\Windows\System32\config\default`"" | Out-Null # HKEY_USERS\.DEFAULT
  Invoke-Expression -Command "reg load HKLM\zNTUSER `"$MountDir\Users\Default\ntuser.dat`"" | Out-Null # HKEY_CURRENT_USER
  Invoke-Expression -Command "reg load HKLM\zSOFTWARE `"$MountDir\Windows\System32\config\SOFTWARE`"" | Out-Null # HKEY_LOCAL_MACHINE\SOFTWARE
  Invoke-Expression -Command "reg load HKLM\zSYSTEM `"$MountDir\Windows\System32\config\SYSTEM`"" | Out-Null # HKEY_LOCAL_MACHINE\SYSTEM

  # Get 'SeTakeOwnershipPrivilege' Privilege
  Get-Privilege

  # Take Ownership of Protected Registry Key
  $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
  $adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
  $rwSubTree = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
  $takeOwnership = [System.Security.AccessControl.RegistryRights]::TakeOwnership
  $changePermission = [System.Security.AccessControl.RegistryRights]::ChangePermissions
  $rKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks', $rwSubTree, $takeOwnership)
  $rACL = $rKey.GetAccessControl()
  $rACL.SetOwner($adminGroup)
  $rKey.SetAccessControl($rACL)
  $rKey.Close()
  $rKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks', $rwSubTree, $changePermission)
  $rACL = $rKey.GetAccessControl()
  $rRule = New-Object System.Security.AccessControl.RegistryAccessRule ($adminGroup, 'FullControl', 'ContainerInherit', 'None', 'Allow')
  $rACL.SetAccessRule($rRule)
  $rKey.SetAccessControl($rACL)
  $rKey.Close()

  #############################
  #    01 Default Settings    #
  #############################
  # Enable Local Account on OOBE
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' -Key 'BypassNRO' -Type REG_DWORD -Value 1

  # Disable Lock Screen
  Write-HInfo 'Disable Lock Screen'
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Personalization' -Key 'NoLockScreen' -Type REG_DWORD -Value 1

  # Enable Automatic Logon
  Write-HInfo 'Enable Automatic Logon'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -Key 'DevicePasswordLessBuildVersion' -Type REG_DWORD -Value 0

  # Prevent TW Folder Spam
  Write-HInfo 'Prevent TW Folder Spam'
  # 'Microsoft\Windows\Management\Provisioning\Logon'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{9C88D42B-6058-46C0-AF51-B164A1AAB4DE}'

  # Disable USB Selective Power Save (Experimental)
  Write-HInfo 'Disable USB Selective Power Save (Experimental)'
  Remove-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\Class\{4D36E965-E325-11CE-BFC1-08002BE10318}' -Key 'LowerFilter'
  Remove-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\Class\{4D36E965-E325-11CE-BFC1-08002BE10318}' -Key 'UpperFilter'

  # Boost USB Speed (Experimental)
  Write-HInfo 'Boost USB Speed (Experimental)'
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\054C00C1' -Key 'DeviceHackFlags' -Type REG_DWORD -Value 536870912
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\054C00C1' -Key 'MaximumTransferLength' -Type REG_DWORD -Value 2097120
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\058F6362' -Key 'DeviceHackFlags' -Type REG_DWORD -Value 256
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\058F6362' -Key 'MaximumTransferLength' -Type REG_DWORD -Value 2097120
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\05AC12XX' -Key 'DeviceHackFlags' -Type REG_DWORD -Value 32
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\05AC12XX' -Key 'MaximumTransferLength' -Type REG_DWORD -Value 2097120
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\05AC13XX' -Key 'DeviceHackFlags' -Type REG_DWORD -Value 32
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\05AC13XX' -Key 'MaximumTransferLength' -Type REG_DWORD -Value 2097120
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\05DCA431' -Key 'DeviceHackFlags' -Type REG_DWORD -Value 16
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\usbstor\05DCA431' -Key 'MaximumTransferLength' -Type REG_DWORD -Value 2097120

  # Disable Network Throttling
  Write-HInfo 'Disable Network Throttling'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Key 'NetworkThrottlingIndex' -Type REG_DWORD -Value 0

  # Disable Startup Program Delay
  Write-HInfo 'Disable Startup Program Delay'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Key 'StartupDelayInMSec' -Type REG_DWORD -Value 0

  # Unblock SetUserFTA
  Write-HInfo 'Unblock SetUserFTA'
  # Prevent UCPD Service Startup
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Services\UCPD' -Key 'Start' -Type REG_DWORD -Value 4
  # 'Microsoft\Windows\AppxDeploymentClient\UCPD velocity'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{471A373A-0CB5-4E87-9FDD-1F86F22036E1}'

  # Disable Automatic Proxy Detection
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Key 'AutoDetect' -Type REG_DWORD -Value 0

  # Disable BitLocker Device Encryption
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' -Key 'PreventDeviceEncryption' -Type REG_DWORD -Value 1


  ####################
  #    02 Privacy    #
  ####################
  # Disable Telemetry
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' -Key 'RestrictImplicitInkCollection' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' -Key 'RestrictImplicitTextCollection' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' -Key 'HarvestContacts' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' -Key 'Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' -Key 'AcceptedPrivacyPolicy' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' -Key 'HasAccepted' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Key 'Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' -Key 'TailoredExperiencesWithDiagnosticDataEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' -Key 'AllowTelemetry' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' -Key 'Start' -Type REG_DWORD -Value 4

  # Delete 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}'
  # Delete 'Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}'
  # Delete 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}'
  # Delete 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}'
  # Delete 'Microsoft\Windows\Application Experience\ProgramDataUpdater' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}'
  # Delete 'autochk proxy' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}'
  # Delete 'QueueReporting' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}'


  #####################
  #    03 Security    #
  #####################


  #########################
  #    04 Default Apps    #
  #########################
  # Prevent Sponsored App Install
  Write-HInfo 'Prevent Sponsored App Install'
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'ContentDeliveryAllowed' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'FeatureManagementEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'OemPreInstalledAppsEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'PreInstalledAppsEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SilentInstalledAppsEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SoftLandingEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-310093Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-338388Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-338389Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-338393Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-353694Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SubscribedContent-353696Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Key 'SystemPaneSuggestionsEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' -Key 'ConfigureStartPins' -Type REG_SZ -Value '{"pinnedList": [{}]}'
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' -Key 'DontOfferThroughWUAU' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' -Key 'DisablePushToInstall' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' -Key 'DisableCloudOptimizedContent' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' -Key 'DisableConsumerAccountStateContent' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' -Key 'DisableWindowsConsumerFeatures' -Type REG_DWORD -Value 1
  Remove-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
  Remove-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'

  # Disable Cortana
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' -Key 'AllowCloudSearch' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' -Key 'AllowCortana' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' -Key 'AllowCortanaAboveLock' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' -Key 'ConnectedSearchUseWeb' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' -Key 'ConnectedSearchUseWebOverMeteredConnections' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' -Key 'DisableWebSearch' -Type REG_DWORD -Value 1

  # Disable OneDrive
  Write-HInfo 'Disable OneDrive'
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive' -Key 'DisableFileSyncNGSC' -Type REG_DWORD -Value 1
  Remove-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Run' -Key 'OneDriveSetup'

  # Prevent DevHome and Outlook Installation
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' -Key 'workCompleted' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' -Key 'workCompleted' -Type REG_DWORD -Value 1
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'


  ###########################
  #    05 File Operation    #
  ###########################


  #############################
  #    06 Windows Explorer    #
  #############################


  ####################
  #    07 Taskbar    #
  ####################
  # Disable Chat Icon
  Add-Reg -Path 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Key 'TaskbarMn' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' -Key 'ChatIcon' -Type REG_DWORD -Value 3



  ###############################
  #    08 MS Edge & WebView2    #
  ###############################


  #######
  # END #
  #######
  # Unmount Registry Files
  Invoke-Expression -Command 'reg unload HKLM\zCOMPONENTS' | Out-Null
  Invoke-Expression -Command 'reg unload HKLM\zDEFAULT' | Out-Null
  Invoke-Expression -Command 'reg unload HKLM\zNTUSER' | Out-Null
  Invoke-Expression -Command 'reg unload HKLM\zSOFTWARE' | Out-Null
  Invoke-Expression -Command 'reg unload HKLM\zSYSTEM' | Out-Null
}

Main -MountDir $MountDir
