param(
  [System.IO.DirectoryInfo][Parameter(Mandatory, Position = 0)] $MountDir # Directory where install.wim is mounted.
)

$ScriptVersion = '251019'

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
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo 'powershell.exe';
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
  if ([string]::IsNullOrEmpty($Key)) {
    $a = "add `"$Path`" /ve /t `"$Type`" /d `"$Value`" /f"
  } else {
    $a = "add `"$Path`" /v `"$Key`" /t `"$Type`" /d `"$Value`" /f"
  }

  if ($Verbose) {
    Start-Process -NoNewWindow -Wait -FilePath 'reg.exe' -ArgumentList $a
  }
  else {
    Start-Process -NoNewWindow -Wait -FilePath 'reg.exe' -ArgumentList $a | Out-Null
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
      Start-Process -NoNewWindow -Wait -FilePath 'reg.exe' -ArgumentList "delete `"$Path`" /f"
    }
    else {
      Start-Process -NoNewWindow -Wait -FilePath 'reg.exe' -ArgumentList "delete `"$Path`" /f" | Out-Null
    }
  }
  else {
    if ($Verbose) {
      Start-Process -NoNewWindow -Wait -FilePath 'reg.exe' -ArgumentList "delete `"$Path`" /v `"$Key`" /f"
    }
    else {
      Start-Process -NoNewWindow -Wait -FilePath 'reg.exe' -ArgumentList "delete `"$Path`" /v `"$Key`" /f" | Out-Null
    }
  }
}

########################################

function Remove-MyPC {
  param([string] $UUID)
  Remove-Reg -Path "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\$UUID"
  Remove-Reg -Path "HKLM\zSOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\$UUID"
}

function Remove-UserDir {
  param([string] $UUID)
  Add-Reg -Path "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\$UUID\PropertyBag" -Key 'ThisPCPolicy' -Type REG_SZ -Value 'Hide'
  Add-Reg -Path "HKLM\zSOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\$UUID\PropertyBag" -Key 'ThisPCPolicy' -Type REG_SZ -Value 'Hide'
}

function Fix-UserDir {
  param(
    [string] $Path,
    [string] $Name
  )
  Add-Reg -Path "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\$Path" -Key 'ParsingName' -Type REG_SZ -Value "shell:::$Name"
  Add-Reg -Path "HKLM\zSOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\$Path" -Key 'ParsingName' -Type REG_SZ -Value "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\$Name"
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
  $installedPackages = Invoke-Expression -Command "dism.exe /English /Image:`"$MountDir`" /Get-ProvisionedAppxPackages" | ForEach-Object {
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
    Invoke-Expression -Command "dism.exe /English /Image:`"$MountDir`" /Remove-ProvisionedAppxPackage /PackageName:$package"
  }

  # TODO: Remove MS Edge only (Leave WebView)

  # Mount Registry Files
  Invoke-Expression -Command "reg.exe load HKLM\zCOMPONENTS `"$MountDir\Windows\System32\config\COMPONENTS`"" | Out-Null
  Invoke-Expression -Command "reg.exe load HKLM\zDEFAULT `"$MountDir\Windows\System32\config\default`"" | Out-Null # HKEY_USERS\.DEFAULT
  Invoke-Expression -Command "reg.exe load HKLM\zNTUSER `"$MountDir\Users\Default\ntuser.dat`"" | Out-Null # HKEY_CURRENT_USER
  Invoke-Expression -Command "reg.exe load HKLM\zSOFTWARE `"$MountDir\Windows\System32\config\SOFTWARE`"" | Out-Null # HKEY_LOCAL_MACHINE\SOFTWARE
  Invoke-Expression -Command "reg.exe load HKLM\zSYSTEM `"$MountDir\Windows\System32\config\SYSTEM`"" | Out-Null # HKEY_LOCAL_MACHINE\SYSTEM

  # Get 'SeTakeOwnershipPrivilege' Privilege
  Get-Privilege

  # Take Ownership of Protected Registry Key
  $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # (Builtin) Administrators
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
  Write-HInfo 'Enable Local Account on OOBE'
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
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Key 'StartupDelayInMSec' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Key 'StartupDelayInMSec' -Type REG_DWORD -Value 0

  # Faster Shutdown
  Write-HInfo 'Faster Shutdown'
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control' -Key 'WaitToKillServiceTimeout' -Type REG_SZ -Value 2500

  # Unblock SetUserFTA
  Write-HInfo 'Unblock SetUserFTA'
  # Prevent UCPD Service Startup
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Services\UCPD' -Key 'Start' -Type REG_DWORD -Value 4
  # 'Microsoft\Windows\AppxDeploymentClient\UCPD velocity'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{471A373A-0CB5-4E87-9FDD-1F86F22036E1}'

  # Disable Automatic Proxy Detection
  Write-HInfo 'Disable Automatic Proxy Detection'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Key 'AutoDetect' -Type REG_DWORD -Value 0

  # Disable BitLocker Device Encryption
  Write-HInfo 'Disable BitLocker Device Encryption'
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' -Key 'PreventDeviceEncryption' -Type REG_DWORD -Value 1

  # Disable Fast Boot
  Write-HInfo 'Disable Fast Boot'
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\Session Manager\Power' -Key 'HiberbootEnabled' -Type REG_DWORD -Value 0

  # No Warning about missing 'ms-gamebar'
  Write-HInfo "No Warning about missing 'ms-gamebar'"
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\ms-gamebar' -Key '' -Type REG_SZ -Value 'URL:ms-gamebar'
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\ms-gamebar' -Key 'URL Protocol' -Type REG_SZ -Value ''
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\ms-gamebar' -Key 'NoOpenWith' -Type REG_SZ -Value ''
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\ms-gamebar\shell\open\command' -Key '' -Type REG_EXPAND_SZ -Value '%SystemRoot%\System32\systray.exe'
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\ms-gamebarservices' -Key '' -Type REG_SZ -Value 'URL:ms-gamebar'
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\ms-gamebarservices' -Key 'URL Protocol' -Type REG_SZ -Value ''
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\ms-gamebarservices' -Key 'NoOpenWith' -Type REG_SZ -Value ''
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\ms-gamebarservices\shell\open\command' -Key '' -Type REG_EXPAND_SZ -Value '%SystemRoot%\System32\systray.exe'

  # Disable ms-gaming Overlay
  Write-HInfo 'Disable ms-gaming Overlay'
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Key 'AppCaptureEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' -Key 'AppCaptureEnabled' -Type REG_DWORD -Value 0

  # Enable NumLock by Default
  Write-HInfo 'Enable NumLock by Default'
  Add-Reg -Path 'HKLM\zNTUSER\Control Panel\Keyboard' -Key 'InitialKeyboardIndicators' -Type REG_SZ -Value 2

  ####################
  #    02 Privacy    #
  ####################
  # Disable Telemetry
  Write-HInfo 'Disable Telemetry'
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' -Key 'Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' -Key 'RestrictImplicitInkCollection' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' -Key 'RestrictImplicitTextCollection' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' -Key 'HarvestContacts' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' -Key 'AcceptedPrivacyPolicy' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Siuf\Rules' -Key 'NumberOfSIUFInPeriod' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' -Key 'HasAccepted' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Key 'Enabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack' -Key 'ShowedToastAtLevel' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' -Key 'TailoredExperiencesWithDiagnosticDataEnabled' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' -Key 'AllowTelemetry' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' -Key 'Start' -Type REG_DWORD -Value 4

  <#
  Microsoft\Windows\AppID\SmartScreenSpecific
  Microsoft\Windows\Application Experience\AitAgent
  Microsoft\Windows\Customer Experience Improvement Program\Uploader
  Microsoft\Windows\Shell\FamilySafetyUpload
  Microsoft\Office\OfficeTelemetry\AgentFallBack2016
  Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016
  Microsoft\Office\OfficeTelemetryAgentLogOn
  Microsoft\Office\OfficeTelemetryAgentFallBack
  Microsoft\Office\Office 15 Subscription Heartbeat
  #>
  # Delete 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}'
  # Delete 'Microsoft\Windows\Application Experience\ProgramDataUpdater' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}'
  # Delete 'Microsoft\Windows\Application Experience\StartupAppTask'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{645AE3F4-2ABB-4B23-BBCC-8501D777B798}'
  # Delete 'Microsoft\Windows\Autochk\Proxy' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}'
  # Delete 'Microsoft\Windows\CertificateServicesClient\KeyPreGenTask' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}'
  # Delete 'Microsoft\Windows\Clip\License Validation'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{D1871301-47D9-4F14-AC6B-B201181F1D14}'
  # Delete 'Microsoft\Windows\CloudExperienceHost\CreateObjectTask'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0AE55DFD-F51D-40DA-AB08-39B8EC339D10}'
  # Delete 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}'
  # Delete 'Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}'
  # Delete 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}'
  # Delete 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{C68DEF50-9094-469B-8AE1-7B82DE1329FB}'
  # Delete 'Microsoft\Windows\DiskFootprint\Diagnostics'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{987F6860-11F5-47B3-889B-0A3D064576EE}'
  # Delete 'Microsoft\Windows\FileHistory\File History (maintenance mode)'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{CF83D93E-BA20-4111-9576-C96A14835C99}'
  # Delete 'Microsoft\Windows\NetTrace\GatherNetworkInfo'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1169460A-DB63-4AC1-8823-39864DDC78CD}'
  # Delete 'Microsoft\Windows\PI\Sqm-Tasks'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8DBCDCA3-980B-406C-89AF-65E51F99C0BB}'
  # Delete 'Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{95FE2315-4715-4B80-8158-D9AA3FFE11D7}'
  # Delete 'Microsoft\Windows\Shell\FamilySafetyMonitor'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{CE486984-DC95-4C4A-9B22-3B4057686F0D}'
  # Delete 'Microsoft\Windows\Shell\FamilySafetyRefresh'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0E07F737-03F6-4FF4-9EDA-D9D551D3E90A}'
  # Delete 'Microsoft\Windows\Windows Error Reporting\QueueReporting' Task
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}'

  # No Advertisement in Windows Explorer
  Write-HInfo 'No Advertisement in Windows Explorer'
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Key 'ShowSyncProviderNotifications' -Type REG_DWORD -Value 0

  #####################
  #    03 Security    #
  #####################
  # UAC Level 3 (default value)
  Write-HInfo 'Set UAC level to 3'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'ConsentPromptBehaviorAdmin' -Type REG_DWORD -Value 5
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'ConsentPromptBehaviorUser' -Type REG_DWORD -Value 3
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'EnableInstallerDetection' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'EnableLUA' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'EnableVirtualization' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'PromptOnSecureDesktop' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'ValidateAdminCodeSignatures' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'FilterAdministratorToken' -Type REG_DWORD -Value 0

  # Queue 'Remove Account Password Exipiration'
  Write-HInfo "Queue 'Remove Account Password Expiration'"
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Key '!RemovePasswordExpiration' -Type REG_SZ -Value 'wmic UserAccount set PasswordExpires=False'

  # Queue 'Allow Symbolic Link for Everyone' (Requires 'ntrights.exe' on %PATH%)
  Write-HInfo "Queue 'Allow Symbolic Link for Everyone'`n     Make sure 'ntrights.exe' is present in %PATH%"
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Key '!AllowSymbolicLink' -Type REG_SZ -Value 'ntrights +r SeCreateSymbolicLinkPrivilege -u Everyone'

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
  Write-HInfo 'Disable Cortana'
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
  Write-HInfo 'Prevent Installation of DevHome & Outlook'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' -Key 'workCompleted' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' -Key 'workCompleted' -Type REG_DWORD -Value 1
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
  Remove-Reg -Path 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'

  ###########################
  #    05 File Operation    #
  ###########################
  # Disable F1 Help
  Write-HInfo 'Disable F1 Help'
  takeown.exe /f "$MountDir\Windows\HelpPane.exe"
  icacls.exe "$MountDir\Windows\HelpPane.exe" /deny Everyone:(X)

  # Save JFIF as JPG
  Write-HInfo 'Save JFIF as JPG'
  Add-Reg -Path 'HKLM\zSOFTWARE\Classes\MIME\Database\Content Type\image/jpeg' -Key 'Extension' -Type REG_SZ -Value '.jpg'

  #######################################
  #    06 Windows Shell (+ Explorer)    #
  #######################################
  # Disable 'Home' in Setting App
  Write-HInfo "Disable 'Home' in Setting"
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Key 'SettingsPageVisibility' -Type REG_SZ -Value 'hide:home'

  # Increase Icon Cache Size
  Write-HInfo 'Increase Icon Cache Size'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Key 'MaxCachedIcons' -Type REG_SZ -Value 65535

  # Disable Aero Shake
  Write-HInfo 'Disable Aero Shake'
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Key 'DisallowShaking' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Key 'DisallowShaking' -Type REG_DWORD -Value 1

  # Show Detailed Status Message on Boot/Shutdown
  Write-HInfo 'Show Detailed Status Message on Boot/Shutdown'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'VerboseStatus' -Type REG_DWORD -Value 1
  Add-Reg -Path 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\System' -Key 'VerboseStatus' -Type REG_DWORD -Value 1

  # Disable BING Integration on Search Box
  Write-HInfo 'Disable BING Integration on Search Box'
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' -Key 'DisableSearchBoxSuggestions' -Type REG_DWORD -Value 1

  # Allow Long Path
  Write-HInfo 'Allow Long Path'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Command Processor' -Key 'CompletionChar' -Type REG_DWORD -Value 9
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\FileSystem' -Key 'LongPathsEnabled' -Type REG_DWORD -Value 1

  # Increase Refresh Rate of Windows Explorer
  Write-HInfo 'Increase Refresh Rate of Windows Explorer'
  Add-Reg -Path 'HKLM\zSYSTEM\ControlSet001\Control\Update' -Key 'UpdateMode' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\explorer.exe' -Key 'DontUseDesktopChangeRouter' -Type REG_DWORD -Value 1

  # Prevent Asking of New Default Program
  Write-HInfo 'Prevent Asking of New Default Program'
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' -Key 'NoNewAppAlert' -Type REG_DWORD -Value 1

  # Remove Unnecessary Folders from My PC
  Write-HInfo 'Remove Unnecessary Folders from My PC'
  $mypc = @(
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' # Desktop
    '{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}' # Documents
    '{D3162B92-9365-467A-956B-92703ACA08AF}' # Documents
    '{374DE290-123F-4565-9164-39C4925E467B}' # Downloads
    '{088E3905-0323-4B02-9826-5D99428E115F}' # Downloads
    '{1CF1260C-4DD0-4EBB-811F-33C572699FDE}' # Music
    '{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}' # Music
    '{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}' # Picture
    '{24AD3AD4-A569-4530-98E1-AB02F9417AA8}' # Picture
    '{A0953C92-50DC-43BF-BE83-3742FED03C9C}' # Video
    '{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}' # Video
    '{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}' # 3D Objects
  )
  foreach ($ns in $mypc) {
    Remove-MyPC -UUID $ns
  }

  # Remove Unnecessary Folders from User Directory
  Write-HInfo 'Remove Unnecessary Folders from User Directory'
  $usrdir = @(
    '{31C0DD25-9439-4F12-BF41-7FF4EDA38722}' # 3D Objects
    '{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}' # Search
    '{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}' # Link
    '{56784854-C6CB-462B-8169-88E350ACB882}' # Contact
    '{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}' # OneDrive
    '{1777F761-68AD-4D8A-87BD-30B759FA33DD}' # Favorite
  )
  foreach ($ns in $usrdir) {
    Remove-UserDir -UUID $ns
  }

  # Fix Names of Folders of User Directory
  Write-HInfo 'Fix Names of Folders of User Directory'
  $namefix = @(
    @('{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}', '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}'), # Desktop
    @('{F42EE2D3-909F-4907-8871-4C22FC0BF756}', '{D3162B92-9365-467A-956B-92703ACA08AF}'), # Documents
    @('{FDD39AD0-238F-46AF-ADB4-6C85480369C7}', '{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}'), # ???
    @('{374DE290-123F-4565-9164-39C4925E467B}', '{374DE290-123F-4565-9164-39C4925E467B}'), # Downloads
    @('{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}', '{088E3905-0323-4B02-9826-5D99428E115F}'), # ???
    @('{A0C69A99-21C8-4671-8703-7934162FCF1D}', '{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}'), # Music
    @('{4BD8D571-6D19-48D3-BE97-422220080E43}', '{1CF1260C-4DD0-4EBB-811F-33C572699FDE}'), # ???
    @('{0DDD015D-B06C-45D5-8C4C-F59713854639}', '{33E28130-4E1E-4676-835A-98395C3BC3BB}'), # Picture
    @('{33E28130-4E1E-4676-835A-98395C3BC3BB}', '{33E28130-4E1E-4676-835A-98395C3BC3BB}'), # ???
    @('{18989B1D-99B5-455B-841C-AB7C74E4DDFC}', '{A0953C92-50DC-43BF-BE83-3742FED03C9C}'), # Video
    @('{35286A68-3C57-41A1-BBB1-0EAE73D76C95}', '{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}') # ???
  )
  foreach ($n in $namefix) {
    Fix-UserDir -Path $n[0] -Name $n[1]
  }

  # Disable Keyboard Accessibility Keys
  Write-HInfo 'Disable Keyboard Accessibility Keys'
  Add-Reg -Path 'HKLM\zNTUSER\Control Panel\Accessibility\StickyKeys' -Key 'Flags' -Type REG_SZ -Value '506'
  Add-Reg -Path 'HKLM\zNTUSER\Control Panel\Accessibility\ToggleKeys' -Key 'Flags' -Type REG_SZ -Value '58'
  Add-Reg -Path 'HKLM\zNTUSER\Control Panel\Accessibility\Keyboard Response' -Key 'Flags' -Type REG_SZ -Value '122'

  # Disable Narrator
  Write-HInfo 'Disable Narrator'
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Narrator\NoRoam' -Key 'WinEnterLaunchEnabled' -Type REG_DWORD -Value 0

  # Set Dark Theme
  Write-HInfo 'Set Dark Theme'
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Key 'AppsUseLightTheme' -Type REG_DWORD -Value 0

  # Enable color in Command Prompt
  Write-HInfo 'Enable color in Command Prompt'
  Add-Reg -Path 'HKLM\zNTUSER\Console' -Key 'VirtualTerminalLevel' -Type REG_DWORD -Value 1

  # Disable Device Configuration Modal
  Write-HInfo 'Disable Device Configuration Modal'
  Add-Reg -Path 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement' -Key 'ScoobeSystemSettingEnabled' -Type REG_DWORD -Value 1

  # Set 'Always on Top' for Task Manager
  Write-HInfo "Set 'Always on Top' for Task Manager"
  Add-Reg -Path 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\TaskManager' -Key 'AlwaysOnTop' -Type REG_DWORD -Value 1

  # Configure Visual Effects
  Write-HInfo 'Configure Visual Effects'
  Add-Reg -Path 'HKLM\zNTUSER\Control Panel\Desktop' -Key 'UserPreferencesMask' -Type REG_BINARY -Value '9e1e038012000000'

  ####################
  #    07 Taskbar    #
  ####################
  # Disable Chat Icon
  Write-HInfo 'Disable Chat Icon'
  Add-Reg -Path 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Key 'TaskbarMn' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' -Key 'ChatIcon' -Type REG_DWORD -Value 3

  ###############################
  #    08 MS Edge & WebView2    #
  ###############################
  # Prevent Edge Prelaunch
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Key 'AllowPrelaunch' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader' -Key 'AllowTabPreloading' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader' -Key 'PreventTabPreloading' -Type REG_DWORD -Value 1

  # Prevent Edge Webview2 Prelaunch
  Write-HInfo 'Prevent Edge Webview2 Prelaunch'
  Add-Reg -Path 'HKLM\zSOFTWARE\Policies\Microsoft\Dsh' -Key 'AllowNewsAndInterests' -Type REG_DWORD -Value 0
  Add-Reg -Path 'HKLM\zSOFTWARE\WOW6432Node\Policies\Microsoft\Dsh' -Key 'AllowNewsAndInterests' -Type REG_DWORD -Value 0

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
