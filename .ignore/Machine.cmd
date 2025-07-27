@REM Prevent launch. This script must be re-encoded to EUC-KR before running.
exit
@echo off
net session 1>nul 2>nul
if %errorlevel% neq 0 goto ELEVATE
goto ADMINTASKS

:ELEVATE
cd /d %~dp0
mshta "javascript: var shell = new ActiveXObject('shell.application'); shell.ShellExecute('%~nx0', '', '', 'runas', 1);close();"
exit

:ADMINTASKS
@REM 01. 부팅
@REM 02. 기본 설정
@REM 03. 사생활 보호
@REM 04. 보안
@REM 05. 기본 앱 비활성화 및 제거
@REM 06. 파일 변경
@REM 07. 파일 탐색기
@REM 08. 작업 표시줄
@REM 09. 엣지 브라우저

@REM =============================================
@REM ==================== 부팅 ====================
@REM =============================================
echo ================= Booting =================

@REM F8 부팅메뉴 활성화
echo Enable F8 boot menu
bcdedit /set {default} bootmenupolicy legacy

@REM ==================================================
@REM ==================== 기본 설정 ====================
@REM ==================================================
echo ============= Default Configuration =============

@REM 1903 부터 생긴 '예약된 저장소' 생성 방지
@REM echo Prevent creating Reserved Space for Windows Update
@REM for /f "tokens=3 delims=.]" %%a in ('ver') do set build=%%a
@REM if %build% GEQ 18362 (reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d 0 /f)

@REM 잠금 화면 비활성화
echo Disable Lockscreen
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "1" /f

@REM '최고의 성능' 전원 구성
echo Enable 'High Performance' power option
@REM powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
for /f "tokens=1-5 delims=-" %%a in ('powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61') do set first=%%a& set last=%%e& set guid=!first:~-8!-%%b-%%c-%%d-!last:~0,12!
powercfg /s %guid%
powercfg /l

@REM 자동 로그인 재활성화
echo Re-enable Auto-Login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" /v "DevicePasswordLessBuildVersion" /t REG_DWORD /d "0" /f

@REM TW 폴더 생성 방지
echo Prevent TW directory generation
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable

@REM USB 선택적 절전 해제 !! 장치 관리자에서 각 USB 허브마다 절전 설정 개별 해제 필요함
echo Disable USB Selective Power Save
powercfg /SetACValueIndex SCHEME_CURRENT 2A737441-1930-4402-8D77-B2BEBBA308A3 48E6B7A6-50F5-4782-A5D4-53BB8F07E226 0
powercfg /SetDCValueIndex SCHEME_CURRENT 2A737441-1930-4402-8D77-B2BEBBA308A3 48E6B7A6-50F5-4782-A5D4-53BB8F07E226 0
@REM 이건 확실치 않음
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E965-E325-11CE-BFC1-08002BE10318}" /v "LowerFilter" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E965-E325-11CE-BFC1-08002BE10318}" /v "UpperFilter" /f

@REM USB 부스트 (확인 안됨)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\054C00C1" /v "DeviceHackFlags" /t REG_DWORD /d "536870912" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\054C00C1" /v "MaximumTransferLength" /t REG_DWORD /d "2097120" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\058F6362" /v "DeviceHackFlags" /t REG_DWORD /d "256" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\058F6362" /v "MaximumTransferLength" /t REG_DWORD /d "2097120" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\05AC12XX" /v "DeviceHackFlags" /t REG_DWORD /d "32" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\05AC12XX" /v "MaximumTransferLength" /t REG_DWORD /d "2097120" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\05AC13XX" /v "DeviceHackFlags" /t REG_DWORD /d "32" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\05AC13XX" /v "MaximumTransferLength" /t REG_DWORD /d "2097120" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\05DCA431" /v "DeviceHackFlags" /t REG_DWORD /d "16" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbstor\05DCA431" /v "MaximumTransferLength" /t REG_DWORD /d "2097120" /f

@REM 네트워크 쓰로틀링 해제
echo Disable network throttling
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "0" /f

@REM 시작 프로그램 대기 시간 (지연 시작) 비활성화
echo Disable start program delay
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f

@REM SetUserFTA 차단 방지
@REM https://kolbi.cz/blog/2024/04/03/userchoice-protection-driver-ucpd-sys/
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UCPD" /v "Start" /t REG_DWORD /d "4" /f
schtasks /Change /TN "Microsoft\Windows\AppxDeploymentClient\UCPD velocity" /Disable
@REM UCPD 제거 (재부팅 필요)
@rem sc delete UCPD

@REM 자동 프록시 비활성화
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoDetect" /t REG_DWORD /d "0" /f

@REM ====================================================
@REM ==================== 사생활 보호 ====================
@REM ====================================================
echo ===================== Privacy =====================

@REM 백그라운드 시스템 정보 수집 스케줄러 비활성화
echo Disable Background system information collection scheduler
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

schtasks /Change /TN "Microsoft\Office\OfficeTelemetry\AgentFallBack2016" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

@REM 진단 데이터 수집 비활성화
echo Prevent telemetry data collection
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "0" /f

@REM 피드백 빈도 비활성화
echo Disable feedback frequency
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f

@REM 원격 측정 사용 안 함
echo Disable telemetry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f

@REM 온라인 Speech 사생활 보호
echo Enable Online Speech Privacy
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f

@REM ==============================================
@REM ==================== 보안 ====================
@REM ==============================================
echo ================= Security =================

@REM Windows Defender 비활성화
@rem echo Disable Windows Defender
@rem reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
@rem reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
@rem reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
@rem reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f

@REM UAC 설정 (Level 3 by default)
echo Set UAC Level to 3
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f

@REM 사용자 계정 암호 만료기한 제한 해제
echo Remove account password expiration
wmic UserAccount set PasswordExpires=False

@REM 심볼릭 링크 활성화
ntrights +r SeCreateSymbolicLinkPrivilege -u Everyone

@REM ===============================================================
@REM ==================== 기본 앱 비활성화 및 제거 ====================
@REM ===============================================================
echo ======================== Default Apps ========================

@REM 스폰서 앱 설치 방지
echo Preventing sposor apps
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d "{\"pinnedList\": [{}]}" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f

@REM 코타나 비활성화
echo Disable Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f

@REM OneDrive 비활성화 및 제거
echo Disable and Remove OneDrive
reg load "HKU\LoadedDefaultUser" "%SystemDrive%\Users\Default\NTUSER.DAT"
reg delete "HKU\LoadedDefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "HKU\LoadedDefaultUser"
del /f "%SystemDrive%\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f

@REM ==================================================
@REM ==================== 파일 변경 ====================
@REM ==================================================
echo ================= File Operation =================

@REM F1 도움말 비활성화
echo Disable F1 help
takeown /f %WinDir%\HelpPane.exe
icacls %WinDir%\HelpPane.exe /deny Everyone:(X)

@REM ====================================================
@REM ==================== 파일 탐색기 ====================
@REM ====================================================
echo ================== File Explorer ==================

@REM 아이콘 캐시 크기 증가
echo Increase Icon Cache Size
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "MaxCachedIcons" /t REG_SZ /d "65535" /f

@REM Aero Shake 비활성화
echo Disable Aero Shake
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f

@REM 부팅 및 종료 시 자세한 상태 메세지 출력
echo Display detailed status message
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f

@REM 검색 상자 BING 통합 방지
echo Disable Bing integration on Search Box
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f

@REM 긴 파일 경로 이름 지원
echo Support long file path name
reg add "HKLM\SOFTWARE\Microsoft\Command Processor" /v "CompletionChar" /t REG_DWORD /d "9" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f

@REM 파일 탐색기 파일 목록 자동 갱신 속도 증가
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Update" /v "UpdateMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\explorer.exe" /v "DontUseDesktopChangeRouter" /t REG_DWORD /d "1" /f

@REM 새 기본 연결 프로그램 설정 창 숨기
echo Disable asking new default program
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d "1" /f

@REM '내 PC'에서 폴더 제거 시작
echo Remove folders from My PC
@REM '내 PC' - 바탕 화면
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
@REM '내 PC' - 문서
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{D3162B92-9365-467A-956B-92703ACA08AF}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{D3162B92-9365-467A-956B-92703ACA08AF}" /f
@REM '내 PC' - 다운로드
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088E3905-0323-4B02-9826-5D99428E115F}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088E3905-0323-4B02-9826-5D99428E115F}" /f
@REM '내 PC' - 음악
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4EBB-811F-33C572699FDE}" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4EBB-811F-33C572699FDE}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" /f
@REM '내 PC' - 사진
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" /f
@REM '내 PC' - 동영상
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43BF-BE83-3742FED03C9C}" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43BF-BE83-3742FED03C9C}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f
@REM '내 PC' - 3D Objects
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
@REM '내 PC'에서 폴더 제거 완료

@REM 사용자 계정 폴더에서 불필요한 폴더 제거 시작
echo Remove folders from User Directory
@REM 사용자 계정 폴더 - 3D Objects
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
@REM 사용자 계정 폴더 - 검색
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
@REM 사용자 계정 폴더 - 링크
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
@REM 사용자 계정 폴더 - 연락처
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{56784854-C6CB-462B-8169-88E350ACB882}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{56784854-C6CB-462B-8169-88E350ACB882}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
@REM 사용자 계정 폴더 - OneDrive
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
@REM 사용자 계정 폴더 - 즐겨찾기
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{1777F761-68AD-4D8A-87BD-30B759FA33DD}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{1777F761-68AD-4D8A-87BD-30B759FA33DD}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
@REM 사용자 계정 폴더에서 불필요한 폴더 제거 완료

@REM 사용자 계정 폴더 경로 오류 수정
echo Fix path of User Directories
@REM 바탕화면
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
@REM 내 문서
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{F42EE2D3-909F-4907-8871-4C22FC0BF756}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{D3162B92-9365-467A-956B-92703ACA08AF}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{F42EE2D3-909F-4907-8871-4C22FC0BF756}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{D3162B92-9365-467A-956B-92703ACA08AF}" /f
@REM ???
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}" /f
@REM 다운로드
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{374DE290-123F-4565-9164-39C4925E467B}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{374DE290-123F-4565-9164-39C4925E467B}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{374DE290-123F-4565-9164-39C4925E467B}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{374DE290-123F-4565-9164-39C4925E467B}" /f
@REM ???
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{088E3905-0323-4B02-9826-5D99428E115F}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{088E3905-0323-4B02-9826-5D99428E115F}" /f
@REM 음악
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A0C69A99-21C8-4671-8703-7934162FCF1D}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A0C69A99-21C8-4671-8703-7934162FCF1D}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
@REM ???
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{4BD8D571-6D19-48D3-BE97-422220080E43}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{1CF1260C-4DD0-4EBB-811F-33C572699FDE}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{4BD8D571-6D19-48D3-BE97-422220080E43}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{1CF1260C-4DD0-4EBB-811F-33C572699FDE}" /f
@REM 사진
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0DDD015D-B06C-45D5-8C4C-F59713854639}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{33E28130-4E1E-4676-835A-98395C3BC3BB}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0DDD015D-B06C-45D5-8C4C-F59713854639}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{33E28130-4E1E-4676-835A-98395C3BC3BB}" /f
@REM ???
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{33E28130-4E1E-4676-835A-98395C3BC3BB}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{33E28130-4E1E-4676-835A-98395C3BC3BB}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{33E28130-4E1E-4676-835A-98395C3BC3BB}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{33E28130-4E1E-4676-835A-98395C3BC3BB}" /f
@REM 동영상
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{18989B1D-99B5-455B-841C-AB7C74E4DDFC}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{A0953C92-50DC-43BF-BE83-3742FED03C9C}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{18989B1D-99B5-455B-841C-AB7C74E4DDFC}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{A0953C92-50DC-43BF-BE83-3742FED03C9C}" /f
@REM ???
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /v "ParsingName" /t REG_SZ /d "shell:::{59031A47-3F72-44A7-89C5-5595FE6B30EE}\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f

@REM ====================================================
@REM ==================== 작업 표시줄 ====================
@REM ====================================================
echo ==================== Task Bar ====================

@REM Chat 아이콘 비활성화
echo Disable Chat icon
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f

@REM ======================================================
@REM ==================== 엣지 브라우저 ====================
@REM ======================================================
echo ==================== Edge Browser ====================

@REM Chromium Edge 자동 설치 비활성화
echo Prevent Chromium Edge auto-install
reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f

@REM Chromium Edge 강제 제거
@REM 제거 후 KB5006670가 지속적으로 실패할 것임
@REM echo Force remove Chromium Edge
@REM rmdir /s /q "C:\Program Files (x86)\Microsoft\Edge"
@REM rmdir /s /q "C:\Program Files (x86)\Microsoft\EdgeCore"
@REM rmdir /s /q "C:\Program Files (x86)\Microsoft\EdgeUpdate"

@REM Edge 실행금지
echo Prevent Edge prelaunch
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "PreventTabPreloading" /t REG_DWORD /d "1" /f

@REM msedgewebview2.exe 실행방지
echo Prevent msedgewebview2.exe prelaunch
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
