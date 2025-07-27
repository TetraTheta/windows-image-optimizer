@REM Prevent launch. This script must be re-encoded to EUC-KR before running.
exit
@echo off
@REM 01. 기본 설정
@REM 02. 사생활 보호
@REM 03. 보안
@REM 04. 기본 앱 비활성화 및 제거
@REM 05. 파일 변경
@REM 06. 파일 탐색기
@REM 07. 작업 표시줄
@REM 08. 엣지 브라우저

@REM ==================================================
@REM ==================== 기본 설정 ===================
@REM ==================================================
echo ============= Default Configuration =============

@REM TW 폴더 생성 방지
echo Prevent TW directory generation
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable

@REM USB 선택적 절전 해제 !! 장치 관리자에서 각 USB 허브마다 절전 설정 개별 해제 필요함
echo Disable USB Selective Power Save
powercfg /SetACValueIndex SCHEME_CURRENT 2A737441-1930-4402-8D77-B2BEBBA308A3 48E6B7A6-50F5-4782-A5D4-53BB8F07E226 0
powercfg /SetDCValueIndex SCHEME_CURRENT 2A737441-1930-4402-8D77-B2BEBBA308A3 48E6B7A6-50F5-4782-A5D4-53BB8F07E226 0

@REM Path 설정
echo Configure PATH
rem start "" /B /WAIT "%~dp0Cleanup_PATH.cmd"

@REM Aero Shake 비활성화
echo Disable Aero Shake
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f

@REM 고정 키 / 토글 키 / 필터 키 비활성화
echo Disable keyboard accessibility keys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f

@REM 시작 프로그램 대기 시간 (지연 시작) 비활성화
echo Disable start program delay
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f

@REM 나레이터 방지
echo Prevent Narrator
reg add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "WinEnterLaunchEnabled" /t REG_DWORD /d "0" /f

@REM 어두운 테마 적용
echo Set dark mode
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f

@REM NumLock 자동 활성화
echo Enable NumLock by default
reg add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f

@REM 장치 설정 모달 비활성화
echo Disable Device Configuration Modal
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "1" /f

@REM 명령 프롬프트 색상 활성화
echo Enable color in Command Prompt
reg add "HKCU\Console" /v "VirtualTerminalLevel" /t REG_DWORD /d "1" /f

@REM 작업 관리자 항상 위에 표시 (기존 작업 관리자, UWP 아님)
echo Task Manager is Always on Top
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v "AlwaysOnTop" /t REG_DWORD /d "1" /f

@REM 시각 효과 (창 그림자 X)
echo Configure visual effects
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9e1e038012000000" /f

@REM ====================================================
@REM ==================== 사생활 보호 ===================
@REM ====================================================
echo ===================== Privacy =====================

@REM 진단 데이터 수집 비활성화
echo Prevent telemetry data collection
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "0" /f

@REM 피드백 빈도 비활성화
echo Disable feedback frequency
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f

@REM 광고 ID 사용 안함
echo Disable Ads ID
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "id" /f

@REM 내 쓰기 정보 MS로 보내지 않음
echo Don't send writing information to MS
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f

@REM 진단 데이터로 권장 사항 추천 안함
echo Don't recommend anything from diagnostics data
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f

@REM 파일 탐색기에서 광고 사용 안 함
echo Disable Ads in File Explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f

@REM dmwappushsvc 서비스 비활성화
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start"  /t REG_DWORD /d "4" /f

@REM ==============================================
@REM ==================== 보안 ====================
@REM ==============================================
echo ================= Security =================

@REM ===============================================================
@REM ================== 기본 앱 비활성화 및 제거 ===================
@REM ===============================================================
echo ======================== Default Apps ========================

@REM 코타나 비활성화
echo Disable Cortana
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f

@REM 잡앱 다운로드 방지
echo Don't install bloatware
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableConsumerAccountStateContent" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f

@REM ms-gaming overlay 비활성화
echo Disable message about missing 'ms-gaming overlay'
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f

@REM ms-gamebar 비활성화
echo Disable message about 'ms-gamebar'
reg add "HKCR\ms-gamebar" /ve /t REG_SZ /d "URL:ms-gamebar" /f
reg add "HKCR\ms-gamebar" /v "URL Protocol" /t REG_SZ /d " " /f
reg add "HKCR\ms-gamebar" /v "NoOpenWith" /t REG_SZ /d " " /f
reg add "HKCR\ms-gamebar\shell\open\command" /ve /t REG_SZ /d "%SystemRoot%\System32\systray.exe" /f
reg add "HKCR\ms-gamebarservices" /ve /t REG_SZ /d "URL:ms-gamebar" /f
reg add "HKCR\ms-gamebarservices" /v "URL Protocol" /t REG_SZ /d " " /f
reg add "HKCR\ms-gamebarservices" /v "NoOpenWith" /t REG_SZ /d " " /f
reg add "HKCR\ms-gamebarservices\shell\open\command" /ve /t REG_SZ /d "%SystemRoot%\System32\systray.exe" /f

@REM ==================================================
@REM ==================== 파일 변경 ===================
@REM ==================================================
echo ================= File Operation =================

@REM ====================================================
@REM ==================== 파일 탐색기 ===================
@REM ====================================================
echo ================== File Explorer ==================

@REM Aero Shake 비활성화
echo Disable Aero Shake
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f

@REM 파일 작업 시 자세한 상태 출력
echo Show graph in file operation
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "1" /f

@REM 검색 상자 BING 통합 방지
echo Disable Bing integration on Search Box
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f

@REM '~의 바로가기' 제거
echo Disable 'Shortcut' from LNK name
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f

@REM JPG 파일이 JFIF로 저장되는 것 막기
echo Save JFIF as JPG
reg add "HKCR\MIME\Database\Content Type\image/jpeg" /v "Extension" /t REG_SZ /d ".jpg" /f

@REM 갤러리 비활성화
echo Hide Gallery
reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f

@REM 폴더 내용 빠르게 표시
echo Display directory content faster
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Background\Refresh" /v "AlwaysRefresh" /t REG_SZ /d "1" /f

@REM 사용자 폴더 경로 변경 (필요 경로 생성)
mkdir "E:\DOCUMENT"
mkdir "E:\DOWNLOAD"
mkdir "E:\PICTURE"
mkdir "E:\VIDEO"

@REM 사용자 폴더 경로 변경
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /t REG_SZ /d "E:\PICTURE" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /t REG_SZ /d "E:\VIDEO" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Personal" /t REG_SZ /d "E:\DOCUMENT" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_SZ /d "E:\DOWNLOAD" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /t REG_EXPAND_SZ /d "E:\PICTURE" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /t REG_EXPAND_SZ /d "E:\VIDEO" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Personal" /t REG_EXPAND_SZ /d "E:\DOCUMENT" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{0DDD015D-B06C-45D5-8C4C-F59713854639}" /t REG_EXPAND_SZ /d "E:\PICTURE" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /t REG_EXPAND_SZ /d "E:\VIDEO" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_EXPAND_SZ /d "E:\DOWNLOAD" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}" /t REG_EXPAND_SZ /d "E:\DOWNLOAD" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" /t REG_EXPAND_SZ /d "E:\DOCUMENT" /f

@REM 사용자 폴더 경로 변경 (DOCUMENT desktop.ini 생성)
(
  echo [.ShellClassInfo]
  echo LocalizedResourceName=@%%SystemRoot%%\system32\shell32.dll,-21770
  echo IconResource=%%SystemRoot%%\system32\imageres.dll,-112
  echo IconFile=%%SystemRoot%%\system32\shell32.dll
  echo IconIndex=-235
) > "E:\DOCUMENT\desktop.ini"
attrib +a +s +h "E:\DOCUMENT\desktop.ini"
attrib +r "E:\DOCUMENT"

@REM 사용자 폴더 경로 변경 (DOWNLOAD desktop.ini 생성)
(
  echo [.ShellClassInfo]
  echo LocalizedResourceName=@%%SystemRoot%%\system32\shell32.dll,-21798
  echo IconResource=%%SystemRoot%%\system32\imageres.dll,-184
) > "E:\DOWNLOAD\desktop.ini"
attrib +a +s +h "E:\DOWNLOAD\desktop.ini"
attrib +r "E:\DOWNLOAD"

@REM 사용자 폴더 경로 변경 (PICTURE desktop.ini 생성)
(
  echo [.ShellClassInfo]
  echo LocalizedResourceName=@%%SystemRoot%%\system32\shell32.dll,-21779
  echo InfoTip=@%%SystemRoot%%\system32\shell32.dll,-12688
  echo IconResource=%%SystemRoot%%\system32\imageres.dll,-113
  echo IconFile=%%SystemRoot%%\system32\shell32.dll
  echo IconIndex=-236
) > "E:\PICTURE\desktop.ini"
attrib +a +s +h "E:\PICTURE\desktop.ini"
attrib +r "E:\PICTURE"

@REM 사용자 폴더 경로 변경 (VIDEO desktop.ini 생성)
(
  echo [.ShellClassInfo]
  echo LocalizedResourceName=@%%SystemRoot%%\system32\shell32.dll,-21791
  echo InfoTip=@%%SystemRoot%%\system32\shell32.dll,-12690
  echo IconResource=%%SystemRoot%%\system32\imageres.dll,-189
  echo IconFile=%%SystemRoot%%\system32\shell32.dll
  echo IconIndex=-238
) > "E:\VIDEO\desktop.ini"
attrib +a +s +h "E:\VIDEO\desktop.ini"
attrib +r "E:\VIDEO"

@REM 기존 경로 삭제
del /S /Q "%UserProfile%\Documents"
del /S /Q "%UserProfile%\Downloads"
del /S /Q "%UserProfile%\Pictures"
del /S /Q "%UserProfile%\Videos"

@REM ====================================================
@REM ==================== 작업 표시줄 ===================
@REM ====================================================
echo ==================== Task Bar ====================

@REM 작업 표시줄 검색바 비활성화
echo Disable Search Bar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f

@REM 작업 표시줄 위젯 비활성화
echo Disable Widget
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "WebView" /t REG_DWORD /d "0" /f

@REM 작업 표시줄 채팅 비활성화
echo Disable Chat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f

@REM 모든 아이콘 표시
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f

@REM Chat 아이콘 비활성화
echo Disable Chat icon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f

@REM ======================================================
@REM ==================== 엣지 브라우저 ===================
@REM ======================================================
echo ==================== Edge Browser ====================

@REM Edge 실행금지
echo Prevent Edge prelaunch
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "PreventTabPreloading" /t REG_DWORD /d "1" /f
