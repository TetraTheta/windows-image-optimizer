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
@REM 최대 절전 모드 및 빠른 시작 비활성화
echo Disable hibernate / fast boot
powercfg /hibernate off

@REM ms-gamebar 비활성화
echo Disable message about 'ms-gamebar'
reg add "HKCR\ms-gamebar" /ve /t REG_SZ /d "URL:ms-gamebar" /f
reg add "HKCR\ms-gamebar" /v "URL Protocol" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamebar" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamebar\shell\open\command" /ve /t REG_SZ /d "%SystemRoot%\System32\systray.exe" /f
reg add "HKCR\ms-gamebarservices" /ve /t REG_SZ /d "URL:ms-gamebar" /f
reg add "HKCR\ms-gamebarservices" /v "URL Protocol" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamebarservices" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCR\ms-gamebarservices\shell\open\command" /ve /t REG_SZ /d "%SystemRoot%\System32\systray.exe" /f

@REM JPG 파일이 JFIF로 저장되는 것 막기
echo Save JFIF as JPG
reg add "HKCR\MIME\Database\Content Type\image/jpeg" /v "Extension" /t REG_SZ /d ".jpg" /f
