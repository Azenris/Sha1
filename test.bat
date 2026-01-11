@echo OFF
cls
setlocal enableDelayedExpansion

for /f "delims=" %%i in ('build\static-mt\builds\debug\sha1 test.txt') do (
	set hash=%%i
)

if %ERRORLEVEL% neq 0 (
	echo Sha1 failed with errorcode: %ERRORLEVEL%
	exit /b %ERRORLEVEL%
)

echo   Result: !hash!
echo Expected: 3f9c069ad399c8970f2deebc71969f72d8a616e3

if "%hash%" == "3f9c069ad399c8970f2deebc71969f72d8a616e3" (
	echo SUCCESS. Same Hash!
) else (
	echo FAILED. Different Hash!
)