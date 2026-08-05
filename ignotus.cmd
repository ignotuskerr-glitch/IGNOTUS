@echo off
setlocal
set "IGNOTUS_PROJECT=C:\Users\Ignotus\Documents\program"

if not exist "%IGNOTUS_PROJECT%\iniciar_ignotus.bat" (
    echo Ignotus nao foi encontrado em: %IGNOTUS_PROJECT%
    exit /b 1
)

call "%IGNOTUS_PROJECT%\iniciar_ignotus.bat" %*
exit /b %ERRORLEVEL%
