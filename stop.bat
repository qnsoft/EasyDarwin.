@echo off

set dir=%~dp0
set NODE_PATH=%dir%
set PATH=%dir%node_modules\.bin;%PATH%

cd %dir%
call pm2 delete EasyDarwin

pause