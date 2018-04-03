 @echo off

set dir=%~dp0
set NODE_PATH=%dir%
set PATH=%dir%node_modules\.bin;%PATH%

call pm2 start pm2.config.js
call pm2 log EasyDarwin --raw --nostream

pause