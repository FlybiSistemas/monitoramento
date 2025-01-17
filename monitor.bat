@echo off
schtasks /create /sc minute /mo 2 /tn "tokenmonitor" /tr "'C:/Program Files/ByToken/ByTokenMonitor.exe'" /ru "SYSTEM" /RL HIGHEST /np /f
schtasks /create /sc onlogon /tn "logonmonitor" /tr "'C:/Program Files/ByToken/ByTokenMonitor.exe'" /ru "SYSTEM" /RL HIGHEST /np /f
echo Sucesso.
start taskmgr
pause