@echo off
setlocal enabledelayedexpansion

set "args="
for /f "delims=" %%a in (.\data\args.txt) do (
    set "args=!args! %%a"
)

vo_scanner.exe %args%