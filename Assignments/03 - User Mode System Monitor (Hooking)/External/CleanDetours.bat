@ECHO OFF
CALL "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd Detours\src
SET DETOURS_TARGET_PROCESSOR=X86
NMAKE clean
SET DETOURS_TARGET_PROCESSOR=X64
NMAKE clean
cd ..\..
DEL DetoursLibs\detours.x86.lib
DEL DetoursLibs\detours.x64.lib
PAUSE