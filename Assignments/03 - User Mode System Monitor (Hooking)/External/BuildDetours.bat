@ECHO OFF
CALL "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd Detours\src
SET DETOURS_TARGET_PROCESSOR=X86
NMAKE
SET DETOURS_TARGET_PROCESSOR=X64
NMAKE
CD ..\..
COPY Detours\lib.X86\detours.lib DetoursLibs\detours.x86.lib
COPY Detours\lib.X64\detours.lib DetoursLibs\detours.x64.lib
PAUSE