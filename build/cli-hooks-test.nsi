!include "LogicLib.nsh"
!include "..\src-tauri\installer\cli-hooks.nsh"
Name "Yougori CLI hook compile test"
OutFile "cli-hooks-test.exe"
RequestExecutionLevel user
Section
  !insertmacro NSIS_HOOK_POSTINSTALL
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd
Section "Uninstall"
  !insertmacro NSIS_HOOK_PREUNINSTALL
SectionEnd
