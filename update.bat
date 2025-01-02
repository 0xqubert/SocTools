@echo off
setlocal

REM Define the source and destination folders
set "sourceFolder=C:\path\to\your\source\folder"
set "destinationFolder=D:\path\to\your\destination\folder"
set "logFile=%destinationFolder%\robocopy_checksum.log"

REM Create the destination directory if it does not exist
if not exist "%destinationFolder%" mkdir "%destinationFolder%"

REM Copy only files with changed content (checksum)
robocopy "%sourceFolder%" "%destinationFolder%" /E /COPYALL /XO /XN /XC /XX /Z /R:3 /W:3 /FFT /LOG:"%logFile%"

REM Check for errors (robocopy returns errorlevel of 1 on most non-fatal issues)
if errorlevel 8 (
    echo "Critical Error copying folder from "%sourceFolder%" to "%destinationFolder%""
) else if errorlevel 4 (
  echo "Some files were not copied due to issues. Check %logFile% for more details."
) else if errorlevel 1 (
    echo "Some files were copied and some were skipped. Check %logFile% for more details."
) else (
    echo "Folder successfully copied from "%sourceFolder%" to "%destinationFolder%""
)

REM %sourceFolder%: Specifies the source directory
REM %destinationFolder%: Specifies the destination directory.
REM /E: Copies all subdirectories, including empty ones.
REM /COPYALL: Copies all file information.
REM /XO: Excludes older files at the destination to overwrite only when the source file is newer.
REM /XN: Excludes newer files at the destination, it will only overwrite a destination file with a source file if it is newer than the destination.
REM /XC: Excludes changed files at the destination, it will only overwrite files that are the same.
REM /XX: Excludes extra files and directories at the destination.
REM /Z: Copies files in restartable mode.
REM /R:3: Retries copying failed files 3 times.
REM /W:3: Waits 3 seconds between retries.
REM /FFT: Assumes FAT file times (less accurate if using NTFS)
REM /LOG:"%logFile%": Logs the robocopy process to a log file.
REM The log file is defined based on the destination folder.

endlocal
pause