:: Launcher for Windows platform
set VERSION=1.0-SNAPSHOT
cd "%~dp0"
java -jar PassiveAnalyzer-%VERSION%-Standalone.jar --graphical --open-live --guess-session-resumption %*

