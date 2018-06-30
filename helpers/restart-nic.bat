%1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
netsh interface set interface "ÒÔÌ«Íø" admin=disable
netsh interface set interface "ÒÔÌ«Íø" admin=enable
