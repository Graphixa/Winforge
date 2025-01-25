Function Show-SplashScreen {
    param (
        [Parameter()]
        [string]$version = ''
    )
Write-Host @"
-----------------------------------------  
"@ -ForegroundColor Cyan
Write-Host @"
           _     ___                 
     _ _ _|_|___|  _|___ ___ ___ ___ 
    | | | | |   |  _| . |  _| . | -_|
    |_____|_|_|_|_| |___|_| |_  |___|
                            |___|                    
"@ -ForegroundColor DarkMagenta

Write-Host @"
-----------------------------------------
"@ -ForegroundColor Cyan
Write-Host @"
          FORGE YOUR OWN SYSTEM
"@ -ForegroundColor White
Write-Host @"
-----------------------------------------
"@ -ForegroundColor Cyan
Write-Host @"
                ver $version
           
"@ -ForegroundColor DarkGray
}

Show-SplashScreen -version '0.2'