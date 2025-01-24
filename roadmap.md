# FEATURES TO ADD

## TESTING
- Test importing task repository from Google drive zip folder
- Test invoking the script config from google drive or pastebin or other online service.
- Test TransparencyEffects to confirm they work.

# BUGFIXES

- Fix Google Drive installation as it prompts user for installation, should be silent.
- Branding: Ensure that downloading of lockscreen and wallpaper file supports downloading as JPG and PNG depending on the file format of the hosted file.
- Remove duplicate of install google drive /chrome from config file. 1 under applications and 1 under google.




FIXING Write-SystemMessage - UP TO:
     # Validate shortcut location exists
                if (-not (Test-Path $shortcutLocation)) {
                    Write-Log "Shortcut location does not exist: $shortcutLocation" -Level Error
                    Write-SystemMessage -errorMsg -msg "Shortcut location does not exist"
                    continue
                }