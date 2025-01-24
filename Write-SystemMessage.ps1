function Write-SystemMessage {
    param (
        [Parameter()]
        [string]$title = '',
  
        [Parameter()]
        [string]$msg = '',

        [Parameter()]
        [string]$value = '',
  
        [Parameter()]
        [ConsoleColor]$titleColor = 'DarkMagenta',
  
        [Parameter()]
        [ConsoleColor]$msgColor = 'Cyan',

        [Parameter()]
        [ConsoleColor]$valueColor = 'White',

        [Parameter()]
        [switch]$errorMsg = $false,

        [Parameter()]
        [switch]$warningMsg = $false,

        [Parameter()]
        [switch]$successMsg = $false
    )

    # Initialize script variables if not exists
    if (-not (Test-Path variable:script:lastMessageCursorPosition)) {
        $script:lastMessageCursorPosition = $null
        $script:lastMessage = $null
        $script:lastValue = $null
    }
    
    # Handle title blocks
    if ($PSBoundParameters.ContainsKey('title')) {
        Write-Host "`n`n $($title.ToUpper()) " -ForegroundColor White -BackgroundColor $titleColor 
        Write-Host ""
        $script:lastMessageCursorPosition = $null
        $script:lastMessage = $null
        $script:lastValue = $null
        return
    }

    # Define status message properties
    $statusTypes = @{
        successMsg = @{ symbol = "✓"; text = "SUCCESS"; color = "Green" }
        warningMsg = @{ symbol = "⚠ "; text = "WARNING"; color = "DarkYellow" }
        errorMsg = @{ symbol = "x"; text = "ERROR"; color = "Red" }
    }

    # Handle msg and value combinations
    if ($PSBoundParameters.ContainsKey('msg') -or $PSBoundParameters.ContainsKey('value')) {
        # If it's a status message with msg/value, handle differently
        $statusType = $statusTypes.Keys | Where-Object { $PSBoundParameters.ContainsKey($_) } | Select-Object -First 1
        if ($statusType) {
            $status = $statusTypes[$statusType]
            if ($script:lastMessageCursorPosition -and $script:lastMessage) {
                # Append to previous line
                $host.UI.RawUI.CursorPosition = $script:lastMessageCursorPosition
                Write-Host (" " * ($host.UI.RawUI.BufferSize.Width - 1))
                $host.UI.RawUI.CursorPosition = $script:lastMessageCursorPosition
                Write-Host " - $script:lastMessage" -ForegroundColor $msgColor -NoNewline
                if ($script:lastValue) {
                    Write-Host ": " -ForegroundColor $msgColor -NoNewline
                    Write-Host "$script:lastValue" -ForegroundColor $valueColor -NoNewline
                }
                Write-Host " - $($status.symbol) $($status.text)" -ForegroundColor $status.color -NoNewline
                if ($PSBoundParameters.ContainsKey('msg')) {
                    Write-Host ": " -ForegroundColor $status.color -NoNewline
                    Write-Host "$msg" -ForegroundColor DarkGray -NoNewline
                    if ($PSBoundParameters.ContainsKey('value')) {
                        Write-Host ": " -ForegroundColor $status.color -NoNewline
                        Write-Host "$value" -ForegroundColor Gray
                    } else {
                        Write-Host ""
                    }
                } else {
                    Write-Host ""
                }
            } else {
                # New status message line
                Write-Host " $($status.symbol) $($status.text)" -ForegroundColor $status.color -NoNewline
                if ($PSBoundParameters.ContainsKey('msg')) {
                    Write-Host " | " -ForegroundColor DarkGray -NoNewline
                    Write-Host "$msg" -ForegroundColor DarkGray -NoNewline
                    if ($PSBoundParameters.ContainsKey('value')) {
                        Write-Host ": " -ForegroundColor $status.color -NoNewline
                        Write-Host "$value" -ForegroundColor Gray
                    } else {
                        Write-Host ""
                    }
                } else {
                    Write-Host ""
                }
            }
            $script:lastMessageCursorPosition = $null
            return
        }

        # Store for potential status append later
        $script:lastMessage = $msg
        $script:lastValue = $value

        if ($PSBoundParameters.ContainsKey('msg')) {
            Write-Host " - $msg" -ForegroundColor $msgColor -NoNewline
            if ($PSBoundParameters.ContainsKey('value')) {
                Write-Host ": " -ForegroundColor $msgColor -NoNewline
                Write-Host $value -ForegroundColor $valueColor
            } else {
                Write-Host ""
            }
        } else {
            Write-Host $value -ForegroundColor $valueColor
        }

        $script:lastMessageCursorPosition = $host.UI.RawUI.CursorPosition
        $script:lastMessageCursorPosition.Y -= 1
        return
    }

    # Handle standalone status messages
    $statusType = $statusTypes.Keys | Where-Object { $PSBoundParameters.ContainsKey($_) } | Select-Object -First 1
    if ($statusType) {
        $status = $statusTypes[$statusType]
        if ($script:lastMessageCursorPosition -and $script:lastMessage) {
            $host.UI.RawUI.CursorPosition = $script:lastMessageCursorPosition
            Write-Host (" " * ($host.UI.RawUI.BufferSize.Width - 1))
            $host.UI.RawUI.CursorPosition = $script:lastMessageCursorPosition
            Write-Host " - $script:lastMessage" -ForegroundColor $msgColor -NoNewline
            if ($script:lastValue) {
                Write-Host ": " -ForegroundColor $msgColor -NoNewline
                Write-Host "$script:lastValue" -ForegroundColor $valueColor -NoNewline
            }
            Write-Host " - $($status.symbol) $($status.text)" -ForegroundColor $status.color -NoNewline
            if ($PSBoundParameters.ContainsKey('msg')) {
                Write-Host ": " -ForegroundColor $status.color -NoNewline
                Write-Host "$msg" -ForegroundColor $status.color -NoNewline
                if ($PSBoundParameters.ContainsKey('value')) {
                    Write-Host ": " -ForegroundColor $status.color -NoNewline
                    Write-Host "$value" -ForegroundColor $valueColor
                } else {
                    Write-Host ""
                }
            } else {
                Write-Host ""
            }
        } else {
            Write-Host " $($status.symbol) $($status.text)" -ForegroundColor $status.color -NoNewline
            if ($PSBoundParameters.ContainsKey('msg')) {
                Write-Host " | " -ForegroundColor DarkGray -NoNewline
                Write-Host "$msg" -ForegroundColor $status.color -NoNewline
                if ($PSBoundParameters.ContainsKey('value')) {
                    Write-Host ": " -ForegroundColor $status.color -NoNewline
                    Write-Host "$value" -ForegroundColor $valueColor
                } else {
                    Write-Host ""
                }
            } else {
                Write-Host ""
            }
        }

        if ($statusType -eq 'errorMsg' -and $_.Exception.Message) {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        
        $script:lastMessageCursorPosition = $null
    }
}