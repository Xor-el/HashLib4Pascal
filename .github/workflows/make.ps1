#!/usr/bin/env pwsh
##############################################################################################################

Function Show-Usage {
    "
vagrant  = 'it-gro/win10-ltsc-eval'
download = 'https://microsoft.com/en-us/evalcenter'
package  = 'https://learn.microsoft.com/en-us/mem/configmgr/develop/apps/how-to-create-the-windows-installer-file-msi'
shell    = 'https://learn.microsoft.com/en-us/powershell'

Usage: pwsh -File $($PSCommandPath) [OPTIONS]
Options:
    build
    lint
" | Out-Host
}

Function Build-Project {
    New-Variable -Option Constant -Name VAR -Value (Get-Content -Path $PSCommandPath.Replace('ps1', 'json') | ConvertFrom-Json)
    If (! (Test-Path -Path $Var.app)) {
        "$([char]27)[31m.... $($Var.app) did not find!$([char]27)[0m" | Out-Host
        Exit 1
    }
    If (Test-Path -Path '.gitmodules') {
        & git submodule update --init --recursive --force --remote | Out-Host
        "$([char]27)[33m.... [[$($LastExitCode)]] git submodule update$([char]27)[0m" | Out-Host
    }
    @(
        @{
            Cmd = 'lazbuild'
            Url = 'https://fossies.org/windows/misc/lazarus-3.6-fpc-3.2.2-win64.exe'
            Path = "C:\Lazarus"
        }
    ) | Where-Object {
        ! (Test-Path -Path $_.Path)
    } | ForEach-Object {
        $_.Url | Request-File | Install-Program
        $Env:PATH+=";$($_.Path)"
        Return (Get-Command $_.Cmd).Source
    } | Out-Host
    $VAR.Pkg | ForEach-Object {
        @{
            Name = $_
            Uri = "https://packages.lazarus-ide.org/$($_).zip"
            Path = "$($Env:HOME)\.lazarus\onlinepackagemanager\packages\$($_)"
            OutFile = (New-TemporaryFile).FullName
        }
    } | Where-Object {
        ! (Test-Path -Path $_.Path) &&
        ! (& lazbuild --verbose-pkgsearch $_.Name ) &&
        ! (& lazbuild --add-package $_.Name)
    } | ForEach-Object -Parallel {
        Invoke-WebRequest -OutFile $_.OutFile -Uri $_.Uri
        New-Item -Type Directory -Path $_.Path | Out-Null
        Expand-Archive -Path $_.OutFile -DestinationPath $_.Path
        Remove-Item $_.OutFile
        (Get-ChildItem -Filter '*.lpk' -Recurse -File –Path $_.Path).FullName |
            ForEach-Object {
                & lazbuild --add-package-link $_ | Out-Null
                Return "$([char]27)[33m.... [$($LastExitCode)] add package link $($_)$([char]27)[0m"
            }
    } | Out-Host
    If (Test-Path -Path $VAR.lib) {
        (Get-ChildItem -Filter '*.lpk' -Recurse -File –Path $VAR.lib).FullName |
            ForEach-Object {
                & lazbuild --add-package-link $_ | Out-Null
                Return "$([char]27)[33m.... [$($LastExitCode)] add package link $($_)$([char]27)[0m"
            } | Out-Host
    }
    Exit $(Switch (Test-Path -Path $Var.tst) {
        true {
            $Output = (
                & lazbuild --build-all --recursive --no-write-project $VAR.tst |
                    Where-Object {
                        $_.Contains('Linking')
                    } | ForEach-Object {
                        $_.Split(' ')[2].Replace('bin', 'bin\.')
                    }
            )
            $Output = (& $Output --all --format=plain --progress)
            $exitCode = Switch ($LastExitCode) {
                0 {0}
                Default {
                    1
                }
            }
            $Output | Out-Host
            Return $exitCode
K        }
        Default {0}
    }) + (
        (Get-ChildItem -Filter '*.lpi' -Recurse -File –Path $Var.app).FullName |
            ForEach-Object {
                $Output = (& lazbuild --build-all --recursive --no-write-project $_)
                $Result = @("$([char]27)[32m.... [$($LastExitCode)] build project $($_)$([char]27)[0m")
                $exitCode = $(Switch ($LastExitCode) {
                    0 {
                        $Result += $Output | Select-String -Pattern 'Linking'
                        0
                    }
                    Default {
                        $Result += $Output | Select-String -Pattern 'Error:', 'Fatal:'
                        1
                    }
                })
                $Result | Out-Host
                Return $exitCode
            } | Measure-Object -Sum
    ).Sum
}

Function Request-File {
    While ($Input.MoveNext()) {
        New-Variable -Option Constant -Name VAR -Value @{
            Uri = $Input.Current
            OutFile = (Split-Path -Path $Input.Current -Leaf).Split('?')[0]
        }
        Invoke-WebRequest @VAR
        Return $VAR.OutFile
    }
}

Function Install-Program {
    While ($Input.MoveNext()) {
        Switch ((Split-Path -Path $Input.Current -Leaf).Split('.')[-1]) {
            'msi' {
                & msiexec /passive /package $Input.Current | Out-Null
            }
            Default {
                & ".\$($Input.Current)" /SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART | Out-Null
            }
        }
        Remove-Item $Input.Current
    }
}

Function Request-URL([Switch] $Post) {
    $VAR = Switch ($Post) {
        true {
            @{
                Method = 'POST'
                Headers = @{
                    ContentType = 'application/json'
                }
                Uri = 'https://postman-echo.com/post'
                Body = @{
                    One = '1'
                } | ConvertTo-Json
            }
        }
        false {
            @{
                Uri = 'https://postman-echo.com/get'
            }
        }
    }
    Return (Invoke-WebRequest @VAR | ConvertFrom-Json).Headers
}

Function Switch-Action {
    $ErrorActionPreference = 'stop'
    Set-PSDebug -Strict #-Trace 1
    Invoke-ScriptAnalyzer -EnableExit -Path $PSCommandPath
    If ($args.count -gt 0) {
        Switch ($args[0]) {
            'lint' {
                Invoke-ScriptAnalyzer -EnableExit -Recurse -Path '.'
                (Get-ChildItem -Filter '*.ps1' -Recurse -Path '.').FullName |
                    ForEach-Object {
                        Invoke-Formatter -ScriptDefinition $(Get-Content -Path $_ | Out-String) |
                            Set-Content -Path $_
                    }
            }
            'build' {
                Build-Project
            }
            Default {
                Show-Usage
            }
        }
    } Else {
        Show-Usage
    }
}

##############################################################################################################
Switch-Action @args
