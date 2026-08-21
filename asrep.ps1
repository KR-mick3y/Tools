<#
Usage:
  .\aduser.ps1 -UserFile users.txt -PasswordFile passwords.txt -DC dc01 -Domain contoso.local -default
  .\aduser.ps1 -UserFile users.txt -PasswordFile passwords.txt -DC dc01 -Domain contoso.local -personal

Options:
  -default          Try each password in PasswordFile against every user in UserFile.
  -personal         Try one password per user. The number of users and passwords must match.
  -DelayPerRequest  Delay in seconds between individual bind attempts.
  -DelayPerLoop     Delay in minutes between password loops in -default mode.

Notes:
  - Empty lines are ignored in both input files.
  - Passwords are read in order from top to bottom.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$UserFile,

    [Parameter(Mandatory=$true)]
    [string]$PasswordFile,

    [Parameter(Mandatory=$true)]
    [string]$DC,

    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [ValidateRange(0, 3600)]
    [double]$DelayPerRequest = 0,

    [ValidateRange(0, 1440)]
    [double]$DelayPerLoop = 0,

    [Alias("default")]
    [switch]$SharedDefault,

    [Alias("personal")]
    [switch]$PerUser
)

Add-Type -AssemblyName System.DirectoryServices.Protocols

function Stop-Script {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    Write-Host $Message -ForegroundColor Red
    exit 1
}

$users = @(Get-Content $UserFile | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
# Passwords must be read verbatim except for trailing CR from Windows line endings.
$passwords = @(Get-Content $PasswordFile | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ($SharedDefault -and $PerUser) {
    Stop-Script "-SharedDefault and -personal cannot be used together."
}

if (($DelayPerRequest * 10) % 1 -ne 0) {
    Stop-Script "DelayPerRequest must be specified in 0.1 second increments."
}

$delayPerLoopSeconds = [int]($DelayPerLoop * 60)

$mode = if ($SharedDefault) { "SharedDefault" } else { "Personal" }

if ($mode -eq "SharedDefault") {
    if ($passwords.Count -lt 1) {
        Stop-Script "Shared default mode requires at least one password in PasswordFile."
    }
}
elseif ($users.Count -ne $passwords.Count) {
    Stop-Script "Personal mode requires the same number of users ($($users.Count)) and passwords ($($passwords.Count)). Use -default to apply one or more shared passwords to all users."
}

$foundCount = 0

if ($mode -eq "SharedDefault") {
    for ($p = 0; $p -lt $passwords.Count; $p++) {
        $password = $passwords[$p]

        for ($i = 0; $i -lt $users.Count; $i++) {
            $user = $users[$i]

            $fullUser = "$Domain\$user"

            $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($DC)
            $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

            try {
                $netCred = New-Object System.Net.NetworkCredential(
                    $user,
                    $password,
                    $Domain
                )

                # Attempt exactly one bind per user/password pair.
                $conn.Bind($netCred)

                $resultText = "SHARED DEFAULT PASSWORD #{0} STILL VALID" -f ($p + 1)

                $foundCount++
                Write-Host ("[{0}] {1}" -f $resultText, $fullUser)
            }
            catch {
                continue
            }
            finally {
                $conn.Dispose()
            }

            if ($DelayPerRequest -gt 0) {
                $isLastPassword = ($p -eq ($passwords.Count - 1))
                $isLastUser = ($i -eq ($users.Count - 1))

                if (-not ($isLastPassword -and $isLastUser)) {
                    Start-Sleep -Milliseconds ([int]($DelayPerRequest * 1000))
                }
            }
        }

        if ($delayPerLoopSeconds -gt 0 -and $p -lt ($passwords.Count - 1)) {
            Start-Sleep -Seconds $delayPerLoopSeconds
        }
    }
}
else {
    for ($i = 0; $i -lt $users.Count; $i++) {
        $user = $users[$i]
        $password = $passwords[$i]

        $fullUser = "$Domain\$user"

        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($DC)
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

        try {
            $netCred = New-Object System.Net.NetworkCredential(
                $user,
                $password,
                $Domain
            )

            # Attempt exactly one bind per user/password pair.
            $conn.Bind($netCred)

            $resultText = "PERSONAL PASSWORD STILL VALID"

            $foundCount++
            Write-Host ("[{0}] {1}" -f $resultText, $fullUser)
        }
        catch {
            continue
        }
        finally {
            $conn.Dispose()
        }

        if ($DelayPerRequest -gt 0 -and $i -lt ($users.Count - 1)) {
            Start-Sleep -Milliseconds ([int]($DelayPerRequest * 1000))
        }
    }
}

if ($foundCount -gt 0) {
    Write-Host ""
    Write-Host ("Total matches: {0}" -f $foundCount)
}
else {
    Write-Host "No accounts were found using the default password."
}
