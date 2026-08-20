param(
    [Parameter(Mandatory=$true)]
    [string]$UserFile,

    [Parameter(Mandatory=$true)]
    [string]$PasswordFile,

    [Parameter(Mandatory=$true)]
    [string]$DC,

    [string]$Domain = "CONTOSO"
)

Add-Type -AssemblyName System.DirectoryServices.Protocols

$users = @(Get-Content $UserFile | ForEach-Object { $_.Trim() })
# Passwords must be read verbatim except for trailing CR from Windows line endings.
$passwords = @(Get-Content $PasswordFile | ForEach-Object { $_.TrimEnd("`r") })

if ($users.Count -ne $passwords.Count) {
    Write-Error "사용자 수($($users.Count))와 비밀번호 수($($passwords.Count))가 다릅니다."
    exit 1
}

$results = for ($i = 0; $i -lt $users.Count; $i++) {

    $user = $users[$i]
    $password = $passwords[$i]

    if ([string]::IsNullOrWhiteSpace($user)) {
        continue
    }

    $fullUser = "$Domain\$user"
    $failureReason = $null

    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($DC)
    $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

    try {
        $netCred = New-Object System.Net.NetworkCredential(
            $user,
            $password,
            $Domain
        )

        # 사용자당 정확히 한 번만 인증 시도
        $conn.Bind($netCred)

        [PSCustomObject]@{
            Username = $fullUser
            Result   = "DEFAULT PASSWORD STILL VALID"
        }
    }
    catch {
        $failureReason = $_.Exception.Message

        if ($_.Exception.InnerException) {
            $failureReason = "$failureReason | Inner: $($_.Exception.InnerException.Message)"
        }

        [PSCustomObject]@{
            Username = $fullUser
            Result   = "Authentication Failed"
            Detail   = $failureReason
        }
    }
    finally {
        $conn.Dispose()
    }
}

$results | Format-Table -AutoSize
