param(
    [Parameter(Mandatory=$true)]
    [string]$UserFile,

    [Parameter(Mandatory=$true)]
    [string]$PasswordFile,

    [Parameter(Mandatory=$true)]
    [string]$DC,

    [string]$Domain = "CONTOSO",

    [Alias("default")]
    [switch]$SharedDefault,

    [Alias("personal")]
    [switch]$PerUser
)

Add-Type -AssemblyName System.DirectoryServices.Protocols

$users = @(Get-Content $UserFile | ForEach-Object { $_.Trim() })
# Passwords must be read verbatim except for trailing CR from Windows line endings.
$passwords = @(Get-Content $PasswordFile | ForEach-Object { $_.TrimEnd("`r") })

if ($SharedDefault -and $PerUser) {
    Write-Error "-SharedDefault 와 -PerUser 는 동시에 사용할 수 없습니다."
    exit 1
}

$mode = if ($SharedDefault) { "SharedDefault" } else { "PerUser" }

if ($mode -eq "SharedDefault") {
    if ($passwords.Count -ne 1) {
        Write-Error "공통 디폴트 비밀번호 모드에서는 PasswordFile 에 비밀번호를 1개만 넣어야 합니다."
        exit 1
    }
}
elseif ($users.Count -ne $passwords.Count) {
    Write-Error "사용자별 비밀번호 모드에서는 사용자 수($($users.Count))와 비밀번호 수($($passwords.Count))가 같아야 합니다."
    exit 1
}

$sharedPassword = if ($mode -eq "SharedDefault") { $passwords[0] } else { $null }

$results = for ($i = 0; $i -lt $users.Count; $i++) {

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

        # 사용자당 정확히 한 번만 인증 시도
        $conn.Bind($netCred)

        [PSCustomObject]@{
            Username = $fullUser
            Result   = if ($mode -eq "SharedDefault") {
                "SHARED DEFAULT PASSWORD STILL VALID"
            }
            else {
                "PERSONAL DEFAULT PASSWORD STILL VALID"
            }
        }
    }
    catch {
        continue
    }
    finally {
        $conn.Dispose()
    }
}

if ($results) {
    $results | Format-Table -AutoSize
}
else {
    Write-Host "기본 비밀번호를 그대로 사용 중인 계정을 찾지 못했습니다."
}
