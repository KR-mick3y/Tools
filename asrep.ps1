param(
    [Parameter(Mandatory=$true)]
    [string]$DC,

    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [string]$SearchBase,

    [string]$CsvPath
)

Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.DirectoryServices.Protocols

function Stop-Script {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Convert-DomainToDn {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )

    return ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

# Summary:
# - Finds user objects with the DONT_REQ_PREAUTH userAccountControl flag set.
# - Uses LDAP so the script can run without the ActiveDirectory PowerShell module.
# - Optionally exports the findings to CSV.

if ([string]::IsNullOrWhiteSpace($SearchBase)) {
    $SearchBase = Convert-DomainToDn -DomainName $Domain
}

try {
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC/$SearchBase")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
}
catch {
    Stop-Script "Failed to connect to LDAP on $DC with base $SearchBase. $($_.Exception.Message)"
}

# 4194304 = DONT_REQ_PREAUTH, 512 = NORMAL_ACCOUNT
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$searcher.PageSize = 1000
$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
$searcher.PropertiesToLoad.AddRange(@(
    'samaccountname',
    'distinguishedname',
    'useraccountcontrol',
    'pwdlastset',
    'lastlogontimestamp',
    'serviceprincipalname'
))

try {
    $entries = $searcher.FindAll()
}
catch {
    if ($_.Exception.Message -like "*A referral was returned from the server*") {
        Stop-Script "LDAP search failed because the server returned a referral. Try specifying -SearchBase more narrowly, for example `"DC=$($Domain.Split('.')[0]),DC=$($Domain.Split('.')[1])`", or point -DC at a writable domain controller for that naming context."
    }

    Stop-Script "LDAP search failed. $($_.Exception.Message)"
}

$results = foreach ($entry in $entries) {
    $uac = if ($entry.Properties['useraccountcontrol'].Count -gt 0) {
        [int]$entry.Properties['useraccountcontrol'][0]
    }
    else {
        0
    }

    $pwdLastSet = if ($entry.Properties['pwdlastset'].Count -gt 0) {
        [datetime]::FromFileTimeUtc([int64]$entry.Properties['pwdlastset'][0]).ToLocalTime()
    }
    else {
        $null
    }

    $lastLogonTimestamp = if ($entry.Properties['lastlogontimestamp'].Count -gt 0) {
        [datetime]::FromFileTimeUtc([int64]$entry.Properties['lastlogontimestamp'][0]).ToLocalTime()
    }
    else {
        $null
    }

    [PSCustomObject]@{
        SamAccountName          = [string]$entry.Properties['samaccountname'][0]
        DistinguishedName      = [string]$entry.Properties['distinguishedname'][0]
        Enabled                = -not (($uac -band 0x0002) -ne 0)
        PasswordLastSet        = $pwdLastSet
        LastLogonTimestamp     = $lastLogonTimestamp
        ServicePrincipalNames  = (($entry.Properties['serviceprincipalname'] | ForEach-Object { [string]$_ }) -join '; ')
        DoesNotRequirePreAuth  = $true
    }
}

if (-not $results -or $results.Count -eq 0) {
    Write-Host "No accounts were found with 'Do not require Kerberos preauthentication' enabled."
    exit 0
}

$results | Sort-Object SamAccountName | Format-Table -AutoSize

if ($CsvPath) {
    try {
        $results | Sort-Object SamAccountName | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "CSV exported to: $CsvPath"
    }
    catch {
        Stop-Script "Failed to export CSV. $($_.Exception.Message)"
    }
}
