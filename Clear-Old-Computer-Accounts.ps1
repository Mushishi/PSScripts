<#
.SYNOPSIS
    Comprehensive AD computer account management for moonisp.dk
.DESCRIPTION
    Handles both inactive systems and those that have never logged on
    Includes all requested switches for flexible management
.PARAMETER TestMode
    Runs in test/reporting mode only (no changes made)
.PARAMETER DaysInactive
    Number of days of inactivity to consider an account stale (default: 30)
.PARAMETER LogPath
    Alternate path for log files (default: C:\Temp)
.PARAMETER List
    Lists all computer accounts with their last logon dates
.PARAMETER Computer
    Specifies a specific computer to delete (requires admin rights)
.PARAMETER IncludeNeverLoggedOn
    Includes computers that have never logged on in cleanup operations
.EXAMPLE
    .\Check-Old-Computer-Accounts.ps1 -List
    (Lists all computers including never-logged-on systems)
.EXAMPLE
    .\Check-Old-Computer-Accounts.ps1 -IncludeNeverLoggedOn
    (Cleans up both inactive AND never-logged-on systems)
.NOTES
    Version     : 3.1
    Author      : Mushishi <mushishi@moonisp.dk>
    Last Updated: 26.04.2024
#>

param (
    [Parameter(Mandatory=$false)]
    [switch]$TestMode,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysInactive = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Temp",
    
    [Parameter(Mandatory=$false)]
    [switch]$List,
    
    [Parameter(Mandatory=$false)]
    [string]$Computer,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNeverLoggedOn
)

# Import AD module with error handling
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "Active Directory module loaded successfully." -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to import Active Directory module." -ForegroundColor Red
    Write-Host "Make sure you're running this on a domain controller or have RSAT installed." -ForegroundColor Yellow
    exit
}

# Create log directory if it doesn't exist
if (-not (Test-Path -Path $LogPath)) {
    try {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }
    catch {
        Write-Host "ERROR: Could not create log directory at $LogPath" -ForegroundColor Red
        exit
    }
}

$LogFile = Join-Path -Path $LogPath -ChildPath "ADComputers_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"

# Discover domain and computer container
try {
    $domain = Get-ADDomain -Current LocalComputer
    $domainDN = $domain.DistinguishedName
    
    # Try common computer container locations
    $computerLocations = @(
        "CN=Computers,$domainDN",
        "OU=Computers,$domainDN",
        "OU=Workstations,$domainDN",
        "OU=Managed Computers,$domainDN"
    )

    $computersContainer = $null
    foreach ($location in $computerLocations) {
        try {
            $null = Get-ADObject -Identity $location
            $computersContainer = $location
            Write-Host "Found computer accounts in: $location" -ForegroundColor Green
            break
        }
        catch {
            Write-Host "Not found: $location" -ForegroundColor DarkGray
        }
    }

    if (-not $computersContainer) {
        Write-Host "ERROR: Could not find computer accounts container." -ForegroundColor Red
        exit
    }
}
catch {
    Write-Host "ERROR: Failed to discover domain information." -ForegroundColor Red
    exit
}

# Function to get computers with last logon date
function Get-ADComputersWithLastLogon {
    param (
        [string]$SearchBase,
        [string]$ComputerName = "*"
    )
    
    $computers = Get-ADComputer -Filter "Name -like '$ComputerName'" -Properties LastLogonTimeStamp, OperatingSystem, Description, WhenCreated -SearchBase $SearchBase
    
    $computers | ForEach-Object {
        if ($_.LastLogonTimeStamp) {
            $lastLogon = [datetime]::FromFileTime($_.LastLogonTimeStamp)
            $status = "Active"
        }
        else {
            $lastLogon = "Never"
            $status = "NeverLoggedOn"
        }
        
        $_ | Add-Member -MemberType NoteProperty -Name "LastLogonDate" -Value $lastLogon -Force
        $_ | Add-Member -MemberType NoteProperty -Name "AccountStatus" -Value $status -Force
        $_ | Add-Member -MemberType NoteProperty -Name "AgeInDays" -Value ((Get-Date) - $_.WhenCreated).Days -Force
    }
    
    return $computers | Sort-Object LastLogonDate
}

# Handle -List switch
if ($List) {
    Write-Host "`nListing all computer accounts:" -ForegroundColor Cyan
    $allComputers = Get-ADComputersWithLastLogon -SearchBase $computersContainer
    
    $allComputers | Select-Object Name, LastLogonDate, AccountStatus, AgeInDays, OperatingSystem, Description | Format-Table -AutoSize
    
    # Export to CSV
    $allComputers | Export-Csv -Path $LogFile -NoTypeInformation -Encoding UTF8
    Write-Host "`nFull list exported to: $LogFile" -ForegroundColor Green
    exit
}

# Handle -Computer switch
if ($Computer) {
    try {
        $targetComputer = Get-ADComputer -Identity $Computer -Properties LastLogonTimeStamp, WhenCreated
        
        # Get last logon date
        if ($targetComputer.LastLogonTimeStamp) {
            $lastLogon = [datetime]::FromFileTime($targetComputer.LastLogonTimeStamp)
            $status = "Last logged on: $lastLogon"
        }
        else {
            $lastLogon = "Never logged on"
            $status = "NEVER LOGGED ON (Created $((Get-Date $targetComputer.WhenCreated).ToShortDateString()))"
        }
        
        Write-Host "`nComputer Account Details:" -ForegroundColor Cyan
        Write-Host "Name: $($targetComputer.Name)"
        Write-Host "Status: $status"
        Write-Host "DistinguishedName: $($targetComputer.DistinguishedName)"
        
        if ($TestMode) {
            Write-Host "`nTEST MODE: Would delete computer '$Computer' (use without -TestMode to actually delete)" -ForegroundColor Yellow
            exit
        }
        
        $confirmation = Read-Host "`nARE YOU SURE you want to DELETE computer '$Computer'? (Y/N)"
        if ($confirmation -eq 'Y') {
            Remove-ADComputer -Identity $targetComputer.DistinguishedName -Confirm:$false
            Write-Host "Computer '$Computer' has been deleted." -ForegroundColor Red
        }
        else {
            Write-Host "Deletion cancelled." -ForegroundColor Yellow
        }
        exit
    }
    catch {
        Write-Host "ERROR: Could not find or process computer '$Computer'" -ForegroundColor Red
        Write-Host "Error details: $_" -ForegroundColor Yellow
        exit
    }
}

# Main cleanup functionality
try {
    $CutoffDate = (Get-Date).AddDays(-$DaysInactive)
    Write-Host "`nSearching for computer accounts..." -ForegroundColor Cyan

    $allComputers = Get-ADComputersWithLastLogon -SearchBase $computersContainer
    
    # Filter computers based on parameters
    if ($IncludeNeverLoggedOn) {
        $StaleComputers = $allComputers | Where-Object {
            $_.AccountStatus -eq "NeverLoggedOn" -or 
            $_.LastLogonDate -lt $CutoffDate
        }
        Write-Host "Including both inactive (>$DaysInactive days) AND never-logged-on systems" -ForegroundColor Yellow
    }
    else {
        $StaleComputers = $allComputers | Where-Object {
            $_.AccountStatus -ne "NeverLoggedOn" -and 
            $_.LastLogonDate -lt $CutoffDate
        }
        Write-Host "Only including systems inactive for >$DaysInactive days (use -IncludeNeverLoggedOn to include never-logged-on systems)" -ForegroundColor Cyan
    }

    if (-not $StaleComputers) {
        Write-Host "No matching computer accounts found." -ForegroundColor Green
        exit
    }

    $StaleComputers | Export-Csv -Path $LogFile -NoTypeInformation -Encoding UTF8
    Write-Host "Found $($StaleComputers.Count) computer accounts for cleanup. List saved to $LogFile" -ForegroundColor Cyan

    $StaleComputers | Select-Object Name, LastLogonDate, AccountStatus, AgeInDays, OperatingSystem, Description | Format-Table -AutoSize

    if ($TestMode) {
        Write-Host "`nRUNNING IN TEST MODE - NO CHANGES WILL BE MADE" -ForegroundColor Yellow
    }
    else {
        Write-Host "`nWARNING: THIS WILL DELETE $($StaleComputers.Count) COMPUTER ACCOUNTS" -ForegroundColor Red
        $confirmation = Read-Host "Type 'DELETE' to confirm or anything else to cancel"
        
        if ($confirmation -eq 'DELETE') {
            $StaleComputers | ForEach-Object {
                try {
                    Remove-ADComputer -Identity $_.DistinguishedName -Confirm:$false
                    Write-Host "Deleted $($_.Name) (Status: $($_.AccountStatus))" -ForegroundColor Red
                }
                catch {
                    Write-Host "Error deleting $($_.Name): $_" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host "ERROR: An unexpected error occurred." -ForegroundColor Red
    Write-Host "Error details: $_" -ForegroundColor Yellow
}