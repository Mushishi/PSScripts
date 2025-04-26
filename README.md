# PSScripts
A collection of my powershell scripts
-------------------------------------------------------------------------------------
# AD Computer Cleanup Script Summary

`Check-Old-Computer-Accounts.ps1`

## 📝 Description
A PowerShell script for managing computer accounts in Active Directory (moonisp.dk) that:
- Identifies stale/inactive computers
- Handles never-logged-on systems
- Provides flexible management options
- Maintains detailed audit logs

## 🎛️ Parameters

| Parameter           | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `-TestMode`         | Runs in report-only mode (no changes made)                                  |
| `-DaysInactive`     | Days threshold for inactivity (default: 30)                                 |
| `-LogPath`          | Alternate log directory (default: `C:\Temp`)                                |
| `-List`             | Lists all computers with last logon dates                                   |
| `-Computer`         | Targets specific computer for deletion                                      |
| `-IncludeNeverLoggedOn` | Includes never-logged-on systems in cleanup operations                 |

## 🛠️ Features

### 🔍 Discovery
- Automatically finds domain structure (`moonisp.dk`)
- Checks multiple common computer containers:
  - Default `CN=Computers`
  - Custom `OU=Computers`
  - Alternative OUs (`Workstations`, `Managed Computers`)

### 📊 Reporting
- **Detailed computer attributes**:
  - Last logon date
  - Account status (Active/NeverLoggedOn)
  - Account age (in days)
  - OS version
  - Description
- **CSV export** with timestamped filenames
- **Color-coded console output**

### 🗑️ Cleanup Options
1. **Standard cleanup** (inactive > X days)
2. **Never-logged-on systems** (optional)
3. **Targeted deletion** (specific computers)

### ⚠️ Safety Features
- Test mode prevents accidental changes
- Explicit confirmation prompts
- DistinguishedName targeting (prevents name conflicts)
- Comprehensive error handling

## 💻 Usage Examples

```powershell
# List all computers (including never-logged-on)
.\Check-Old-Computer-Accounts.ps1 -List

# Standard cleanup (30+ days inactive)
.\Check-Old-Computer-Accounts.ps1

# Include never-logged-on systems
.\Check-Old-Computer-Accounts.ps1 -IncludeNeverLoggedOn

# Targeted computer deletion
.\Check-Old-Computer-Accounts.ps1 -Computer "WS-12345"

# Custom inactivity period (60 days)
.\Check-Old-Computer-Accounts.ps1 -DaysInactive 60

# Test run (no changes)
.\Check-Old-Computer-Accounts.ps1 -IncludeNeverLoggedOn -TestMode
