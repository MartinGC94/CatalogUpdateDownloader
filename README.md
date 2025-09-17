# CatalogUpdateDownloader
This PowerShell module allows you to find and download updates from https://www.catalog.update.microsoft.com  
It uses https://html-agility-pack.net/ to parse the update search results page retrieved with `Invoke-WebRequest`.

# Getting started
Install the module from the PowerShell gallery: `Install-Module CatalogUpdateDownloader`  
Then check the available commands in the module: `Get-Command -Module CatalogUpdateDownloader`  
Here's a few example of what can be done with this module:
```powershell
# Find and download the latest cumulative OS and .NET updates for Windows server 2025
$CommonParams = @{
    OperatingSystem = 'WindowsServer'
    OsVersion       = "24H2"
    Architecture    = "x64"
    SortBy          = "Date"
    Descending      = $true
    First           = 1
}
@(
    Find-CatalogUpdate -UpdateKind CumulativeOS @CommonParams
    Find-CatalogUpdate -UpdateKind CumulativeNET @CommonParams
) | Save-CatalogUpdate -OutputDirectory $HOME\Downloads -PrimaryOnly

# Use a custom search query to find updates
# Note the use of quotes, +, and -
# + and - are used to include/exclude updates that matches the specified phrases
# Quotes are used to encapsulate each phrase
PS C:\> Find-CatalogUpdate -SearchText '"2025-08"+"Windows 11"+"24H2"-"Dynamic"'

Title          : 2025-08 Cumulative Update Preview for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2 for arm64 (KB5064401)
ReleaseDate    : 29-08-2025 00:00:00
Size           : 88.15 MB
Classification : Updates
Products       : Windows 11
UpdateId       : 69e90a35-8d45-40e6-9567-a39ff8106bee

Title          : 2025-08 Cumulative Update Preview for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2 for x64 (KB5064401)
ReleaseDate    : 29-08-2025 00:00:00
Size           : 71.58 MB
...

# Use a custom search query to find device drivers based on the hardware ID
PS C:\> $DisplayHwId = (Get-PnpDevice -Class Display)[0].HardwareID[1]
Find-CatalogUpdate -SearchText $DisplayHwId -First 1

Title          : NVIDIA - Display - 32.0.15.7317
ReleaseDate    : 07-05-2025 00:00:00
Size           : 1.01 GB
Classification : Drivers (Video)
Products       : Windows 10 version 1803 and Later Servicing Drivers, Windows 10 Version 1803 and Later Upgrade   & Servicing Drivers
UpdateId       : d80f8070-617f-4a7c-a38c-69b9ff63811c

# Find and list download info for an update
PS C:\> Find-CatalogUpdate -UpdateKind MSRT -OperatingSystem Windows11 -SortBy Date -Descending -First 1 | Get-CatalogUpdateDownloadInfo

Title        : Windows Malicious Software Removal Tool - v5.135 (KB890830)
UpdateId     : c9b07798-a1a6-43ae-b1ee-cae3f691504c
DownloadLink : https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/uprl/2025/08/windows-kb890830-v5.135_ba8e26dcedee8a76399125cffe757729ed36126c.exe
Sha1         : BA8E26DCEDEE8A76399125CFFE757729ED36126C
Sha256       : 7DC58FAE1D771C34570FA13A0CCA6C685D7C94A942675A863647D9D3F9F53CB0
IsPrimary    : True
```
