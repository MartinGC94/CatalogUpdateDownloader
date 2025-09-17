@{
    RootModule             = "CatalogUpdateDownloader.psm1"
    ModuleVersion          = "1.0.0"
    CompatiblePSEditions   = @("Core", "Desktop")
    GUID                   = '5dce3ccf-0494-44c7-b715-569052152501'
    Author                 = 'MartinGC94'
    CompanyName            = 'Unknown'
    Copyright              = '(c) 2025 MartinGC94. All rights reserved.'
    Description            = 'Module for finding and downloading updates from catalog.update.microsoft.com.'
    PowerShellVersion      = '5.1'
    FormatsToProcess       = 'CatalogUpdateDownloaderFormat.ps1xml'
    FunctionsToExport      = 'Find-CatalogUpdate', 'Get-CatalogUpdateDownloadInfo', 'Save-CatalogUpdate'
    CmdletsToExport        = @()
    VariablesToExport      = @()
    AliasesToExport        = @()
    DscResourcesToExport   = @()
    FileList               = 'CatalogUpdateDownloader.psm1', 'CatalogUpdateDownloader.psd1', 'CatalogUpdateDownloaderFormat.ps1xml', 'HtmlAgilityPack.dll'
    PrivateData            = @{
        PSData = @{
             Tags         = @("WU", "Update", "WindowsUpdate", "Updatecatalog")
             ProjectUri   = 'https://github.com/MartinGC94/CatalogUpdateDownloader'
             ReleaseNotes = @'
1.0.0:
    Initial release
'@
        }
    }
}
