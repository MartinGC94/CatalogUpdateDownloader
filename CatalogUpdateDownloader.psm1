#requires -Modules BitsTransfer
try
{
    # Check if the required assembly has already been loaded (by the user or another module)
    # If not, we load it from the module folder.
    # We do this to avoid assembly conflicts which seem more likely than breaking changes in the assembly itself.
    $null = [HtmlAgilityPack.HtmlDocument]
}
catch
{
    Add-Type -LiteralPath "$PSScriptRoot\HtmlAgilityPack.dll" -ErrorAction Stop
}

#region Classes

class CatalogUpdate
{
    [string] $Title
    [datetime] $ReleaseDate
    [uint64] $Size
    [string] $Classification
    [string] $Products
    [string] $UpdateId
}

class CatalogDownloadInfo
{
    [string] $Title
    [string] $UpdateId
    [string] $DownloadLink
    [string] $Sha1
    [string] $Sha256
    [bool] $IsPrimary
}

#endregion

#region Public functions

<#
.SYNOPSIS
    Finds updates in the Microsoft Update Catalog.

.DESCRIPTION
    Finds updates in the Microsoft Update Catalog.

.EXAMPLE
    Find-CatalogUpdate -UpdateKind CumulativeNET -OperatingSystem Windows11 -OsVersion 24H2 -Architecture x64 -SortBy Date -Descending -First 1
    This finds the most recent .NET framework update for Windows 11 24H2 x64

.EXAMPLE
    Find-CatalogUpdate -SearchText 'PCI\VEN_10DE&DEV_2488&SUBSYS_88251043' -First 1
    This uses the free text function to search for a device driver using the hardware ID. In this case it's an Nvidia GPU.

.PARAMETER UpdateKind
    The type of update to search for. eg. Cumulative OS/.NET update, Microsoft Malicious Software Removal Tool, etc.

.PARAMETER OperatingSystem
    The operating system to find updates for. For Server 2022 and up specify "WindowsServer" + the OsVersion parameter.
    This parameter only applies if UpdateKind is set to one of the Cumulative* or MSRT options.

.PARAMETER OsVersion
    The specific OS version, eg. 24H2, 1809, etc.
    This parameter only applies if UpdateKind is set to one of the Cumulative* options.

.PARAMETER Architecture
    The architecture, eg. x64, arm64, etc.
    This parameter only applies if UpdateKind is set to one of the Cumulative* options.

.PARAMETER DateString
    The year and month in the format yyyy-MM to find updates for.
    This parameter only applies if UpdateKind is set to one of the Cumulative* options.

.PARAMETER KB
    The specific KB to search for.
    This parameter only applies if UpdateKind is set to one of the Cumulative* options.

.PARAMETER SearchText
    The custom text filter used to search the update catalog with.
    Use quotes to search for specific text. Use + and - to include/exclude items based on the specified phrases. For example:
    Find-CatalogUpdate -SearchText '"Cumulative update"-"Dynamic"-"Framework"+"Windows 10"'
    This searches for the phrase "Cumulative update", excludes items with the phrases "Dynamic" and "Framework" and includes items with "Windows 10".

.PARAMETER SortBy
    The property to sort the items by.
    The sorting happens serverside.

.PARAMETER Descending
    Reverses the sorting order from Ascending to Descending.
    This parameter only applies if SortBy has also been specified.
#>
function Find-CatalogUpdate
{
    [OutputType([CatalogUpdate])]
    [CmdletBinding(SupportsPaging, DefaultParameterSetName = "Custom")]
    Param
    (
        [Parameter(Mandatory, ParameterSetName = "Predefined")]
        [ValidateSet("CumulativeOS", "CumulativeOSPreview", "CumulativeNET", "CumulativeNETPreview", "MSRT", "SecurityPlatform")]
        [string]
        $UpdateKind,

        [Parameter(ParameterSetName = "Predefined")]
        [ValidateSet("Windows10", "Windows11", "WindowsServer", "WindowsServer2019", "WindowsServer2016")]
        [string]
        $OperatingSystem,

        [Parameter(ParameterSetName = "Predefined")]
        [ValidateNotNullOrEmpty()]
        [ArgumentCompleter(
        {
            param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
            $TrimmedWord = $wordToComplete.Trim(("'",'"'))
            $Versions = @(
                @{Text = "25H2"; List = "25H2"}
                @{Text = "24H2"; List = "24H2 (Server 2025)"}
                @{Text = "23H2"; List = "23H2"}
                @{Text = "22H2"; List = "22H2"}
                @{Text = "21H2"; List = "21H2 (Server 2022)"}
            )
            foreach ($Item in $Versions)
            {
                if ($Item.Text -like "$TrimmedWord*")
                {
                    $CompletionText = $Item.Text
                    $ListItemText   = $Item.List
                    $ResultType     = [System.Management.Automation.CompletionResultType]::ParameterValue
                    $ToolTip        = $Item.List

                    [System.Management.Automation.CompletionResult]::new($CompletionText,$ListItemText,$ResultType,$ToolTip)
                }
            }
        }
        )]
        [string]
        $OsVersion,

        [Parameter(ParameterSetName = "Predefined")]
        [ValidateSet("x64", "x86", "arm64")]
        [string]
        $Architecture,

        [Parameter(ParameterSetName = "Predefined")]
        [ValidatePattern('^\d{4}-\d{2}$')]
        [ArgumentCompleter(
        {
            param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
            $TrimmedWord = $wordToComplete.Trim(("'",'"'))
            
            $DateNow = Get-Date
            $Dates = if ($TrimmedWord -match "^(\d{4})-?$" -and $Matches[1] -ne $DateNow.Year)
            {
                12..1 | ForEach-Object -Process {"$($Matches[1])-$("$_".PadLeft(2, "0"))"}
            }
            else
            {
                0..-11 | ForEach-Object -Process {$DateNow.AddMonths($_).ToString("yyyy-MM")}
            }

            foreach ($Item in $Dates)
            {
                if ($Item -like "$TrimmedWord*")
                {
                    $CompletionText = $Item
                    $ListItemText   = $Item
                    $ResultType     = [System.Management.Automation.CompletionResultType]::ParameterValue
                    $ToolTip        = $Item

                    [System.Management.Automation.CompletionResult]::new($CompletionText,$ListItemText,$ResultType,$ToolTip)
                }
            }
        }
        )]
        [string]
        $DateString,

        [Parameter(ParameterSetName = "Predefined")]
        [ValidatePattern("^KB\d+$")]
        [string]
        $KB,

        [Parameter(Mandatory, ParameterSetName = "Custom")]
        [string]
        $SearchText,

        [Parameter()]
        [ValidateSet("Title", "Products", "Classification", "Date", "Size")]
        [string]
        $SortBy,

        [Parameter()]
        [switch]
        $Descending
    )

    $UrlBuilder = [System.Text.StringBuilder]::new("https://www.catalog.update.microsoft.com/Search.aspx?q=")
    if ($SearchText)
    {
        $null = $UrlBuilder.Append($SearchText)
    }
    else
    {
        $OsString = switch ($OperatingSystem)
        {
            'Windows10' {'Windows 10'}
            'Windows11' {'Windows 11'}
            'WindowsServer' {'Microsoft server operating system'}
            'WindowsServer2019' {'Windows Server 2019'}
            'WindowsServer2016' {'Windows Server 2016'}
            default {''}
        }

        if ($UpdateKind -like "Cumulative*")
        {
            $UpdateText = switch ($UpdateKind)
            {
                'CumulativeOS' {"$DateString Cumulative Update for $OsString"}
                'CumulativeOSPreview' {"$DateString Cumulative  Update Preview for $OsString"}
                'CumulativeNET' {"$DateString Cumulative Update for .NET Framework"}
                'CumulativeNETPreview' {"$DateString Cumulative Update Preview for .NET Framework"}
            }

            $null = $UrlBuilder.Append("`"$($UpdateText.Trim())`"")

            if ($UpdateKind -like "CumulativeOS*")
            {
                # Exclude dynamic and framework updates. This is needed if the date and/or OS name is not included in the searchstring
                $null = $UrlBuilder.Append('-"Dynamic"-"Framework"')
            }

            if ($UpdateKind -like "CumulativeNET*" -and $OperatingSystem)
            {
                $null = $UrlBuilder.Append("+`"$OsString`"")
            }

            if ($OsVersion)
            {
                $null = $UrlBuilder.Append("+`"version $OsVersion`"")
            }

            if ($Architecture)
            {
                $null = $UrlBuilder.Append("+`"for $Architecture`"")
            }

            if ($KB)
            {
                $null = $UrlBuilder.Append("+`"$KB`"")
            }
        }
        elseif ($UpdateKind -eq "MSRT")
        {
            $null = $UrlBuilder.Append('"Windows Malicious Software Removal Tool"')
            if ($OperatingSystem)
            {
                $null = $UrlBuilder.Append("+`"$OsString`"")
            }
        }
        elseif ($UpdateKind -eq 'SecurityPlatform')
        {
            $null = $UrlBuilder.Append('"Update for Windows Security platform"')
        }
    }
    
    if ($SortBy)
    {
        $InternalSortName = switch ($SortBy)
        {
            'Classification' {'ClassificationComputed'}
            'Date' {'DateComputed'}
            'Size' {'SizeInBytes'}
            default {$_}
        }

        $null = $UrlBuilder.Append("&scol=$InternalSortName")
        if ($Descending)
        {
            $null = $UrlBuilder.Append("&sdir=desc")
        }
        else
        {
            $null = $UrlBuilder.Append("&sdir=asc")
        }
    }

    $BaseUrl = $UrlBuilder.ToString()
    $WriteTotalCount = $PSCmdlet.PagingParameters.IncludeTotalCount
    $SkipCounter = 0
    $UpdateCounter = 0
    $PageCounter = 0
    do
    {
        $PageCounter++
        $Url = if ($PageCounter -eq 1)
        {
            $BaseUrl
        }
        else
        {
            "$BaseUrl&p=$PageCounter"
        }

        Write-Verbose -Message "URL: $Url"
        $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop -Headers @{
            "accept-language"="en-US;q=0.8,en;q=0.7"
        }

        $Document = [HtmlAgilityPack.HtmlDocument]::new()
        $Document.LoadHtml($Response.Content)
        $Table = $Document.GetElementbyId('ctl00_catalogBody_updateMatches')
        if ($null -eq $Table)
        {
            # Found no updates
            if ($PageCounter -eq 1 -and $WriteTotalCount)
            {
                $PSCmdlet.PagingParameters.NewTotalCount(0, 1)
            }

            return
        }

        if ($PageCounter -eq 1 -and $WriteTotalCount)
        {
            $PageInfo = $Document.GetElementbyId('ctl00_catalogBody_searchDuration')
            $TotalCount = [regex]::Match($PageInfo.InnerText, '\d+ - \d+ of (\d+)').Groups[1].Value
            $PSCmdlet.PagingParameters.NewTotalCount($TotalCount, 1)
        }

        foreach ($Row in $Table.SelectNodes('tr') | Select-Object -Skip 1)
        {
            if ($PSCmdlet.PagingParameters.Skip -gt $SkipCounter++)
            {
                continue
            }

            $Data = $Row.SelectNodes('td')
            $Title = $Data[1].InnerText.Trim()
            $Products = $Data[2].InnerText.Trim()
            $Classification = $Data[3].InnerText.Trim()
            $UpdateDate = [datetime]::Parse($Data[4].InnerText.Trim(), [cultureinfo]::InvariantCulture)
            $Size = [uint64]([regex]::Match($Data[6].InnerText.Trim(), '\d+$').Value)
            $UpdateId = $Data[7].SelectSingleNode('input').Id

            [CatalogUpdate]@{
                Title          = $Title
                ReleaseDate    = $UpdateDate
                Size           = $Size
                Classification = $Classification
                Products       = $Products
                UpdateId       = $UpdateId
            }

            if (++$UpdateCounter -eq $PSCmdlet.PagingParameters.First)
            {
                return
            }
        }

        $HasNextPage = $null -ne $Document.GetElementbyId('ctl00_catalogBody_nextPageLink')
    } while ($HasNextPage)
}

<#
.SYNOPSIS
    Retrives download info (Download link, filehash, etc.) for the specified updates.

.DESCRIPTION
    Retrives download info (Download link, filehash, etc.) for the specified updates.

.EXAMPLE
    Find-CatalogUpdate -UpdateKind CumulativeNETPreview -First 1 -OperatingSystem WindowsServer2019 -SortBy Date -Descending | Get-CatalogUpdateDownloadInfo
    Finds the most recent .NET preview update for 2019 and retrieves the download info.

.PARAMETER UpdateId
    The ID of the update to get info for. The ID can be found with Find-CatalogUpdate.
#>
function Get-CatalogUpdateDownloadInfo
{
    [OutputType([CatalogDownloadInfo])]
    Param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string[]]
        $UpdateId
    )
    Process
    {
        $RequestParams = @{
            UseBasicParsing = $true
            Uri             = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
            Method          = "Post"
            ContentType     = "application/x-www-form-urlencoded"
            Headers         = @{
                "accept-language" = "en-US;q=0.8,en;q=0.7"
            }
        }
        foreach ($ID in $UpdateId)
        {
            $Response = Invoke-WebRequest @RequestParams -Body "updateIDs=$(ConvertTo-Json -InputObject (,@{updateID = $ID}) -Compress)"
            $FoundLinks = ParseDownloadDialogResponse -Content $Response.Content -ID $ID
            if ($null -eq $FoundLinks)
            {
                Write-Error -Message "Failed to find downloadinfo for update: $ID"
                continue
            }

            $FoundLinks
        }
    }
}

<#
.SYNOPSIS
    Downloads the specified update IDs to the specified folder.

.DESCRIPTION
    Downloads the specified update IDs to the specified folder.

.EXAMPLE
    Find-CatalogUpdate -UpdateKind CumulativeNETPreview -First 1 -OperatingSystem WindowsServer2019 -SortBy Date -Descending | Save-CatalogUpdate -OutputDirectory $Home
    Finds the most recent .NET preview update for 2019 and downloads it to the user folder.

.PARAMETER UpdateId
    The ID of the update to download. The ID can be found with Find-CatalogUpdate.

.PARAMETER OutputDirectory
    The directory where the files should be downloaded. If it doesn't exist it will be created.

.PARAMETER PrimaryOnly
    Specifies that only the primary update should be downloaded.
    Some updates include multiple file downloads.
    The primary download link is defined as the following:
    A file with a KB number that matches the overall update package or if that is not found, the first file in the list.

.PARAMETER Async
    Specifies that the downloads should happen asynchronously via Bits jobs.
#>
function Save-CatalogUpdate
{
    [OutputType([Microsoft.BackgroundIntelligentTransfer.Management.BitsJob])]
    Param
    (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string[]]
        $UpdateId,

        [Parameter(Mandatory)]
        [string]
        $OutputDirectory,

        [Parameter()]
        [switch]
        $PrimaryOnly,

        [Parameter()]
        [switch]
        $Async
    )
    begin
    {
        $OutputPath = (New-Item -Path $OutputDirectory -ItemType Directory -Force -ErrorAction Stop).FullName
    }
    Process
    {
        foreach ($ID in $UpdateId)
        {
            $DownloadInfo = Get-CatalogUpdateDownloadInfo -UpdateId $ID
            foreach ($Item in $DownloadInfo)
            {
                if ($PrimaryOnly -and !$Item.IsPrimary)
                {
                    continue
                }

                Start-BitsTransfer -Asynchronous:$Async -Source $Item.DownloadLink -Destination $OutputPath
            }
        }
    }
}

#endregion

#region Private functions

function ParseDownloadDialogResponse
{
    [OutputType([CatalogDownloadInfo])]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $Content,

        [Parameter(Mandatory)]
        [string]
        $ID
    )

    $UpdateTitle = $null
    $KB = $null
    if ($Content -match "downloadInformation\[0]\.enTitle\s='(.+)';")
    {
        $UpdateTitle = $Matches[1]
        if ($UpdateTitle -match 'KB\d+')
        {
            $KB = $Matches[0]
        }
    }

    $i = 0
    $FoundLinks = while ($true)
    {
        if ($Content -match "downloadInformation\[0]\.files\[$i]\.url\s=\s'(.+)';")
        {
            $Url = $Matches[1]
        }
        else
        {
            break
        }

        if ($Content -match "downloadInformation\[0]\.files\[$i]\.digest\s=\s'(.+)';")
        {
            $Sha1 = [System.BitConverter]::ToString([System.Convert]::FromBase64String($Matches[1])) -replace '-'
        }
        else
        {
            $Sha1 = ''
        }

        if ($Content -match "downloadInformation\[0]\.files\[$i]\.sha256\s=\s'(.+)';")
        {
            $Sha256 = [System.BitConverter]::ToString([System.Convert]::FromBase64String($Matches[1])) -replace '-'
        }
        else
        {
            $Sha256 = ''
        }

        [CatalogDownloadInfo]@{
            Title        = $UpdateTitle
            UpdateId     = $ID
            DownloadLink = $Url
            Sha1         = $Sha1
            Sha256       = $Sha256
            IsPrimary    = $Url -match $KB
        }
        $i++
    }

    if ($FoundLinks.Count -ge 1 -and $FoundLinks.IsPrimary -notcontains $true)
    {
        $FoundLinks[0].IsPrimary = $true
    }

    $FoundLinks
}

#endregion