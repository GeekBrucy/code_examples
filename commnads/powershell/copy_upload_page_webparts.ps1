# ==============================
# Migrate single ASPX page + WebParts
# SharePointPnPPowerShell2016 3.13
# ==============================

# ---------- Config ----------
$SourceSiteUrl = "http://sp2016/sites/demo/subsite"
$TargetSiteUrl = "http://sp2022/sites/demo/subsite"

# SitePages 或 Pages
$PageLibrary = "SitePages"
$PageName = "test.aspx"

$TempRoot = "D:\temp\sp-page-migration"
$PageTempFolder = Join-Path $TempRoot "page"
$WebPartTempFolder = Join-Path $TempRoot "webparts"

$PageUrl = "$PageLibrary/$PageName"
$LocalPageFile = Join-Path $PageTempFolder $PageName

# ---------- Prepare ----------
Import-Module SharePointPnPPowerShell2016 -ErrorAction Stop

foreach ($folder in @($TempRoot, $PageTempFolder, $WebPartTempFolder)) {
  if (!(Test-Path $folder)) {
    New-Item -ItemType Directory -Path $folder | Out-Null
  }
}

# 清理旧的导出 WebPart XML
Get-ChildItem $WebPartTempFolder -Filter "*.xml" -ErrorAction SilentlyContinue |
Remove-Item -Force

# ---------- Step 1: Download ASPX ----------
Write-Host "Connecting to source: $SourceSiteUrl"
Connect-PnPOnline -Url $SourceSiteUrl -CurrentCredentials

Write-Host "Downloading page: $PageUrl"
Get-PnPFile `
  -Url $PageUrl `
  -Path $PageTempFolder `
  -FileName $PageName `
  -AsFile `
  -Force

if (!(Test-Path $LocalPageFile)) {
  throw "Page download failed: $LocalPageFile"
}

# ---------- Step 2: Export WebParts ----------
Write-Host "Reading WebParts from source page..."

$webparts = Get-PnPWebPart -ServerRelativePageUrl $PageUrl

if ($null -eq $webparts -or $webparts.Count -eq 0) {
  Write-Host "No WebParts found on source page."
}
else {
  $counter = 1

  foreach ($wp in $webparts) {
    # 用 WebPart 原始标题作为文件名基础
    $title = $wp.Title

    if ([string]::IsNullOrWhiteSpace($title)) {
      $title = "UntitledWebPart"
    }

    # Windows 文件名不能包含这些字符，所以只替换非法字符
    $safeTitle = $title -replace '[\\/:*?"<>|]', '_'

    # 加 counter 防止多个 WebPart 同名时覆盖
    $xmlFileName = "{0:D2}-{1}.xml" -f $counter, $safeTitle
    $xmlPath = Join-Path $WebPartTempFolder $xmlFileName

    Write-Host "Exporting WebPart: $title"

    Get-PnPWebPartXml `
      -ServerRelativePageUrl $PageUrl `
      -Identity $wp.Id `
    | Out-File $xmlPath -Encoding UTF8

    $counter++
  }
}

# ---------- Step 3: Upload ASPX ----------
Write-Host "Connecting to target: $TargetSiteUrl"
Connect-PnPOnline -Url $TargetSiteUrl -CurrentCredentials

Write-Host "Uploading page to target: $PageLibrary"
Add-PnPFile `
  -Path $LocalPageFile `
  -Folder $PageLibrary

# ---------- Step 4: Import WebParts ----------
$xmlFiles = Get-ChildItem $WebPartTempFolder -Filter "*.xml" | Sort-Object Name

foreach ($xml in $xmlFiles) {
  Write-Host "Reading WebPart XML: $($xml.Name)"

  [xml]$wpXml = Get-Content $xml.FullName

  $zoneIdNode = $wpXml.SelectSingleNode("//*[local-name()='ZoneID']")
  $partOrderNode = $wpXml.SelectSingleNode("//*[local-name()='PartOrder']")

  $zoneId = "Main"
  $zoneIndex = 0

  if ($zoneIdNode -ne $null -and ![string]::IsNullOrWhiteSpace($zoneIdNode.InnerText)) {
    $zoneId = $zoneIdNode.InnerText
  }

  if ($partOrderNode -ne $null -and ![string]::IsNullOrWhiteSpace($partOrderNode.InnerText)) {
    $zoneIndex = [int]$partOrderNode.InnerText
  }

  Write-Host "Importing WebPart: $($xml.Name) | ZoneID: $zoneId | PartOrder: $zoneIndex"

  Add-PnPWebPartToWebPartPage `
    -ServerRelativePageUrl $PageUrl `
    -Path $xml.FullName `
    -ZoneId $zoneId `
    -ZoneIndex $zoneIndex
}

Write-Host "Migration completed."
Write-Host "Target page: $TargetSiteUrl/$PageUrl"