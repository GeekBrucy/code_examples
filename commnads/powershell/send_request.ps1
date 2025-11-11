<#
===========================================================================================
  HttpPostWithFile.ps1
  Purpose: Send an HTTP POST request with form data and file upload
           using Basic Authentication in PowerShell.
===========================================================================================
#>

# ======================
# 1️⃣ Basic variables
# ======================

# Target endpoint
$uri = "https://api.example.com/upload"

# Basic auth credentials
$username = "myuser"
$password = "mypassword"

# Encode to Base64 for Basic Authentication header
$pair = "$username`:$password"
$encodedCreds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))

# ======================
# 2️⃣ Build the multipart form data
# ======================

# File to upload
$filePath = "C:\Files\report.pdf"

# Boundary string (used to separate multipart fields)
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"

# Build multipart body manually (for full control)
$bodyLines = @()

# Example: add a text field
$bodyLines += "--$boundary"
$bodyLines += 'Content-Disposition: form-data; name="description"'
$bodyLines += ""
$bodyLines += "Weekly report upload"

# Add the file field
$bodyLines += "--$boundary"
$bodyLines += "Content-Disposition: form-data; name=`"file`"; filename=`"$(Split-Path $filePath -Leaf)`""
$bodyLines += "Content-Type: application/pdf"
$bodyLines += ""
$bodyLines += [System.IO.File]::ReadAllText($filePath)

# End boundary
$bodyLines += "--$boundary--"
$bodyLines += ""

# Join everything with CRLF
$body = $bodyLines -join $LF

# ======================
# 3️⃣ Send POST request
# ======================

$response = Invoke-RestMethod `
  -Uri $uri `
  -Method Post `
  -Headers @{ 
  "Authorization" = "Basic $encodedCreds"
  "Content-Type"  = "multipart/form-data; boundary=$boundary"
} `
  -Body $body

Write-Host "✅ Upload completed. Response:"
$response

# ======================
# 4️⃣ Alternate: Use .NET HttpClient (for large files or binary-safe uploads)
# ======================

# Create the client
$handler = New-Object System.Net.Http.HttpClientHandler
$client = New-Object System.Net.Http.HttpClient($handler)

# Apply basic auth header
$client.DefaultRequestHeaders.Authorization = `
  New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Basic", $encodedCreds)

# Create multipart form content
$content = New-Object System.Net.Http.MultipartFormDataContent

# Add text fields
$content.Add((New-Object System.Net.Http.StringContent("Weekly report upload")), "description")

# Add file content as binary stream
$fileStream = [System.IO.File]::OpenRead($filePath)
$fileContent = New-Object System.Net.Http.StreamContent($fileStream)
$fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/pdf")
$content.Add($fileContent, "file", (Split-Path $filePath -Leaf))

# Send the request
$response = $client.PostAsync($uri, $content).Result

Write-Host "`n✅ Response Code: $($response.StatusCode)"
Write-Host "Response Body:"
$response.Content.ReadAsStringAsync().Result

# Dispose objects
$fileStream.Dispose()
$client.Dispose()