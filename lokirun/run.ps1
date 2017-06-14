# LokiRun
# PowerShell Automation for IOC Scanning
#
# By Chris Campbell
# @phage_nz
#
# Requires:
# Loki (https://github.com/Neo23x0/Loki)
#
# Automate scans using task scheduler (as an example, will run weekly on Saturday @ 03:00 under the user profile):
# SchTasks /Create /SC WEEKLY /D SAT /ST 03:00 /RU "NT AUTHORITY\SYSTEM" /TN "Loki IOC Scanner" /TR "PowerShell -File \"c:\tools\loki\run.ps1\""

# Loki installation directory.
$baseDirectory = "C:\tools\loki"

# Log directory.
$logDirectory = "C:\tools\loki\logs"

# Update Loki prior to scan?
$updateLoki = "yes" # "yes" or "no".

#Define mail settings.
$msg = New-Object System.Net.Mail.MailMessage # Do not change.
$msg.To.Add("bob@example.com")
$msg.CC.Add("jane@example.com") 
$msg.From = "noreply@example.com" 
$smtpServer = "smtp.example.com" 
$smtpClient = New-Object Net.Mail.SmtpClient($smtpServer) # Do not change.

# Fixed variables.
$timeStamp = Get-Date -format yyyy-MM-dd-HH-mm-ss
$baseDirectory = $baseDirectory.TrimEnd('\')
$logDirectory = $logDirectory.TrimEnd('\')
$lokiBin = "{0}\loki.exe" -f $baseDirectory
$lokiLog = "{0}\loki_{1}_{2}.log" -f $logDirectory, $env:computername, $timeStamp
$procArgs = "--csv --dontwait --intense --noindicator --onlyrelevant -l {0}" -f $lokiLog

Function UpdateLoki()
{
    # Update Loki.
    Write-Host "Updating Loki..."
    $runProc = Start-Process $lokiUpdater $updateArgs -WindowStyle Hidden -PassThru -Wait
    $exitCode = $runProc.ExitCode
    Write-Host "Update complete!"
}

Function RunLoki()
{
    # Run Loki.
    Write-Host "Running Loki..."
    $runProc = Start-Process $lokiBin $procArgs -WindowStyle Hidden -PassThru -Wait
    $exitCode = $runProc.ExitCode
    Write-Host "Loki run complete!"

    # Process output.
    if ($exitCode -eq 0)
    {
        Write-Host "Processing log..."

        $logContent = Get-Content $lokiLog

        if ($logContent.Count -gt 0)
        {
            $alerts = @()
            Write-Host "Warnings and/or Alerts have been recorded! Note: Only alerts will generate an event."

            foreach ($line in $logContent)
            {
                $elements = $line.Split(",")

                if ($elements[2] -eq "ALERT")
                {
                    $alert = $elements[3]
                    $alerts += $alert
                }
            }

            if ($alerts.Count -gt 0)
            {
                Write-Host "Processing alerts..."

                ProcessAlerts($alerts)
            }

            else
            {
                Write-Host "No alerts recorded!"
            }
        }

        else
        {
            Write-Host "No warnings or alerts recorded!"
        }

        #Write-Host "Cleaning up log..."
        #Remove-Item -Path $lokiLog

        Write-Host "Run complete!"
    }

    else
    {
        Write-Host "Loki returned non-zero exit code. Scan assumed as failed."
    }
}

Function ProcessAlerts ($alerts)
{   
    foreach ($alert in $alerts)
    {
        $alert = $alert -creplace "(\w)(REASON_[0-9]+:)", '$1 $2'

        $regex = "{0}:\s(.*?)(?=((\s[\d\w]+:\s)|$))"

        if ($alert.Contains("PID:"))
        {
            $alert = ("REASON: {0}" -f $alert)

            $procPID = [regex]::Matches($alert, ($regex -f "PID")).Value
            $procName = [regex]::Matches($alert, ($regex -f "NAME")).Value

            Write-Host ("Process Alert: {0} (PID: {1})..." -f $procName, $procPID)
        }

        else
        {
            $fileName = [regex]::Matches($alert, ($regex -f "FILE")).Value
            $fileMD5 = [regex]::Matches($alert, ($regex -f "MD5")).Value

            Write-Host ("File Alert: {0} ({1})..." -f $fileName, $fileMD5)
        }

        Write-Host ("Raw log:`n`n{0}`n" -f $alert)

        # Convoluted method to insert new lines.
        $randomString = GetRandomString(12)
        $event = $alert -creplace "([A-Z0-9_]{3,}_?[0-9]*?:)", ('{0}$1' -f $randomString)
        $event = $event -replace $randomString, "`r`n"
        $event += "`r`n"

        $body += $event
    }

    Write-Host "Sending notification..."

    # Form and send message.
    $msg.Body = "`n`nLoki has produced one or more alerts. Please investigate:`r`n{0}" -f $body
    $msg.Subject = "Loki Compromise Alert for: {0}" -f $env:computername  
    $smtpClient.Send($msg)
}

Function GetRandomString ($length)
{
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEDFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray()
    $randomString = ""
    
    for ($i = 0; $i -lt $length; $i++)
    {
        $randomString += $charSet | Get-Random
    }
    
    Return $randomString   
}

if ($updateLoki.ToLower() -eq "yes")
{
    UpdateLoki
}

RunLoki