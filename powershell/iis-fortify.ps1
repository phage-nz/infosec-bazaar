# IISFortify-PS
# By Chris Campbell

# Define TLS protocol support:
# 1: TLSv1.0, TLSv1.1, TLSv1.2 (default)
# 2: TLSv1.1, TLSv1.2
# 3: TLSv1.2
$tls_support = 1

# Configure security response headers:
# $true OR $false
$apply_headers = $true

function Restrict-Information {
    $appcmd = $(Join-Path $env:windir 'system32\inetsrv\appcmd.exe')

    Write-Output '[*] Removing IIS and ASP.NET server identification...'
    & $appcmd set config  -section:system.webServer/rewrite/outboundRules "/+[name='Remove_RESPONSE_Server']" /commit:apphost
    & $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].patternSyntax:`"Wildcard`"" /commit:apphost
    & $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].match.serverVariable:RESPONSE_Server" "/[name='Remove_RESPONSE_Server'].match.pattern:`"*`"" /commit:apphost
    & $appcmd set config  -section:system.webServer/rewrite/outboundRules "/[name='Remove_RESPONSE_Server'].action.type:`"Rewrite`"" "/[name='Remove_RESPONSE_Server'].action.value:`" `"" /commit:apphost

    & $appcmd set config /section:httpProtocol "/-customHeaders.[name='X-Powered-By']"

    #HSTS header
    Write-Output '[*] Configuring HSTS header...'
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='Strict-Transport-Security',value='max-age=31536000; includeSubDomains']"

    # Prevent framejacking.
    Write-Output '[*] Configuring other Security headers...'
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='cache-control',value='private, max-age=0, no-cache']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Content-Type-Options',value='nosniff']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-XSS-Protection',value='1; mode=block']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Frame-Options',value='SAMEORIGIN']"
    & $appcmd set config /section:httpProtocol "/+customHeaders.[name='X-Download-Options',value='noopen']"
}

function Harden-Crypto($protocol_value) {
    Write-Output '[*] Applying hardened SSL/TLS configuration...'
    
    New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -name SchUseStrongCrypto -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -name SchUseStrongCrypto -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -name SchUseStrongCrypto -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -name SchUseStrongCrypto -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name DefaultSecureProtocols -value $protocol_value -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name DefaultSecureProtocols -value $protocol_value -PropertyType 'DWord' -Force | Out-Null
}

if ($apply_headers -eq $true)
{
    Restrict-Information
}

else
{
    Write-Output '[!] Skipping response header configuration...'
}

$protocol_value = '0x00000A80'

if ($tls_support -eq 2)
{
    $protocol_value = '0x00000A00'
}
    
elseif ($tls_support -eq 3)
{
    $protocol_value = '0x00000800'
}

Harden-Crypto $protocol_value

Write-Output '[!] IISFortify-PS complete!'