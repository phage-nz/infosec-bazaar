## MHN Notes ##

### Install Issues ###

- The legacy MaxMind geo databases have been discontinued. Pull them from a mirror such as that hosted by Slackware and replace the DAT file values in/opt/hpfeeds/examples/geoloc/geoloc.py from GeoLite2-City.dat to the respective legacy file names for v4 and v6:  

*wget https://mirrors.slackware.com/mb-sources/GeoIP/GeoLiteCity.dat.gz && gzip -d GeoLiteCity.dat.gz  
wget https://mirrors.slackware.com/mb-sources/GeoIP/GeoLiteCityv6.dat.gz && gzip -d GeoLiteCityv6.dat.gz  
wget https://mirrors.slackware.com/mb-sources/GeoIP/GeoIPASNum.dat.gz && gzip -d GeoLiteCity.dat.gz  
wget https://mirrors.slackware.com/mb-sources/GeoIP/GeoIPASNumv6.dat.gz && gzip -d GeoIPASNumv6.dat.gz*  
    
- As per this Google Groups thread (https://groups.google.com/forum/#!searchin/modern-honey-network/logstash%7Csort:relevance/modern-honey-network/vUO1B_1hzPw/8NpVAo0cBgAJ) change 'index_type' to 'document_type' in \/opt\/logstash\/mhn.conf, and define a since_db path for Logstash.  
- Provide www-data permission to write to mhn.log (reference: https://github.com/threatstream/mhn/wiki/MHN-Troubleshooting-Guide#password-reset-through-the-web-app-is-not-working-andor-retrieving-httpyour-sitestaticmhnrules-causes-a-404), as required by the Celery worker: sudo chown www-data:www-data \/var\/log\/mhn\/mhn.log  
- Enable HTTPS for MHN and HoneyMap by referring to: https://github.com/threatstream/mhn/wiki/Running-MHN-Over-HTTPS  
- Enable HTTPS for ELK using an nginx reverse proxy (similar to that used for HoneyMap), and enable basic auth (or similar): https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/  

### Dionaea Hardening ###

deploy_dionaea.sh (still for Ubuntu 14.04, ugh) has been altered to generate a random server name, use a proper MS-SQL version string and present accurate IIS FTP welcome banners. This should help harden it against fingerprinting.  

### Wordpot Hardening ###

If deploying Wordpot alongside RDPY and/or Dionaea you may want to tweak the server header to create a consistent Microsoft platformed facade:  

*sed -i 's/Apache\\/2.2.22 (Ubuntu)/Microsoft-IIS\\/7.5/g' /opt/wordpot/wordpot.conf*


### RDPY Integration ###

**Note: Work in progress!**  
 
Configure a new deployment script for RDPY through the 'Deploy' page of the MHN web interface using the contents of deploy_rdpy.sh  

Copy rdpy_events.py to \/opt\/mnemosyne\/normalizer\/module\s/rdpy_events.py  

In \/opt\/hpfeeds\/examples\/geoloc\/processors.py create a new processor for RDPY events:  
```
def rdpy_events(identifier, payload, gi):  
    try:  
        dec = ezdict(json.loads(str(payload)))  
    except:  
        print 'exception processing rdpy event'  
        traceback.print_exc()  
        return None  
    return create_message('rdpy.events', identifier, gi, src_ip=dec.src_ip, dst_ip=dec.dst_ip)
```

Add rdpy.events to the channels mappings in:  
- \/opt\/mhn/server\/config.py  
- \/opt\/hpfeeds\/geoloc.json  
- \/opt\/mnemosyne\/normalizer\/normalizer.py  
- \/opt\/hpfeeds\/geoloc.json  
- \/opt/hpfeeds\/examples\/geoloc\/geoloc.py  

More info is available here: https://github.com/threatstream/mhn/wiki/Howto%3A-Add-Support-for-New-Sensors-to-the-MHN

Add hpfeeds permissions in mongodb:

*mongo hpfeeds  
db.auth_key.update({"identifier": "collector"}, {"$push": {"subscribe": "rdpy.events"} })  
db.auth_key.update({"identifier": "geoloc"}, {"$push":{ "subscribe": "rdpy.events" }})  
db.auth_key.update({"identifier": "hpfeeds-logger-json"}, {"$push": {"subscribe": "rdpy.events"} })  
db.auth_key.update({"identifier": "mnemosyne"}, {"$push": {"subscribe": "rdpy.events"} })*  

Deploy your sensor as per usual.

#### To-Do: ####
- Log RDPY login credentials to MHN ELK.
