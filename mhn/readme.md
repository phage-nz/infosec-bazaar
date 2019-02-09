## MHN Notes ##

### Install Issues ###

- The legacy MaxMind geo databases have been discontinued. Until MHN is updated to support the new format the legacy databases are available under the geo_databases folder of this repo and should be extracted to into \/opt on the MHN server. May need to make a copy of the city file as \/opt\/GeoLite2-City.dat  
- As per this Google Groups thread (https://groups.google.com/forum/#!searchin/modern-honey-network/logstash%7Csort:relevance/modern-honey-network/vUO1B_1hzPw/8NpVAo0cBgAJ) change 'index_type' to 'document_type' in \/opt\/logstash\/mhn.conf, and define a since_db path for Logstash.  
- Provide www-data permission to write to mhn.log (reference: https://github.com/threatstream/mhn/wiki/MHN-Troubleshooting-Guide#password-reset-through-the-web-app-is-not-working-andor-retrieving-httpyour-sitestaticmhnrules-causes-a-404), as required by the Celery worker: sudo chown www-data:www-data \/var\/log\/mhn\/mhn.log  


### Dionaea Hardening ###

deploy_dionaea.sh (still for Ubuntu 14.04, ugh) has been altered to generate a random server name and use a proper MS-SQL version string. This should help harden it against fingerprinting.  


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

#### Known Issues: ####
- RDPY events don't seem to be logging to HoneyMap.
