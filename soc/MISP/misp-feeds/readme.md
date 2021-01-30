## Python Service for MISP Feed Management
This set of scripts is designed to offer better reliability and more control over the fetching of feeds into MISP. For the moment, the schedule is broken up into multiple components, at the top of feed_manager.py:
- **MISP_TIMES:** An array of times (24hr format) when enabled MISP feeds will be fetched and cached.  
- **TEXT_TIMES:** An array of times (24hr format) when enabled plaintext and CSV feeds will be fetched and cached.  
- **TWITTER_TIMES:** An array of times (24hr format) when the Twitter API will be queried for new tweets.  
- **OTX_TIMES:** An array of times (24hr format) when the OTX API will be queried for new+updated pulses.  
- **XFORCE_TIMES:** An array of times (24hr format) when the X-Force API will be queried for new+updated cases.  
- **HOURLY_FEEDS** An array of the ID's of enabled feeds that you wish to run at the beginning of every hour.  
- **FULL_EXPORT_TIME** The time (24hr format) that you want to run a full text export of attributes.  

In addition to this are "ENABLE" options for all external services. By default, Abuse.ch is configured to run every hour.

Am still working out the best way of going about granular scheduling.

### Variable Notes:
- **MISP_ADMIN_KEY:** MISP feeds must be fetched by a Site Admin user.  
- **MISP_USER_KEY:** This can be the key of an Org Admin, Sync User or your own custom role. They must be able to both manage and publish events, and hold the Tag Editor permission.  

### Installation:
- Recommended: Ensure that the fetch_feeds and cache_feeds Scheduled Tasks are not enabled.   Also, disable the default Abuse.ch feeds as this project includes a module that loads the data with more context and into a separate event each day.
- SCP this folder to your MISP server.  
- Alter the paths in misp-feeds.service and start_worker.sh to point to where you've dropped the folder.  
- Correct the user in misp-feeds.service if it is not ubuntu.  
- Complete the variables at the top of the feed_manager.py, misp_export.py, otx_misp.py, twitter_misp.py and xforce_misp.py scripts.  
- Run the following (in the misp-feeds folder):  
```
chmod +x start_worker.sh
apt install nodejs
pip3 install -r requirements.txt
sudo mv misp-feeds.service /etc/systemd/system
sudo chown root:root /etc/systemd/system/misp-feeds.service
sudo systemctl daemon-reload
sudo systemctl start misp-feeds.service
```
- nodejs is required for cfscrape (used by the Twitter module to get Ghostbin pastes).  
- Check misp_feeds.log for errors. You can also run both of the Python scripts from the command line for standalone, ad-hoc operation.  

### Module Notes:
#### Export:
- This is a rough script that I use for exporting a plaintext list of attributes for ingestion into external facilities. They're output to a subfolder of the MISP webroot, so ensure the script user has permission to write here and there's adequate access control in place.  
- A full export is run once a day for the number of days defined by EXPORT_DAYS. Incremental updates are made daily.  
- The sample values for EXPORT_TAGS and EXPORT_TYPES should give you an idea of how to configure this. 'domain' and 'hostname' can be output separately or together. Use EXPORT_MERGE_HOSTNAME to configure this.  

#### Twitter:
- Twitter is considered a feed of indicators as opposed to events. Indicators are therefore put in a fixed event. Ensure that you define a unique event title (variable: MISP_EVENT_TITLE). All attributes are commented with the source tweet.  
- The accuracy of pulling domains from Twitter is sketchy, at best. I prefer to leave this disabled (variable: INCLUDE_DOMAINS).  

#### X-Force:
- Tagging of X-Force sourced events is currently limited to string matches in the case title. Cases are generically tagged (i.e. not tagged with specific adversary or tool names), and string matches on text bodies is unreliable.  