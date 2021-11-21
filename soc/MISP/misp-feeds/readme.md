## Python Service for MISP Feed Management
This set of scripts is designed to offer better reliability and more control over the fetching of feeds into MISP. For the moment, the schedule is broken up into multiple components, at the top of each plugin and in config.py:
- **MISP_TIMES:** An array of times (24hr format) when enabled MISP feeds will be fetched and cached.  
- **TEXT_TIMES:** An array of times (24hr format) when enabled plaintext and CSV feeds will be fetched and cached.  
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

#### Plugins:

At the top of each plugin are three variables which determine its operation:

- PLUGIN_NAME: The friendly name of the Plugin. Only used for logging and ad-hoc operation.

- PLUGIN_ENABLED: Boolean setting to enable/disable the plugin.

- PLUGIN_TIMES: The times throughout the day to run the plugin. Also accepts 'hourly', which will run it on the hour every hour.

Default plugins are as follows:

- Abuse.ch: Pulls URLhaus, Feodo Tracker, MalwareBazaar and ThreatFox into a single event per day. Attributes are tagged according to the feed tags and/or classification.
- CleanMX: Virus and Phishing feeds are pulled into a single event per day. No tagging yet.
- OTX: Individual pulses form a separate events in MISP. OTX tags can be spammy so are ignored, but Adversary, Malware and ATT&CK techniques are used. Galaxy tags are attempted, and if no appropriate tag can be found, the feed supplied tag is used.
- RiskIQ: Individual articles form a separate events in MISP. The same method of tagging is employed as OTX.
- Twitter: Pulls IOC's found on Twitter into a single event per day. GitHub, PasteBin and GhostBin links are followed and also scraped. Attributes are tagged with the hashtags included in the Tweet and the same method as OTX.
- X-Force: Individual articles form a separate events in MISP. X-Force articles are not tagged, so the Title of the article is parsed to identify Galaxy tags that match Title keywords.
