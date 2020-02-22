## Python Service for MISP Feed Management
This set of scripts is designed to offer better reliability and more control over the fetching of feeds into MISP. For the moment, the schedule is broken up into four components, at the top of feed_manager.py:
- **MISP_TIMES:** An array of times (24hr format) when enabled MISP feeds will be fetched and cached.  
- **TEXT_TIMES:** An array of times (24hr format) when enabled plaintext and CSV feeds will be fetched and cached.  
- **OTX_TIMES:** An array of times (24hr format) when the OTX API will be queried for new+updated pulses.  
- **HOURLY_FEEDS** An array of the ID's of enabled feeds that you wish to run at the beginning of every hour.  

### Variable Notes:
- **MISP_ADMIN_KEY:** MISP feeds must be fetched by a Site Admin user.  
- **MISP_USER_KEY:** This can be the key of an Org Admin, Sync User or your own custom role. They must be able to both manage and publish events, and hold the Tag Editor permission.  
- By setting it to True, TEST_RUN allows you to bypass the schedule and immediately fetch all enabled feeds.

### Installation:
- Recommended: Ensure that the fetch_feeds and cache_feeds Scheduled Tasks are not enabled.  
- SCP this folder to your MISP server.  
- Alter the paths in misp-feeds.service and start_worker.sh to point to where you've dropped the folder.  
- Correct the user in misp-feeds.service if it is not ubuntu.  
- Complete the variables at the top of both the feed_manager.py and otx_misp.py scripts.  
- Run the following (in the misp-feeds folder):  
```
chmod +x start_worker.sh
pip3 install -r requirements.txt
sudo mv misp-feeds.service /etc/systemd/system
sudo systemctl daemon-reload
sudo systemctl start misp-feeds.service
```
- Check misp_feeds.log for errors. You can also run both of the Python scripts from the command line for standalone, ad-hoc operation.  