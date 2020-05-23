## Modular Sysmon Configuration

### Notes
Event types are separated into individual folders. A single file is used for Include rule groups (include.xml), and individual files for each category of rules that form an Exclude rule group. Separating out Exclude rule groups enables Sysmon configurations to be tailored more specifically to the exclusion requirements of a target host group - keeping exclusions at a minimum.

### Building the Config
Alter the GCI file filter as required:
```
. .\Merge-AllSysmonXml.ps1
Merge-AllSysmonXml -Path (Get-ChildItem '*\*.xml') -AsString | Out-File sysmonconfig.xml
```

### Credit
Many thanks to Olaf Hartong for the concept of a modular configuration and the PowerShell script:  
https://github.com/olafhartong/sysmon-modular

This configuration was built upon the one distributed with:  
https://github.com/BlueTeamLabs/sentinel-attack