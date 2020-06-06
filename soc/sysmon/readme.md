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
This configuration is mostly derived from the following projects:  
- https://github.com/olafhartong/sysmon-modular  
- https://github.com/BlueTeamLabs/sentinel-attack  

It's just pieced together in a way that better suits my needs.