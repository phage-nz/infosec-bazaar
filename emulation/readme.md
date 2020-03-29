## Adversary Emulation

In this folder are sample wrapper scripts for the Atomic Red Team Attack Runner (https://github.com/redcanaryco/atomic-red-team/tree/master/execution-frameworks/contrib/python), to give you an idea how ART can be used for emulation of groups. The general method can be applied to any group, just drop in a config specific to it.

Only a few of the tests undo the changes that they make. Either be prepared to unpick the changes or - ideally - take a snapshot of the target before running them.  

Also contained in this folder is "cradle.ps1". Use this to PowerShell script to download live samples (either specific, or random) to test and execute endpoint detection capability.

### Use Cases
Some ideas:
- SIEM+EDR capability demos and benchmarking.  
- Identifying gaps in detection.  
- Analyst training. Fire the scripts at a server and set your analysts on a hunt!  

### Setup
The folder structure you should end up with is:
```
\atomic-tests
\atomic-tests\apt33.py
\atomic-tests\atomic-requirements.txt
\atomic-tests\fin10.py
\atomic-tests\python-requirements.txt
\atomic-tests\runner.py
\atomic-tests\turla.py
\atomic-tests\atomics\
```

- Clone or download ("Clone or download" > "Download ZIP") the Atomic Red Team project from: https://github.com/redcanaryco/atomic-red-team/  
- Discard all except the atomics folder.  
- Drop my patched T1086.yml into the T1086 atomics folder. It fixes a problem with the HTA test command syntax.  
- Into the same folder, download runner.py from: https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/execution-frameworks/contrib/python/runner.py    
- Line 26 of runner.py should be modified to point to the atomic subdirectory:  
```
ATOMICS_DIR_RELATIVE_PATH = os.path.join("atomics")
```
- Manually install the pre-req's described in atomic-requirements.txt (not exhaustive, there may be others needed) and use pip to install Python requirements from python-requirements.txt (pip install -r python-requirements.txt).  

### Operation
Once the folder structure is set up you can either develop new tests or run the samples (as simple as 'python filename.py'). To develop a new test, all you really need to do is redefine ACTOR_NAME, ACTOR_URL and ACTOR_CONFIG. The name and URL are purely for the standard output, but ACTOR_CONFIG will need changing:
- Begin by listing the techniques employed by the group, either based on your own intel or by referring to attack.mitre.org.  
- The config is a JSON key value list of the format:
```
"TECHNIQUE_ID": {"name": "TECHNIQUE_NAME", "tests": [TEST_INT, TEST_INT], "parameters": {"PARAM_NAME": "PARAM_VALUE", "PARAM_NAME": "PARAM_VALUE"}}
```
For example:
```
"T1048": {"name": "Exfiltration Over Alternative Protocol", "tests": [0], "parameters": {"ip_address": "127.0.0.1"}}
```
The "parameters" value is optional. Where all tests for the technique do not require optional parameters, you can leave this out. Just refer to any of the samples to get an idea.

To determine the list of tests to run (i.e. the TEST_INT values):
- Run "python runner.py interactive".  
- Enter the technique ID (e.g. T1077).  
- Above each test is a number. These numbers go in the "tests" list of your config. Where only a single test is available, just enter "0".  
