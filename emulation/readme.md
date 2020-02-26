## Adversary Emulation

In this folder are sample wrapper scripts for the Atomic Red Team Attack Runner (https://github.com/redcanaryco/atomic-red-team/tree/master/execution-frameworks/contrib/python), to give you an idea how ART can be used. The general method can be applied to any group, just drop a config specific to the it in.

Only a few of the tests undo the changes that they make. Either be prepared to unpick the changes or - ideally - take a snapshot on the target before running them.

### Use Cases
Some ideas:
- SIEM+EDR capability demos and benchmarking.  
- Identifying gaps in detection.  
- Analyst training. Fire the scripts at a server and set your analysts on a hunt!  

### Setup
The folder structure I've used is:
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

- Get the atomics folder here: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics  
- Drop my patched T1086.yml in the T1086 atomics folder. It fixes a problem with the HTA test command syntax.  
- Get runner.py here: https://github.com/redcanaryco/atomic-red-team/blob/master/execution-frameworks/contrib/python/runner.py  
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