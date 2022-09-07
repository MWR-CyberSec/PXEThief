# PXEThief

PXEThief is a set of tooling that implements attack paths discussed at the DEF CON 30 talk _Pulling Passwords out of Configuration Manager_ (https://forum.defcon.org/node/241925) against the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager (or ConfigMgr, still commonly known as SCCM). It allows for credential gathering from configured Network Access Accounts ([https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#network-access-account](https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#network-access-account)) and any Task Sequence Accounts or credentials stored within ConfigMgr Collection Variables that have been configured for the "All Unknown Computers" collection. These Active Directory accounts are commonly over permissioned and allow for privilege escalation to administrative access somewhere in the domain, at least in my personal experience. 

Likely, the most serious attack that can be executed with this tooling would involve PXE-initiated deployment being supported for "All unknown computers" on a distribution point without a password, or with a weak password. The overpermissioning of ConfigMgr accounts exposed to OSD mentioned earlier can then allow for a full Active Directory attack chain to be executed with only network access to the target environment. 

## Usage Instructions

```
python pxethief.py -h 
pxethief.py 1 - Automatically identify and download encrypted media file using DHCP PXE boot request. Additionally, attempt exploitation of blank media password when auto_exploit_blank_password is set to 1 in 'settings.ini'
pxethief.py 2 <IP Address of DP Server> - Coerce PXE Boot against a specific MECM Distribution Point server designated by IP address
pxethief.py 3 <variables-file-name> <Password-guess> - Attempt to decrypt a saved media variables file (obtained from PXE, bootable or prestaged media) and retrieve sensitive data from MECM DP
pxethief.py 4 <variables-file-name> <policy-file-path> <password> - Attempt to decrypt a saved media variables file and Policy XML file retrieved from a stand-alone TS media
pxethief.py 5 <variables-file-name> - Print the hash corresponding to a specified media variables file for cracking in Hashcat
pxethief.py 6 <identityguid> <identitycert-file-name> - Retrieve task sequences using the values obtained from registry keys on a DP
pxethief.py 7 <Reserved1-value> - Decrypt stored PXE password from SCCM DP registry key (reg query HKLM\software\microsoft\sms\dp /v Reserved1)
pxethief.py 8 - Write new default 'settings.ini' file in PXEThief directory
pxethief.py 10 - Print Scapy interface table to identify interface indexes for use in 'settings.ini'
pxethief.py -h - Print PXEThief help text
```

`pxethief.py 5 <variables-file-name>` should be used to generate a 'hash' of a media variables file that can be used for password guessing attacks with the Hashcat module published at [https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module](https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module).

## Configuration Options

A file contained in the main PXEThief folder is used to set more static configuration options. These are as follows: 
```
[SCAPY SETTINGS]
automatic_interface_selection_mode = 1
manual_interface_selection_by_id = 

[HTTP CONNECTION SETTINGS]
use_proxy = 0
use_tls = 0

[GENERAL SETTINGS]
sccm_base_url = 
auto_exploit_blank_password = 1
```

### Scapy settings

* `automatic_interface_selection_mode` will attempt to determine the best interface for Scapy to use automatically, for convenience. It does this using two main techniques. If set to `1` it will attempt to use the interface that can reach the machine's default GW as output interface. If set to `2`, it will look for the first interface that it finds that has an IP address that is not an autoconfigure or localhost IP address. This will fail to select the appropriate interface in some scenarios, which is why you can force the use of a specific inteface with 'manual_interface_selection_by_id'. 
* `manual_interface_selection_by_id` allows you to specify the integer index of the interface you want Scapy to use. The ID to use in this file should be obtained from running `pxethief.py 10`.

### General settings

* `sccm_base_url` is useful for overriding the Management Point that the tooling will speak to. This is useful if DNS does not resolve (so the value read from the media variables file cannot be used) or if you have identified multiple Management Points and want to send your traffic to a specific one. This should be provided in the form of a base URL e.g. `http://mp.configmgr.com` instead of `mp.configmgr.com` or `http://mp.configmgr.com/stuff`.
* `auto_exploit_blank_password` changes the behaviour of `pxethief 1` to automatically attempt to exploit a non-password protected PXE Distribution Point. Setting this to `1` will enable auto exploitation, while setting it to `0` will print the tftp client string you should use to download the media variables file. Note that almost all of the time you will want this set to `1`, since non-password protected PXE makes use of a binary key that is sent in the DHCP response that you receive when you ask the Distribution Point to perform a PXE boot. 

### HTTP Connection Settings 

Not implemented in this release

## Setup Instructions

1. Create a new Windows VM
2. Install Python (From https://www.python.org/ or through the store, both should work fine)
3. Install all the requirements through pip (`pip install -r requirements.txt`)
4. Install Npcap (https://npcap.com/#download) (or Wireshark, which comes bundled with it) for Scapy 
5. Bridge the VM to the network running a ConfigMgr Distribution Point set up for PXE/OSD
6. If using `pxethief.py 1` or `pxethief.py 2` to identify and generate a media variables file, make sure the interface used by the tool is set to the correct one, if it is not correct, manually set it in 'settings.ini' by identifying the right index ID to use from `pxethief.py 10`

## Limitations

* Proxy support for HTTP requests - Currently only configurable in code. Proxy support can be enabled on line 35 of `pxethief.py` and the address of the proxy can be set on line 693. I am planning to move this feature to be configurable in 'settings.ini' in the next update to the code base
* HTTPS and mutual TLS support - Not implemented at the moment. Can use an intercepting proxy to handle this though, which works well in my experience; to do this, you will need to configure a proxy as mentioned above 
* Linux support - PXEThief currently makes use of `pywin32` in order to utilise some built-in Windows cryptography functions. This is not available on Linux, since the Windows cryptogrphy APIs are not available on Linux :P The Scapy code in `pxethief.py`, however, is fully functional on Linux, but you will need to patch out (at least) the include of `win32crypt` to get it to run under Linux

## Proof of Concept note

Expect to run into issues with error handling with this tool; there are subtle nuances with everything in ConfigMgr and while I have improved the error handling substantially in preparation for the tool's release, this is in no way complete. If there are edge cases that fail, make a detailed issue or fix it and make a pull request :) I'll review these to see where reasonable improvements can be made. Read the code/watch the talk and understand what is going on if you are going to run it in a production environment. Keep in mind the licensing terms - i.e. use of the tool is at your own risk.

## Related work

[Identifying and retrieving credentials from SCCM/MECM Task Sequences](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences) - In this post, I explain the entire flow of how ConfigMgr policies are found, downloaded and decrypted after a valid OSD certificate is obtained. I also want to highlight the first two references in this post as they show very interesting offensive SCCM research that is ongoing at the moment.
[DEF CON 30 Slides](https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Christopher%20Panayi%20-%20Pulling%20Passwords%20out%20of%20Configuration%20Manager%20Practical%20Attacks%20against%20Microsofts%20Endpoint%20Management%20Software.pdf) - Link to the talk slides

## Author Credit 

Copyright (C) 2022 Christopher Panayi, MWR CyberSec
