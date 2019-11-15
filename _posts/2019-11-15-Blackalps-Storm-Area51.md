---
layout: post
title: Blackalps 2019 - Storm Area 51
---

This writeup is about one out of two forensic challenges from the Blackalps 2019 CTF. It is about memory analysis. It's topic is the Area 51 Raid that happened on September 20, 2019.

<!--more-->

## Description
Hello young NSA trainee,

Here are more informations about the memory you have to analyze:
- This dump was realized just after immobilizing Jean-Kevin Doe, our suspect, at
  his domicile.
- His computer is an old PC with Windows 7 as operating system.
- He is suspected to be a RAID leader of the people who stormed Area51.

As you may already know the US Forces has mandated us to investigate the recent
event called "Storm Area51".
We are actually looking at the plan they made before attacking Area51 on 
September 20, 2019. We know that as the leader of a RAID group Jean-Kevin Doe 
own such a plan on his computer. We need you to find it at all cost!

These little smartass were all arrested on the day of the event but we to know
what they could have seen in order to refine our communication.

Thank you in advance.

NAW


## Solution
The first step when analysing a memory image with `volatility` is to find the correct profile. In order to do this, use the *imageinfo* plugin.

```bash
root@kali:~# volatility -f memory.dmp imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : VirtualBoxCoreDumpElf64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/root/Documents/ctf/blackalps_19/forensics/StormArea51/memory.dmp)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82767c78L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82768d00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2019-10-25 14:36:18 UTC+0000
     Image local date and time : 2019-10-25 16:36:18 +0200
```

It is obvious that the system is a Window 7 32-bit machine. However, it is not clear if it is SP0 or SP1. For the future commands I used the profile **Win7SP1x86_23418**. In order to find out what has been running on the system, the `pslist` plugin will show all the running processes.

```bash
root@kali:~# volatility -f memory.dmp --profile=Win7SP1x86_23418 pslist
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x839af930 System                    4      0     79      356 ------      0 2019-10-25 14:34:49 UTC+0000                                 
0x849ca9c8 smss.exe                268      4      2       29 ------      0 2019-10-25 14:34:49 UTC+0000                                 
0x84a83030 csrss.exe               344    336      8      323      0      0 2019-10-25 14:34:51 UTC+0000                                 
0x849a4390 wininit.exe             388    336      4       80      0      0 2019-10-25 14:34:51 UTC+0000                                 
0x848bb030 csrss.exe               396    380      7      202      1      0 2019-10-25 14:34:51 UTC+0000                                 
0x84add568 winlogon.exe            444    380      5      115      1      0 2019-10-25 14:34:51 UTC+0000                                 
0x84b66030 services.exe            480    388      9      184      0      0 2019-10-25 14:34:51 UTC+0000                                 
0x84b74530 lsass.exe               488    388      7      461      0      0 2019-10-25 14:34:51 UTC+0000                                 
0x84b767d0 lsm.exe                 496    388     10      149      0      0 2019-10-25 14:34:51 UTC+0000                                 
0x84c0c030 svchost.exe             604    480     12      358      0      0 2019-10-25 14:34:52 UTC+0000                                 
0x84c28030 VBoxService.ex          668    480     11      114      0      0 2019-10-25 14:34:52 UTC+0000                                 
0x84c2f820 svchost.exe             720    480      8      237      0      0 2019-10-25 14:34:52 UTC+0000                                 
0x84c4ca58 svchost.exe             772    480     17      355      0      0 2019-10-25 14:34:52 UTC+0000                                 
0x84bff720 svchost.exe             892    480     25      464      0      0 2019-10-25 14:34:52 UTC+0000                                 
0x84c980f8 svchost.exe             940    480     13      243      0      0 2019-10-25 14:34:52 UTC+0000                                 
0x84ca17d8 svchost.exe             992    480     26      679      0      0 2019-10-25 14:34:52 UTC+0000                                 
0x84ca7030 audiodg.exe            1032    772      5      126      0      0 2019-10-25 14:34:52 UTC+0000                                 
0x84cf1d28 svchost.exe            1240    480     14      313      0      0 2019-10-25 14:34:53 UTC+0000                                 
0x84d023b8 spoolsv.exe            1324    480     15      291      0      0 2019-10-25 14:34:53 UTC+0000                                 
0x84d29b40 svchost.exe            1360    480     19      302      0      0 2019-10-25 14:34:53 UTC+0000                                 
0x84d75b00 svchost.exe            1456    480     11      142      0      0 2019-10-25 14:34:53 UTC+0000                                 
0x84d84528 svchost.exe            1492    480      8      159      0      0 2019-10-25 14:34:53 UTC+0000                                 
0x83a55328 taskhost.exe           1912    480     10      237      1      0 2019-10-25 14:34:59 UTC+0000                                 
0x842d33d0 dwm.exe                1972    892      5       75      1      0 2019-10-25 14:34:59 UTC+0000                                 
0x84aa2b58 explorer.exe           1984   1960     39      976      1      0 2019-10-25 14:34:59 UTC+0000                                 
0x84ea23d8 VBoxTray.exe            836   1984     13      153      1      0 2019-10-25 14:35:00 UTC+0000                                 
0x84c626c8 SearchIndexer.         1884    480     13      762      0      0 2019-10-25 14:35:07 UTC+0000                                 
0x84edad28 SearchFilterHo         1588   1884      4       95      0      0 2019-10-25 14:35:07 UTC+0000                                 
0x842ed4a8 SearchProtocol          884   1884      8      281      0      0 2019-10-25 14:35:26 UTC+0000                                 
0x84ee2a40 SumatraPDF.exe         2428   1984      7      143      1      0 2019-10-25 14:35:46 UTC+0000                                 
0x83aeb558 KeePass.exe            2544   1984     12      312      1      0 2019-10-25 14:35:50 UTC+0000 
```

Two processes are of special interest, namely **SumatraPDF.exe** and **KeePass.exe**. As we are looking for a document, SumatraPDF.exe might be a good way to go. So as this is a PDF viewer, looking for PDF files would be a good next step.

```bash
root@kali:~# volatility -f memory.dmp --profile=Win7SP1x86_23418 filescan | grep -i pdf
Volatility Foundation Volatility Framework 2.6
0x000000001e8013f8      6      0 R--r-- \Device\HarddiskVolume2\Program Files\SumatraPDF\SumatraPDF.exe
0x000000001ec67e28      8      0 RW---- \Device\HarddiskVolume2\Users\jean-kevin\Documents\secret_plan_area51.pdf
0x000000001ec69830      2      0 R--r-d \Device\HarddiskVolume2\Program Files\SumatraPDF\SumatraPDF.exe
0x000000001ecb5038      2      1 R--rwd \Device\HarddiskVolume2\Users\jean-kevin\AppData\Roaming\SumatraPDF
0x000000001ece4038      7      0 R--r-- \Device\HarddiskVolume2\Windows\Prefetch\SUMATRAPDF.EXE-43A5BBE4.pf
0x000000001eee4438     11      0 R--rwd \Device\HarddiskVolume2\Program Files\SumatraPDF\libmupdf.dll
0x000000001effceb8      8      0 R--r-- \Device\HarddiskVolume2\Users\jean-kevin\AppData\Roaming\SumatraPDF\SumatraPDF-settings.txt
```

The file `\Device\HarddiskVolume2\Users\jean-kevin\Documents\secret_plan_area51.pdf` looks promising, so lets try to extract it.

```bash
root@kali:~# volatility -f memory.dmp --profile=Win7SP1x86_23418 dumpfiles -D files/ -Q 0x000000001ec67e28
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x1ec67e28   None   \Device\HarddiskVolume2\Users\jean-kevin\Documents\secret_plan_area51.pdf
root@kali:~# file files/file.None.0x84eeeb38.dat 
files/file.None.0x84eeeb38.dat: PDF document, version 1.7
```

Looks like we have successfully extracted a PDF file, lets have a look at it.

![extracted PDF](/resources/2019/blackalps/images/password_protected_pdf.png)

Unfortunately, the PDF is password protected. Luckily, we have seen a password manager running on the system, so there might be a chance to find the password there. As the database files of KeePass have a **.kdbx** extension, lets look for such a file.

```bash
root@kali:~# volatility -f memory.dmp --profile=Win7SP1x86_23418 filescan | grep -i kdbx
Volatility Foundation Volatility Framework 2.6
0x000000001ee6a3d0      2      0 R--rw- \Device\HarddiskVolume2\Users\jean-kevin\AppData\Roaming\Microsoft\Windows\Recent\passwords.kdbx.lnk
0x000000001fd7d250      8      0 R--r-- \Device\HarddiskVolume2\Users\jean-kevin\Documents\passwords.kdbx
```

And indeed there is. So lets dump this file and try to get access to it.

```bash
root@kali:~# volatility -f memory.dmp --profile=Win7SP1x86_23418 dumpfiles -D files/ -Q 0x000000001fd7d250
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x1fd7d250   None   \Device\HarddiskVolume2\Users\jean-kevin\Documents\passwords.kdbx
root@kali:~# file files/file.None.0x84e
file.None.0x84ec23b8.dat  file.None.0x84eeeb38.dat  
root@kali:~# file files/file.None.0x84ec23b8.dat 
files/file.None.0x84ec23b8.dat: Keepass password database 2.x KDBX
root@kali:~# keepass2john files/file.None.0x84ec23b8.dat > keepass.hash
root@kali:~# cat keepass.hash 
file.None.0x84ec23b8.dat:$keepass$*2*60000*0*6b3ee9664f9fd6dd1c72d333ba36877fb5dd0dbb8795190762238cdf14fe39ca*2310fef1b01787420ef1960ae27785fc7706f7b53edd7f5f611bf2c5df79b414*f5fd96bd4f25a1e110c0826dc200b19a*49c1889b51bb1961e4f19275eef87ee082c7efb1ae71e46dcd4902911da117a3*e25d77d2368b07821f23056aa9577c520412abb44c852f56af4ef9dab182f254
root@kali:~# john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
aliens           (file.None.0x84ec23b8.dat)
1g 0:00:00:40 DONE (2019-11-14 23:01) 0.02490g/s 188.2p/s 188.2c/s 188.2C/s emilee..aliens
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The password to access the KeePass database is **aliens**. Accessing the database reveals the password for the PDF, which eventually allows us to open the PDF and find the flag.

![password for the PDF](/resources/2019/blackalps/images/password_for_pdf.png)
![blackalps flag](/resources/2019/blackalps/images/storm_area51_flag.png)

The flag is: **BA19{P30pl3_l0v3_c0n5p1r4cy_th3or1e5}**
