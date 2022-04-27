---
layout: post
title: "[TAMUCTF 2022] Non-stick Disk"
author: desp
---

## Challenge

> Author: `Addison`

> We've established a persistence mechanism on the attached disk. Can you determine what that is?

> Hint: the flag is in the standard format. You'll know it when you see it. :)

>[non-stick-disk.zlib]()
<br><br>

 - Solves: 2 (first blood)
 - Points: 500/500
 - Category: Forensics
<br><br><br>


## Snooping around
Since we are provided with a `.zlib` file, we can start by inflating it and figuring out the file format. Just like in UTCTF's [IRC](/2022/03/utctf-irc/), a quick run of the same commands can give us a good idea of what we are dealing with:
```
$ openssl zlib -d < non-stick-disk.zlib > non-stick-disk
$ file non-stick-disk
non-stick-disk: Linux rev 1.0 ext4 filesystem data, UUID=72fbaadf-5159-4ab8-ffff90dd-2c3748050d93 (extents) (64bit) (large files) (huge files)
```
Ah, so that's what it means by attached "disk" - the file is essentially copy of the ext4 partition on a disk. Funnily enough, 7-zip can actually read this without the need for mounting the file as a drive:

![7zipeverything.png](/assets/images/tamuctf2022/non-stick-disk/7zipeverything.png)

Our task is to figure out the persistence mechanism, so let's start with looking into the usual locations for code persistence, such as `cron.d` or `init.d`.

![treasurehunt.png](/assets/images/tamuctf2022/non-stick-disk/treasurehunt.png)

Hmm, the timestamps are all much older than what would be a feasible creation date of the challenge. Let's look into the contents just to be sure:
```sh
#!/bin/sh
### BEGIN INIT INFO
# Provides:          console-setup.sh
# Required-Start:    $remote_fs
# Required-Stop:
# Should-Start:      console-screen kbd
# Default-Start:     2 3 4 5
# Default-Stop:
# X-Interactive:     true
# Short-Description: Set console font and keymap
### END INIT INFO

if [ -f /bin/setupcon ]; then
    case "$1" in
        stop|status)
        # console-setup isn't a daemon
        ;;
        start|force-reload|restart|reload)
            if [ -f /lib/lsb/init-functions ]; then
                . /lib/lsb/init-functions
            else
                log_action_begin_msg () {
	            echo -n "$@... "
                }

                log_action_end_msg () {
	            if [ "$1" -eq 0 ]; then
	                echo done.
	            else
	                echo failed.
	            fi
                }
            fi
            log_action_begin_msg "Setting up console font and keymap"
            if /lib/console-setup/console-setup.sh; then
	        log_action_end_msg 0
	    else
	        log_action_end_msg $?
	    fi
	    ;;
        *)
            echo 'Usage: /etc/init.d/console-setup {start|reload|restart|force-reload|stop|status}'
            exit 3
            ;;
    esac
fi
```
Yep, looks just like a normal startup script. Digging around in `cron.d` also reveals nothing special - was it perhaps not referring to this kind of persistence?

Since a lot of the directories are actually emptied, it narrowed the scope enough that we can do a manual search for any suspicious new files. However, upon searching, there still isn't much to look at, even in the log files.
```
2022-04-13 21:42:33 URL:http://archive.ubuntu.com/ubuntu/dists/focal/InRelease [264892/264892] -> "/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/mnt/var/lib/apt/lists/partial/archive.ubuntu.com_ubuntu_dists_focal_InRelease" [1]
gpgv: Signature made Thu 23 Apr 2020 12:34:17 PM CDT
gpgv:                using RSA key 3B4FE6ACC0B21F32
gpgv: Good signature from "Ubuntu Archive Automatic Signing Key (2012) <ftpmaster@ubuntu.com>"
gpgv: Signature made Thu 23 Apr 2020 12:34:17 PM CDT
gpgv:                using RSA key 871920D1991BC93C
gpgv: Good signature from "Ubuntu Archive Automatic Signing Key (2018) <ftpmaster@ubuntu.com>"
2022-04-13 21:42:36 URL:http://archive.ubuntu.com/ubuntu/dists/focal/main/binary-amd64/by-hash/SHA256/7757921ff8feed9c3934a0c9936d441ba4a238bee3ea6c8c1df5cbcd43fc9861 [970408/970408] -> "/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/mnt/var/lib/apt/lists/partial/archive.ubuntu.com_ubuntu_dists_focal_main_binary-amd64_Packages.xz" [1]
2022-04-13 21:42:37 URL:http://archive.ubuntu.com/ubuntu/pool/main/a/adduser/adduser_3.118ubuntu2_all.deb [162792/162792] -> "/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/mnt//var/cache/apt/archives/partial/adduser_3.118ubuntu2_all.deb" [1]
2022-04-13 21:42:38 URL:http://archive.ubuntu.com/ubuntu/pool/main/a/apt/apt_2.0.2_amd64.deb [1288960/1288960] -> "/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/mnt//var/cache/apt/archives/partial/apt_2.0.2_amd64.deb" [1]
2022-04-13 21:42:39 URL:http://archive.ubuntu.com/ubuntu/pool/main/a/apt/apt-utils_2.0.2_amd64.deb [213336/213336] -> "/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/mnt//var/cache/apt/archives/partial/apt-utils_2.0.2_amd64.deb" [1]
2022-04-13 21:42:40 URL:http://archive.ubuntu.com/ubuntu/pool/main/b/base-files/base-files_11ubuntu5_amd64.deb [60132/60132] -> "/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/mnt//var/cache/apt/archives/partial/base-files_11ubuntu5_amd64.deb" [1]
```
Wait... The log files might have nothing special in it, but since we now know `tamuctf` is probably in any path related to building this challenge, can't we just grep for that string and see if there is any hints?
```
$ strings non-stick-disk | grep 'tamuctf'
(...)
2022-04-13 21:43:51 URL:http://archive.ubuntu.com/ubuntu/pool/main/r/readline/libreadline8_8.0-4_amd64.deb [130880/130880] -> "/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/mnt//var/cache/apt/archives/partial/libreadline8_8U
/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/pam_backdoor/linux-pam-1.3.1/libpam/.libs:/lib64
/home/addisoncrump/git/tamuctf-2022/forensics/non-stick-disk/pam_backdoor/linux-pam-1.3.1/modules/pam_unix
```
Bingo! The last 2 lines definitely say something about a backdoor, and that is without a doubt related to this challenge. Let's investigate into it.
<br><br><br>


## Key to the (back)Door
Since the filesystem is for Ubuntu, `pam_unix.so` most likely resides somewhere in one of the `/lib/security` paths. Sure enough, this one is found under `/usr/lib/x86_64-linux-gnu/security/pam_unix.so`. The timestamp is oddly old at `2019-12-17 09:41:40`, just like most of the other pam modules - but since the string we found is quite a strong evidence, we might as well at least check it out first.

Opening it in IDA, we are greeted with a DWARF loading prompt:
```
DWARF: File "D:\Downloads\tamuctf2022\pam_unix.so" contains DWARF information.
DWARF: Functions: 51 symbols applied
DWARF: Globals: 3 symbols applied
```
Nice! Not only will it help in figuring out what the backdoor is, but it is also likely another indication of us being in the right place, as distributed pam modules are usually stripped of debug information. Since a backdoor in this context most likely involves some form of authentication bypass, checking out the standard `pam_sm_authenticate` function wouldn't hurt:

![pam.png](/assets/images/tamuctf2022/non-stick-disk/pam.png)

Hmm, this part of the code looks much more complicated than it should. It is comparing the entered password with `alternative`, and only falling back to the usual `unix_verify_password` if they don't match. Then isn't the data in `alternative` exactly what we are looking for - a hardcoded backdoor?

The obfuscation code for constructing `alternative` looks quite simple, so we most likely won't have to get the entire `pam_unix.so` running and dynamically obtain the resultant value. By cleaning up the decompiler output and referencing the `xmmword_*`s, we can obtain something like the following:
```c
#include <stdio.h>

int main()
{
    char alternative_key[38]; // [rsp+18h] [rbp-88h] BYREF
    char alternative[39]; // [rsp+48h] [rbp-58h] BYREF

      *(short *)&alternative[36] = 0x549A;
      char* v10 = &alternative_key[1];
      char* v11 = alternative;
      *(long long *)&alternative[8] = 0x036A0C686E6C2FA6LL;
      *(long long *)&alternative[0] = 0x7143BBBA2760C78DLL;
      char v12 = -22;
      *(short *)&alternative_key[36] = 0x29FF;
      char v13 = -115;
      *(long long *)&alternative[24] = 0xCC77F1FE4BCDA44ELL;
      *(long long *)&alternative[16] = 0x922C4994040BC68CLL;
      *(int *)&alternative[32] = 0xEB6DCED;
      *(long long *)&alternative_key[8] = 0x5C05631C311846C4LL;
      *(long long *)&alternative_key[0] = 0x2E22C0D74207AEEALL;
      alternative[38] = 0;
      *(int *)&alternative_key[32] = 0x63E9B79E;
      *(long long *)&alternative_key[24] = 0xAD2884913292C227LL;
      *(long long *)&alternative_key[16] = 0xCD5F3CFB6D7DA4E3LL;
      while ( 1 )
      {
        *v11++ = v12 ^ v13;
        if ( &alternative[38] == v11 )
          break;
        v13 = *v11;
        v12 = *v10++;
      }

    printf("%s\n", alternative);
}
```
Compiling this and running gives us `gigem{a_bit_too_obvious_if_you_ask_me}` - the flag we are looking for!