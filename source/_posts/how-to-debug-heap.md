---
title: How to debug heap challenge in CTF?
date: 2023-05-24 18:12:10
tags:
  - CTF
  - heap
categories:
  - pwn
description: Before start to learn pwning heap challenge, how do we debug binaries which needs different versions of glibc?
---

Every beginner who attempts to start heap challenge will face a problem, that is: different challenges require different libc and linkers, how to debug each binary on one machine with the same environment? Downloading virtual machine images with different versions of libc is a brute force method but still works, here I won't discuss about this way and I will suggest two methods in the following content.

## Use the 'LD_PRELOAD' environment variable

If you google some question like 'how to debug with different version of libc', you might get this [result](https://reverseengineering.stackexchange.com/questions/25998/debugging-an-older-version-of-libc). Usually, a heap challenge with adequate information provides a libc file (end with .so) and a linker (start with ld). Below is a typical command line to run the bianry by this method:
```sh
LD_PRELOAD=./libc-2.23.so
./ld-2.23.so ./heapchall
```

This method can be combined with pwntools to debug:
```python
r = process(["./ld-2.23.so", "./heapchall"], env={"LD_PRELOAD": "./libc-2.23.so"})
gdb.attach(r)
```

But the biggest problem is, the symbol table used in the executing process belongs to linker (`ld-2.23.so`), not the binary itself. A lot of information is lost during the debug process so I recommend the second method.

## Use `patchelf` tool
`patchelf` is a tool to modify the ELF excutables and libraries. According to the manual of `patchelf`:
>It can change the dynamic loader ("ELF interpreter") of ex‐ecutables and change the RPATH of executables and libraries.

Easy to understand this sentence that `patchelf` can change a elf file's linker (ELF interpreter) and a path contains all the necessary files to run a elf file (RPATH). We need to download the full RPATH from [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one), and I post a concrete example as below:
```shell
patchelf --set-interpreter ./ld-2.23.so --set-rpath /path/to/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ ./heapchall
```

Then we can debug the heap challenge without bothering libc issue.

If we make the exploit works but don't get shell, try the method below:
```shell
patchelf --add-needed path/to/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/libc-2.23.so ./heapchall
```

Reference: https://blog.wjhwjhn.com/archives/762/
           https://reverseengineering.stackexchange.com/questions/25998/debugging-an-older-version-of-libc