---
title: pwnable.kr rootkit
date: 2023-08-15 21:43:25
tags:
  - pwnable.kr
categories:
  - pwn
description: pwnable.kr rootkit题解
---

写这题之前我以为会需要很多rootkit的前置知识，但是做完之后发现并不需要，但还是要知道内核模块相关的知识即LKM，以及内核处理syscall的过程。

# 逆向

逆向是解决问题的第一步，我们首先需要明白这一题的rootkit究竟做了什么事情。

```C
undefined4 init_module(void)

{
  int iVar1;
  
  sct = 0xc15fa020;
  sys_open = _DAT_c15fa034;
  sys_openat = _DAT_c15fa4bc;
  sys_symlink = _DAT_c15fa16c;
  sys_symlinkat = _DAT_c15fa4e0;
  sys_link = _DAT_c15fa044;
  sys_linkat = _DAT_c15fa4dc;
  sys_rename = _DAT_c15fa0b8;
  sys_renameat = _DAT_c15fa4d8;
  wp();
  iVar1 = sct;
  *(code **)(sct + 0x14) = sys_open_hooked;
  *(code **)(iVar1 + 0x49c) = sys_openat_hooked;
  *(code **)(iVar1 + 0x14c) = sys_symlink_hooked;
  *(code **)(iVar1 + 0x4c0) = sys_symlinkat_hooked;
  *(code **)(iVar1 + 0x24) = sys_link_hooked;
  *(code **)(iVar1 + 0x4bc) = sys_linkat_hooked;
  *(code **)(iVar1 + 0x98) = sys_rename_hooked;
  *(code **)(iVar1 + 0x4b8) = sys_renameat_hooked;
  wp();
  *(undefined4 *)(__this_module._4_4_ + 4) = __this_module._8_4_;
  *(undefined4 *)__this_module._8_4_ = __this_module._4_4_;
  __this_module._4_4_ = 0x105a4;
  __this_module._8_4_ = 0x105a4;
  return 0;
}
```

`sct`即`system call table`，顾名思义，`system call table`把syscall ID映射到对应实现syscall的内核函数地址。内核在处理syscall时并不会直接去在内核中寻找对应实现syscall的内核函数，而是以**系统调用号**作为偏移，在系统调用表中索引实现syscall的内核函数地址。于是，使用最多也是最经典的rootkit方法就是劫持系统调用表，通过篡改系统调用表中存放的数据以劫持系统调用。Linux内核提供了简单的获取内核函数和符号地址的方法，简单的来说，当内核编译选项`CONFIG_KALLSYMS`开启时，内核会将符号地址存放在文件`/proc/kallsyms`中。需要注意的是，`rootkit.ko`直接使用了系统调用表的绝对地址`0xc15fa020`，但在如今大部分的Linux kernel中是行不通的，当KASLR选项开启时，内核函数的地址会在每次重启内核时发生变化。通过`uname -a`可以知道pwnable.kr上使用的内核大版本号为3.7，而KASLR这一特性在3.14后才被引入，所以直接使用系统调用表的绝对地址是可行的。

```shell
$~ cat /proc/kallsyms | grep sys_call_table  
c15fa020 R sys_call_table

$~ cat /proc/kallsyms | grep sys_open  
c106c7c0 W compat_sys_open_by_handle_at  
c1158bc0 T do_sys_open  
c1158d70 T sys_open  
c1158db0 T sys_openat  
c11a37b0 T sys_open_by_handle_at  
c11b47d0 t proc_sys_open
```

在`kallsyms`可以找到一些重要的符号地址，比如`sys_call_table`和`sys_open`，其中`sys_open`就是内核中真正用于处理系统调用`open`的函数。取得系统调用表后，rootkit不能直接去修改表中对应系统调用的数据，还需要关闭写保护，关于写保护要细说起来就更麻烦了，这里简单的理解成开启内核内存的写权限就行。最终，通过在系统调用表对应位置写入hook函数`sys_xxx_hooked`以完成系统调用的hook。

以`sys_open_hooked`举例：

```C
undefined4 sys_open_hooked(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  char *pcVar1;
  undefined4 uVar2;
  char *in_stack_ffffffec;
  char *in_stack_fffffff0;
  
  mcount();
  pcVar1 = strstr(in_stack_ffffffec,in_stack_fffffff0);
  if (pcVar1 == (char *)0x0) {
    uVar2 = (*sys_open)(param_1,param_2,param_3);
  }
  else {
    printk("You will not see the flag...\n");
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
```

Ghidra和IDA反编译都看不到函数`strstr`的参数字符串`flag`，这是因为内核中传参的调用约定与用户态不同，汇编能看到`strstr`的两个参数分别放在寄存器`eax`和`edx`中。当open的参数含有`flag`子串时，`sys_open_hooked`会过滤掉这一系统调用不予处理，否则使用`sys_open`执向的函数，即原本用于处理系统调用open的内核函数`sys_open`。

总结一下`rootkit.ko`做了以下几件事：
1. 保留原本处理系统调用的内核函数地址至符号`sys_xxx`中。
2. 将系统调用表中存放的相关函数地址更改为`sys_xxx_hooked`。
3. `sys_xxx_hooked`函数对原本系统调用的参数进行检查，若不包含`flag`子串则使用`sys_xxx`处理系统调用，否则过滤不予执行。

# 解决

类比用户态pwn的一些技巧，很容易联想到劫持系统调用表的方式与修改GOT表类似。那么最直接的方法，直接还原系统调用表就可以了，即把我们需要的系统调用表中的`open`所存放的数据还原成`sys_open`的地址。其对应的kernel module代码也比较好写，我这里提供一份不完整的伪代码：

```C
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define ___NR_open_ 5

static int __init antikit_init(void)
{
	void** sct = 0xc15fa020;
	void*  sys_open = 0xc1158d70;
	wp();
	// x86 write protection
	sct[___NR_open_] = sys_open;
	wp();
	return 0;
}

static void __exit antikit_exit(void)
{
}

module_init(antikit_init);
module_exit(antikit_exit);
```

麻烦之处在于需要找服务器对应版本的Linux Header去编译，所以我这里详细解释第二种方法，也是我主要参考的方式。

既然编译kernel module很麻烦，那么直接修改原本的rootkit是否可行呢？答案是肯定的。分析一下系统调用被过滤掉的主要原因，即`sys_xxx_hooked`函数的被写入了系统调用表中，那么重写系统调用表就可以再次hook系统调用到正常的`sys_xxx`函数中去。

那能联想到最朴素的一个思路就是，修改原本rootkit中的`sys_xxx_hooked`函数的汇编代码，或者把`flag`子串替换成无意义的字符串。除此之外，原本的rootkit已经存在于内核模块中，还需要把module name即`rootkit`替换成其他字符串：

```python
with open("./rootkit", "rb") as f:
    rootkit = f.read()

antikit = (
    rootkit.replace(b"\x75\x1d", b"\x90\x90")
    .replace(b"\x75\x24", b"\x90\x90")
    .replace(b"rootkit", b"antikit")
)
```

我这里把`jnz`指令替换为两个`nop`，从而令控制流改变。这个过程还算简单，但直接放在服务器上跑是行不通的，我们需要再次分析`sys_xxx_hooked`的逻辑。再次`insmod`的过程的确改变了系统调用表中存放的地址，但`sys_xxx_hooked`使用的并不是内核内存中的真正用于处理系统调用的`sys_xxx`函数，而是从系统调用表中获得的函数地址！在系统启动时rootkit就被装载入内核中，此时内核系统调用表中存放的函数地址已经被替换为`sys_xxx_hooked`，仅仅替换子串再次加载module只会再次调用第一次rootkit装载时使用的`sys_xxx_hooked`，这条路似乎走向了瓶颈。

再次仔细查看`init_module`的实现方式，我们需要注意到`sys_xxx_hooked`通过保存在`.bss`段的全局变量`sys_xxx`从系统调用表中获取对应的`sys_xxx`函数地址，注意这两者的区别，一个是全局变量，另一个是真正存放在内存中用于处理系统调用的内核函数地址。

而全局变量`sys_xxx`，是通过如下方式赋值的：

```
                    undefined init_module()
   00010300    55      PUSH        EBP

   00010301    a1 34   MOV         EAX,[DAT_c15fa034]
               a0 5f 
               c1

   00010306    89 e5   MOV         EBP,ESP
                                       004
   00010308    c7 05   MOV         dword ptr [sct],0xc15fa020
               40 07 
               01 0...

   00010312    a3 3c   MOV         [sys_open],EAX
               07 01 
               00
```

那么答案很简单了，只需要把`MOV EAX,[DAT_c15fa034]`这条命令修改为`MOV EAX, [ADDR OF sys_open]`，`sys_xxx_hooked`就会直接调用`sys_open`而不是第一个rootkit的`sys_open_hooked`。所以最终修改后的rootkit为：

```python
from base64 import b64encode

with open("./rootkit", "rb") as f:
    rootkit = f.read()

antikit = (
    rootkit.replace(b"\x75\x1d", b"\x90\x90")
    .replace(b"\x75\x24", b"\x90\x90")
    .replace(b"\xa1\x34\xa0\x5f\xc1", b"\xb8\x70\x8d\x15\xc1")
    .replace(b"rootkit", b"antikit")
)
antikit_b64 = b64encode(antikit)
with open("./antikit_b64", "wb") as f:
    f.write(antikit_b64)
```

服务器上不能直接传rawdata，所以大部分解决方式都使用了base64传输本地patch后的rootkit，我是用vi保存生成的base64编码，然后：

```shell
cat antikit.base64 | base64 -d > antikit.ko
insmod antikit.ko
```

这样就可以打开flag了，但flag格式不是纯文本，而是压缩文件，`tar xvf flag`就可以读到flag了。

# Reference

1. [Linux Rootkits — Multiple ways to hook syscall(s)](https://foxtrot-sq.medium.com/linux-rootkits-multiple-ways-to-hook-syscall-s-7001cc02a1e6)
2. [How does the Linux kernel handle a system call](https://web.archive.org/web/20230308144822/https://0xax.gitbooks.io/linux-insides/content/SysCall/linux-syscall-2.html)
3. https://aufarg.github.io/pwnablekr-rootkit-400.html
4. [System.map](https://en.wikipedia.org/wiki/System.map)
5. [Differences between ASLR, KASLR and KARL](https://www.daniloaz.com/en/differences-between-aslr-kaslr-and-karl/)