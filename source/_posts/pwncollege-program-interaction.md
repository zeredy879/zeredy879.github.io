---
title: 我是如何被pwn.college的program-interaction level139折磨一周的
date: 2023-10-02 21:19:39
tags:
  - General
  - diary
categories:
  - pwn
description: 做完program-interaction后感觉自己变成了进程管理大师😅
---

[pwn.college](https://pwn.college/)是ASU精心打造的网络安全公开课平台，其授课形式采取了CTF的方式，并且搭建在CTF平台CTFd上，很适合对pwn有兴趣的人~~折磨自己~~入门。Program Interaction属于pwn.college中基础模块的一部分，也能在[pwn.collge的dojos](https://pwn.college/fundamentals/program-interaction)找到。这一部分要求自学者能够熟练的使用各种编程语言完成进程间通信，语言包括不仅限于：C、Python、Shell和ipython等，共有142个挑战。接下来我会描述通过数最低的挑战之一，也就是level139，其解决过程中遇到的不计其数的坑。

# Challenge -- level139
在开始之前，我先简单描述一下level139要求我们做的事情，以下是直接运行`/challenge/embryoio_level139`得到的挑战描述：

>\- the challenge checks for a specific parent process : binary
\- the challenge checks for a specific process at the other end of stdin : cat
\- the challenge checks for a specific process at the other end of stdout : cat
\- the challenge will force the parent process to solve a number of arithmetic problems : 50
\- the challenge will use the following arithmetic operations in its arithmetic problems : +*&^%|
\- the complexity (in terms of nested expressions) of the arithmetic problems : 5

其大意是：
1. `/challenge/embryoio_level139`的父进程为二进制程序
2. `/challenge/embryoio_level139`的标准输入为`cat`程序
3. `/challenge/embryoio_level139`的标准输出为`cat`程序
4. `/challenge/embryoio_level139`会陆续生成单个算数表达式，你需要计算当前算数表达式并将答案写入标准输入以获得下一个表达式，完成50次即达成目标

说Linux话就是，我们需要写一个程序来模拟`cat | /challenge/embryoio_level139 | cat`这样的命令行，并且`/challenge/embryoio_level139`的父进程应当是一个二进制程序。

# Bypass
写过简单的脚本语言的大部分人都不太希望在所有场景下都用最原始的C去完成功能，对于这一挑战也是如此。如果采用朴素的思维，那么这一题的解决方式应当是，用编译型语言完成上述所有功能然后将其编译为二进制文件，包括完成算数表达式的解析运算以及程序的IO。好在我们在这里可以使用一点技巧，只需要做一点简单的包装就可以绕过对程序父进程的检查：

```C
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>

void pwncollege()
{
    int pid = fork();
    if (pid == 0)
    {
        execve("/challenge/embryoio_level139", NULL, NULL);
    }
    else
    {
        waitpid(pid, NULL, 0);
    }
}

int main()
{
    pwncollege();
}
```

注意我们不能直接`execve`这一challenge，因为`execve`的逻辑是替换当前进程而不是产生一个子进程，而Linux中所有的子进程创建都依赖于`fork`系统调用，这里我就不再细述。但如果有人通过搜索引擎看到这篇博客，我估计也没人会对这一部分有疑问，毕竟在前面的challenges中这一技巧已经被玩烂了...

# Pain -- 苦痛的开始

根据过去的经验我很快开始了脚本的编写，之前的138个level已经让我遭受了巨量的毒打，但没想到这里还是棋差一着：

```python
from pwn import *
context.log_level = "debug"

r1, w1 = os.pipe()
r2, w2 = os.pipe()
r = process(["cat"], stdout=w1)
w = process(["cat"], stdin=r2)
p = process(["./a.out"], stdin=r1, stdout=w2)

for _ in range(50):
    w.recvuntil(b"solution for: ")
    expr = w.recvline()[:-1].decode()
    success(expr)
    res = eval(expr)
    success(res)
    r.sendline(str(res).encode())

w.interactive()
```

`./a.out`是在上一节叙述过用于绕过父进程检查的程序，上述脚本的逻辑易于理解：创建两个管道用于目标进程的stdin与stdio重定向，并且读取50个表达式。但实际运行后我收到了折磨我近一周的报错：
>[FAIL]    Executable must be 'cat'. Yours is: python3.8

这怎么看都像是`pwn.process`的问题，因此我尝试了不同的进程创建方式：`subprocess.run`，`subprocess.Popen`，但最后都病情稳定：`Yours is: python3.8`！我开始变得焦躁以及感受到备受折磨，并且开始逃避level139，有一种阴影笼罩在我的脑海中：用Python是解决不了问题的，对level139使用Golang/C吧！

# Bugshooting -- The Real 'python3.8'
痛定思痛后，我决定找出问题的根源。`/challenge/embryoio_level139`虽然是一个ELF格式的可执行文件，但事实上是由python脚本完成的大部分功能（或许使用了Pyinstaller之类的打包工具？），同目录下的`checker.py`即为所有完成challenge功能的源程序。我提取出了必要的部分以在本地完成bug的复现：

```python
from pwn import *
import psutil
import shutil

SELF = psutil.Process(os.getpid())
PARENT = SELF.parent()


r1, w1 = os.pipe()
r2, w2 = os.pipe()
cat1 = process("cat", stdout=w1)
cat2 = process("cat", stdin=r2)
ps = process(["bash"], stdin=r1, stdout=w2)


def resolve_fd_path(pid, fd):
    path = os.path.realpath(f"/proc/{pid}/fd/{fd}")
    if path.startswith(f"/proc/{pid}/fd/"):
        # fixup for sockets and pipes
        path = os.path.basename(path)
    return path


def resolve_fd_pipe_partner(pid, fd, parent_ok=False):
    our_pipe = resolve_fd_path(pid, fd)
    for p in psutil.process_iter():
        if p == SELF:
            continue
        if p.pid == PARENT.pid and not parent_ok:
            continue

        try:
            for ofd in os.listdir(f"/proc/{p.pid}/fd"):
                their_pipe = resolve_fd_path(p.pid, int(ofd))
                if their_pipe == our_pipe:
                    return p.pid
        except PermissionError:
            pass


def check_exe_basename(process: psutil.Process, basename):
    print(f"[INFO] The process' executable is {process.exe()}.")
    actual_basename = os.path.basename(os.path.realpath(shutil.which(basename)))
    print(f"[INFO] To pass the checks, the executable must be {actual_basename}.")
    print(process.exe())
    assert (
        os.path.basename(process.exe()) == actual_basename
    ), f"Executable must be '{basename}'. Yours is: {os.path.basename(process.exe())}"


ps_0_pid = resolve_fd_pipe_partner(ps.pid, 0)

ps_0 = psutil.Process(ps_0_pid)
print(ps_0.exe)
check_exe_basename(ps_0, "cat")
```

`resolve_fd_pipe_partner`会返回指定pid进程指定fd进程的pid，而`check_exe_basename`会检查进程的运行命令行是否与`basename`相同。这一示例程序中我进行了与challenge近乎完全相同的模拟，不同的是这里为了方便我把`/challenge/embryoio_level139`换成了`bash`。

在进入更深层次的探索之前，我觉得这里有必要对我和读者都进行一次拷打。如果你是Linux用户，在终端中执行以下命令：

```shell
$ ls -alh /proc/$$/fd
总计 0
dr-x------ 2 gardener gardener  4 Oct 1日 22:57 .
dr-xr-xr-x 9 gardener gardener  0 Oct 1日 22:57 ..
lrwx------ 1 gardener gardener 64 Oct 1日 22:57 0 -> /dev/pts/5
lrwx------ 1 gardener gardener 64 Oct 1日 22:57 1 -> /dev/pts/5
lrwx------ 1 gardener gardener 64 Oct 1日 22:57 2 -> /dev/pts/5
lrwx------ 1 gardener gardener 64 Oct 1日 22:57 255 -> /dev/pts/5
$ tty
/dev/pts/5
$ file /proc/$$/fd/0
/proc/33643/fd/0: symbolic link to /dev/pts/5
```

我们都知道任何一个Linux进程都默认开启三个文件描述符：stdin，stdout以及stderr，分别对应0、1、2，这也是最特殊的文件描述符，因为他们相比其他的fd承担了进程IO的职能。`$$`用于获取当前终端的pid，我们可以看到，打开一个交互式的`bash terminal`，作为进程而言他的stdin，stdout以及stderr都只是一个指向`/dev/pts/5`的软链接，而`/dev/pts/5`，通过`tty`命令可以发现，正是当前进程`bash`处在的终端！我们平时看到的所谓stdin，stdout以及stderr用于IO的文件流，其本身也是文件，甚至只是简单的软链接，而这也是Linux/Unix中一切皆文件哲学的体现。我第一次发现这一事实时有一种醍醐灌顶，又理所应当的感觉，这种时候才能切实体会到Linux中文件无所不在的事实。

使用`bash`作为目标程序的情况下我们会得到以下输出：

```
pipe:[409388]
<bound method Process.exe of psutil.Process(pid=33220, name='cat', status='sleeping', started='22:53:17')>
[INFO] The process' executable is /usr/bin/cat.
[INFO] To pass the checks, the executable must be cat.
/usr/bin/cat
```

这似乎并没有什么问题，甚至没有报错。但如果把`bash`换成`ls`：

```
<bound method Process.exe of psutil.Process(pid=36010, name='python', status='running', started='23:17:48')>
[INFO] The process' executable is /usr/bin/python3.11.
[INFO] To pass the checks, the executable must be cat.
/usr/bin/python3.11
Traceback (most recent call last):
  File "/home/gardener/Play/fun.py", line 56, in <module>
    check_exe_basename(ps_0, "cat")
  File "/home/gardener/Play/fun.py", line 48, in check_exe_basename
    os.path.basename(process.exe()) == actual_basename
AssertionError: Executable must be 'cat'. Yours is: python3.11
```

！！这正是与原始脚本运行时一模一样的报错！！进一步溯源，我们能发现造成这一错误的根源是`ps_0_pid = resolve_fd_pipe_partner(ps.pid, 0)`并没有返回我们想要的`cat`进程的pid，而是None。`psutil.Process`在参数为空时会选择当前进程，也就是python脚本本身的pid作为参数创建Process：

```python
    def _init(self, pid, _ignore_nsp=False):
        if pid is None:
            pid = os.getpid()
```

也就是说，`resolve_fd_pipe_partner`什么都没有找到，没有任何返回值。但同样的情况在`bash`中不会发生，`bash`和`ls`最大的区别在哪里呢？从IO的角度分析，我们可以在`bash`中运行各种各样的命令行程序，而`ls`一运行就会很快结束。我们知道Linux中用管道串起来的进程不会顺序运行，而是并行的运行，在`ls`很快的运行完成后，`ls`进程很快关闭，而我们甚至无法在`psutil.process_iter()`中找到这一进程，那么对应的fd更不可能知道了。

# Solution -- Close the pipe!

这位前辈的[writeup](https://github.com/Cipher731/pwn_college_writeup/blob/main/1.interaction/embryoio_level139.py)给了我启发，我们的脚本并没有太大的差别，细微的差别在于：他关闭了所有管道的fd。在stackoverflow上关于python subprocess管道有这样一个显眼的问题：[Usage of stdout.close() in python's subprocess module when piping](https://stackoverflow.com/questions/23074705/usage-of-stdout-close-in-pythons-subprocess-module-when-piping)，这件事其实相当费解，为什么创建管道并且建立重定向后必须关闭呢？需要注意的是，调用`os.close()`的主体并不是子进程而是主进程，关闭管道fd的目的是在管道右端的进程退出后，管道左端的进程能意识到stdout已经被关闭，无需再传输数据。

虽然对管道理解的还不够，但已经足以解决问题了：
```python
from pwn import *
context.log_level = "debug"

r1, w1 = os.pipe()
r2, w2 = os.pipe()
r = process(["cat"], stdout=w1)
w = process(["cat"], stdin=r2)
p = process(["./a.out"], stdin=r1, stdout=w2)
os.close(r1)
os.close(w1)
os.close(r2)
os.close(w2)


for _ in range(50):
    w.recvuntil(b"solution for: ")
    expr = w.recvline()[:-1].decode()
    success(expr)
    res = eval(expr)
    success(res)
    r.sendline(str(res).encode())

w.interactive()
```

# In the end
Fxxkyou Shellphish!!!