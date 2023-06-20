---
title: Rust逆向初探
date: 2023-06-20 17:49:49
tags:
  - untagged
categories:
  - reverse engineering
keywords: rust, tutorial
description: 在SCTF 2023中被rust pwn题虐哭...
---

斜颚的出题人已经不满足于在re中添加go和rust的题目，在SCTF2023中更是把触手伸到了pwn题目。算是轻松地拿下ancient cgi后，直接被后续的rust pwn吓退，从此一蹶不振在pwn方向颗粒无收，流下了没有re基础的眼泪。最后被彪哥带飞到第五名。

先从最简单的print hello world程序开始分析，这里用的rust源码很简单：
```rust
fn main() {
    println!("Hello, world!");
}
```

在target/debug中生成了二进制文件，checksec一下：
```shell
zyd@Dori:~/ctf/world/target/debug$ checksec ./world 
[*] '/home/zyd/ctf/world/target/debug/world'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
很有武德，除了canary默认全开，接下来直接上ghidra：
```C
void main(int param_1,u8 **param_2)

{
  std::rt::lang_start<()>(world::world::main,(long)param_1,param_2,0);
  return;
}

void world::world::main(void)

{
  &[&str] in_stack_ffffffffffffffc8;
  
  core::fmt::Arguments::new_const((Arguments *)&stack0xffffffffffffffd0,in_stack_ffffffffffffffc8);
  std::io::stdio::_print(&stack0xffffffffffffffd0);
  return;
}
```
终于理解了原来上周末我逆向的是个鬼，跑到std::rt::lang_start里看什么都没找到。不过用ghidra不会把namespace中的函数归类为function而是直接放在namespaces里，上周碌碌无为在funtion里找了半天什么都没有，乐。

hello world字符串在new_const函数中被初始化：
```C
Arguments * core::fmt::Arguments::new_const(Arguments *__return_storage_ptr__,&[&str] pieces)

{
  ulong in_RDX;
  &str *in_RSI;
  Arguments *__return_storage_ptr___00;
  Arguments local_50;
  undefined8 local_18;
  
  if (in_RDX < 2) {
    (__return_storage_ptr__->pieces).data_ptr = in_RSI;
    (__return_storage_ptr__->pieces).length = in_RDX;
    *(undefined8 *)&__return_storage_ptr__->fmt = 0;
    *(undefined8 *)&(__return_storage_ptr__->fmt).field_0x8 = local_18;
    (__return_storage_ptr__->args).data_ptr = (ArgumentV1 *)"Hello, world!\n";
    (__return_storage_ptr__->args).length = 0;
    return __return_storage_ptr__;
  }
  __return_storage_ptr___00 = &local_50;
  new_const(__return_storage_ptr___00,(&[&str])CONCAT88(in_RDX,__return_storage_ptr___00));
                    /* WARNING: Subroutine does not return */
  panicking::panic_fmt(__return_storage_ptr___00,&DAT_0014c308);
}
```
接下来做一点稍微复杂的操作，看看二进制文件逆向结果又会怎么样。简简单单找了个Caesar Cipher：
```rust
fn encrypt(msg: &str, shift: u32) -> String {
    let alphabet_upper: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let alphabet_lower: &str = "abcdefghijklmnopqrstuvwxyz";
    let mut result: String = String::new();

    for c in msg.chars() {
        if c.is_whitespace() {
            result.push(c);
            continue;
        }

        if shift >= 26 {
            panic!("Please specify a smaller shift.");
        }

        if c.is_uppercase() {
            match alphabet_upper.chars().position(|b| c == b) {
                Some(x) => {
                    let idx: usize = shift as usize + x;

                    let new_index = if (idx as u32) >= 26u32 {
                        idx - 26usize
                    } else {
                        idx
                    };

                    match alphabet_upper.chars().nth(new_index) {
                        Some(x) => {
                            result.push(x);
                        }
                        None => {
                            panic!("No element could be found at index {}.", new_index);
                        }
                    };
                }
                None => {
                    panic!("'{}' is not a valid element in the alphabet.", c);
                }
            };
        } else {
            match alphabet_lower.chars().position(|b| c == b) {
                Some(x) => {
                    let idx: usize = shift as usize + x;

                    let new_index = if (idx as u32) >= 26u32 {
                        idx - 26usize
                    } else {
                        idx
                    };

                    match alphabet_lower.chars().nth(new_index) {
                        Some(x) => {
                            result.push(x);
                        }
                        None => {
                            panic!("No element could be found at index {}", new_index);
                        }
                    };
                }
                None => {
                    panic!("'{}' is not a valid element in the ASCII alphabet", c);
                }
            };
        }
    }
    return result;
}

fn decrypt(msg: &str, shift: u32) -> String {
    return encrypt(msg, 26u32 - shift);
}

fn main() {
    let msg: &str = "The quick brown fox jumped over the lazy dog";
    let shift = 2;
    let encrypted: String = encrypt(msg, shift);
    println!("{}\n in a shift of {} is:\n{}", msg, shift, encrypted);
    println!("{}\n is\n{}", encrypted, decrypt(&encrypted, shift));
}
```
可以看到现在的main已经惨不忍睹了😅：
```C
void world::world::main(void)

{
  &str &Var1;
  undefined8 in_stack_fffffffffffffe68;
  undefined8 in_stack_fffffffffffffe70;
  undefined8 in_stack_fffffffffffffe78;
  undefined8 in_stack_fffffffffffffe80;
  &str local_108;
  u32 local_f4;
  String local_f0;
  Arguments local_d8;
  ArgumentV1 local_a8;
  ArgumentV1 local_98;
  ArgumentV1 local_88;
  Arguments local_78;
  &[core::fmt::ArgumentV1] local_48;
  ArgumentV1 local_38;
  String local_28;
  
  local_108.data_ptr = (u8 *)0x1422ed;
  local_108.length = 0x2c;
  local_f4 = 2;
  encrypt(&local_f0,(&str)CONCAT88(in_stack_fffffffffffffe70,in_stack_fffffffffffffe68),0x1422ed);
                    /* try { // try from 0010b586 to 0010b592 has its CatchHandler @ 0010b5b7 */
  local_a8 = core::fmt::ArgumentV1::new_display<&str>(&local_108);
                    /* try { // try from 0010b5e7 to 0010b71a has its CatchHandler @ 0010b5b7 */
  local_98 = core::fmt::ArgumentV1::new_display<u32>(&local_f4);
  local_88 = core::fmt::ArgumentV1::new_display<alloc::string::String>(&local_f0);
  core::fmt::Arguments::new_v1
            (&local_d8,(&[&str])CONCAT88(in_stack_fffffffffffffe70,in_stack_fffffffffffffe68),
             (&[core::fmt::ArgumentV1])CONCAT88(in_stack_fffffffffffffe80,in_stack_fffffffffffffe78)
            );
  std::io::stdio::_print(&local_d8);
  local_48 = (&[core::fmt::ArgumentV1])
             core::fmt::ArgumentV1::new_display<alloc::string::String>(&local_f0);
  &Var1 = alloc::string::{impl#38}::deref(&local_f0);
  decrypt(&local_28,(&str)CONCAT88(in_stack_fffffffffffffe70,in_stack_fffffffffffffe68),
          SUB164((undefined  [16])&Var1,0));
                    /* try { // try from 0010b71d to 0010b729 has its CatchHandler @ 0010b747 */
  local_38 = core::fmt::ArgumentV1::new_display<alloc::string::String>(&local_28);
                    /* try { // try from 0010b790 to 0010b7c9 has its CatchHandler @ 0010b747 */
  core::fmt::Arguments::new_v1
            (&local_78,
             (&[&str])CONCAT88(SUB168((undefined  [16])local_38,0),
                               SUB168((undefined  [16])local_38,8)),local_48);
  std::io::stdio::_print(&local_78);
                    /* try { // try from 0010b7cc to 0010b7d8 has its CatchHandler @ 0010b5b7 */
  core::ptr::drop_in_place<alloc::string::String>(&local_28);
  core::ptr::drop_in_place<alloc::string::String>(&local_f0);
  return;
}
```
我有点难蚌，不过更让我难蚌的是encrypt函数的逆向，今天的逆向到此为止了。
