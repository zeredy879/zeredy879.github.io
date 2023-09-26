---
title: Metasploit SUB Encoder Analysis
date: 2023-09-26 18:44:55
tags:
  - shellcode
categories:
  - pwn
description: 简要分析Metasploit SUB Encoder的编码方式
---

之前投在[WASP](https://wasp-workshop.github.io/program)的论文中了，这周五需要做个英文的presentation。借着做PPT的机会再回看一些经典的printable shellcode编码算法。printable shellcode指仅包含可打印字符(0x21-0x7E)

用一句话概括SUB encoder的算法就是：

>Any dword (4 bytes) can be derived from two or three SUB instructions whose operands are printable bytes.

即，任何dword（4字节）都可以由操作数为可打印字符的2-3个SUB指令生成。举一个简单的例子，双字`0xAAAAAAAA`可以由0减去`0x22222222`和`0x33333334`得到，后两者都只包含可打印字符。SUB encoder的代码也不算多，总共只有140多行。

```ruby
class MetasploitModule < Msf::Encoder
  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'Add/Sub Encoder',
      'Description'      => %q{
          Encodes payload with add or sub instructions. This idea came
          from (offensive-security) muts' hp nnm 7.5.1 exploit.
      },
      'Author'           => 'Melih Sarica <ms[at]sevure.com>',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'BlockSize'  => 4
        })
  end

  def add_or_sub(avchars)
    add = [0x05, 0x50, 0x58, 0x25, 0x54, 0x5C]
    sub = [0x2D, 0x50, 0x58, 0x25, 0x54, 0x5C]
    return 1 if add.all?{|ch|avchars.include?ch.chr}
    return 2 if sub.all?{|ch|avchars.include?ch.chr}
    return 0
  end

  def write_inst(inst, mcode)
    @data << inst
    if mcode != 0
      for i in 0...4
        t = mcode & 0x000000FF;
        @data << t
        mcode = mcode >> 8;
      end
    end
  end

  def rand_with_av_chars()
    t2 = 0
    for i in 0...4
      c = @avchars[rand(@avchars.size)].ord.to_i()
      t2 = t2 <<8
      t2 += c
    end
    return t2
  end

  def check_non_av_chars(target)
    for i in 0...4
      t = target & 0x000000FF;
      return true if not @avchars.include?t.chr
      target = target >> 8;
    end
    return false
  end

  def encode_inst(target)
    begin
      a = rand_with_av_chars()
      b = rand_with_av_chars()
      c = target - a - b if @set == 1
      c = 0 - target - a - b if @set == 2
      c = c%(0xFFFFFFFF+1)
    end while check_non_av_chars(c) == true
    write_inst(@inst["opcode"], a)
    write_inst(@inst["opcode"], b)
    write_inst(@inst["opcode"], c)
  end

  def encode_shellcode(target, z1, z2)
    write_inst(@inst["and"], z1);
    write_inst(@inst["and"], z2);
    encode_inst(target);
    write_inst(@inst["push"], 0);
  end

  def decoder_stub(state)
    buf = ""
    shellcode = state.buf.split(//)
    while shellcode.size>0
      buf << shellcode.pop(4).join
    end
    state.buf = buf
    @data = ""
    @avchars = ""
    for i in 0..255
      @avchars = @avchars + i.chr.to_s if not state.badchars.include?i.chr.to_s
    end
    offset = (datastore['BufferOffset'] || 0).to_i
    @inst = {}
    @set = add_or_sub(@avchars)
    if @set == 0 then
      raise EncodingError, "Bad character list includes essential characters."
      exit
    elsif @set == 1 then #add
      @inst["opcode"] = 0x05
    else #sub
      @inst["opcode"] = 0x2d
    end
    @inst["push"] = 0x50
    @inst["pop"] = 0x58
    @inst["and"] = 0x25
    @inst["push_esp"] = 0x54
    @inst["pop_esp"] = 0x5c
    if state.buf.size%4 != 0 then
      raise EncodingError, "Shellcode size must be divisible by 4, try nop padding."
      exit
    end
    #init
    write_inst(@inst["push_esp"], 0)
    write_inst(@inst["pop"], 0)
    encode_inst(offset)
    write_inst(@inst["push"], 0)
    write_inst(@inst["pop_esp"], 0)
    #zeroing registers
    begin
      @z1 = rand_with_av_chars()
      @z2 = rand_with_av_chars()
    end while @z1&@z2 != 0
    decoder = @data
    return decoder
  end

  def encode_block(state, block)
    #encoding shellcode
    @data = ""
    target = block.split(//)
    return if target.size<4
    t = 0
    for i in 0..3
      t1 = target[3-i][0].ord.to_i
      t = t<<8
      t = t + t1
    end
    encode_shellcode(t, @z1, @z2);
    encoded = @data
    return encoded
  end
end
```

让我们拜请GPT3.5，无所不知的博识尊：

1. add_or_sub方法用于检测是否可以使用"add"或"sub"指令来编码Payload。具体来说，它检查给定的Payload是否包含特定的字节，如果包含，就返回1（表示可以使用"add"指令编码），如果包含另一组特定字节，则返回2（表示可以使用"sub"指令编码），否则返回0。
2. write_inst方法用于将指令和相关数据写入编码器的数据缓冲区。
3. rand_with_av_chars方法用于生成具有可用字符集的随机数据。
4. check_non_av_chars方法检查给定的目标是否包含非可用字符集的字节。
5. encode_inst方法编码一条指令，具体来说，它使用随机生成的数据来计算指令的操作数，并将指令和操作数写入数据缓冲区。
6. encode_shellcode方法编码整个Shellcode。它首先使用"and"指令对两个操作数进行位运算，然后调用encode_inst方法编码Shellcode的余下部分，最后将"push"指令写入数据缓冲区。
7. decoder_stub方法是一个解码器的存根（stub），用于解码Payload。它将输入的Shellcode分解为4字节块，然后通过反向操作还原Shellcode，同时考虑了可用字符集和指令。
8.  encode_block方法用于对Shellcode块执行编码操作。它将给定的Shellcode块进行编码，并返回编码后的Shellcode。

算法的实现映证了开头对SUB Encoder的总结，SUB Encoder随机的生成3组只包含可打印字符的双字，从而通过3次SUB或ADD指令将所有双字集合映射到仅由可打印字符组成的双字集合，数学证明感觉会用到一些组合，或者通过暴力计算证明。SUB Encoder的随机性保证了生成的shellcode不易被检测，但还是有迹可循，一个很明显的特征就是连续三次的SUB指令会留下相当明显的痕迹，但仅仅去绕过可打印字符的限制已经游刃有余。作为混淆方式，SUB Encoder的复杂度已经足够，但从编码的角度看其编码方式有相当大的改进空间，[psc](https://github.com/dhrumil29699/Printable-Encoder)就是从编码的角度优化算法，并且大幅降低了信息冗余度。

写完这篇博客看了下，感觉真没什么好分析的，希望以后的blog再少点水分。