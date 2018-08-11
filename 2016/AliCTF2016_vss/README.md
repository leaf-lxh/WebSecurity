# VSS (Very secure System)
 **使用到pwntools**
  ```
  $sudo pip install pwntools
  ```
 **ROPgadget Tool**
  
 **IDA**
  [GitHub页面](https://github.com/JonathanSalwan/ROPgadget)
## 第一步、初步分析目标程序
 * 1.使用file命令查看文件类型
  ```
  root@VM-206-74-ubuntu:/workspace/rop/vss# file vss
  vss: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=5589f2e4e8d5a8e810f9b425baabccc04745b40a, stripped
  ```
  __x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24__ 64位静态链接的在linux上跑的程序
 
 __stripped__ 意思是目标文件里面的符号信息在编译的时候删掉了，这意味着API名称是看不到的，想知道call的函数是什么API需要分析传递的参数。同时想要拿shell需要用到 ROPgadget
 
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
  要求输入什么东西，试试输入超长的字符串看看会不会崩掉
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
   
