# Founding 🛠️
![GitHub Logo](/Founding/eren1.png)

##
[📩 LinkedIn](https://linkedin.com/in/bmgrodrigues) | [功能特性](https://github.com/SenSecurity/Founding/tree/main#功能特性-) | [使用方法](https://github.com/SenSecurity/Founding/tree/main?tab=readme-ov-file#使用方法-) | [演示](https://github.com/SenSecurity/Founding/tree/main#演示-)

## 概述 📖
**Founding** 是一款处理 `.bin`、`.exe` 或 `.dll` 格式 shellcode 的工具，应用先进的**混淆**或**加密**技术，生成具有复杂执行方法的隐蔽二进制文件。

## 功能特性 ✨
### 核心功能（每次编译都会应用）

- **动态 API 哈希**   
  在运行时为 API 函数生成唯一哈希值以逃避检测。
- **IAT 伪装**   
  调用选定的 Windows API 函数以增强二进制文件的合法性。
- **最小化 CRT**   
  移除 CRT 库以精确控制导入地址表。
- **水印**   
  在 DOS Stub、校验和、PE 节或文件覆盖层中嵌入自定义水印。
- **资源文件**   
  嵌入类似于 `cleanmgr.exe` 的文件属性以提高真实性。
- **前导码 0xFC 0x48**   
  在 shellcode 前添加 `xFCx48` 以绕过静态分析。
 
### 加密和混淆

- 支持 **IPv4/IPv6/MAC/UUID** 混淆。
- 提供 **XOR**、**RC4** 和 **AES** 加密。
- 包含**载荷填充**以实现额外混淆。
- 每次运行生成**随机加密密钥**。

### 生成器类型

- **Raw**   
  直接处理 `.bin` 载荷。
- **Donut**  
  使用 Donut 创建不包含 AMSI 绕过的 `.bin`。
- **Clematis**   
  使用 Clematis 创建包含 garble 混淆和压缩的 `.bin`。
- **Powershell-donut**   
  使用 PS2EXE 和 Donut 将 `.exe` 转换为 `.bin`。


### 执行类型
- **APC**   
  通过异步过程调用执行。
- **Early-Bird-Debug**   
  使用带有远程调试或挂起进程的 APC。
- **EnumThreadWindows**  
  利用 EnumThreadWindows 回调函数。
- **Local-Mapping-Inject**   
  使用挂起线程执行本地映射。
- **Early-Cascade**   
  挂钩 `ntdll!SE_DllLoaded` 以执行载荷。
- **Fibers**   
  在不创建新线程的情况下切换执行上下文。
- **Process-Hypnosis**   
  在调试的子进程中运行载荷，然后分离。
- **Tp-Alloc**   
  使用线程池 API (`TpAllocWait`/`TpSetWait`) 将 shellcode 加入队列。
- **Local-Hollowing**   
  在挂起的主线程中复制并运行 PE。

### 可选功能

#### 间接系统调用 
- **Hells-Hall**   
  将所有实现更改为间接系统调用 (HellsHall)，包括可选标志。
- **Syswhispers3**   
  将所有实现更改为间接系统调用 (SysWhispers3)，包括可选标志。

#### 编译器 
- **Clang-LLVM**   
  使用 Clang-LLVM 混淆以逃避静态分析。

#### AMSI 绕过 
- **Amsi-Opensession**   
  修补 `AmsiOpenSession` 以返回无效参数。
- **Amsi-Scanbuffer**   
  修补 `AmsiScanBuffer` 以返回无效参数。
- **Amsi-Signature**   
  修补 `AmsiSignature` 以返回无效字符串，破坏签名值。
- **Amsi-Codetrust**   
  修补 `WldpQueryDynamicCodeTrust` 以返回无效参数。

#### 解钩 
- **Unhooking-Createfile**   
  从使用 `CreateFileMappingA` 映射的 `ntdll.dll` 中解除所有函数的钩子。
- **Unhooking-Knowndlls**   
  从 KnownDlls 目录中的 `ntdll.dll` 中解除所有函数的钩子。
- **Unhooking-Debug**   
  通过从新的调试进程复制新的 NTDLL 来解除 `ntdll.dll` 中所有函数的钩子。
- **Hookchain**   
  修改 IAT 以重新路由函数调用，允许拦截和处理它们。

#### ETW 绕过 
- **Etw-Eventwrite**   
  修补 `EtwEventWriteFull`、`EtwEventWrite` 和 `EtwEventWriteEx` 以屏蔽 EDR 遥测。
- **Etw-Trace-Event**   
  修补 `NtTraceEvent` 以屏蔽 EDR 遥测。
- **Etw-pEventWriteFull**   
  修补私有函数 `EtwpEventWriteFull` 以返回无效参数，屏蔽 EDR 遥测。

#### 沙箱绕过 
- **Api-Hammering**   
  创建随机文件，读取/写入随机数据，延迟执行 10 秒。
- **Delay-Mwfmoex**   
  使用 `MsgWaitForMultipleObjectsEx` 延迟执行 10 秒。
- **Fibonacci**   
  计算斐波那契数列以延迟执行 10 秒。
- **Mouse-Clicks**   
  记录 20 秒内的点击；如果少于 1 次点击，则假定为沙箱环境。
- **Resolution**   
  检查分辨率以识别沙箱环境。
- **Processes**   
  检查系统是否运行少于 50 个进程；假定为沙箱环境。
- **Hardware**   
  检查系统是否少于 2 个处理器、2 GB RAM 和 2 个已挂载的 USB；假定为沙箱环境。

#### 载荷控制 
- **Check-Running**   
  检查可执行文件是否已在运行；如果是，则阻止重复执行。
- **Self-Delete**   
  确保载荷在执行期间删除自身；如果删除失败，则删除文件内容，将其大小减小到零字节。

#### 其他功能 
- **Dll**   
  创建带有可选导出函数名称（默认：`runme`）的 DLL，在后台运行 `rundll32`。
- **Dll-Stealthy**   
  创建更隐蔽的 DLL，带有可选导出函数名称（默认：`runme`）。
- **Service**   
  创建一个可作为服务运行的可执行文件。
- **Inflate**   
  使用随机葡萄牙语单词填充可执行文件以增加其大小。
- **Sign**   
  使用证书对最终可执行文件进行签名。
- **No-Window**   
  运行时不打开终端窗口。
- **No-Print**   
  运行时不打印任何输出，从实现中删除所有 `printf`。
- **Decoy**   
  嵌入一个诱饵文件（例如 PDF）与载荷一起执行。

## 使用方法 📖
### 生成器类型
![GitHub Logo](/Founding/generators.png)

### 执行类型和可选标志
![GitHub Logo](/Founding/helper1.png)
![GitHub Logo](/Founding/helper2.png)

### 语法

```bash
Founding.exe <生成器类型> <文件.bin/.exe/.dll> <加密/混淆选项> <执行类型> <可选标志>
```

### 示例命令
```bash
Founding.exe donut mimikatz.exe mac fibers --hells-hall

[+] 正在运行 donut
[+] 是否包含参数？(Y/N): n

  [ Donut shellcode 生成器 v1 (构建于 Oct 23 2024 07:55:06)
  [ 版权所有 (c) 2019-2021 TheWover, Odzhan

  [ 实例类型 : 嵌入式
  [ 模块文件   : ".\mimikatz.exe"
  [ 熵值       : 随机名称 + 加密
  [ 文件类型     : EXE
  [ 目标 CPU    : x86+amd64
  [ AMSI/WDLP/ETW : 无
  [ PE 头    : 覆盖
  [ Shellcode     : "output\code\Erwin.bin"
  [ 退出方式          : 线程

[+] 使用 donut 创建了 Erwin.bin。
[+] 在编译中包含 EXEC (Fibers) 功能...
[+] 在编译中包含间接系统调用 (初始化间接系统调用) 功能...
[+] 在编译中包含间接系统调用 (Hells Hall Fibers) 功能...
[+] 使用 GCC 编译中...
[+] 编译成功。
[+] Shinzo wo Sasageyo! Erwin.exe 已创建。
```

### 注意事项
- 需要交互式 shell 的 shellcode（例如 *Mimikatz*）与远程进程技术不兼容。
- 从 releases 下载 zip 文件
- 每次编译的代码可以在 \output\code\ 中找到
- 要测试新制作的 DLL，已准备了一个专用的可执行文件 `dlltest.exe`，可以在 `\founding\misc\dll_test` 目录中找到。
- 在 `\founding\dependencies\` 目录中，你会找到 `vs_BuildTools.exe` 文件以及 Readme.txt 文档，这两者对于 Clang-LLVM 编译器都是必需的。
  
## 演示 🎥
### Falcon Crowd Strike 上的 Cobalt Strike Beacon
[![Cobalt](https://i.imgur.com/ilgUtBA.png)](https://youtu.be/YTB3MrO5PiE)

### Cortex Palo Alto 上的 PowerUp
[![Cortex](https://i.imgur.com/aJz4aFI.png)](https://youtu.be/zrT6AcZFC1o?si=gkxY7Dj7cI8Lv2s5)

## 致谢 🙌
- 使用的一些技术学习自 [Maldev Academy](https://maldevacademy.com)，这是一门很棒的课程，强烈推荐
- 灵感来自 [HellShell](https://github.com/NUL0x4C/HellShell)
- 特别感谢以下作者：
  - [Clematis](https://github.com/CBLabresearch/Clematis)
  - [Donut](https://github.com/TheWover/donut)
  - [PS2EXE](https://github.com/MScholtes/PS2EXE)
