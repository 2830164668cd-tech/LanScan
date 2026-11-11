# LanScan — 局域网IP发现工具

单文件 C# 命令行工具，用于局域网设备发现与识别。不依赖第三方库，`csc` 一条命令编译。

## 功能

- **主动扫描**：ARP 轮询 + ICMP + TCP 端口判活（SYN-ACK 与 RST 均判在线，屏蔽 ping 的设备也能发现）
- **被动监听 + 主动诱探**：mDNS / SSDP / WSD / NetBIOS / LLMNR 广播查询并行发出，唤醒沉默设备
- **交换机转发表查询**（可选，`-snmp <community>`）：SNMPv2c 只读 GetBulk 走 dot1dTpFdbPort / Q-BRIDGE——**设备完全不应答也能被交换机的表揪出来**
- **OS 识别**：SNMP sysDescr（只读 GET）/ SSH·HTTP banner / TTL 指纹（Linux≈64 / Windows≈128），结果标注证据来源，猜测不冒充确定
- **工控端口默认清单**：502 Modbus / 102 S7 / 2404 IEC104 / 44818 EtherNet-IP / 4840 OPC UA / 20000 DNP3 / 47808 BACnet
- **IP 冲突检测**：比对本机连接表剔除自身流量，避免误报
- **接收窗口三态口径**：窗口内 / 延迟应答（同样算存在）/ 未确认（**不代表不存在**）
- **CSV 导出**

## 编译

Windows（.NET Framework 4.5+，VS 开发者命令提示符）：

```
csc /codepage:utf8 /out:局域网IP发现工具.exe LanScan_v1.4.cs
```

## 使用

```
局域网IP发现工具.exe                    &REM 交互式菜单
局域网IP发现工具.exe scan               &REM 扫描本机所有网段
局域网IP发现工具.exe scan 192.168.1.0/24
局域网IP发现工具.exe listen 60 -recv 20 &REM 被动监听60秒，前20秒为主接收窗口
局域网IP发现工具.exe full -export 结果.csv
局域网IP发现工具.exe scan -snmp public  &REM 附加交换机转发表（需管理员+管理型交换机）
局域网IP发现工具.exe snmpvec            &REM 编解码自检，应全部 PASS
局域网IP发现工具.exe help               &REM 完整参数说明
```

被动监听与混杂模式相关功能需要管理员权限运行。

## 原则

- 探测全部走**只读手段**（ARP / ICMP / SYN / UDP GET / banner），不使用任何漏洞利用包
- 负结果只记「未确认」，不写「不存在」；猜测标注来源与「(推测)」，实证可覆盖猜测
- 仅用于自己有权管理的网络

## 文件

- `LanScan_v1.4.cs` — 全部源码（单文件，C# 5 兼容语法）
