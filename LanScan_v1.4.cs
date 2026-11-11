// =============================================================
// 局域网IP发现工具 (LanScan)
// 单文件 C# 实现，目标 .NET Framework 4.x (建议 4.5+)，csc 直接编译
// 功能：主动扫描(ARP+ICMP+TCP)、被动监听、DHCP探测、IP冲突检测、
//       跨网段辅助IP扫描、结果导出CSV
// 注意：使用 C# 5 兼容语法（不用字符串内插等新特性）
//
// ── 本版补丁（v1.1）改动一览 ────────────────────────────────
// [P1] 修复 IP 冲突检测误报：本机自身出站流量（TCP/UDP）此前会被
//      判为冲突。现用 GetExtendedTcpTable / GetExtendedUdpTable 查
//      本机连接表，能确认是本机进程发出的包直接忽略；ICMP 类流量
//      无法与本机自身活动区分，默认不再计入冲突（-strict 可改回）。
// [P2] 新增 TCP 端口判活（-notcp 关闭，-tcpports 自定义端口）：
//      跨网段时 ARP 失效、ICMP 又常被屏蔽，TCP 探测是唯一补强。
//      收到 RST(连接被拒) 同样判定主机在线。
// [P3] 被动监听支持多网卡：不指定 -nic 时对所有活动 IPv4 网卡同时
//      监听 + 诱探；控制台输出加锁避免交错。
// [P4] 主动诱探的 SendARP 改为以本网卡 IP 为源地址，避免多网卡/
//      多网段时路由选错网卡。
// [P5] mDNS 应答解析：提取 PTR/SRV 服务类型（_rtsp/_airplay/_ipp/
//      _googlecast…），直接给出设备类型；SSDP 应答解析 SERVER/
//      LOCATION 字段，输出设备型号信息。此前只记了源 IP。
// [P6] OUI 厂商库支持外部全量表：-oui <oui.txt>，或自动读取程序
//      同目录 / 当前目录下的 oui.txt（IEEE 官方格式），与内置表合并。
// [P7] 冲突检测结论细化，区分"真冲突"与"已忽略的本机流量"。
// [P8] 小修：ReverseDns 超时后回收异步句柄；监听开始时提示"交换
//      网络中混杂模式仅对广播/组播有效。
//
// ── v1.2 改动 ────────────────────────────────────────────────
// [W1] 接收窗口与"延迟应答"口径：新增 -recv <秒>。前 N 秒为主接收
//      窗口，窗口内应答记为「窗口内」；窗口之后才收到的回传仍然记录，
//      标注「延迟应答」，同样计为存在；全程无应答的地址列为「未确认」，
//      未确认 ≠ 不存在。结果表新增"应答"列，汇总尾部固定打印口径说明。
// [W2] 诱探提速：mDNS/SSDP/WSD/NetBIOS 四个查询改为并行发出，单轮
//      收包预算压到 1 秒（原为串行 11 秒），ARP 轮询频率随之提高约 8 倍。
//
// ── v1.3 改动 ────────────────────────────────────────────────
// [S1] 交换机 MAC 转发表（可选，默认关闭）：-snmp <community>
//      用 SNMPv2c GetBulk 只读走 dot1dTpFdbPort，空表再试 Q-BRIDGE。
//      对得上本机已见 MAC 的，并入该 IP 并注明交换端口；
//      对不上 IP 的单独列出。转发表里有 = 交换机见过，不是「没有」。
//      不指定 -snmp 时行为与 v1.2 相同。snmpvec 只打编解码自检，不访问网络。
//
// ── v1.4 改动（OS 识别，全部干净手段，不使用任何漏洞）─────────
// [F1] 结果表/CSV 新增"OS判断"列：只报猜测并标注来源（SNMP/banner/
//      TTL指纹），无把握显示"-"，不冒充确定——与「未确认≠不存在」
//      同一口径。
// [F2] SNMP v2c 只读查询 sysDescr/sysName（UDP 161，public/private，
//      -noosnmp 关闭）：Linux 设备常直接回内核版本字符串，工控/路由/
//      打印机的 sysDescr 常含厂商+固件。识别陌生 Linux 的主通道。
//      与 S1 的 -snmp（交换机转发表）互不相干：那是读网桥表，这是读设备自述。
// [F3] 工控常见 TCP 端口并入默认探测清单：502 Modbus / 102 S7 /
//      2404 IEC104 / 44818 EtherNet-IP / 4840 OPC UA / 20000 DNP3 /
//      47808 BACnet。端口应答只证明在线与服务，不触碰任何协议漏洞。
// [F4] Banner 识别：SSH(22)/FTP(21) 等先说话的端口读自报版本；
//      HTTP 类端口(80/8000/8080/8899) 发一个 GET / 读 Server: 头。
// [F5] OS TTL 指纹：ICMP 回包 TTL（PingReply.Options.Ttl，普通权限即可）
//      + SYN-ACK TTL/窗口（仅管理员运行 listen/full 时，raw socket 可见）。
//      Linux/嵌入式初始 TTL≈64，Windows≈128，老设备 255；均标注"(推测)"。
//      证据优先级：SNMP/banner（实证）> TTL 猜测，实证会覆盖猜测。
// =============================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LanScan
{
    // ---------------- 数据结构 ----------------
    class DeviceInfo
    {
        public string Ip = "";
        public string Mac = "";
        public string Hostname = "";
        public string Vendor = "";
        public List<string> Sources = new List<string>();
        public List<string> Services = new List<string>();   // [P5] mDNS/SSDP 得到的服务或型号线索
        public string Note = "";
        public bool IsLocal;
        public bool SshOpen;        // 22 端口是否可达
        public string SshBanner = ""; // SSH 服务自报版本（协议握手第一步）
        public int OpenPort;        // [P2] TCP 探测到的开放端口，0=仅确认在线
        // [F1] OS 判断（v1.4）：字符串尾部标注来源，如 "Linux xxx (SNMP)"
        public string Os = "";
        public bool SnmpTried;      // [F2] 已做过 OS 识别 SNMP 查询，避免多阶段重复
        // [W1] 应答时效：InWindow=主接收窗口内应答过；LateReplies=窗口之后才首次应答
        public bool InWindow;
        public int LateReplies;
        public DateTime LastSeen;
    }

    // [S1] 交换机见过、本机还没对上 IP 的 MAC。不计为不存在。
    class SnmpMacHit
    {
        public string Mac = "";
        public int Port;
        public string Vendor = "";
    }

    class DhcpMsg
    {
        public int Op;            // 1=request 2=reply
        public int MsgType;       // option 53
        public string ClientMac = "";
        public string YourIp = "";     // yiaddr
        public string ServerIp = "";   // siaddr
        public string ServerId = "";   // option 54
        public string Mask = "";
        public string Router = "";
        public string Dns = "";
        public string HostName = "";
        public uint Lease;
    }

    class Program
    {
        // ---------------- 全局状态 ----------------
        static readonly object DevicesLock = new object();
        static readonly object OutLock = new object();
        static readonly Dictionary<string, DeviceInfo> Devices = new Dictionary<string, DeviceInfo>();
        static readonly HashSet<string> MyIps = new HashSet<string>();
        static readonly HashSet<string> SeenSrc = new HashSet<string>();   // [P3] 全局共享，避免多网卡重复打印
        static readonly Queue<string> ConflictSamples = new Queue<string>();
        static int ConflictCount = 0;
        static string ExportPath = null;
        static bool UseColor = true;
        static bool ProbeEnabled = true;

        // [P1] 冲突检测：ICMP 无法与本机自身活动区分，默认不计入
        static bool StrictConflict = false;
        // [P2] TCP 判活；[F3] v1.4 默认端口追加工控常见端口
        //      502 Modbus / 102 S7 / 2404 IEC104 / 44818 EtherNet-IP / 4840 OPC UA / 20000 DNP3 / 47808 BACnet
        static List<int> ProbePorts = new List<int> { 80, 443, 22, 23, 554, 8554, 3389, 8000, 8080, 8899, 34567, 37777,
            502, 102, 2404, 44818, 4840, 20000, 47808 };
        static bool TcpSweepEnabled = true;
        // [F2] OS 识别 SNMP 查询开关（默认开启；与 S1 的 -snmp 转发表查询无关）
        static bool NoOsSnmp = false;
        const int TcpTimeoutMs = 200;
        // [P6] OUI 外部表
        static string OuiFilePath = null;
        static string OuiSource = "内置表";
        // [W1] 接收窗口：RecvWindowSec<0 表示不切分（全程都算窗口内）
        static int RecvWindowSec = -1;
        static DateTime WindowEnd = DateTime.MaxValue;
        static bool ShowUnconfirmed = false;
        // [S1] 交换机转发表。SnmpCommunity==null 表示关闭，不改变 v1.2 行为。
        static string SnmpCommunity = null;
        static string SnmpHost = null;
        const int SnmpTimeoutMs = 800;
        const int SnmpMaxRows = 2048;
        static readonly List<SnmpMacHit> SnmpUnmatched = new List<SnmpMacHit>();

        // ---------------- Win32 API ----------------
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern uint SendARP(uint DestIP, uint SrcIP, [Out] byte[] pMacAddr, ref uint PhyAddrLen);

        [DllImport("iphlpapi.dll")]
        static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        // [P1] 本机连接表（Windows Vista+）
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

        const int AF_INET = 2;
        const int TCP_TABLE_OWNER_PID_ALL = 5;
        const int UDP_TABLE_OWNER_PID = 1;

        const int SIO_RCVALL = unchecked((int)0x98000001);

        // ---------------- OUI 厂商表（内置常用子集，可被 oui.txt 扩充） ----------------
        static readonly Dictionary<string, string> OuiTable = new Dictionary<string, string>
        {
            {"00-0C-29","VMware 虚拟机"},{"00-50-56","VMware"},{"08-00-27","VirtualBox 虚拟机"},
            {"00-15-5D","Hyper-V 虚拟设备"},{"00-1C-42","Parallels 虚拟机"},
            {"00-1B-21","Intel"},{"68-05-CA","Intel"},{"AC-DE-48","私有/本地管理"},
            {"3C-15-C2","Apple"},{"AC-87-A3","Apple"},{"F0-18-98","Apple"},
            {"50-C7-BF","TP-Link"},{"EC-08-6B","TP-Link"},{"C4-6E-1F","TP-Link"},
            {"00-E0-FC","华为"},{"48-46-FB","华为"},{"28-6C-07","小米"},
            {"64-CC-2E","小米"},{"8C-71-F8","三星"},{"AC-36-13","三星"},
            {"00-00-0C","思科"},{"00-40-0B","思科"},{"00-14-22","戴尔"},
            {"00-1F-29","惠普"},{"B8-27-EB","树莓派"},{"DC-A6-32","树莓派"},
            {"24-0A-C4","乐鑫 ESP系列"},{"30-AE-A4","乐鑫 ESP系列"},{"A4-CF-12","乐鑫 ESP系列"},
            {"44-19-B6","海康威视"},{"00-E0-4C","Realtek 网卡"},{"00-0F-E2","H3C 华三"},
            {"00-D0-F8","锐捷网络"},{"00-26-F2","网件 Netgear"},{"28-10-7B","D-Link"},
            {"00-10-18","Broadcom"},{"00-50-43","Marvell"},{"00-03-7F","高通"},
            {"00-0C-E7","联发科"},{"00-1C-62","LG"},{"00-1D-BA","索尼"},
            {"00-09-BF","任天堂"},{"F4-F5-D8","Google"}
        };

        // =========================================================
        // 入口
        // =========================================================
        static int Main(string[] args)
        {
            try { Console.OutputEncoding = Encoding.UTF8; } catch { }
            try { Console.InputEncoding = Encoding.UTF8; } catch { }
            try { Console.ForegroundColor = ConsoleColor.Gray; Console.ResetColor(); }
            catch { UseColor = false; }

            PrintBanner();
            CollectMyIps();

            // 解析参数
            var mode = "";
            var positional = new List<string>();
            int listenSeconds = 30;
            bool tSpecified = false;
            string aliasCidr = null;
            string nicSpec = null;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                if (a == "-export" && i + 1 < args.Length) { ExportPath = args[++i]; continue; }
                if (a == "-alias" && i + 1 < args.Length) { aliasCidr = args[++i]; continue; }
                if (a == "-nic" && i + 1 < args.Length) { nicSpec = args[++i]; continue; }
                if (a == "-noprobe") { ProbeEnabled = false; continue; }
                if (a == "-notcp") { TcpSweepEnabled = false; continue; }            // [P2]
                if (a == "-strict") { StrictConflict = true; continue; }              // [P1]
                if (a == "-showall") { ShowUnconfirmed = true; continue; }             // [W1]
                if (a == "-snmp" && i + 1 < args.Length) { SnmpCommunity = args[++i]; continue; } // [S1]
                if (a == "-snmphost" && i + 1 < args.Length) { SnmpHost = args[++i]; continue; }   // [S1]
                if (a == "-noosnmp") { NoOsSnmp = true; continue; }                     // [F2]
                if (a == "-recv" && i + 1 < args.Length)                              // [W1]
                {
                    int rv; if (int.TryParse(args[++i], out rv) && rv > 0) RecvWindowSec = rv;
                    continue;
                }
                if (a == "-oui" && i + 1 < args.Length) { OuiFilePath = args[++i]; continue; }  // [P6]
                if (a == "-tcpports" && i + 1 < args.Length)                          // [P2]
                {
                    var plist = new List<int>();
                    foreach (var pp in args[++i].Split(','))
                    {
                        int v;
                        if (int.TryParse(pp.Trim(), out v) && v > 0 && v < 65536) plist.Add(v);
                    }
                    if (plist.Count > 0) ProbePorts = plist;
                    continue;
                }
                if (a == "-t" && i + 1 < args.Length)
                {
                    int v; if (int.TryParse(args[++i], out v) && v > 0) { listenSeconds = v; tSpecified = true; }
                    continue;
                }
                if (a == "-h" || a == "--help" || a == "help" || a == "/?") { PrintHelp(); return 0; }
                if (mode == "") mode = a; else positional.Add(args[i]);
            }

            // [P6] 加载外部 OUI 表（-oui 指定 → 程序同目录 → 当前目录）
            LoadOuiFromDisk();

            if (mode == "snmpvec")
                return SnmpSelfCheck() ? 0 : 1;

            try
            {
                if (mode == "")
                {
                    if (InputRedirected()) FullScan(listenSeconds, aliasCidr);
                    else InteractiveMenu();
                }
                else if (mode == "menu") InteractiveMenu();
                else if (mode == "list") ListAdapters();
                else if (mode == "scan")
                {
                    if (aliasCidr != null) ScanWithAlias(aliasCidr, positional.Count > 0 ? positional[0] : null);
                    else if (positional.Count > 0) { ActiveScanCidr(positional[0]); AfterScan(); }
                    else { ScanAllLocalSubnets(); AfterScan(); }
                }
                else if (mode == "listen") PassiveListen(GetSecs(positional, listenSeconds), nicSpec);
                else if (mode == "dhcp") DhcpDiscover(GetSecs(positional, tSpecified ? listenSeconds : 10));
                else if (mode == "conflict") ConflictCheck(GetSecs(positional, 20));
                else if (mode == "full") FullScan(GetSecs(positional, listenSeconds), aliasCidr, nicSpec);
                else { CWriteLine(ConsoleColor.Yellow, "[!] 未知模式: " + mode + "，使用 help 查看用法"); PrintHelp(); return 1; }
            }
            catch (Exception ex)
            {
                CWriteLine(ConsoleColor.Red, "[错误] " + ex.Message);
                return 2;
            }

            try
            {
                if (SnmpCommunity != null) SnmpWalkAndMerge();
                PrintResults();
                if (ExportPath != null) ExportCsv(ExportPath);
            }
            catch (Exception ex)
            {
                try { CWriteLine(ConsoleColor.Red, "[输出错误] " + ex.Message); } catch { }
            }
            return 0;
        }

        static int GetSecs(List<string> positional, int def)
        {
            int v;
            if (positional.Count > 0 && int.TryParse(positional[0], out v) && v > 0) return v;
            return def;
        }

        static void AfterScan()
        {
            ResolveNames();
        }

        // .NET 4.5+ 才提供 Console.IsInputRedirected；老框架下退化为"交互模式"
        static bool InputRedirected()
        {
            try { return Console.IsInputRedirected; }
            catch { return false; }
        }

        // =========================================================
        // 界面输出
        // =========================================================
        static void PrintBanner()
        {
            CWriteLine(ConsoleColor.Cyan, "======================================================");
            CWriteLine(ConsoleColor.Cyan, "        局域网IP发现工具 v1.4  (Windows)");
            CWriteLine(ConsoleColor.Cyan, "  ARP/ICMP/TCP扫描 · 被动监听 · 服务识别 · 冲突检测 · 接收窗口 · 交换机转发表 · OS识别");
            CWriteLine(ConsoleColor.Cyan, "======================================================");
        }

        // [P3] 多线程监听时输出加锁，避免行与行交错
        static void CWriteLine(ConsoleColor c, string s)
        {
            lock (OutLock)
            {
                if (!UseColor) { Console.WriteLine(s); return; }
                try { Console.ForegroundColor = c; Console.WriteLine(s); }
                finally { try { Console.ResetColor(); } catch { } }
            }
        }

        static void PrintHelp()
        {
            Console.WriteLine();
            Console.WriteLine("用法: 局域网IP发现工具.exe [模式] [参数]");
            Console.WriteLine();
            Console.WriteLine("模式:");
            Console.WriteLine("  menu               交互式菜单（不带参数时默认进入）");
            Console.WriteLine("  list               列出本机网卡信息");
            Console.WriteLine("  scan [网段]        主动扫描（ARP+ICMP+TCP），如 scan 192.168.1.0/24");
            Console.WriteLine("                     不带网段则扫描本机所有网段");
            Console.WriteLine("  listen [秒数]      被动监听+主动诱探（发现任意网段广播设备+唤醒沉默设备+IP冲突检测），默认30秒");
            Console.WriteLine("                     监听同时自动发送 ARP轮询/mDNS/SSDP/WSD/NetBIOS 查询，");
            Console.WriteLine("                     不主动广播的沉默设备也会被诱出应答；非管理员时自动降级为纯诱探");
            Console.WriteLine("                     不指定 -nic 时对所有活动网卡同时监听");
            Console.WriteLine("  dhcp [秒数]        发送 DHCP Discover，探测 DHCP 服务器");
            Console.WriteLine("  conflict           检测本机 IP 是否与局域网内其他设备冲突");
            Console.WriteLine("  full [秒数]        完整扫描（网卡+主动扫描+被动监听+DHCP探测）");
            Console.WriteLine("  snmpvec            编解码自检：打印固定报文十六进制并解析样例，不访问网络");
            Console.WriteLine();
            Console.WriteLine("参数:");
            Console.WriteLine("  -alias <网段>      跨网段扫描：临时为本机网卡添加该网段的辅助IP，");
            Console.WriteLine("                     扫描完成后自动删除（需管理员权限）");
            Console.WriteLine("                     例: scan 192.168.5.0/24 -alias 192.168.5.0/24");
            Console.WriteLine("  -nic <编号|名称>   指定被动监听使用的网卡（list 中的编号，或网卡名称/关键词）");
            Console.WriteLine("                     不指定时对所有活动 IPv4 网卡同时监听");
            Console.WriteLine("  -export <文件>     将结果导出为 CSV 文件");
            Console.WriteLine("  -t <秒数>          监听/等待时长");
            Console.WriteLine("  -noprobe           关闭主动诱探，仅纯被动监听（默认边听边诱探）");
            Console.WriteLine("  -notcp             关闭 TCP 端口判活（默认开启；跨网段时建议保持开启）");
            Console.WriteLine("  -tcpports <列表>   自定义 TCP 探测端口，逗号分隔");
            Console.WriteLine("                     默认: 80,443,22,23,554,8554,3389,8000,8080,8899,34567,37777,502,102,");
            Console.WriteLine("                     2404,44818,4840,20000,47808（后七个为工控常见端口）");
            Console.WriteLine("  -oui <文件>        加载 IEEE oui.txt 扩充厂商库（默认自动读取同目录/当前目录）");
            Console.WriteLine("  -strict            冲突检测把 ICMP 流量也计入（误报率高，仅在确知无本机ICMP活动时用）");
            Console.WriteLine("  -recv <秒>         主接收窗口时长：前 N 秒内收到的回传记为「窗口内」；窗口之后");
            Console.WriteLine("                     收到的回传照样记录并标为「延迟应答」，同样计为存在。不指定=全程窗口内");
            Console.WriteLine("  -showall           扫描结束后列出「未确认」地址完整清单（默认只报数量）");
            Console.WriteLine("  -noosnmp           关闭 OS 识别的 SNMP 系统描述查询（默认开启；只读 GET，与 -snmp 无关）");
            Console.WriteLine("  -snmp <community>  只读查询交换机 MAC 转发表（默认关闭；不指定则与 v1.2 相同）");
            Console.WriteLine("                     对上已见 MAC 的并入该 IP；对不上的单独列出，不算「没有」");
            Console.WriteLine("  -snmphost <IP>     指定交换机地址。不指定则用本机默认网关");
            Console.WriteLine();
            Console.WriteLine("示例:");
            Console.WriteLine("  局域网IP发现工具.exe full -export 结果.csv");
            Console.WriteLine("  局域网IP发现工具.exe scan 10.0.0.0/24 -alias 10.0.0.0/24");
            Console.WriteLine("  局域网IP发现工具.exe listen 60");
            Console.WriteLine("  局域网IP发现工具.exe scan 192.168.1.0/24 -tcpports 80,554,8000,37777");
            Console.WriteLine("  局域网IP发现工具.exe scan 192.168.1.0/24 -snmp public");
            Console.WriteLine("  局域网IP发现工具.exe snmpvec");
            Console.WriteLine();
            Console.WriteLine("OS判断列口径: 来源分 SNMP(sysDescr) / banner / TTL指纹，均为猜测并标注来源；");
            Console.WriteLine("              SNMP 与 banner 为实证、可覆盖 TTL 猜测；无把握显示\"-\"。猜测不冒充");
            Console.WriteLine("              确定，与「未确认≠不存在」是同一口径。");
        }

        // =========================================================
        // 工具函数
        // =========================================================
        static void CollectMyIps()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                            MyIps.Add(ua.Address.ToString());
                    }
                }
            }
            catch { }
        }

        static bool IsAdmin()
        {
            try
            {
                var id = WindowsIdentity.GetCurrent();
                var p = new WindowsPrincipal(id);
                return p.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        static uint IpToUint(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            return (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
        }

        static IPAddress UintToIp(uint v)
        {
            return new IPAddress(new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });
        }

        // 转为 inet_addr 风格（网络字节序按小端读取的 uint）
        static uint ToNetOrder(uint hostOrder)
        {
            byte[] b = UintToIp(hostOrder).GetAddressBytes();
            return BitConverter.ToUInt32(b, 0);
        }

        static string BytesToMac(byte[] mac, int len)
        {
            if (mac == null || len <= 0) return "";
            var sb = new StringBuilder();
            for (int i = 0; i < len && i < mac.Length; i++)
            {
                if (i > 0) sb.Append('-');
                sb.Append(mac[i].ToString("X2"));
            }
            return sb.ToString();
        }

        static string LookupVendor(string mac)
        {
            if (string.IsNullOrEmpty(mac) || mac.Length < 8) return "";
            string prefix = mac.Substring(0, 8).ToUpperInvariant();
            string v;
            if (OuiTable.TryGetValue(prefix, out v)) return v;
            return "";
        }

        static void AddDevice(string ip, string source, string mac, string note)
        {
            AddDevice(ip, source, mac, note, 0);
        }

        static void AddDevice(string ip, string source, string mac, string note, int openPort)
        {
            if (string.IsNullOrEmpty(ip)) return;
            lock (DevicesLock)
            {
                DeviceInfo d;
                if (!Devices.TryGetValue(ip, out d))
                {
                    d = new DeviceInfo();
                    d.Ip = ip;
                    d.IsLocal = MyIps.Contains(ip);
                    Devices[ip] = d;
                }
                if (!d.Sources.Contains(source)) d.Sources.Add(source);
                // [W1] 应答时效：窗口内应答 → InWindow；窗口之后才首次现身 → LateReplies
                d.LastSeen = DateTime.Now;
                if (DateTime.Now <= WindowEnd) d.InWindow = true;
                else if (!d.InWindow && d.LateReplies == 0) d.LateReplies = 1;
                if (!string.IsNullOrEmpty(mac) && d.Mac == "")
                {
                    d.Mac = mac;
                    string v = LookupVendor(mac);
                    if (v != "") d.Vendor = v;
                }
                if (openPort > 0 && d.OpenPort == 0) d.OpenPort = openPort;
                if (!string.IsNullOrEmpty(note) && !d.Note.Contains(note))
                {
                    if (d.Note != "") d.Note += "; ";
                    d.Note += note;
                }
            }
        }

        // [P5] 记录服务/型号线索，去重
        static void AddService(string ip, string svc)
        {
            if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(svc)) return;
            lock (DevicesLock)
            {
                DeviceInfo d;
                if (!Devices.TryGetValue(ip, out d))
                {
                    // 尚不存在则创建，保持与 AddDevice 一致
                    d = new DeviceInfo();
                    d.Ip = ip;
                    d.IsLocal = MyIps.Contains(ip);
                    Devices[ip] = d;
                }
                if (!d.Services.Contains(svc)) d.Services.Add(svc);
            }
        }

        // 解析 CIDR: 支持 "1.2.3.0/24"、"1.2.3.4/255.255.255.0"、"1.2.3.4"(按/24)
        static bool ParseCidr(string s, out uint network, out int bits)
        {
            network = 0; bits = 24;
            if (string.IsNullOrEmpty(s)) return false;
            s = s.Trim();
            string ipPart = s; int bitsPart = 24;
            int slash = s.IndexOf('/');
            if (slash >= 0)
            {
                ipPart = s.Substring(0, slash);
                string rest = s.Substring(slash + 1);
                if (rest.Contains('.'))
                {
                    IPAddress m;
                    if (!IPAddress.TryParse(rest, out m)) return false;
                    uint mv = IpToUint(m);
                    bitsPart = 0;
                    for (int i = 31; i >= 0; i--) if ((mv & (1u << i)) != 0) bitsPart++; else break;
                }
                else
                {
                    if (!int.TryParse(rest, out bitsPart)) return false;
                }
            }
            IPAddress a;
            if (!IPAddress.TryParse(ipPart, out a)) return false;
            if (bitsPart < 1 || bitsPart > 30) return false;
            uint mask = bitsPart == 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - bitsPart)) & 0xFFFFFFFFu;
            network = IpToUint(a) & mask;
            bits = bitsPart;
            return true;
        }

        static List<uint> EnumHosts(uint network, int bits)
        {
            var list = new List<uint>();
            uint mask = bits >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - bits)) & 0xFFFFFFFFu;
            uint net = network & mask;
            uint bcast = net | (~mask & 0xFFFFFFFFu);
            if (bcast - net <= 1) { list.Add(net); return list; }
            for (uint h = net + 1; h < bcast; h++) list.Add(h);
            return list;
        }

        // =========================================================
        // [P1] 本机连接表判定：区分"本机自己发出的包"
        // =========================================================
        // dwLocalPort / dwRemotePort 的低16位是网络序端口
        static int DwPortToHost(int dw)
        {
            return ((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF);
        }

        // inet_addr 风格的 DWORD → 点分 IP
        static string DwAddrToIp(int dw)
        {
            byte[] b = BitConverter.GetBytes(dw);
            return b[3] + "." + b[2] + "." + b[1] + "." + b[0];
        }

        // TCP：源端口必须属于本机某个 socket，且地址是本机地址（或通配）
        static bool TcpOwnedByLocal(int srcPort, string dstIp, int dstPort)
        {
            int size = 0;
            uint rc = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return false;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                rc = GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (rc != 0) return false;
                int count = Marshal.ReadInt32(buf);
                for (int i = 0; i < count; i++)
                {
                    IntPtr row = new IntPtr(buf.ToInt64() + 4 + i * 24);
                    int lp = DwPortToHost(Marshal.ReadInt32(row, 8));
                    if (lp != srcPort) continue;
                    int ra = Marshal.ReadInt32(row, 12);
                    int rp = DwPortToHost(Marshal.ReadInt32(row, 16));
                    if (DwAddrToIp(ra) == dstIp && rp == dstPort) return true;      // 远端完全匹配
                    string la = DwAddrToIp(Marshal.ReadInt32(row, 4));
                    if (la == "0.0.0.0" || MyIps.Contains(la)) return true;         // 本地端口确属本机
                }
            }
            catch { }
            finally { Marshal.FreeHGlobal(buf); }
            return false;
        }

        // UDP：无连接，源端口出现在本机 UDP 绑定表即视为本机发出
        static bool UdpOwnedByLocal(int srcPort)
        {
            int size = 0;
            uint rc = GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) return false;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                rc = GetExtendedUdpTable(buf, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
                if (rc != 0) return false;
                int count = Marshal.ReadInt32(buf);
                for (int i = 0; i < count; i++)
                {
                    IntPtr row = new IntPtr(buf.ToInt64() + 4 + i * 12);
                    int lp = DwPortToHost(Marshal.ReadInt32(row, 4));
                    if (lp != srcPort) continue;
                    string la = DwAddrToIp(Marshal.ReadInt32(row, 0));
                    if (la == "0.0.0.0" || MyIps.Contains(la)) return true;
                }
            }
            catch { }
            finally { Marshal.FreeHGlobal(buf); }
            return false;
        }

        static bool IsLocalOutbound(int proto, int srcPort, string dstIp, int dstPort)
        {
            if (srcPort <= 0) return false;
            if (proto == 6) return TcpOwnedByLocal(srcPort, dstIp, dstPort);
            if (proto == 17) return UdpOwnedByLocal(srcPort);
            return false;
        }

        // =========================================================
        // 1. 网卡列表
        // =========================================================
        static void ListAdapters()
        {
            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "─── 本机网卡信息 ───");
            bool admin = IsAdmin();
            CWriteLine(admin ? ConsoleColor.Green : ConsoleColor.Yellow,
                admin ? "当前以管理员权限运行（被动监听/跨网段辅助IP可用）"
                      : "当前为普通用户权限（被动监听/跨网段辅助IP不可用，建议右键-以管理员身份运行）");
            Console.WriteLine("厂商库: " + OuiSource + "（" + OuiTable.Count + " 条）");
            Console.WriteLine();
            int idx = 0;
            foreach (var ni in GetActiveNics())
            {
                var ipProps = ni.GetIPProperties();
                idx++;
                Console.WriteLine(string.Format("[{0}] {1} ({2})", idx, ni.Name, ni.NetworkInterfaceType));
                Console.WriteLine("    描述   : " + ni.Description);
                var v4s = ipProps.UnicastAddresses
                    .Where(x => x.Address.AddressFamily == AddressFamily.InterNetwork).ToList();
                foreach (var ua in v4s)
                    Console.WriteLine("    IPv4   : " + ua.Address + "  掩码: " + ua.IPv4Mask);
                Console.WriteLine("    MAC    : " + BytesToMac(ni.GetPhysicalAddress().GetAddressBytes(), 6));
                var gw = ipProps.GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                Console.WriteLine("    网关   : " + (gw != null ? gw.Address.ToString() : "无"));
                var dns = ipProps.DnsAddresses.FirstOrDefault(d => d.AddressFamily == AddressFamily.InterNetwork);
                Console.WriteLine("    DNS    : " + (dns != null ? dns.ToString() : "无"));
                Console.WriteLine();
            }
            if (idx == 0) CWriteLine(ConsoleColor.Yellow, "未发现活动的 IPv4 网卡");
        }

        // =========================================================
        // 2. 主动扫描（ARP + ICMP + TCP）
        // =========================================================
        static void ScanAllLocalSubnets()
        {
            var seen = new HashSet<string>();
            var targets = new List<KeyValuePair<uint, int>>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (ua.IPv4Mask == null) continue;
                    uint ip = IpToUint(ua.Address);
                    uint mask = IpToUint(ua.IPv4Mask);
                    int bits = 0;
                    for (int i = 31; i >= 0; i--) if ((mask & (1u << i)) != 0) bits++; else break;
                    if (bits < 8 || bits > 30) continue;
                    uint net = ip & mask;
                    string key = net + "/" + bits;
                    if (seen.Contains(key)) continue;
                    seen.Add(key);
                    targets.Add(new KeyValuePair<uint, int>(net, bits));
                }
            }
            if (targets.Count == 0)
            {
                CWriteLine(ConsoleColor.Yellow, "[!] 未找到可扫描的本机网段");
                return;
            }
            foreach (var t in targets)
                ActiveScan(t.Key, t.Value, "本机网段 " + UintToIp(t.Key) + "/" + t.Value);
            MergeArpTable(0u, 0);
        }

        static void ActiveScanCidr(string cidr)
        {
            uint net; int bits;
            if (!ParseCidr(cidr, out net, out bits))
            {
                CWriteLine(ConsoleColor.Red, "[!] 网段格式错误: " + cidr + "（示例: 192.168.1.0/24）");
                return;
            }
            ActiveScan(net, bits, "指定网段 " + UintToIp(net) + "/" + bits);
            MergeArpTable(net, bits);
        }

        static void ActiveScan(uint network, int bits, string label)
        {
            var hosts = EnumHosts(network, bits);
            if (hosts.Count > 4094)
            {
                CWriteLine(ConsoleColor.Yellow, "[!] 网段过大（>" + 4094 + " 台主机），请指定更小的网段（掩码不小于 /20）");
                return;
            }
            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "─── 主动扫描 " + label + "（" + hosts.Count + " 个地址，快速ARP触发式）───");
            if (RecvWindowSec > 0) WindowEnd = DateTime.Now.AddSeconds(RecvWindowSec);   // [W1]
            var sw = Stopwatch.StartNew();

            // 阶段1: 全量异步并发发射 ICMP 探针（300ms短超时，只用于触发系统ARP解析，
            //        不等待完整握手确认；顺带收到回复的记为 ICMP 存活）
            const int chunk = 256;
            for (int off = 0; off < hosts.Count; off += chunk)
            {
                int end = Math.Min(off + chunk, hosts.Count);
                using (var gate = new CountdownEvent(end - off))
                {
                    for (int i = off; i < end; i++)
                    {
                        uint h = hosts[i];
                        string ipStr = UintToIp(h).ToString();
                        var p = new Ping();
                        PingCompletedEventHandler handler = (s, e) =>
                        {
                            try
                            {
                                if (e.Reply != null && e.Reply.Status == IPStatus.Success)
                                {
                                    AddDevice(ipStr, "ICMP", "", "");
                                    int ittl = 0;                                        // [F5]
                                    if (e.Reply.Options != null) ittl = e.Reply.Options.Ttl;
                                    if (ittl > 0) RecordIcmpTtl(ipStr, ittl);
                                }
                            }
                            catch { }
                            finally
                            {
                                try { p.Dispose(); } catch { }
                                try { gate.Signal(); } catch { }
                            }
                        };
                        try
                        {
                            p.PingCompleted += handler;
                            p.SendAsync(UintToIp(h), 300, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }, null);
                        }
                        catch
                        {
                            try { p.Dispose(); } catch { }
                            try { gate.Signal(); } catch { }
                        }
                    }
                    gate.Wait(3000); // 探针自身300ms超时，此处仅为保险上限
                }
            }

            // 阶段2: 给系统ARP解析留一点时间，然后一次性读ARP缓存确认存活
            //        （ARP缓存中有有效MAC记录 = 设备存在，屏蔽ICMP的设备也能抓到）
            Thread.Sleep(800);
            MergeArpTable(network, bits);
            FillLocalMacs(network, bits);

            // 阶段3: [P2] TCP 端口判活——补上"ARP 到不了 + ICMP 被屏蔽"的空档
            TcpSweep(network, bits, label);

            // 阶段4: [F2] SNMP 系统描述查询——对已发现设备读 sysDescr/sysName
            SnmpSweep();

            // [W1] 未确认清单：没有任何应答的地址，只能记为"未确认"
            ReportUnconfirmed(network, bits, label);

            sw.Stop();
            Console.WriteLine("    " + label + " 全部完成，耗时 " + sw.Elapsed.TotalSeconds.ToString("F1") + " 秒");
        }

        // =========================================================
        // [P2] TCP 端口判活
        // =========================================================
        static bool TcpAlive(string ip, out int openPort)
        {
            openPort = 0;
            IPAddress addr;
            if (!IPAddress.TryParse(ip, out addr)) return false;
            foreach (int port in ProbePorts)
            {
                TcpClient c = null;
                try
                {
                    c = new TcpClient();
                    IAsyncResult ar = c.BeginConnect(addr, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(TcpTimeoutMs))
                    {
                        try { c.Close(); } catch { }
                        continue;
                    }
                    try
                    {
                        c.EndConnect(ar);          // SYN-ACK：端口开放
                        openPort = port;
                        try { c.Close(); } catch { }
                        return true;
                    }
                    catch (SocketException se)
                    {
                        try { c.Close(); } catch { }
                        if (se.SocketErrorCode == SocketError.ConnectionRefused)
                        {
                            openPort = 0;          // RST：主机在线但该端口关闭
                            return true;
                        }
                    }
                    catch { try { c.Close(); } catch { } }
                }
                catch { try { if (c != null) c.Close(); } catch { } }
            }
            return false;
        }

        // 只对"ARP/ICMP 都还没确认存在"的地址做 TCP 探测，省时间
        static void TcpSweep(uint network, int bits, string label)
        {
            if (!TcpSweepEnabled) return;
            var hosts = EnumHosts(network, bits);
            if (hosts.Count == 0) return;
            if (hosts.Count > 1024)
            {
                CWriteLine(ConsoleColor.Yellow, "[!] 网段过大（" + hosts.Count + " 个地址），跳过 TCP 端口探测（-notcp 可静默关闭）");
                return;
            }

            var pending = new List<string>();
            lock (DevicesLock)
            {
                foreach (var h in hosts)
                {
                    string s = UintToIp(h).ToString();
                    if (MyIps.Contains(s)) continue;
                    DeviceInfo d;
                    if (Devices.TryGetValue(s, out d))
                    {
                        if (!string.IsNullOrEmpty(d.Mac)) continue;          // ARP 已确认
                        if (d.Sources.Contains("ICMP")) continue;            // ICMP 已确认
                        if (d.Sources.Contains("TCP端口")) continue;
                    }
                    pending.Add(s);
                }
            }
            if (pending.Count == 0) return;

            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "─── TCP 端口判活 " + label + "（" + pending.Count
                + " 个待确认地址，端口 " + ProbePortsText() + "）───");
            var sw = Stopwatch.StartNew();
            int found = 0;
            Parallel.ForEach(pending, new ParallelOptions { MaxDegreeOfParallelism = 64 }, ip =>
            {
                int port;
                if (TcpAlive(ip, out port))
                {
                    Interlocked.Increment(ref found);
                    AddDevice(ip, "TCP端口", "", port > 0 ? ("开放端口 " + port) : "主机在线(拒绝连接)", port);
                    CWriteLine(ConsoleColor.Green, "    [TCP发现] " + ip.PadRight(16)
                        + (port > 0 ? ("开放端口 " + port) : "在线(RST)"));
                    if (port > 0) TryBanner(ip, port);      // [F4] 抓一次服务自报版本
                }
            });
            sw.Stop();
            Console.WriteLine("    TCP 判活完成，新发现 " + found + " 台，耗时 " + sw.Elapsed.TotalSeconds.ToString("F1") + " 秒");
        }

        // [W1] 统计本网段内"未收到任何应答"的地址：未确认 ≠ 不存在
        static void ReportUnconfirmed(uint network, int bits, string label)
        {
            var hosts = EnumHosts(network, bits);
            if (hosts.Count == 0 || hosts.Count > 1024) return;
            var pending = new List<string>();
            lock (DevicesLock)
            {
                foreach (var h in hosts)
                {
                    string s = UintToIp(h).ToString();
                    if (MyIps.Contains(s)) continue;
                    if (!Devices.ContainsKey(s)) pending.Add(s);
                }
            }
            if (pending.Count == 0) return;
            Console.WriteLine();
            CWriteLine(ConsoleColor.Gray, "  [未确认] " + label + " 内 " + pending.Count
                + " 个地址未收到任何应答（未确认 ≠ 不存在：对方可能屏蔽 ICMP/ARP，或整段静默）");
            if (ShowUnconfirmed)
            {
                foreach (var s in pending) Console.WriteLine("      " + s);
            }
            else
            {
                Console.WriteLine("      （加 -showall 可列出完整清单）");
            }
        }

        static string ProbePortsText()
        {
            return string.Join(",", ProbePorts.Select(delegate (int x) { return x.ToString(); }).ToArray());
        }

        // =========================================================
        // 3a4. [F2] OS 识别 SNMP v2c 只读查询（sysDescr / sysName）
        //     手工 BER 编码一个最小 GET 包；应答里定位 OID 后取值。
        //     这是网络管理的标准只读请求，不含任何侵入动作。
        //     与 S1 的交换机转发表查询（-snmp）互不相干。
        // =========================================================
        static readonly byte[] OidSysDescr = new byte[] { 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 }; // 1.3.6.1.2.1.1.1.0
        static readonly byte[] OidSysName  = new byte[] { 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00 }; // 1.3.6.1.2.1.1.5.0
        static readonly string[] SnmpCommunities = new string[] { "public", "private" };

        static byte[] SnmpBuildGet(string community, byte[] oid)
        {
            byte[] comm = Encoding.ASCII.GetBytes(community);
            byte[] ver = new byte[] { 0x02, 0x01, 0x01 };                        // INTEGER 1 = v2c
            byte[] commTlv = new byte[2 + comm.Length];
            commTlv[0] = 0x04; commTlv[1] = (byte)comm.Length;                    // OCTET STRING
            Buffer.BlockCopy(comm, 0, commTlv, 2, comm.Length);
            byte[] reqId = new byte[] { 0x02, 0x01, 0x07 };                      // request-id 7
            byte[] errStat = new byte[] { 0x02, 0x01, 0x00, 0x02, 0x01, 0x00 };  // error-status=0, error-index=0
            byte[] oidTlv = new byte[2 + oid.Length];
            oidTlv[0] = 0x06; oidTlv[1] = (byte)oid.Length;                       // OID
            Buffer.BlockCopy(oid, 0, oidTlv, 2, oid.Length);
            byte[] vbContent = new byte[oidTlv.Length + 2];                       // OID + NULL(05 00)
            Buffer.BlockCopy(oidTlv, 0, vbContent, 0, oidTlv.Length);
            vbContent[oidTlv.Length] = 0x05; vbContent[oidTlv.Length + 1] = 0x00;
            byte[] varbind = new byte[2 + vbContent.Length];                     // SEQUENCE
            varbind[0] = 0x30; varbind[1] = (byte)vbContent.Length;
            Buffer.BlockCopy(vbContent, 0, varbind, 2, vbContent.Length);
            byte[] vbList = new byte[2 + varbind.Length];                         // varbind-list SEQUENCE
            vbList[0] = 0x30; vbList[1] = (byte)varbind.Length;
            Buffer.BlockCopy(varbind, 0, vbList, 2, varbind.Length);
            byte[] pduBody = new byte[reqId.Length + errStat.Length + vbList.Length];
            Buffer.BlockCopy(reqId, 0, pduBody, 0, reqId.Length);
            Buffer.BlockCopy(errStat, 0, pduBody, reqId.Length, errStat.Length);
            Buffer.BlockCopy(vbList, 0, pduBody, reqId.Length + errStat.Length, vbList.Length);
            byte[] pdu = new byte[2 + pduBody.Length];                            // GetRequest [A0]
            pdu[0] = 0xA0; pdu[1] = (byte)pduBody.Length;
            Buffer.BlockCopy(pduBody, 0, pdu, 2, pduBody.Length);
            byte[] msgBody = new byte[ver.Length + commTlv.Length + pdu.Length];
            Buffer.BlockCopy(ver, 0, msgBody, 0, ver.Length);
            Buffer.BlockCopy(commTlv, 0, msgBody, ver.Length, commTlv.Length);
            Buffer.BlockCopy(pdu, 0, msgBody, ver.Length + commTlv.Length, pdu.Length);
            byte[] msg = new byte[2 + msgBody.Length];                           // 整体 SEQUENCE（总长恒 <128）
            msg[0] = 0x30; msg[1] = (byte)msgBody.Length;
            Buffer.BlockCopy(msgBody, 0, msg, 2, msgBody.Length);
            return msg;
        }

        // 在应答里定位我们请求的 OID，其后第一个 OCTET STRING 即返回值
        static string SnmpParseValue(byte[] resp, byte[] oid)
        {
            if (resp == null || resp.Length < oid.Length + 8) return null;
            for (int i = 0; i <= resp.Length - oid.Length - 4; i++)
            {
                if (resp[i] != 0x06 || resp[i + 1] != oid.Length) continue;
                bool match = true;
                for (int j = 0; j < oid.Length; j++)
                    if (resp[i + 2 + j] != oid[j]) { match = false; break; }
                if (!match) continue;
                int v = i + 2 + oid.Length;
                if (v + 2 > resp.Length) return null;
                int tag = resp[v];
                int len = resp[v + 1];
                int hdr = 2;
                if ((len & 0x80) != 0)
                {
                    int nb = len & 0x7F;
                    if (nb > 2 || v + 2 + nb > resp.Length) return null;
                    len = 0;
                    for (int k = 0; k < nb; k++) len = (len << 8) | resp[v + 2 + k];
                    hdr = 2 + nb;
                }
                if (tag != 0x04) return null;          // 只要 OCTET STRING；NULL/异常值/整数都不算
                if (len <= 0 || len > 4096) return null;
                if (v + hdr + len > resp.Length) return null;
                string raw = Encoding.ASCII.GetString(resp, v + hdr, len);
                var sb = new StringBuilder();
                foreach (char ch in raw) if (ch >= ' ' && ch <= '~') sb.Append(ch);
                string val = sb.ToString().Trim();
                return val.Length > 0 ? val : null;
            }
            return null;
        }

        static string SnmpQuery(string ip, string community, byte[] oid, int timeoutMs)
        {
            try
            {
                using (UdpClient u = new UdpClient())
                {
                    u.Client.ReceiveTimeout = timeoutMs;
                    u.Client.SendTimeout = timeoutMs;
                    u.Connect(ip, 161);
                    byte[] pkt = SnmpBuildGet(community, oid);
                    u.Send(pkt, pkt.Length);
                    IPEndPoint any = new IPEndPoint(IPAddress.Any, 0);
                    byte[] resp = u.Receive(ref any);
                    return SnmpParseValue(resp, oid);
                }
            }
            catch { return null; }
        }

        // [F2] 对单台设备依次尝试默认 community；成功即写 Os/Hostname。
        //      SNMP 证据（实证）优先于 TTL 猜测，会覆盖含"(推测"的判断。
        static bool SnmpProbeDevice(DeviceInfo d)
        {
            for (int c = 0; c < SnmpCommunities.Length; c++)
            {
                string descr = SnmpQuery(d.Ip, SnmpCommunities[c], OidSysDescr, 500);
                if (!string.IsNullOrEmpty(descr))
                {
                    string name = SnmpQuery(d.Ip, SnmpCommunities[c], OidSysName, 500);
                    lock (DevicesLock)
                    {
                        if (d.Os == "" || d.Os.Contains("(推测")) d.Os = Trunc(descr, 44) + " (SNMP)";
                        if (d.Hostname == "" && !string.IsNullOrEmpty(name)) d.Hostname = name;
                        if (!d.Sources.Contains("SNMP")) d.Sources.Add("SNMP");
                    }
                    return true;
                }
            }
            return false;
        }

        // [F2] 收尾阶段：对全部已发现、还没做过 OS 识别 SNMP 的设备做只读查询
        static void SnmpSweep()
        {
            if (NoOsSnmp) return;
            var targets = new List<DeviceInfo>();
            lock (DevicesLock)
            {
                foreach (var d in Devices.Values)
                    if (!MyIps.Contains(d.Ip) && !d.SnmpTried && !d.Ip.Contains("?")) targets.Add(d);
            }
            if (targets.Count == 0) return;
            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "─── SNMP 系统描述查询（" + targets.Count + " 台设备，只读 GET，-noosnmp 关闭）───");
            var sw = Stopwatch.StartNew();
            int got = 0;
            Parallel.ForEach(targets, new ParallelOptions { MaxDegreeOfParallelism = 24 }, d =>
            {
                d.SnmpTried = true;
                if (SnmpProbeDevice(d))
                {
                    Interlocked.Increment(ref got);
                    CWriteLine(ConsoleColor.Green, "    [SNMP] " + d.Ip.PadRight(16) + " " + d.Os);
                }
            });
            sw.Stop();
            Console.WriteLine("    SNMP 查询完成，" + got + " 台返回了系统描述，耗时 " + sw.Elapsed.TotalSeconds.ToString("F1") + " 秒");
        }

        // =========================================================
        // 3a5. [F4] Banner 识别：先说话的端口(SSH/FTP)被动读自报版本；
        //     HTTP 类端口发一个 GET / 读 Server: 头。均只读，无侵入。
        // =========================================================
        static void TryBanner(string ip, int port)
        {
            DeviceInfo d = null;
            lock (DevicesLock) { if (!Devices.TryGetValue(ip, out d)) return; }
            if (d == null) return;
            if (d.Os != "" && !d.Os.Contains("(推测")) return;      // 已有实证，不覆盖
            string b = TcpBanner(ip, port);
            if (string.IsNullOrEmpty(b)) return;
            lock (DevicesLock)
            {
                if (d.Os == "" || d.Os.Contains("(推测")) d.Os = Trunc(b, 44) + " (banner)";
            }
        }

        static string TcpBanner(string ip, int port)
        {
            try
            {
                using (TcpClient tc = new TcpClient())
                {
                    tc.ReceiveTimeout = 800;
                    tc.SendTimeout = 400;
                    tc.Connect(ip, port);
                    NetworkStream ns = tc.GetStream();
                    bool http = (port == 80 || port == 8000 || port == 8080 || port == 8899);
                    if (http)
                    {
                        byte[] req = Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: " + ip + "\r\nUser-Agent: LanScan/1.4\r\n\r\n");
                        ns.Write(req, 0, req.Length);
                        ns.Flush();
                    }
                    byte[] buf = new byte[512];
                    int n = ns.Read(buf, 0, buf.Length);
                    if (n <= 0) return "";
                    string txt = Encoding.ASCII.GetString(buf, 0, n);
                    return ExtractOsFromBanner(txt);
                }
            }
            catch { return ""; }
        }

        static string ExtractOsFromBanner(string txt)
        {
            if (string.IsNullOrEmpty(txt)) return "";
            string[] lines = txt.Replace("\r", "").Split('\n');
            foreach (string line in lines)
            {
                string L = line.Trim();
                if (L == "") continue;
                if (L.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase)) return L;
                if (L.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                    return "HTTP " + L.Substring(7).Trim();
                if (L.StartsWith("220 ", StringComparison.OrdinalIgnoreCase) ||
                    L.StartsWith("220-", StringComparison.OrdinalIgnoreCase)) return L;
                if (L.StartsWith("<", StringComparison.OrdinalIgnoreCase)) continue;   // HTML 正文跳过
                if (L.Length > 0 && (L[0] < ' ' || L[0] > '~')) return "";               // 二进制协议，不是文本 banner
            }
            return "";
        }

        // =========================================================
        // 3a6. [F5] OS TTL 指纹（ICMP 回包 + SYN-ACK）
        //     Linux/嵌入式 初始 TTL≈64；Windows≈128；老设备 255。
        //     只作猜测并标注"(推测)"，不作确定性结论。
        // =========================================================
        static void RecordIcmpTtl(string ip, int ttl)
        {
            if (ttl <= 0) return;
            DeviceInfo d = null;
            lock (DevicesLock) { if (!Devices.TryGetValue(ip, out d)) return; }
            if (d == null || (d.Os != "" && !d.Os.Contains("(推测"))) return;
            string guess;
            if (ttl <= 64) guess = "Linux/嵌入式(推测,ICMP TTL64)";
            else if (ttl <= 128) guess = "Windows(推测,ICMP TTL128)";
            else guess = "嵌入式/老设备(推测,ICMP TTL" + ttl + ")";
            lock (DevicesLock) { if (d.Os == "" || d.Os.Contains("(推测")) d.Os = guess; }
        }

        // [F5] SYN-ACK 指纹：发往本机的 SYN-ACK 记 TTL/窗口（仅管理员 listen/full 时可见）
        static void RecordSynAckFingerprint(string ip, int ttl, int win)
        {
            DeviceInfo d = null;
            lock (DevicesLock) { if (!Devices.TryGetValue(ip, out d)) return; }
            if (d == null || (d.Os != "" && !d.Os.Contains("(推测"))) return;
            string guess;
            if (ttl <= 64) guess = "Linux/嵌入式(推测,TTL64)";
            else if (ttl <= 128) guess = "Windows(推测,TTL128)";
            else guess = "嵌入式/老设备(推测,TTL" + ttl + ")";
            if (win == 8192 || win == 16384 || win == 65535) guess = guess + " W" + win;
            lock (DevicesLock) { if (d.Os == "" || d.Os.Contains("(推测")) d.Os = guess + " (SYN-ACK)"; }
        }

        // 读取系统 ARP 缓存合并结果；network/bits 为 0 时合并全部
        static void MergeArpTable(uint network, int bits)
        {
            try
            {
                int size = 0;
                GetIpNetTable(IntPtr.Zero, ref size, false);
                if (size <= 0) return;
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetIpNetTable(buf, ref size, false) != 0) return;
                    int count = Marshal.ReadInt32(buf);
                    uint mask = bits >= 32 ? 0xFFFFFFFFu : bits <= 0 ? 0u : (0xFFFFFFFFu << (32 - bits)) & 0xFFFFFFFFu;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr row = new IntPtr(buf.ToInt64() + 4 + i * 24);
                        int macLen = Marshal.ReadInt32(row, 4);
                        if (macLen <= 0 || macLen > 8) continue;
                        byte[] mac = new byte[macLen];
                        bool allZero = true;
                        for (int j = 0; j < macLen; j++)
                        {
                            mac[j] = Marshal.ReadByte(row, 8 + j);
                            if (mac[j] != 0) allZero = false;
                        }
                        if (allZero) continue; // 全零MAC是Windows探测失败的幽灵记录，跳过
                        byte[] ab = new byte[] {
                            Marshal.ReadByte(row, 16), Marshal.ReadByte(row, 17),
                            Marshal.ReadByte(row, 18), Marshal.ReadByte(row, 19) };
                        var ip = new IPAddress(ab);
                        int type = Marshal.ReadInt32(row, 20);
                        if (type != 2 && type != 3) continue; // 只取动态/静态有效项
                        uint ipv = IpToUint(ip);
                        if (mask != 0 && (ipv & mask) != (network & mask)) continue;
                        AddDevice(ip.ToString(), "ARP缓存", BytesToMac(mac, macLen), "");
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            catch { }
        }

        // 本机 IP 不会出现在自己的 ARP 缓存中，扫描收尾时用网卡自身 MAC 回填
        static void FillLocalMacs(uint network, int bits)
        {
            try
            {
                uint mask = bits >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - bits)) & 0xFFFFFFFFu;
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    byte[] macBytes = ni.GetPhysicalAddress().GetAddressBytes();
                    if (macBytes == null || macBytes.Length != 6) continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        uint ipv = IpToUint(ua.Address);
                        if ((ipv & mask) != (network & mask)) continue;
                        AddDevice(ua.Address.ToString(), "本机", BytesToMac(macBytes, 6), "");
                    }
                }
            }
            catch { }
        }

        // =========================================================
        // 3. 被动监听（混杂模式，发现任意网段设备 + 冲突检测）
        // =========================================================
        static void PassiveListen(int seconds)
        {
            PassiveListen(seconds, null);
        }

        // [P3] 不指定网卡时对所有活动 IPv4 网卡同时监听 + 诱探
        static void PassiveListen(int seconds, string nicSpec)
        {
            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "─── 被动监听模式（" + seconds + " 秒）───");

            var nics = new List<NetworkInterface>();
            if (nicSpec != null && nicSpec.Trim() != "")
            {
                var one = ResolveNic(nicSpec.Trim());
                if (one == null)
                {
                    CWriteLine(ConsoleColor.Yellow, "[!] 找不到匹配 \"" + nicSpec + "\" 的活动网卡，可用网卡如下:");
                    PrintNicChoices();
                    return;
                }
                Console.WriteLine("    已按指定选择网卡: [" + one.Name + "]");
                nics.Add(one);
            }
            else
            {
                nics.AddRange(GetActiveNics());
            }

            if (nics.Count == 0)
            {
                CWriteLine(ConsoleColor.Yellow, "[!] 未找到活动网卡，跳过被动监听");
                return;
            }

            bool admin = IsAdmin();
            if (!admin)
                CWriteLine(ConsoleColor.Yellow, "[!] 非管理员权限：无法开启混杂监听，将仅用主动诱探(ARP+广播查询)发现设备。建议以管理员身份运行获取完整结果。");

            if (!admin && !ProbeEnabled)
            {
                CWriteLine(ConsoleColor.Yellow, "[!] 非管理员且诱探已禁用，无可用发现手段，已跳过。");
                return;
            }

            ConflictCount = 0;
            lock (ConflictSamples) { ConflictSamples.Clear(); }

            DateTime deadline = DateTime.Now.AddSeconds(seconds);
            // [W1] 主接收窗口：前 N 秒内应答记为「窗口内」，之后记为「延迟应答」
            if (RecvWindowSec > 0 && RecvWindowSec < seconds)
            {
                WindowEnd = DateTime.Now.AddSeconds(RecvWindowSec);
                Console.WriteLine("    主接收窗口: 前 " + RecvWindowSec + " 秒（窗口之后的回传仍会记录，标为「延迟应答」）");
            }
            else
            {
                WindowEnd = deadline;
                Console.WriteLine("    接收窗口: 全程 " + seconds + " 秒（全程应答均记为「窗口内」）");
            }

            var threads = new List<Thread>();

            foreach (var ni in nics)
            {
                var ua = ni.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                if (ua == null) continue;
                var niCap = ni;
                var ipCap = ua.Address;

                if (ProbeEnabled)
                {
                    var tp = new Thread(delegate () { RunProbes(niCap, ipCap, deadline); });
                    tp.IsBackground = true;
                    tp.Start();
                    threads.Add(tp);
                }

                if (admin)
                {
                    var tl = new Thread(delegate () { ListenOnNic(niCap, ipCap, deadline); });
                    tl.IsBackground = true;
                    tl.Start();
                    threads.Add(tl);
                }
            }

            if (admin)
            {
                Console.WriteLine("    在 " + nics.Count + " 块网卡上监听广播流量...");
                Console.WriteLine("    可发现: DHCP客户端/服务器、mDNS、SSDP、NetBIOS、LLMNR 及任意网段广播设备");
                Console.WriteLine("    注意: 交换网络中混杂模式仅对广播/组播有效，看不到其他主机之间的单播");
                Console.WriteLine();
            }

            bool windowNotice = false;
            while (DateTime.Now < deadline)
            {
                if (!windowNotice && RecvWindowSec > 0 && RecvWindowSec < seconds && DateTime.Now >= WindowEnd)
                {
                    windowNotice = true;
                    CWriteLine(ConsoleColor.Yellow, "    ── 主接收窗口结束，此后收到的回传将标为「延迟应答」 ──");
                }
                Thread.Sleep(200);
            }
            foreach (var t in threads) { try { t.Join(1500); } catch { } }

            // [W1] 延迟应答统计（窗口之后才现身的设备，仍计为存在）
            int lateCount = 0;
            lock (DevicesLock)
                lateCount = Devices.Values.Count(delegate (DeviceInfo d) { return d.LateReplies > 0 && !d.InWindow; });
            if (lateCount > 0)
                CWriteLine(ConsoleColor.Yellow, "[监听结论] 另有 " + lateCount + " 台设备在主接收窗口之后才应答（已记为存在，不算没有）。");

            // [F2] 监听收尾：对已发现设备做一次 OS 识别 SNMP 查询（-noosnmp 关闭）
            SnmpSweep();

            Console.WriteLine();
            int cc = ConflictCount;
            if (cc > 0)
            {
                CWriteLine(ConsoleColor.Red, "[冲突结论] 监听期间收到 " + cc + " 个以本机IP为源、且不属于本机的数据包，");
                lock (ConflictSamples)
                {
                    foreach (var s in ConflictSamples) CWriteLine(ConsoleColor.Red, "            样本: " + s);
                }
                CWriteLine(ConsoleColor.Red, "            → 局域网内存在与本机 IP 冲突的设备！");
            }
            else
            {
                CWriteLine(ConsoleColor.Green, "[冲突结论] 监听期间未发现 IP 冲突迹象。");
            }
        }

        // 单网卡的 raw socket 监听循环
        static void ListenOnNic(NetworkInterface ni, IPAddress localIp, DateTime deadline)
        {
            Socket raw = null;
            try
            {
                raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                raw.Bind(new IPEndPoint(localIp, 0));
                raw.IOControl((IOControlCode)SIO_RCVALL, new byte[] { 1, 0, 0, 0 }, null);
                raw.ReceiveTimeout = 500;
            }
            catch (Exception ex)
            {
                CWriteLine(ConsoleColor.Red, "[!] 网卡 [" + ni.Name + "] 无法开启监听: " + ex.Message);
                if (raw != null) { try { raw.Close(); } catch { } }
                return;
            }

            CWriteLine(ConsoleColor.Green, "    [监听] [" + ni.Name + "] " + localIp);

            byte[] buf = new byte[65535];
            while (DateTime.Now < deadline)
            {
                int n = 0;
                try
                {
                    if (raw.Poll(400000, SelectMode.SelectRead))
                        n = raw.Receive(buf);
                }
                catch (SocketException) { continue; }
                catch (ObjectDisposedException) { break; }
                if (n < 20) continue;
                try { ProcessPacket(buf, n); } catch { }
            }
            try { raw.Close(); } catch { }
        }

        // 单包解析（原监听循环主体，抽出以便多网卡复用）
        static void ProcessPacket(byte[] buf, int n)
        {
            int ihl = (buf[0] & 0x0F) * 4;
            if (ihl < 20 || ihl > n) return;
            int proto = buf[9];
            int ttl = buf[8];
            var src = new IPAddress(new byte[] { buf[12], buf[13], buf[14], buf[15] });
            var dst = new IPAddress(new byte[] { buf[16], buf[17], buf[18], buf[19] });
            string srcStr = src.ToString();

            // --- [P1] IP 冲突检测：以本机 IP 为源的陌生人流量 ---
            if (MyIps.Contains(srcStr))
            {
                if (IsOwnProbePacket(proto, buf, ihl, n)) return;   // 本工具诱探包

                int sp = 0, dp = 0;
                if (n >= ihl + 4)
                {
                    sp = buf[ihl] * 256 + buf[ihl + 1];
                    dp = buf[ihl + 2] * 256 + buf[ihl + 3];
                }

                // 本机自己的出站流量：查本机连接表确认
                if (proto == 6 && IsLocalOutbound(6, sp, dst.ToString(), dp)) return;
                if (proto == 17 && IsLocalOutbound(17, sp, dst.ToString(), dp)) return;
                // ICMP 无法与本机自身 ping 等活动区分，默认不计（-strict 打开）
                if (proto == 1 && !StrictConflict) return;

                Interlocked.Increment(ref ConflictCount);
                lock (ConflictSamples)
                {
                    if (ConflictSamples.Count < 5)
                        ConflictSamples.Enqueue(string.Format("协议{0} TTL={1} {2}:{3} → {4}:{5}",
                            proto, ttl, srcStr, sp, dst, dp));
                }
                if (ConflictCount <= 3)
                    CWriteLine(ConsoleColor.Red, "[冲突警报] 检测到其他设备正在使用本机IP " + srcStr + "！");
                return;
            }

            string tag = "";
            if (proto == 17 && n >= ihl + 8)
            {
                int sport = buf[ihl] * 256 + buf[ihl + 1];
                int dport = buf[ihl + 2] * 256 + buf[ihl + 3];
                if (sport == 67 || sport == 68 || dport == 67 || dport == 68)
                {
                    int pstart = ihl + 8;
                    if (n >= pstart + 240)
                    {
                        byte[] payload = new byte[n - pstart];
                        Array.Copy(buf, pstart, payload, 0, n - pstart);
                        var msg = ParseDhcpPayload(payload);
                        if (msg != null) HandleSniffedDhcp(msg, srcStr);
                    }
                    tag = "DHCP";
                }
                else if (dport == 5353 || sport == 5353) tag = "mDNS";
                else if (dport == 1900 || sport == 1900) tag = "SSDP/UPnP";
                else if (dport == 137 || sport == 137 || dport == 138) tag = "NetBIOS";
                else if (dport == 5355 || sport == 5355) tag = "LLMNR";     // [P5] 补充
                else tag = "UDP/" + dport;
            }
            else if (proto == 1) tag = "ICMP";
            else if (proto == 6 && n >= ihl + 4)
            {
                tag = "TCP/" + (buf[ihl + 2] * 256 + buf[ihl + 3]);
                // [F5] SYN-ACK 指纹：对发往本机的 SYN-ACK 记 TTL/窗口（管理员监听时可见）
                if (n >= ihl + 16)
                {
                    int tflags = buf[ihl + 13];
                    if ((tflags & 0x12) == 0x12 && MyIps.Contains(dst.ToString()))
                        RecordSynAckFingerprint(srcStr, ttl, buf[ihl + 14] * 256 + buf[ihl + 15]);
                }
            }
            else tag = "IP协议" + proto;

            bool isNew;
            lock (SeenSrc) { isNew = SeenSrc.Add(srcStr); }
            if (isNew)
            {
                AddDevice(srcStr, "被动监听", "", tag);
                CWriteLine(ConsoleColor.Green, "    [发现] " + srcStr.PadRight(16) + " " + tag);
            }
        }

        // =========================================================
        // 3b. 主动诱探（与被动监听并行，唤醒沉默设备）
        //     手段：子网 ARP 轮询（二层，屏蔽ICMP也逃不掉）
        //           + mDNS / SSDP / WSD / NetBIOS 广播查询
        // =========================================================
        static void RunProbes(NetworkInterface ni, IPAddress localIp, DateTime deadline)
        {
            uint net = 0; int bits = 0; bool hasSubnet = false;
            foreach (var u in ni.GetIPProperties().UnicastAddresses)
            {
                if (u.Address.AddressFamily != AddressFamily.InterNetwork || u.IPv4Mask == null) continue;
                uint mask = IpToUint(u.IPv4Mask);
                int b = 0; for (int i = 31; i >= 0; i--) { if ((mask & (1u << i)) != 0) b++; else break; }
                if (b >= 8 && b <= 30) { net = IpToUint(u.Address) & mask; bits = b; hasSubnet = true; break; }
            }

            CWriteLine(ConsoleColor.Gray, "    [诱探] [" + ni.Name + "] 开始主动诱探（ARP轮询 + mDNS/SSDP/WSD/NetBIOS 广播查询）");

            while (DateTime.Now < deadline)
            {
                try { BroadcastQueries(); } catch { }
                if (hasSubnet && DateTime.Now < deadline)
                    ArpSweepQuiet(localIp, net, bits);
                if (DateTime.Now >= deadline) break;
                Thread.Sleep(200);
            }
        }

        // 静默 ARP 轮询：发现新设备时记录并输出
        // [P4] SrcIP 传本网卡地址，避免多网卡/多网段时系统路由选错网卡
        static void ArpSweepQuiet(IPAddress localIp, uint network, int bits)
        {
            var hosts = EnumHosts(network, bits);
            if (hosts.Count > 4094) return;
            uint srcNetOrder = ToNetOrder(IpToUint(localIp));
            Parallel.ForEach(hosts, new ParallelOptions { MaxDegreeOfParallelism = 32 }, host =>
            {
                try
                {
                    byte[] mac = new byte[6]; uint macLen = 6;
                    if (SendARP(ToNetOrder(host), srcNetOrder, mac, ref macLen) == 0)
                    {
                        string ipStr = UintToIp(host).ToString();
                        if (MyIps.Contains(ipStr)) return;
                        bool isNew;
                        lock (SeenSrc) { isNew = SeenSrc.Add(ipStr); }
                        if (isNew)
                        {
                            AddDevice(ipStr, "主动诱探", BytesToMac(mac, (int)macLen), "ARP轮询");
                            CWriteLine(ConsoleColor.Green, "    [诱探发现] " + ipStr.PadRight(16) + " ARP轮询");
                        }
                    }
                }
                catch { }
            });
        }

        // [W2] 单轮收包预算：四个查询并行发出，各收 1 秒
        const int ProbeRecvBudgetMs = 1000;

        // 发一轮多播/广播服务查询（并行，一轮约 1 秒；原串行版约 11 秒）
        static void BroadcastQueries()
        {
            var workers = new List<Thread>();
            workers.Add(StartQueryThread(delegate () { QueryMdns(); }));
            workers.Add(StartQueryThread(delegate () { QuerySsdp(); }));
            workers.Add(StartQueryThread(delegate () { QueryWsd(); }));
            workers.Add(StartQueryThread(delegate () { QueryNbns(); }));
            foreach (var t in workers) { try { t.Join(ProbeRecvBudgetMs + 800); } catch { } }
        }

        static Thread StartQueryThread(ThreadStart body)
        {
            var t = new Thread(body);
            t.IsBackground = true;
            t.Start();
            return t;
        }

        // --- mDNS: 枚举所有注册服务（AirPlay/Chromecast/打印机/多数智能家居都会应答）---
        static void QueryMdns()
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, false);
                    s.ReceiveTimeout = ProbeRecvBudgetMs;
                    byte[] q = BuildMdnsServiceEnumQuery();
                    s.SendTo(q, new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353));
                    CollectProbeReplies(s, ProbeRecvBudgetMs, "mDNS应答", ReplyKind.Mdns);
                }
            }
            catch { }
        }

        // --- SSDP M-SEARCH: UPnP 设备（路由器、电视、NAS、ONVIF摄像头）---
        static void QuerySsdp()
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, false);
                    s.ReceiveTimeout = ProbeRecvBudgetMs;
                    byte[] q = Encoding.ASCII.GetBytes(
                        "M-SEARCH * HTTP/1.1\r\n" +
                        "HOST: 239.255.255.250:1900\r\n" +
                        "MAN: \"ssdp:discover\"\r\n" +
                        "MX: 2\r\n" +
                        "ST: ssdp:all\r\n\r\n");
                    s.SendTo(q, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900));
                    CollectProbeReplies(s, ProbeRecvBudgetMs, "SSDP/UPnP应答", ReplyKind.Ssdp);
                }
            }
            catch { }
        }

        // --- WS-Discovery: Windows 网络发现协议（屏蔽ping的Windows设备通常会答）---
        static void QueryWsd()
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, false);
                    s.ReceiveTimeout = ProbeRecvBudgetMs;
                    byte[] q = Encoding.UTF8.GetBytes(BuildWsdProbeSoap());
                    s.SendTo(q, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 3702));
                    CollectProbeReplies(s, ProbeRecvBudgetMs, "WSD应答", ReplyKind.Unknown);
                }
            }
            catch { }
        }

        // --- NetBIOS 通配名称查询：老式Windows/SMB设备 ---
        static void QueryNbns()
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.EnableBroadcast = true;
                    s.ReceiveTimeout = ProbeRecvBudgetMs;
                    byte[] q = BuildNbnsWildcardQuery();
                    s.SendTo(q, new IPEndPoint(IPAddress.Broadcast, 137));
                    CollectProbeReplies(s, ProbeRecvBudgetMs, "NetBIOS应答", ReplyKind.Unknown);
                }
            }
            catch { }
        }

        enum ReplyKind { Unknown, Mdns, Ssdp }

        // 收取查询回应，把新出现的源记录为设备；[P5] 解析应答内容
        static void CollectProbeReplies(Socket s, int budgetMs, string tag, ReplyKind kind)
        {
            byte[] buf = new byte[4096];
            DateTime until = DateTime.Now.AddMilliseconds(budgetMs);
            while (DateTime.Now < until)
            {
                try
                {
                    if (!s.Poll(200000, SelectMode.SelectRead)) continue;
                    EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                    int n = s.ReceiveFrom(buf, ref ep);
                    if (n <= 0) continue;
                    var rep = (IPEndPoint)ep;
                    string ipStr = rep.Address.ToString();
                    if (MyIps.Contains(ipStr)) continue;

                    bool isNew;
                    lock (SeenSrc) { isNew = SeenSrc.Add(ipStr); }
                    if (isNew)
                    {
                        AddDevice(ipStr, "主动诱探", "", tag);
                        CWriteLine(ConsoleColor.Green, "    [诱探发现] " + ipStr.PadRight(16) + " " + tag);
                    }

                    // [P5] 解析内容，提取服务/型号线索
                    if (kind == ReplyKind.Mdns) HandleMdnsReply(ipStr, buf, n);
                    else if (kind == ReplyKind.Ssdp) HandleSsdpReply(ipStr, buf, n);
                }
                catch (SocketException) { continue; }
                catch (ObjectDisposedException) { break; }
            }
        }

        // [P5] mDNS 应答：提取 PTR/SRV 的服务类型，映射为设备类型
        static void HandleMdnsReply(string ipStr, byte[] buf, int n)
        {
            try
            {
                if (n < 12) return;
                int qd = (buf[4] << 8) | buf[5];
                int an = (buf[6] << 8) | buf[7];
                if (an <= 0) return;
                int idx = 12;
                for (int i = 0; i < qd && idx < n; i++) { ReadDnsName(buf, n, ref idx); idx += 4; }
                for (int i = 0; i < an && idx < n; i++)
                {
                    ReadDnsName(buf, n, ref idx);   // 记录名（此处只需推进游标）
                    if (idx + 10 > n) return;
                    int type = (buf[idx] << 8) | buf[idx + 1];
                    int rdlen = (buf[idx + 8] << 8) | buf[idx + 9];
                    idx += 10;
                    if (idx + rdlen > n) return;
                    if (type == 12)                                  // PTR：服务类型
                    {
                        int save = idx;
                        string target = ReadDnsName(buf, n, ref idx);
                        idx = save + rdlen;
                        string hint = ServiceHint(target);
                        if (hint != "") AddService(ipStr, hint);
                    }
                    else if (type == 16)                             // TXT：设备型号/名称
                    {
                        string txt = ExtractTxtRecord(buf, idx, rdlen);
                        if (txt != "") AddService(ipStr, txt);
                        idx += rdlen;
                    }
                    else idx += rdlen;
                }
            }
            catch { }
        }

        static string ExtractTxtRecord(byte[] buf, int start, int len)
        {
            try
            {
                int idx = start;
                int end = start + len;
                while (idx < end)
                {
                    int l = buf[idx];
                    if (l <= 0 || idx + 1 + l > end) break;
                    string kv = Encoding.UTF8.GetString(buf, idx + 1, l);
                    idx += 1 + l;
                    // 只挑有信息量的键
                    string lower = kv.ToLowerInvariant();
                    if (lower.StartsWith("model=") || lower.StartsWith("ty=") || lower.StartsWith("md="))
                        return kv;
                }
            }
            catch { }
            return "";
        }

        // DNS 名读取，处理 0xC0 压缩指针
        static string ReadDnsName(byte[] buf, int n, ref int idx)
        {
            var sb = new StringBuilder();
            int guard = 0;
            int cur = idx;
            bool jumped = false;
            while (cur < n && guard++ < 128)
            {
                int len = buf[cur];
                if (len == 0) { cur++; break; }
                if ((len & 0xC0) == 0xC0)
                {
                    if (cur + 1 >= n) break;
                    int ptr = ((len & 0x3F) << 8) | buf[cur + 1];
                    if (!jumped) { idx = cur + 2; jumped = true; }
                    if (ptr >= cur) break;   // 只允许向前压缩，防止死循环
                    cur = ptr;
                    continue;
                }
                if (cur + 1 + len > n) break;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(buf, cur + 1, len));
                cur += 1 + len;
            }
            if (!jumped) idx = cur;
            return sb.ToString();
        }

        // 服务类型 → 中文设备类型
        static string ServiceHint(string svc)
        {
            if (string.IsNullOrEmpty(svc)) return "";
            string s = svc.ToLowerInvariant();
            if (s.Contains("_rtsp")) return "RTSP视频流(疑似摄像头/图传)";
            if (s.Contains("_onvif")) return "ONVIF摄像头";
            if (s.Contains("_googlecast")) return "Chromecast投屏";
            if (s.Contains("_airplay")) return "AirPlay";
            if (s.Contains("_raop")) return "AirPlay音频";
            if (s.Contains("_ipp") || s.Contains("_printer") || s.Contains("_pdl-datastream")) return "打印机";
            if (s.Contains("_smb") || s.Contains("_adisk") || s.Contains("_afpovertcp")) return "文件共享";
            if (s.Contains("_ssh")) return "SSH服务";
            if (s.Contains("_rfb") || s.Contains("_rdlink")) return "远程桌面";
            if (s.Contains("_hap")) return "HomeKit设备";
            if (s.Contains("_spotify")) return "Spotify";
            if (s.Contains("_device-info") || s.Contains("_workstation")) return "苹果设备";
            if (s.Contains("_companion-link") || s.Contains("_sleep-proxy")) return "苹果设备";
            if (s.Contains("_http")) return "HTTP服务";
            if (s.Contains("_sftp")) return "SFTP服务";
            return "";
        }

        // [P5] SSDP 应答：SERVER / LOCATION 字段含设备型号与描述地址
        static void HandleSsdpReply(string ipStr, byte[] buf, int n)
        {
            try
            {
                string txt = Encoding.ASCII.GetString(buf, 0, Math.Min(n, 2048));
                string server = ExtractHeader(txt, "SERVER:");
                string st = ExtractHeader(txt, "ST:");
                if (server != "") AddService(ipStr, "UPnP: " + Trunc(server, 60));
                if (st != "")
                {
                    string hint = ServiceHint(st);
                    if (hint != "") AddService(ipStr, hint);
                }
            }
            catch { }
        }

        static string ExtractHeader(string txt, string key)
        {
            try
            {
                int i = 0;
                while (i < txt.Length)
                {
                    int e = txt.IndexOf("\r\n", i);
                    if (e < 0) e = txt.Length;
                    string line = txt.Substring(i, e - i).Trim();
                    if (line.ToUpperInvariant().StartsWith(key))
                        return line.Substring(key.Length).Trim();
                    i = e + 2;
                    if (e >= txt.Length) break;
                }
            }
            catch { }
            return "";
        }

        // mDNS 查询 "_services._dns-sd._udp.local" PTR（服务枚举，应答面最广）
        static byte[] BuildMdnsServiceEnumQuery()
        {
            var ms = new MemoryStream();
            var hdr = new byte[] { 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 }; // ID=0 flags=0 QD=1
            ms.Write(hdr, 0, hdr.Length);
            string[] labels = { "_services", "_dns-sd", "_udp", "local" };
            foreach (var lb in labels)
            {
                byte[] b = Encoding.ASCII.GetBytes(lb);
                ms.WriteByte((byte)b.Length);
                ms.Write(b, 0, b.Length);
            }
            ms.WriteByte(0);
            var tail = new byte[] { 0x00, 0x0C, 0x00, 0x01 }; // QTYPE=PTR QCLASS=IN
            ms.Write(tail, 0, tail.Length);
            return ms.ToArray();
        }

        // WS-Discovery Probe SOAP 报文
        static string BuildWsdProbeSoap()
        {
            return "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
                "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
                "xmlns:tns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">" +
                "<soap:Header>" +
                "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>" +
                "<wsa:MessageID>urn:uuid:" + Guid.NewGuid().ToString() + "</wsa:MessageID>" +
                "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>" +
                "</soap:Header>" +
                "<soap:Body><tns:Probe/></soap:Body>" +
                "</soap:Envelope>";
        }

        // NetBIOS 通配名称查询（NB, type=0x21）
        static byte[] BuildNbnsWildcardQuery()
        {
            byte[] q = new byte[50];
            q[0] = 0x2A; q[1] = 0x2A;       // TxID
            q[2] = 0x01; q[3] = 0x10;       // flags: RD
            q[5] = 0x01;                    // QDCOUNT=1
            q[12] = 0x20;                   // 名称长度32
            string name = "CK" + new string('A', 30); // 通配名
            for (int i = 0; i < 32; i++) q[13 + i] = (byte)name[i];
            q[45] = 0x00;
            q[46] = 0x00; q[47] = 0x21;     // QTYPE=NB
            q[48] = 0x00; q[49] = 0x01;     // QCLASS=IN
            return q;
        }

        // 判断是否为本工具自己发出的诱探查询包（防误报冲突的第一道快速筛选）
        static bool IsOwnProbePacket(int proto, byte[] buf, int ihl, int n)
        {
            if (proto != 17 || n < ihl + 8) return false;
            int dport = buf[ihl + 2] * 256 + buf[ihl + 3];
            return dport == 5353 || dport == 1900 || dport == 3702 || dport == 137;
        }

        static NetworkInterface PickMainInterface()
        {
            NetworkInterface best = null;
            foreach (var ni in GetActiveNics())
            {
                bool hasGw = ni.GetIPProperties().GatewayAddresses
                    .Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                if (hasGw) return ni;   // 优先有网关的主网卡
                if (best == null) best = ni;
            }
            return best;
        }

        // 活动且带 IPv4 的网卡（编号与 list 命令输出一致）
        static List<NetworkInterface> GetActiveNics()
        {
            var r = new List<NetworkInterface>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                bool hasIpv4 = ni.GetIPProperties().UnicastAddresses
                    .Any(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                if (!hasIpv4) continue;
                r.Add(ni);
            }
            return r;
        }

        // 按编号（list 中的 [n]）或名称/描述解析网卡
        static NetworkInterface ResolveNic(string spec)
        {
            var nics = GetActiveNics();
            int idx;
            if (int.TryParse(spec, out idx))
            {
                if (idx >= 1 && idx <= nics.Count) return nics[idx - 1];
                return null;
            }
            foreach (var ni in nics)
                if (ni.Name.Equals(spec, StringComparison.OrdinalIgnoreCase)
                    || ni.Id.Equals(spec, StringComparison.OrdinalIgnoreCase))
                    return ni;
            foreach (var ni in nics)
                if (ni.Name.IndexOf(spec, StringComparison.OrdinalIgnoreCase) >= 0
                    || ni.Description.IndexOf(spec, StringComparison.OrdinalIgnoreCase) >= 0)
                    return ni;
            return null;
        }

        static void PrintNicChoices()
        {
            var nics = GetActiveNics();
            for (int i = 0; i < nics.Count; i++)
            {
                var ni = nics[i];
                var ips = ni.GetIPProperties().UnicastAddresses
                    .Where(x => x.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(x => x.Address.ToString());
                Console.WriteLine(string.Format("    [{0}] {1} ({2})  IP: {3}",
                    i + 1, ni.Name, ni.NetworkInterfaceType, string.Join(",", ips.ToArray())));
            }
            if (nics.Count == 0) Console.WriteLine("    (未发现活动的 IPv4 网卡)");
        }

        // 交互菜单中询问使用哪块网卡（回车=自动选主网卡）
        static string AskNicSpec()
        {
            Console.WriteLine();
            Console.WriteLine("    可用网卡（输入编号或名称，直接回车 = 全部监听）:");
            PrintNicChoices();
            Console.Write("    监听网卡> ");
            string s;
            try { s = Console.ReadLine(); } catch { return null; }
            if (s == null) return null;
            s = s.Trim();
            return s == "" ? null : s;
        }

        static void HandleSniffedDhcp(DhcpMsg msg, string srcIp)
        {
            string mac = msg.ClientMac;
            switch (msg.MsgType)
            {
                case 1: // Discover（客户端寻找服务器 → 陌生DHCP客户端现身）
                    CWriteLine(ConsoleColor.Magenta, "    [DHCP] 客户端 Discover: MAC=" + mac + "（正在申请IP的设备）");
                    if (mac != "") AddDevice("0.0.0.0?" + mac, "DHCP监听", mac, "DHCP Discover 客户端");
                    break;
                case 2: // Offer
                    CWriteLine(ConsoleColor.Magenta, "    [DHCP] 服务器 Offer: 服务器=" + (msg.ServerId != "" ? msg.ServerId : srcIp)
                        + " 拟分配IP=" + msg.YourIp + (msg.Mask != "" ? " 掩码=" + msg.Mask : ""));
                    AddDevice(msg.ServerId != "" ? msg.ServerId : srcIp, "DHCP监听", "", "DHCP服务器(Offer)");
                    break;
                case 3: // Request
                    CWriteLine(ConsoleColor.Magenta, "    [DHCP] 客户端 Request: MAC=" + mac + " 请求IP=" + msg.YourIp);
                    if (msg.YourIp != "" && msg.YourIp != "0.0.0.0")
                        AddDevice(msg.YourIp, "DHCP监听", mac, "DHCP Request 客户端");
                    break;
                case 5: // ACK（权威记录：MAC ↔ 分配IP）
                    CWriteLine(ConsoleColor.Magenta, "    [DHCP] 服务器 ACK: 分配 " + msg.YourIp + " → MAC=" + mac);
                    if (msg.YourIp != "" && msg.YourIp != "0.0.0.0")
                        AddDevice(msg.YourIp, "DHCP监听", mac, "DHCP服务器分配的客户端");
                    break;
            }
        }

        // =========================================================
        // 4. DHCP 服务器探测
        // =========================================================
        static void DhcpDiscover(int seconds)
        {
            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "─── DHCP 服务器探测（等待 " + seconds + " 秒）───");
            var ni = PickMainInterface();
            if (ni == null) { CWriteLine(ConsoleColor.Yellow, "[!] 未找到活动网卡"); return; }
            byte[] myMac = ni.GetPhysicalAddress().GetAddressBytes();

            byte[] pkt = BuildDhcpDiscover(myMac);
            Socket s = null;
            bool bound68 = false;
            try
            {
                s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                try { s.Bind(new IPEndPoint(IPAddress.Any, 68)); bound68 = true; }
                catch { s.Bind(new IPEndPoint(IPAddress.Any, 0)); }
                s.EnableBroadcast = true;
                s.ReceiveTimeout = 500;
            }
            catch (Exception ex)
            {
                CWriteLine(ConsoleColor.Red, "[!] 创建套接字失败: " + ex.Message);
                return;
            }

            var target = new IPEndPoint(IPAddress.Broadcast, 67);
            try { s.SendTo(pkt, target); }
            catch (Exception ex)
            {
                CWriteLine(ConsoleColor.Red, "[!] 发送 DHCP Discover 失败: " + ex.Message);
                s.Close();
                return;
            }
            Console.WriteLine("    已广播 DHCP Discover（MAC=" + BytesToMac(myMac, 6) + "）"
                + (bound68 ? "" : "  [注:68端口被占用，OFFER可能无法直接收到，可配合 listen 模式]"));

            byte[] buf = new byte[2048];
            DateTime deadline = DateTime.Now.AddSeconds(seconds);
            bool found = false;
            int sent = 1;
            DateTime nextResend = DateTime.Now.AddSeconds(5);
            var seenServers = new HashSet<string>();
            while (DateTime.Now < deadline)
            {
                // 每5秒重发一次（最多3次）
                if (sent < 3 && DateTime.Now >= nextResend)
                {
                    try { s.SendTo(pkt, target); } catch { }
                    sent++;
                    nextResend = DateTime.Now.AddSeconds(5);
                }
                try
                {
                    if (!s.Poll(400000, SelectMode.SelectRead)) continue;
                    int n = s.Receive(buf);
                    if (n < 240) continue;
                    byte[] payload = new byte[n];
                    Array.Copy(buf, payload, n);
                    var msg = ParseDhcpPayload(payload);
                    if (msg == null || msg.Op != 2 || msg.MsgType != 2) continue;
                    found = true;
                    string server = msg.ServerId != "" ? msg.ServerId : msg.ServerIp;
                    if (!seenServers.Add(server)) continue; // 同一服务器重复Offer去重
                    CWriteLine(ConsoleColor.Green, "    [发现] DHCP 服务器: " + server);
                    Console.WriteLine("           拟分配IP : " + msg.YourIp);
                    if (msg.Mask != "") Console.WriteLine("           子网掩码 : " + msg.Mask);
                    if (msg.Router != "") Console.WriteLine("           默认网关 : " + msg.Router);
                    if (msg.Dns != "") Console.WriteLine("           DNS      : " + msg.Dns);
                    if (msg.Lease > 0) Console.WriteLine("           租约     : " + msg.Lease + " 秒");
                    AddDevice(server, "DHCP探测", "", "DHCP服务器");
                }
                catch (SocketException) { continue; }
            }
            s.Close();
            if (!found)
                CWriteLine(ConsoleColor.Yellow, "    未收到 DHCP Offer。可能原因: 本网段无DHCP服务器、服务器未响应广播，");
            if (!found)
                CWriteLine(ConsoleColor.Yellow, "    或回复被系统DHCP客户端截获。可尝试 listen 模式被动观察。");
        }

        static byte[] BuildDhcpDiscover(byte[] mac)
        {
            byte[] p = new byte[300]; // 全零填充，BOOTP/DHCP 最小长度
            var rnd = new Random();
            rnd.NextBytes(p); int xid = rnd.Next();
            Array.Clear(p, 0, p.Length);
            p[0] = 1;      // op: BOOTREQUEST
            p[1] = 1;      // htype: Ethernet
            p[2] = 6;      // hlen: MAC 长度
            p[3] = 0;      // hops
            p[4] = (byte)(xid >> 24); p[5] = (byte)(xid >> 16);
            p[6] = (byte)(xid >> 8); p[7] = (byte)xid;
            // secs[8..9] = 0
            p[10] = 0x80; p[11] = 0x00; // flags: 广播位
            // ciaddr/yiaddr/siaddr/giaddr [12..27] 保持 0
            // chaddr
            for (int i = 0; i < 6 && i < mac.Length; i++) p[28 + i] = mac[i];
            // sname[64..127]、file[128..235] 保持 0
            // magic cookie
            p[236] = 99; p[237] = 130; p[238] = 83; p[239] = 99;
            int i2 = 240;
            // option 53: DHCP Discover
            p[i2++] = 53; p[i2++] = 1; p[i2++] = 1;
            // option 61: client id
            p[i2++] = 61; p[i2++] = 7; p[i2++] = 1;
            for (int i = 0; i < 6 && i < mac.Length; i++) p[i2++] = mac[i];
            // option 12: hostname
            byte[] hn = Encoding.ASCII.GetBytes("lanscan");
            p[i2++] = 12; p[i2++] = (byte)hn.Length;
            foreach (var b in hn) p[i2++] = b;
            // option 55: parameter request list
            p[i2++] = 55; p[i2++] = 4; p[i2++] = 1; p[i2++] = 3; p[i2++] = 6; p[i2++] = 15;
            // option 255: end（其余保持 pad=0）
            p[i2++] = 255;
            return p;
        }

        static DhcpMsg ParseDhcpPayload(byte[] p)
        {
            if (p == null || p.Length < 240) return null;
            if (p[236] != 99 || p[237] != 130 || p[238] != 83 || p[239] != 99) return null;
            var m = new DhcpMsg();
            m.Op = p[0];
            m.YourIp = new IPAddress(new byte[] { p[16], p[17], p[18], p[19] }).ToString();
            m.ServerIp = new IPAddress(new byte[] { p[20], p[21], p[22], p[23] }).ToString();
            byte[] cm = new byte[6]; Array.Copy(p, 28, cm, 0, 6);
            m.ClientMac = BytesToMac(cm, 6);
            int i = 240;
            while (i + 1 < p.Length)
            {
                byte opt = p[i];
                if (opt == 255) break;
                if (opt == 0) { i++; continue; }
                int len = p[i + 1];
                if (i + 2 + len > p.Length) break;
                switch (opt)
                {
                    case 53: if (len >= 1) m.MsgType = p[i + 2]; break;
                    case 54: if (len >= 4) m.ServerId = new IPAddress(new byte[] { p[i + 2], p[i + 3], p[i + 4], p[i + 5] }).ToString(); break;
                    case 1: if (len >= 4) m.Mask = new IPAddress(new byte[] { p[i + 2], p[i + 3], p[i + 4], p[i + 5] }).ToString(); break;
                    case 3: if (len >= 4) m.Router = new IPAddress(new byte[] { p[i + 2], p[i + 3], p[i + 4], p[i + 5] }).ToString(); break;
                    case 6: if (len >= 4) m.Dns = new IPAddress(new byte[] { p[i + 2], p[i + 3], p[i + 4], p[i + 5] }).ToString(); break;
                    case 51: if (len >= 4) m.Lease = (uint)((p[i + 2] << 24) | (p[i + 3] << 16) | (p[i + 4] << 8) | p[i + 5]); break;
                    case 12: m.HostName = Encoding.ASCII.GetString(p, i + 2, len).Trim(); break;
                }
                i += 2 + len;
            }
            return m;
        }

        // =========================================================
        // 5. IP 冲突检测
        // =========================================================
        static void ConflictCheck(int seconds)
        {
            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "─── 本机 IP 冲突检测 ───");
            Console.WriteLine("    本机 IPv4 地址: " + string.Join(", ", MyIps.ToArray()));
            Console.WriteLine();

            // 方法1: 被动监听（管理员）
            if (IsAdmin())
            {
                Console.WriteLine("    [步骤1] 被动监听 " + seconds + " 秒，捕捉以本机IP为源的陌生流量...");
                PassiveListen(seconds, null);
            }
            else
            {
                CWriteLine(ConsoleColor.Yellow, "    [步骤1] 跳过被动监听（需管理员权限）");
            }

            // 方法2: 检查 ARP 缓存中本机IP对应的 MAC（最可靠的一条证据）
            Console.WriteLine();
            Console.WriteLine("    [步骤2] 检查 ARP 缓存中本机 IP 的 MAC 记录...");
            bool arpConflict = false;
            try
            {
                int size = 0;
                GetIpNetTable(IntPtr.Zero, ref size, false);
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetIpNetTable(buf, ref size, false) == 0)
                    {
                        int count = Marshal.ReadInt32(buf);
                        for (int i = 0; i < count; i++)
                        {
                            IntPtr row = new IntPtr(buf.ToInt64() + 4 + i * 24);
                            byte[] ab = new byte[] {
                                Marshal.ReadByte(row,16), Marshal.ReadByte(row,17),
                                Marshal.ReadByte(row,18), Marshal.ReadByte(row,19) };
                            string ip = new IPAddress(ab).ToString();
                            if (!MyIps.Contains(ip)) continue;
                            int macLen = Marshal.ReadInt32(row, 4);
                            byte[] mac = new byte[macLen];
                            for (int j = 0; j < macLen && j < 8; j++) mac[j] = Marshal.ReadByte(row, 8 + j);
                            string macStr = BytesToMac(mac, macLen);
                            // 与本机网卡 MAC 比对
                            bool matchSelf = false;
                            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                            {
                                if (BytesToMac(ni.GetPhysicalAddress().GetAddressBytes(), 6) == macStr)
                                { matchSelf = true; break; }
                            }
                            if (!matchSelf)
                            {
                                arpConflict = true;
                                CWriteLine(ConsoleColor.Red, "    [ARP冲突] IP " + ip + " 在ARP缓存中对应 MAC " + macStr + "，不是本机网卡！");
                            }
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            catch { }

            Console.WriteLine();
            if (arpConflict)
                CWriteLine(ConsoleColor.Red, "[结论] 确认存在 IP 冲突（ARP 证据），上方 MAC 即冲突设备。");
            else
                CWriteLine(ConsoleColor.Green, "[结论] ARP 缓存未发现冲突证据（若监听阶段有冲突警报，则以警报为准）。");
            if (!StrictConflict)
                Console.WriteLine("    说明: 默认模式下 ICMP 类流量不计入冲突（无法与本机自身活动区分），如需更激进判定可加 -strict。");
        }

        // =========================================================
        // 6. 跨网段辅助IP扫描
        // =========================================================
        static void ScanWithAlias(string cidr, string positionalCidr)
        {
            string target = positionalCidr != null ? positionalCidr : cidr;
            uint net; int bits;
            if (!ParseCidr(target, out net, out bits))
            {
                CWriteLine(ConsoleColor.Red, "[!] 网段格式错误: " + target);
                return;
            }
            if (!IsAdmin())
            {
                CWriteLine(ConsoleColor.Red, "[!] 跨网段辅助IP扫描需要管理员权限，请右键-以管理员身份运行。");
                return;
            }
            var ni = PickMainInterface();
            if (ni == null) { CWriteLine(ConsoleColor.Yellow, "[!] 未找到活动网卡"); return; }

            // 选辅助IP：网段内第200个主机地址（不足则第2个）
            var hosts = EnumHosts(net, bits);
            if (hosts.Count == 0) { CWriteLine(ConsoleColor.Red, "[!] 网段内无可用主机地址"); return; }
            uint aliasUint = hosts.Count > 200 ? hosts[199] : hosts[hosts.Count - 1];
            string aliasIp = UintToIp(aliasUint).ToString();
            string maskStr = UintToIp(bits >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - bits)) & 0xFFFFFFFFu).ToString();

            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "─── 跨网段扫描（辅助IP模式）───");
            Console.WriteLine("    网卡     : " + ni.Name);
            Console.WriteLine("    目标网段 : " + UintToIp(net) + "/" + bits);
            Console.WriteLine("    辅助IP   : " + aliasIp + "（临时添加，扫描后自动删除）");

            string outMsg;
            int rc = RunNetsh("interface ipv4 add address \"" + ni.Name + "\" " + aliasIp + " " + maskStr, out outMsg);
            if (rc != 0)
            {
                CWriteLine(ConsoleColor.Red, "[!] 添加辅助IP失败: " + outMsg.Trim());
                CWriteLine(ConsoleColor.Yellow, "    （若目标网段与现有地址段重叠，Windows 会拒绝添加）");
                return;
            }
            Thread.Sleep(1500);
            try
            {
                ActiveScan(net, bits, "跨网段 " + UintToIp(net) + "/" + bits);
                MergeArpTable(net, bits);
            }
            finally
            {
                RunNetsh("interface ipv4 delete address \"" + ni.Name + "\" " + aliasIp, out outMsg);
                Console.WriteLine("    已移除辅助IP " + aliasIp);
            }
            ResolveNames();
        }

        static int RunNetsh(string args, out string output)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh", args);
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                psi.StandardOutputEncoding = Encoding.Default;
                var p = Process.Start(psi);
                string o = p.StandardOutput.ReadToEnd();
                string e = p.StandardError.ReadToEnd();
                if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } }
                output = o + e;
                return p.ExitCode;
            }
            catch (Exception ex) { output = ex.Message; return -1; }
        }

        // =========================================================
        // 7. 完整扫描
        // =========================================================
        static void FullScan(int listenSeconds, string aliasCidr)
        {
            FullScan(listenSeconds, aliasCidr, null);
        }

        static void FullScan(int listenSeconds, string aliasCidr, string nicSpec)
        {
            ListAdapters();
            ScanAllLocalSubnets();
            if (aliasCidr != null) ScanWithAlias(aliasCidr, null);
            if (IsAdmin())
            {
                PassiveListen(listenSeconds, nicSpec);
                DhcpDiscover(10);
            }
            else
            {
                CWriteLine(ConsoleColor.Yellow, "[提示] 当前非管理员权限，跳过被动监听与DHCP探测（建议以管理员身份重跑获取完整结果）");
            }
            ResolveNames();
        }

        // =========================================================
        // 8. 主机名解析（DNS反向 + NetBIOS）
        // =========================================================
        static void ResolveNames()
        {
            List<DeviceInfo> targets;
            lock (DevicesLock)
            {
                targets = Devices.Values
                    .Where(d => !d.Ip.Contains("?") && d.Hostname == "")
                    .Take(200).ToList();
            }
            if (targets.Count == 0) return;
            Console.WriteLine();
            Console.WriteLine("    正在解析主机名（" + targets.Count + " 台设备）...");
            Parallel.ForEach(targets, new ParallelOptions { MaxDegreeOfParallelism = 32 }, d =>
            {
                string nb = NbStat(d.Ip);
                string dns = "";
                if (nb == "") dns = ReverseDns(d.Ip);
                string name = nb != "" ? nb : dns;
                if (name != "")
                {
                    lock (DevicesLock) d.Hostname = name;
                    if (nb != "")
                    {
                        lock (DevicesLock)
                        {
                            if (!d.Sources.Contains("NetBIOS")) d.Sources.Add("NetBIOS");
                        }
                    }
                }
            });
        }

        static string ReverseDns(string ip)
        {
            try
            {
                IPAddress addr = IPAddress.Parse(ip);
                IAsyncResult ar = Dns.BeginGetHostEntry(addr, null, null);
                if (ar.AsyncWaitHandle.WaitOne(800))
                {
                    try
                    {
                        IPHostEntry e = Dns.EndGetHostEntry(ar);
                        if (e != null) return e.HostName;
                    }
                    catch { }
                }
                else
                {
                    // [P8] 超时：交给线程池收尾，避免异步句柄泄漏
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try { Dns.EndGetHostEntry(ar); } catch { }
                    });
                }
            }
            catch { }
            return "";
        }

        static string NbStat(string ip)
        {
            try
            {
                byte[] q = new byte[50];
                q[0] = 0x12; q[1] = 0x34;
                q[4] = 0x00; q[5] = 0x01;
                q[12] = 0x20;
                string name = "CK" + new string('A', 30);
                for (int i = 0; i < 32; i++) q[13 + i] = (byte)name[i];
                q[45] = 0x00;
                q[46] = 0x00; q[47] = 0x21;
                q[48] = 0x00; q[49] = 0x01;

                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.ReceiveTimeout = 500;
                    s.SendTo(q, new IPEndPoint(IPAddress.Parse(ip), 137));
                    byte[] buf = new byte[1024];
                    if (!s.Poll(450000, SelectMode.SelectRead)) return "";
                    int n = s.Receive(buf);
                    return ParseNbStat(buf, n);
                }
            }
            catch { return ""; }
        }

        static string ParseNbStat(byte[] q, int n)
        {
            try
            {
                if (n < 60) return "";
                int idx = 12;
                if ((q[idx] & 0xC0) == 0xC0) idx += 2;
                else { int len = q[idx]; idx += len + 1; }
                idx += 4; // qtype+qclass
                if (idx >= n) return "";
                if ((q[idx] & 0xC0) == 0xC0) idx += 2;
                else { int len = q[idx]; idx += len + 1; }
                idx += 2 + 2 + 4; // type class ttl
                if (idx + 2 > n) return "";
                idx += 2; // rdlength
                if (idx >= n) return "";
                int nameCount = q[idx]; idx++;
                if (nameCount <= 0 || nameCount > 30) return "";
                for (int k = 0; k < nameCount; k++)
                {
                    if (idx + 18 > n) return "";
                    string nm = Encoding.ASCII.GetString(q, idx, 15).Trim();
                    byte flags = q[idx + 15];
                    idx += 18;
                    // 第一个非组名（flags 低位非 group）且非空的名字通常是计算机名
                    if (nm != "" && nm != "__MSBROWSE__" && (flags & 0x80) == 0)
                        return nm;
                }
            }
            catch { }
            return "";
        }

        // =========================================================
        // 9. 结果输出 / 导出
        // =========================================================
        static void PrintResults()
        {
            List<DeviceInfo> list;
            lock (DevicesLock)
            {
                list = Devices.Values
                    .Where(d => !d.Ip.Contains("?"))
                    .OrderBy(d => IpToUint(IPAddress.Parse(d.Ip))).ToList();
            }
            Console.WriteLine();
            CWriteLine(ConsoleColor.Cyan, "═══════════════ 发现结果汇总（共 " + list.Count + " 台设备）═══════════════");
            if (list.Count == 0)
            {
                Console.WriteLine("  （未发现设备）");
                PrintSnmpOnly();
                if (SnmpCommunity != null)
                    CWriteLine(ConsoleColor.Gray, "  【判定口径】交换机转发表里有的 MAC，即使本机没收到应答，也不是「没有」。没读到转发表，也不代表设备不存在。");
                return;
            }
            Console.WriteLine(string.Format("  {0,-16}{1,-19}{2,-16}{3,-18}{4,-22}{5,-20}{6,-26}{7,-10}{8}",
                "IP地址", "MAC地址", "主机名", "厂商", "发现方式", "服务/端口", "OS判断(猜测)", "应答", "备注"));
            Console.WriteLine("  " + new string('-', 176));
            foreach (var d in list)
            {
                string src = string.Join("+", d.Sources.ToArray());
                string host = d.Hostname == "" ? "-" : d.Hostname;
                string ven = d.Vendor == "" ? "-" : d.Vendor;
                string svc = ServicePortText(d);
                // [F1] OS 判断列：只报猜测并标来源；无把握显示 "-"
                string os = d.Os == "" ? "-" : d.Os;
                // [W1] 应答时效列
                string reply = d.InWindow ? "窗口内" : (d.LateReplies > 0 ? "延迟应答" : "-");
                string mark = d.IsLocal ? " ←本机" : "";
                Console.WriteLine(string.Format("  {0,-16}{1,-19}{2,-16}{3,-18}{4,-22}{5,-20}{6,-26}{7,-10}{8}{9}",
                    d.Ip, d.Mac == "" ? "-" : d.Mac, Trunc(host, 15), Trunc(ven, 17),
                    Trunc(src, 21), Trunc(svc, 19), Trunc(os, 25), reply, Trunc(d.Note, 40), mark));
            }

            // 单独列出仅听到 DHCP Discover（尚无IP）的客户端
            lock (DevicesLock)
            {
                var noIp = Devices.Values.Where(d => d.Ip.Contains("?")).ToList();
                if (noIp.Count > 0)
                {
                    Console.WriteLine();
                    CWriteLine(ConsoleColor.Magenta, "  正在申请IP的DHCP客户端（尚未获得地址）:");
                    foreach (var d in noIp)
                        Console.WriteLine("    MAC=" + d.Mac + "  (" + d.Note + ")");
                }
            }

            PrintSnmpOnly();

            // [W1] 固定打印判定口径，避免"没扫到"被误读成"不存在"
            Console.WriteLine();
            CWriteLine(ConsoleColor.Gray, "  【判定口径】未出现在上表的地址 = 本次未收到任何应答，只代表「未确认」，");
            CWriteLine(ConsoleColor.Gray, "              不代表设备不存在——对方可能屏蔽了 ICMP/ARP，或整段处于静默。");
            if (SnmpCommunity != null)
                CWriteLine(ConsoleColor.Gray, "              交换机转发表里有的 MAC，即使本机没收到应答，也不是「没有」。");
            if (RecvWindowSec > 0)
                CWriteLine(ConsoleColor.Gray, "              标「延迟应答」的设备在主接收窗口之后才应答，同样计为存在。");
        }

        static string ServicePortText(DeviceInfo d)
        {
            var parts = new List<string>();
            if (d.OpenPort > 0) parts.Add("TCP:" + d.OpenPort);
            foreach (var s in d.Services) parts.Add(s);
            if (parts.Count == 0) return "-";
            return string.Join("; ", parts.ToArray());
        }

        static string Trunc(string s, int w)
        {
            if (s == null) return "";
            return s.Length <= w ? s : s.Substring(0, w - 1) + "…";
        }

        static void ExportCsv(string path)
        {
            try
            {
                List<DeviceInfo> list;
                lock (DevicesLock) list = Devices.Values.Where(d => !d.Ip.Contains("?")).ToList();
                using (var sw = new StreamWriter(path, false, new UTF8Encoding(true)))
                {
                    sw.WriteLine("IP地址,MAC地址,主机名,厂商,发现方式,服务/端口,OS判断(猜测),备注,是否本机");
                    foreach (var d in list)
                    {
                        sw.WriteLine(string.Join(",",
                            Csv(d.Ip), Csv(d.Mac), Csv(d.Hostname), Csv(d.Vendor),
                            Csv(string.Join("+", d.Sources.ToArray())),
                            Csv(ServicePortText(d)), Csv(d.Os), Csv(d.Note),
                            d.IsLocal ? "是" : "否"));
                    }
                    foreach (var hit in SnmpUnmatched)
                    {
                        sw.WriteLine(string.Join(",",
                            Csv("(交换机见过)"), Csv(hit.Mac), "", Csv(hit.Vendor),
                            Csv("交换机转发表"), "",
                            Csv("交换端口 " + hit.Port + "；本机未对上IP"), "否"));
                    }
                }
                CWriteLine(ConsoleColor.Green, "[✓] 结果已导出: " + Path.GetFullPath(path));
            }
            catch (Exception ex)
            {
                CWriteLine(ConsoleColor.Red, "[!] 导出失败: " + ex.Message);
            }
        }

        static string Csv(string s)
        {
            if (s == null) return "";
            if (s.Contains(",") || s.Contains("\"") || s.Contains("\n"))
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        // =========================================================
        // [P6] 外部 OUI 表加载（IEEE oui.txt）
        // =========================================================
        static void LoadOuiFromDisk()
        {
            var candidates = new List<string>();
            if (OuiFilePath != null) candidates.Add(OuiFilePath);
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (!string.IsNullOrEmpty(baseDir))
                {
                    candidates.Add(Path.Combine(baseDir, "oui.txt"));
                    candidates.Add(Path.Combine(baseDir, "oui.csv"));
                }
            }
            catch { }
            try { candidates.Add(Path.Combine(Directory.GetCurrentDirectory(), "oui.txt")); } catch { }

            foreach (var f in candidates)
            {
                try
                {
                    if (string.IsNullOrEmpty(f) || !File.Exists(f)) continue;
                    int added = LoadOuiFile(f);
                    OuiSource = f + "（+" + added + " 条）";
                    CWriteLine(ConsoleColor.Green, "[厂商库] 已加载 " + f + "，新增 " + added + " 条，总计 " + OuiTable.Count + " 条");
                    return;
                }
                catch (Exception ex)
                {
                    CWriteLine(ConsoleColor.Yellow, "[厂商库] 读取 " + f + " 失败: " + ex.Message);
                }
            }
        }

        // 解析 IEEE oui.txt：行首 8 字符为 "XX-XX-XX"，制表符后为厂商名
        static int LoadOuiFile(string path)
        {
            int added = 0;
            string[] lines = File.ReadAllLines(path);
            foreach (var raw in lines)
            {
                if (raw == null || raw.Length < 10) continue;
                if (raw.Length > 0 && raw[0] == '#') continue;
                string p = raw.Substring(0, 8).ToUpperInvariant();
                if (p.Length != 8 || p[2] != '-' || p[5] != '-') continue;   // 只要 MA-L 形式，跳过 (base 16) 行
                int tab = raw.IndexOf('\t');
                if (tab < 0 || tab + 1 >= raw.Length) continue;
                string vendor = raw.Substring(tab + 1).Trim();
                if (vendor == "") continue;
                vendor = vendor.Replace("\r", "").Replace("\n", "").Trim();
                if (vendor.Length > 40) vendor = vendor.Substring(0, 40);
                if (OuiTable.ContainsKey(p)) continue;
                OuiTable[p] = vendor;
                added++;
            }
            return added;
        }

        // =========================================================
        // [S1] 交换机 MAC 转发表（SNMPv2c 只读）
        // 编解码必须与 snmp_codec_check.py 的 REQ/RESP 十六进制一致。
        // =========================================================
        class SnmpBind
        {
            public int[] Oid;
            public int IntValue;
            public bool IsInt;
            public bool EndOfMib;
        }

        class SnmpPdu
        {
            public int ErrStatus;
            public List<SnmpBind> Binds = new List<SnmpBind>();
        }

        class SnmpCursor
        {
            byte[] b;
            int i;
            public SnmpCursor(byte[] buf) { b = buf; i = 0; }
            public int Remaining { get { return b.Length - i; } }
            public byte ReadByte() { return b[i++]; }
            public int ReadLen()
            {
                int n = ReadByte();
                if (n < 128) return n;
                int c = n & 0x7f;
                int v = 0;
                for (int k = 0; k < c; k++) v = (v << 8) | ReadByte();
                return v;
            }
            public byte[] ReadTlv(out byte tag)
            {
                tag = ReadByte();
                int n = ReadLen();
                if (n < 0 || i + n > b.Length) throw new InvalidOperationException("BER 截断");
                var body = new byte[n];
                Buffer.BlockCopy(b, i, body, 0, n);
                i += n;
                return body;
            }
        }

        static int SnmpReqId = 1;

        static int NextReqId()
        {
            SnmpReqId++;
            if (SnmpReqId <= 0) SnmpReqId = 1;
            return SnmpReqId;
        }

        static byte[] BerLen(int n)
        {
            if (n < 128) return new byte[] { (byte)n };
            var tmp = new List<byte>();
            int v = n;
            while (v > 0) { tmp.Add((byte)(v & 0xff)); v >>= 8; }
            tmp.Reverse();
            var r = new byte[1 + tmp.Count];
            r[0] = (byte)(0x80 | tmp.Count);
            for (int i = 0; i < tmp.Count; i++) r[1 + i] = tmp[i];
            return r;
        }

        static byte[] BerTlv(byte tag, byte[] body)
        {
            byte[] len = BerLen(body.Length);
            var r = new byte[1 + len.Length + body.Length];
            r[0] = tag;
            Buffer.BlockCopy(len, 0, r, 1, len.Length);
            Buffer.BlockCopy(body, 0, r, 1 + len.Length, body.Length);
            return r;
        }

        static byte[] Cat(params byte[][] parts)
        {
            int n = 0;
            foreach (var p in parts) n += p.Length;
            var r = new byte[n];
            int o = 0;
            foreach (var p in parts)
            {
                Buffer.BlockCopy(p, 0, r, o, p.Length);
                o += p.Length;
            }
            return r;
        }

        static byte[] BerInt(int v)
        {
            if (v == 0) return BerTlv(0x02, new byte[] { 0 });
            byte[] raw = new byte[4];
            raw[0] = (byte)((v >> 24) & 0xff);
            raw[1] = (byte)((v >> 16) & 0xff);
            raw[2] = (byte)((v >> 8) & 0xff);
            raw[3] = (byte)(v & 0xff);
            int i = 0;
            if (v >= 0)
            {
                while (i < 3 && raw[i] == 0 && raw[i + 1] < 0x80) i++;
            }
            else
            {
                while (i < 3 && raw[i] == 0xff && raw[i + 1] >= 0x80) i++;
            }
            var body = new byte[4 - i];
            Buffer.BlockCopy(raw, i, body, 0, body.Length);
            return BerTlv(0x02, body);
        }

        static byte[] BerStr(string s)
        {
            byte[] body = Encoding.ASCII.GetBytes(s == null ? "" : s);
            return BerTlv(0x04, body);
        }

        static byte[] BerOid(int[] parts)
        {
            var body = new List<byte>();
            body.Add((byte)(40 * parts[0] + parts[1]));
            for (int i = 2; i < parts.Length; i++)
            {
                int p = parts[i];
                if (p < 128) { body.Add((byte)p); continue; }
                var stack = new List<byte>();
                stack.Add((byte)(p & 0x7f));
                p >>= 7;
                while (p > 0)
                {
                    stack.Add((byte)(0x80 | (p & 0x7f)));
                    p >>= 7;
                }
                stack.Reverse();
                body.AddRange(stack);
            }
            return BerTlv(0x06, body.ToArray());
        }

        static byte[] BuildGetBulk(string community, int reqId, int maxRep, int[] oid)
        {
            byte[] vb = BerTlv(0x30, Cat(BerOid(oid), new byte[] { 0x05, 0x00 }));
            byte[] vbl = BerTlv(0x30, vb);
            byte[] pduBody = Cat(BerInt(reqId), BerInt(0), BerInt(maxRep), vbl);
            return BerTlv(0x30, Cat(BerInt(1), BerStr(community), BerTlv(0xA5, pduBody)));
        }

        static byte[] BuildGetNext(string community, int reqId, int[] oid)
        {
            byte[] vb = BerTlv(0x30, Cat(BerOid(oid), new byte[] { 0x05, 0x00 }));
            byte[] vbl = BerTlv(0x30, vb);
            byte[] pduBody = Cat(BerInt(reqId), BerInt(0), BerInt(0), vbl);
            return BerTlv(0x30, Cat(BerInt(1), BerStr(community), BerTlv(0xA1, pduBody)));
        }

        static int BerDecInt(byte[] body)
        {
            int v = 0;
            for (int k = 0; k < body.Length; k++) v = (v << 8) | body[k];
            if (body.Length > 0 && (body[0] & 0x80) != 0 && body.Length < 4)
                v -= 1 << (body.Length * 8);
            return v;
        }

        static int[] BerDecOid(byte[] body)
        {
            var parts = new List<int>();
            int first = body[0];
            if (first < 40) { parts.Add(0); parts.Add(first); }
            else if (first < 80) { parts.Add(1); parts.Add(first - 40); }
            else { parts.Add(2); parts.Add(first - 80); }
            int idx = 1;
            while (idx < body.Length)
            {
                int v = 0;
                int x = 0;
                do
                {
                    x = body[idx++];
                    v = (v << 7) | (x & 0x7f);
                } while ((x & 0x80) != 0 && idx < body.Length);
                parts.Add(v);
            }
            return parts.ToArray();
        }

        static SnmpPdu ParsePdu(byte[] msg)
        {
            var outer = new SnmpCursor(msg);
            byte tag;
            byte[] seq = outer.ReadTlv(out tag);
            var inner = new SnmpCursor(seq);
            inner.ReadTlv(out tag);
            inner.ReadTlv(out tag);
            byte[] pdu = inner.ReadTlv(out tag);
            var pr = new SnmpCursor(pdu);
            pr.ReadTlv(out tag);
            byte[] err = pr.ReadTlv(out tag);
            pr.ReadTlv(out tag);
            byte[] vbl = pr.ReadTlv(out tag);
            var result = new SnmpPdu();
            result.ErrStatus = BerDecInt(err);
            var vr = new SnmpCursor(vbl);
            while (vr.Remaining > 0)
            {
                byte[] vb = vr.ReadTlv(out tag);
                var br = new SnmpCursor(vb);
                byte[] oidBody = br.ReadTlv(out tag);
                byte[] val = br.ReadTlv(out tag);
                var item = new SnmpBind();
                item.Oid = BerDecOid(oidBody);
                item.EndOfMib = tag == 0x80 || tag == 0x81 || tag == 0x82;
                item.IsInt = tag == 0x02 || tag == 0x41 || tag == 0x42 || tag == 0x43;
                if (item.IsInt) item.IntValue = BerDecInt(val);
                result.Binds.Add(item);
            }
            return result;
        }

        static bool OidStarts(int[] oid, int[] prefix)
        {
            if (oid == null || oid.Length < prefix.Length) return false;
            for (int i = 0; i < prefix.Length; i++)
                if (oid[i] != prefix[i]) return false;
            return true;
        }

        static int CmpOid(int[] a, int[] b)
        {
            int n = a.Length < b.Length ? a.Length : b.Length;
            for (int i = 0; i < n; i++)
                if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
            return a.Length.CompareTo(b.Length);
        }

        static string MacFromIndex(int[] oid, int[] prefix, bool qbridge)
        {
            int extra = oid.Length - prefix.Length;
            int macStart;
            if (qbridge)
            {
                if (extra != 7) return null;
                macStart = prefix.Length + 1;
            }
            else
            {
                if (extra != 6) return null;
                macStart = prefix.Length;
            }
            var sb = new StringBuilder();
            for (int i = 0; i < 6; i++)
            {
                int b = oid[macStart + i];
                if (b < 0 || b > 255) return null;
                if (i > 0) sb.Append('-');
                sb.Append(b.ToString("X2"));
            }
            return sb.ToString();
        }

        static void NoteSwitchMac(string mac, int port)
        {
            string ip = null;
            lock (DevicesLock)
            {
                foreach (var d in Devices.Values)
                {
                    if (string.Equals(d.Mac, mac, StringComparison.OrdinalIgnoreCase) && d.Ip.IndexOf('?') < 0)
                    {
                        ip = d.Ip;
                        break;
                    }
                }
            }
            if (ip != null)
            {
                AddDevice(ip, "交换机转发表", mac, "交换端口 " + port);
                return;
            }
            var hit = new SnmpMacHit();
            hit.Mac = mac;
            hit.Port = port;
            hit.Vendor = LookupVendor(mac);
            lock (DevicesLock)
            {
                foreach (var old in SnmpUnmatched)
                    if (string.Equals(old.Mac, mac, StringComparison.OrdinalIgnoreCase)) return;
                SnmpUnmatched.Add(hit);
            }
        }

        static void PrintSnmpOnly()
        {
            List<SnmpMacHit> hits;
            lock (DevicesLock) hits = new List<SnmpMacHit>(SnmpUnmatched);
            if (hits.Count == 0) return;
            Console.WriteLine();
            CWriteLine(ConsoleColor.Magenta, "  交换机见过、本机还没对上 IP 的 MAC（这些设备存在，只是没应答我们）:");
            foreach (var h in hits)
            {
                string ven = h.Vendor == "" ? "" : "  " + h.Vendor;
                Console.WriteLine("    MAC=" + h.Mac + "  端口 " + h.Port + ven);
            }
        }

        static SnmpPdu SnmpAsk(IPAddress host, byte[] req)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    using (var udp = new UdpClient())
                    {
                        udp.Client.ReceiveTimeout = SnmpTimeoutMs;
                        udp.Client.SendTimeout = SnmpTimeoutMs;
                        udp.Send(req, req.Length, new IPEndPoint(host, 161));
                        IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                        byte[] resp = udp.Receive(ref ep);
                        return ParsePdu(resp);
                    }
                }
                catch (SocketException) { }
                catch (Exception) { return null; }
            }
            return null;
        }

        static int WalkColumn(IPAddress host, int[] prefix, bool qbridge)
        {
            int[] cursor = (int[])prefix.Clone();
            bool useNext = false;
            int rows = 0;
            int stuck = 0;
            while (rows < SnmpMaxRows)
            {
                byte[] req = useNext
                    ? BuildGetNext(SnmpCommunity, NextReqId(), cursor)
                    : BuildGetBulk(SnmpCommunity, NextReqId(), 10, cursor);
                SnmpPdu pdu = SnmpAsk(host, req);
                if (pdu == null)
                {
                    if (!useNext) { useNext = true; continue; }
                    break;
                }
                if (pdu.ErrStatus != 0 && !useNext)
                {
                    useNext = true;
                    continue;
                }
                if (pdu.ErrStatus != 0 || pdu.Binds.Count == 0) break;
                bool advanced = false;
                foreach (var b in pdu.Binds)
                {
                    if (b.Oid == null || !OidStarts(b.Oid, prefix)) return rows;
                    if (b.EndOfMib) return rows;
                    if (CmpOid(b.Oid, cursor) <= 0)
                    {
                        stuck++;
                        if (stuck > 3) return rows;
                        continue;
                    }
                    stuck = 0;
                    cursor = b.Oid;
                    advanced = true;
                    string mac = MacFromIndex(b.Oid, prefix, qbridge);
                    if (mac != null && b.IsInt)
                    {
                        NoteSwitchMac(mac, b.IntValue);
                        rows++;
                    }
                    if (rows >= SnmpMaxRows) break;
                }
                if (!advanced) break;
            }
            return rows;
        }

        static void SnmpWalkAndMerge()
        {
            var hosts = new List<IPAddress>();
            if (!string.IsNullOrEmpty(SnmpHost))
            {
                IPAddress h;
                if (!IPAddress.TryParse(SnmpHost, out h) || h.AddressFamily != AddressFamily.InterNetwork)
                {
                    CWriteLine(ConsoleColor.Yellow, "[!] -snmphost 不是 IPv4 地址: " + SnmpHost);
                    return;
                }
                hosts.Add(h);
            }
            else
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    foreach (var gw in ni.GetIPProperties().GatewayAddresses)
                    {
                        if (gw.Address == null) continue;
                        if (gw.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        if (gw.Address.Equals(IPAddress.Any)) continue;
                        if (!hosts.Contains(gw.Address)) hosts.Add(gw.Address);
                    }
                }
            }
            if (hosts.Count == 0)
            {
                CWriteLine(ConsoleColor.Yellow, "[!] 没有可用的交换机地址。请用 -snmphost 指定。没读到转发表不代表网段里没有设备。");
                return;
            }
            int[] dot1d = new int[] { 1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2 };
            int[] qbridge = new int[] { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 };
            foreach (var h in hosts)
            {
                CWriteLine(ConsoleColor.Cyan, "─── 交换机转发表 " + h + "（只读 SNMP）───");
                int n = WalkColumn(h, dot1d, false);
                string which = "dot1d";
                if (n == 0)
                {
                    n = WalkColumn(h, qbridge, true);
                    which = "Q-BRIDGE";
                }
                if (n == 0)
                    CWriteLine(ConsoleColor.Yellow, "    没有读到转发表。可能未开 SNMP、community 不对、或这台不是网桥。这不代表网段里没有设备。");
                else
                    CWriteLine(ConsoleColor.Green, "    读到 " + n + " 条（" + which + "）。对上 IP 的已并入上表。");
            }
        }

        static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        static byte[] HexToBytes(string hex)
        {
            var r = new byte[hex.Length / 2];
            for (int i = 0; i < r.Length; i++)
                r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }

        static bool SnmpSelfCheck()
        {
            const string expectReq = "302802010104067075626c6963a51b02010702010002010a3010300e060a2b0601020111040301020500";
            const string expectResp = "303d02010104067075626c6963a2300201070201000201003025301506102b060102011104030102001122334455020107300c06082b060102010101008200";
            int[] fdb = new int[] { 1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2 };
            bool ok = true;
            byte[] req = BuildGetBulk("public", 7, 10, fdb);
            string got = ToHex(req);
            Console.WriteLine("[snmpvec] 请求 " + got);
            Console.WriteLine("[snmpvec] 期望 " + expectReq);
            if (got != expectReq) { CWriteLine(ConsoleColor.Red, "[snmpvec] 请求编码不一致"); ok = false; }
            byte[] oid170 = BerOid(new int[] { 1, 3, 170 });
            if (ToHex(oid170) != "06032b812a")
            {
                CWriteLine(ConsoleColor.Red, "[snmpvec] 大于 127 的 OID 子项编码不一致: " + ToHex(oid170));
                ok = false;
            }
            else
            {
                int[] back = BerDecOid(new byte[] { 0x2b, 0x81, 0x2a });
                if (back.Length != 3 || back[0] != 1 || back[1] != 3 || back[2] != 170)
                {
                    CWriteLine(ConsoleColor.Red, "[snmpvec] OID 解码回环失败");
                    ok = false;
                }
            }
            try
            {
                SnmpPdu pdu = ParsePdu(HexToBytes(expectResp));
                string mac = null;
                int port = -1;
                if (pdu.ErrStatus == 0 && pdu.Binds.Count >= 2)
                {
                    mac = MacFromIndex(pdu.Binds[0].Oid, fdb, false);
                    port = pdu.Binds[0].IntValue;
                }
                Console.WriteLine("[snmpvec] 样例 MAC=" + (mac == null ? "(无)" : mac) + " 端口=" + port);
                if (mac != "00-11-22-33-44-55" || port != 7 || !pdu.Binds[1].EndOfMib)
                {
                    CWriteLine(ConsoleColor.Red, "[snmpvec] 样例应答解析不一致");
                    ok = false;
                }
            }
            catch (Exception ex)
            {
                CWriteLine(ConsoleColor.Red, "[snmpvec] 解析异常: " + ex.Message);
                ok = false;
            }
            // [F2] OS 识别 GET 包向量（sysDescr，public）＋应答解析回环
            {
                string gethex = ToHex(SnmpBuildGet("public", OidSysDescr));
                Console.WriteLine("[snmpvec] GET请求 " + gethex);
                const string expectGet = "302602010104067075626c6963a019020107020100020100300e300c06082b060102010101000500";
                if (gethex != expectGet) { CWriteLine(ConsoleColor.Red, "[snmpvec] GET 编码不一致"); ok = false; }
                const string sampleResp = "304002010104067075626c6963a2330201070201000201003028302606082b06010201010100041a4c696e7578206e617320352e31352e302d3931207838365f3634";
                string vv = SnmpParseValue(HexToBytes(sampleResp), OidSysDescr);
                Console.WriteLine("[snmpvec] sysDescr样例 " + (vv == null ? "(无)" : vv));
                if (vv != "Linux nas 5.15.0-91 x86_64") { CWriteLine(ConsoleColor.Red, "[snmpvec] GET 应答解析不一致"); ok = false; }
            }
            if (ok) CWriteLine(ConsoleColor.Green, "[snmpvec] PASS");
            else CWriteLine(ConsoleColor.Red, "[snmpvec] FAIL");
            return ok;
        }

        // =========================================================
        // 10. 交互式菜单
        // =========================================================
        static void InteractiveMenu()
        {
            while (true)
            {
                Console.WriteLine();
                CWriteLine(ConsoleColor.Cyan, "─────────── 请选择操作 ───────────");
                Console.WriteLine("  1. 列出本机网卡信息");
                Console.WriteLine("  2. 主动扫描本机网段（ARP + ICMP + TCP）");
                Console.WriteLine("  3. 主动扫描指定网段");
                Console.WriteLine("  4. 跨网段扫描（临时添加辅助IP，需管理员）");
                Console.WriteLine("  5. 监听+诱探发现设备（全部网卡，唤醒沉默设备，含IP冲突检测）");
                Console.WriteLine("  6. 探测 DHCP 服务器");
                Console.WriteLine("  7. 检测本机 IP 冲突");
                Console.WriteLine("  8. 完整扫描（以上全部）");
                Console.WriteLine("  9. 显示当前已发现设备 / 导出CSV");
                Console.WriteLine("  0. 退出");
                Console.Write("> ");
                string line;
                try { line = Console.ReadLine(); } catch { break; }
                if (line == null) break;
                line = line.Trim();
                try
                {
                    if (line == "0" || line.ToLowerInvariant() == "q") break;
                    else if (line == "1") ListAdapters();
                    else if (line == "2") { ScanAllLocalSubnets(); ResolveNames(); }
                    else if (line == "3")
                    {
                        Console.Write("请输入网段（如 192.168.1.0/24）: ");
                        string c = Console.ReadLine();
                        if (c != null && c.Trim() != "") { ActiveScanCidr(c.Trim()); ResolveNames(); }
                    }
                    else if (line == "4")
                    {
                        Console.Write("请输入要扫描的网段（如 192.168.5.0/24）: ");
                        string c = Console.ReadLine();
                        if (c != null && c.Trim() != "") ScanWithAlias(c.Trim(), null);
                    }
                    else if (line == "5") PassiveListen(30, AskNicSpec());
                    else if (line == "6") DhcpDiscover(10);
                    else if (line == "7") ConflictCheck(20);
                    else if (line == "8") FullScan(30, null);
                    else if (line == "9")
                    {
                        PrintResults();
                        Console.Write("导出CSV路径（直接回车跳过）: ");
                        string p = Console.ReadLine();
                        if (p != null && p.Trim() != "") ExportCsv(p.Trim());
                    }
                    else Console.WriteLine("无效选择");
                }
                catch (Exception ex)
                {
                    CWriteLine(ConsoleColor.Red, "[错误] " + ex.Message);
                }
            }
        }
    }
}
