# vpnbridge

把宿主机（Linux）上访问特定网段的流量，通过一条自定义代理链交给
KVM 里的 Windows 虚拟机去发起——虚拟机上跑着 Sangfor / 奇安信等 VPN 客户端，
只有它能看到那些内网网段。

```
  宿主机 (Linux)                            虚拟机 (Windows)
 ┌────────────────────────────┐            ┌──────────────────────────┐
 │ app  →  10.20.1.5:443      │            │                          │
 │   │  内核路由: 10.20.0.0/16│            │  vpnbridge-vm            │
 │   ↓         dev vpnbr0     │            │     │ connect()          │
 │ TUN(vpnbr0)                │            │     ↓                    │
 │   ↓  用户态 TCP/IP (ipstack)│           │  Sangfor / 奇安信 虚拟网卡│
 │ vpnbridge-host ────────────┼── TCP ────→│     ↓                    │
 │        192.168.122.1       │ 122.100    │   VPN 隧道 → 内网         │
 └────────────────────────────┘  :17321    └──────────────────────────┘
```

每条流一条 TCP 连接，握手协议见 `crates/proto/src/lib.rs`。

## 组成

| crate | 跑在哪 | 作用 |
|---|---|---|
| `crates/proto` (`vpnbridge-proto`) | 两端 | 握手 / 地址 / 数据报分帧的线格式 |
| `crates/host` (`vpnbridge-host`) | 宿主机 Linux | 建 TUN、装路由、用户态收 TCP/UDP、转发给虚拟机；可选 DNS 转发器 |
| `crates/vm` (`vpnbridge-vm`) | 虚拟机 Windows | 收到请求后在本地 `connect()`，走 VPN，回传数据 |

## 编译

宿主机端（Linux）：

```bash
cargo build --release -p vpnbridge-host
# target/release/vpnbridge-host
```

虚拟机端。两种方式，任选其一：

```bash
# A. 在 Windows 上直接编译（装 rustup + MSVC 或 GNU 工具链）
cargo build --release -p vpnbridge-vm

# B. 在宿主机交叉编译（openSUSE: zypper in mingw64-cross-gcc）
rustup target add x86_64-pc-windows-gnu
cargo build --release -p vpnbridge-vm --target x86_64-pc-windows-gnu
# target/x86_64-pc-windows-gnu/release/vpnbridge-vm.exe
```

`vpnbridge-vm` 只用到 tokio + std，Linux 上也能编能跑，方便先在宿主机上自测协议。
交叉编译前可以先只做类型检查，不需要链接器：

```bash
rustup target add x86_64-pc-windows-msvc
cargo check -p vpnbridge-vm --target x86_64-pc-windows-msvc
```

## 配置

示例见 `config/host.toml`、`config/vm.toml`，两边的 `token` 必须一致。

两端都可以用 `--config <路径>`（或 `-c <路径>`）明确指定配置文件。未指定时，
程序先查找当前工作目录下的 `host.toml` / `vm.toml`，再查找可执行文件所在目录下
的同名文件；两处都不存在则报错退出。

宿主机关键项：

- `routes` —— 要转发给虚拟机的网段列表，其余流量走宿主机原有路由，完全不受影响。
- `exclude` —— 绝不捕获的网段。宿主机 ↔ 虚拟机所在的网段（libvirt 默认
  `192.168.122.0/24`）如果被 `routes` 覆盖，一定要写进来，否则隧道自己的连接
  会被自己抓进 TUN，形成死循环。程序还会自动为 `server.address` 单独钉一条
  `/32` 直连路由做兜底。
- `tun.auto_route = true` 时，启动装路由、退出（Ctrl-C / SIGTERM）删路由。
  `exclude` 里已存在的同名路由不会被改动，也不会在退出时被删。
- `server.reconnect_interval_ms` —— host 连接 VM 失败后的重试间隔，默认
  `10000` 毫秒。连接失败或超时会保留当前流并持续重试；认证失败、目标被拒绝等
  VM 明确返回的错误不会重试。

虚拟机关键项：

- `allow` / `deny` —— 服务端白名单，防止宿主机借道乱连；`allow` 为空表示放行任意目标
  （相当于把虚拟机的默认路由借给宿主机）。
- `bind_ip` —— 当 Windows 选错出口网卡时，填 VPN 虚拟网卡的地址强制指定源地址。

先验证配置再跑：

```bash
vpnbridge-host --config config/host.toml --check
vpnbridge-vm   --config config/vm.toml   --check
```

## 运行

虚拟机里（VPN 已连上）：

```powershell
vpnbridge-vm.exe --config vm.toml
# 放行入站端口，否则宿主机连不进来
netsh advfirewall firewall add rule name="vpnbridge" dir=in action=allow protocol=TCP localport=17321
```

宿主机（需要 root 或 CAP_NET_ADMIN）：

```bash
sudo ./target/release/vpnbridge-host --config config/host.toml --log debug
```

常驻：

```bash
sudo install -Dm755 target/release/vpnbridge-host /usr/local/bin/vpnbridge-host
sudo install -Dm600 config/host.toml /etc/vpnbridge/host.toml
sudo install -Dm644 dist/vpnbridge-host.service /etc/systemd/system/vpnbridge-host.service
sudo systemctl enable --now vpnbridge-host
```

虚拟机端做成开机自启，可以用计划任务（触发器选“计算机启动时”、勾选“不管用户是否登录”），
或者 NSSM 之类的服务包装器。

## DNS

内网域名通常只有 VPN 的 DNS 能解析。`[dns]` 段会在本地起一个 UDP 转发器，把查询
通过隧道丢给 VPN 侧的 resolver：

```bash
# 只让内网域名走它，其余域名不受影响
sudo resolvectl dns vpnbr0 127.0.0.1:15353
sudo resolvectl domain vpnbr0 ~corp.example.com
```

不想动系统 DNS 的话，直接测：`dig @127.0.0.1 -p 15353 host.corp.example.com`。

## 验证

不需要真的虚拟机就能验完整条链路：`scripts/chain-test.sh` 用一个 network
namespace 冒充 Windows 客户机，把 `198.51.100.5`（TEST-NET-2）放进 namespace 里，
所以只有走隧道才够得着它。

```bash
cargo build
./scripts/chain-test.sh      # 需要 sudo，跑完自动清理 netns / veth / 路由
```

覆盖：TCP 转发、UDP 转发、DNS 转发器、目标不可达时能否立刻断开。

接上真实虚拟机之后：

```bash
# 隧道是否通（会在 host 日志里看到 tcp flow）
curl -v http://10.20.1.5/
nc -vz 10.20.1.5 443

# 路由是否装上
ip route show | grep vpnbr0
```

## 已知边界

- **ICMP 不代理**：`ping 10.20.x.x` 不通是预期行为。本地伪造 echo reply 只会
  制造“通了”的假象，所以没做；请用 TCP/UDP 验证连通性。
- **目标不可达时不是 `ECONNREFUSED`**：用户态协议栈会先跟本地程序把三次握手做完，
  之后才知道虚拟机那边拨不通，所以表现为 `connect()` 成功、紧接着收到 FIN（读到
  EOF）。所有 tun2socks 类方案都是这个行为。程序会显式发 FIN，不会让应用干等到
  自己超时。
- **不加密**：宿主机 ↔ 虚拟机是一条虚拟网卡链路，只有共享 token 做身份校验。
  别把 `listen` 暴露到 VPN 网段或外网上。
- **每流一连接**，没有多路复用。虚拟链路上连接建立开销可以忽略，换来的是没有
  队头阻塞、错误处理简单。
- IPv6 在配置和路由层面是支持的（`routes` 可以写 IPv6 前缀），但 TUN 只配了
  IPv4 地址，IPv6 需要自己给设备加地址。
- 没有 GUI。需要的话下一步用 iced 加一个 `crates/ui`：显示连接数/流量、开关
  单条网段、编辑配置后热重载。

## 排错

| 现象 | 检查 |
|---|---|
| `creating TUN device ... (needs root or CAP_NET_ADMIN)` | 用 sudo 跑，或 `setcap cap_net_admin+ep` |
| 日志里 `connecting to VM agent failed; retrying` | 虚拟机上 agent 没跑，或 Windows 防火墙没放行；host 会按 `server.reconnect_interval_ms` 自动重试 |
| `VM agent refused ...: authentication failed` | 两边 `token` 不一致 |
| `VM agent refused ...: target not allowed by server policy` | 目标不在 `vm.toml` 的 `allow` 里 |
| 连上后马上断、或者整个网络卡死 | `exclude` 没写宿主机 ↔ 虚拟机网段，隧道被自己抓了 |
| 内网 IP 能通、域名不通 | DNS 没配，见上面 DNS 一节 |
