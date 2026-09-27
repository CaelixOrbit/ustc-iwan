# Windows 用户态代理修复说明

本说明仅覆盖本 fork 的 Windows 用户态 SOCKS5/HTTP 代理修复与运行方式。项目基于 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan)，上游完整用法、Clash 集成与规则说明仍适用。

## 问题边界

本次处理的是三个彼此独立的问题：

1. 某些 Windows 安全软件环境中，官方 Panabit 客户端曾触发 `0x139`。这只是采用用户态代理的背景；本 fork 没有定位或修复官方驱动，也不宣传解决所有安全软件冲突。
2. 本 fork 修复非官方 iWAN 用户态代理在 Windows 下将 UDP 非阻塞 `WouldBlock`/10035 当作致命错误退出的问题。
3. 修复稳定后，某些链路仍对 TLS 包长敏感。`--proxy-mtu 1200` 是已经验证有效的运行参数，不是通用物理 PMTU 结论。

Windows 用户态模式的范围是 TCP/HTTP(S) 代理；它不等价于官方客户端的全部 UDP 功能。Linux TUN 路径没有因本补丁改变。

## UDP `WouldBlock` 修复

旧发送路径会在 `UdpSocket::send` 返回 `WouldBlock` 后经 `context("send VPN packet")?` 返回上层，导致进程退出。更重要的是，旧实现会先弹出 TX 队首并原位 XOR 数据，不能安全重试。

本 fork 的相关修改仅在以下文件中：

```text
src/core/netstack/device.rs
src/core/netstack/tunnel.rs
src/core/netstack/mod.rs
src/core/local_proxy/engine.rs
```

发送数据的算法为：

1. 查看 TX 队首的原文数据包，不立即弹出。
2. 克隆副本，在副本上做 XOR 和 iWAN 数据报封装。
3. 只有整个 UDP 数据报发送成功，才弹出原文队首。
4. `WouldBlock` 时保留原文和队首，稍后重试。
5. UDP 短写作为异常报告；其他真实 socket 错误继续上报。

因此，重试不会丢失数据，也不会对同一原文重复 XOR。该实现没有把 UDP 当作字节流拼接续传。

`device.rs` 将 RX 与 TX 队列各限制为 256 包；TX 满时不再提供新的 transmit token，接收 RX 前先确认 TX 有容量。控制帧 FIFO 限制为 64 包：心跳间隔 10 秒，未发送的 keepalive 会去重，且只有真实发送成功才更新时间。队列满时暂停继续取包，这是有限内存的取舍，不承诺内核 UDP 缓冲区在长期上游突发时绝不丢包。

`engine.rs` 仅在真实 `WouldBlock` 后退避 10ms，控制帧优先于数据帧；正常 `poll_delay` 不会被改为全局固定节流。关闭时只做有限次尽力发送，不无限等待。

认证/OIDC、加密和 wire 协议、Cargo 依赖与锁文件均未修改。

## 包长敏感链路与 `--proxy-mtu 1200`

在一个受影响链路上，HTTP CONNECT 已成功并不等于 TLS 已完成：默认 TLS 的首个约 1596 字节 ClientHello 仍可能无响应超时。缩小用户态代理 MTU 到 1200 后，默认 TLS 和证书验证恢复正常。

这表明该路径存在包长/时序敏感性，但没有测得精确物理 PMTU，也不能确定问题发生在安全软件、网络路径或远端设备。为避免过度推断，本 fork 没有降低 TLS 版本、关闭证书校验、修改系统网卡 MTU 或加入全局 pacing。

CLI 默认 `--proxy-mtu` 仍为 1380；`1200` 没有写进源码默认值。仅在确认自己遇到相同现象时使用该参数。

## Windows 使用示例

以下命令应在解压或构建产物所在目录执行。首次登录、线路选择与回调 URL 的完整说明请参阅 README。

```powershell
# 首次登录并保存本机线路配置
.\iwan-client-oidc-windows-x86_64.exe --fetch

# 查看本机可用线路；server 2 只是示例，实际请据此选择
.\iwan-client-oidc-windows-x86_64.exe --list

# 启动本地 HTTP 代理
.\iwan-client-oidc-windows-x86_64.exe --connect --server 2 --http --http-listen 127.0.0.1:18080 --dns https://dns.alidns.com/dns-query --proxy-mtu 1200
```

不要分享登录回调 URL、token 或本机配置文件。用户态 HTTP 代理可被宿主机 Agent 直接使用，也可通过 Clash 指向 `127.0.0.1:18080`。Clash 的 fake-ip、规则、物理网卡直连和防环路思路请保留上游 [使用技巧](usage-tips.md) 与 [iWAN 规则](iwan-rules.yaml) 的做法。

## Windows 构建

安装 Rust 的 MSVC 工具链、Visual Studio Build Tools 与 Windows SDK 后，在 **VS Developer PowerShell** 的源码根目录运行：

```powershell
$env:RUSTFLAGS='-C target-feature=+crt-static -C strip=symbols'
cargo test --locked
cargo build --locked --release --bin iwan-client-oidc --target x86_64-pc-windows-msvc
```

首次构建需要联网下载依赖；依赖已缓存时可使用 `--offline`。产物为：

```text
target\x86_64-pc-windows-msvc\release\iwan-client-oidc.exe
```

若要交给与 Windows 后台脚本配套的运行包，发行时应重命名为 `iwan-client-oidc-windows-x86_64.exe` 并保持脚本所期待的相对目录布局。

历史验证在 Windows Rust 1.98.1 环境完成：22 个测试通过（库 19、OIDC 3），release build 成功，默认 TLS 与校园 API 真实请求可用。修复验证未运行 clippy。不要将此结果外推为所有平台或所有网络环境均已验证。

## 验证与排查边界

`GET /v1/models` 的无凭据 `401` 只能说明端点可达；HTTP CONNECT `200` 只说明代理建立了目标 TCP 连接；`HEAD /responses` 的 `405` 只说明 TLS 后收到 HTTP 响应。它们都不能代替真实的已授权模型请求。

如果出现问题，先确认本地监听端口、线路选择和本机登录状态，再按上游文档检查 fake-ip、规则顺序和 iWAN 服务器的直连防环路规则。不要为了排查而永久启用调试输出、降低 TLS 或关闭证书验证。
