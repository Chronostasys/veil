# Veil ArkTS 前端说明

本目录实现 Veil 的 HarmonyOS NEXT 前端。UI 进程**不加载** `libveilcore.so`，它与核心只通过
一个 Unix domain socket 通信；核心本体运行在 **VPN 扩展进程** 里。

```
┌──────────────── UI 进程 ─────────────────┐        ┌────────── VPN 扩展进程 ──────────┐
│ pages/Index.ets                         │        │ vpn/VeilVpnAbility.ets           │
│   views/{Home,Nodes,Rules,Settings}View │        │   NAPI 加载 libveilcore.so       │
│   core/CoreClient.ets  ──┐              │        │   持有 VpnConnection（tun fd）    │
└──────────────────────────┼──────────────┘        └──────┬───────────────────────────┘
                           │                              │
                           ▼                              ▼
                 <filesDir>/veil.sock  ────────  Go 核心（RPC server, newline JSON）
```

## 1. 套接字约定

- 路径：`context.filesDir + '/veil.sock'`（UI 与扩展进程共享同一个沙箱，路径一致）
- 传输：本地套接字流式字节；**帧分隔符为 `\n`**，单帧必须是合法 JSON，不允许在帧内换行。
- 编码：UTF-8。读取端用 `util.TextDecoder` 解码 `ArrayBuffer` 后按 `\n` 切分，残片留在缓冲区
  等下一条消息拼接（一次 socket 读取可能包含半帧或多帧）。

### 客户端 → 核心（请求）

```json
{"id": 1, "method": "status", "params": {}}
```

- `id`：客户端自增整数，用于多路复用；同一连接内不得重复使用未完成的 id。
- `method` / `params`：与 `core/internal/rpc/rpc.go` 的常量一一对应（见 §3）。

### 核心 → 客户端（应答）

```json
{"id": 1, "ok": true, "result": {...}}
{"id": 1, "ok": false, "error": "unknown method \"foo\""}
```

- `ok:false` 时 `error` 是**可直接展示给用户的原文**，UI 不做包装、不改写。
- 超时（默认 8s，订阅更新 60s，`start`/`stop`/`set_config` 15–20s）由客户端计时器负责，
  超时后该 `id` 从待决表移除，迟到的应答被静默丢弃。

### 主机（VPN 扩展）注册

扩展进程建立连接后**第一行**发送：

```json
{"role":"host"}
```

核心据此知道这条连接可以接收 host 请求。UI 进程不发这一行。

### 核心 → 主机（host 请求）

```json
{"host": true, "id": 7, "method": "tun_up", "params": {}}
```

| method    | params        | 主机成功应答                                   |
|-----------|---------------|-----------------------------------------------|
| `tun_up`  | `{}` 或 `{"mtu":1400}` | `{"id":7,"ok":true,"result":{"fd":42}}` |
| `tun_down`| `{}`          | `{"id":7,"ok":true,"result":{}}`              |
| `protect` | `{"fd":42}`   | `{"id":7,"ok":true,"result":{}}`              |

失败一律 `{"id":7,"ok":false,"error":"<原因>"}`。主机**必须**以 `ok:false` 报告失败
（例如尚未建 tun 时收到 `protect`），让核心自行降级并记录，而不是假装成功。

host 请求的 `id` 与客户端请求的 `id` 属于两个独立命名空间，靠 `host:true` 区分。

## 2. 代码结构

| 文件 | 职责 |
| --- | --- |
| `core/LocalRpc.ets` | socket 连接、帧拆分、id 多路复用、超时、host 请求分发 |
| `core/CoreClient.ets` | 单例；启动扩展能力 + 重试连接；把 RPC 结果 cast 成 `model/Types.ets` 的类型 |
| `core/Format.ets` | 字节 / 速率 / 时长 / 时间格式化（等宽数字） |
| `model/Types.ets` | 与 Go 结构体逐字段对应的接口；唯一允许出现 JSON 形状的文件 |
| `theme/Theme.ets` | Canvas 用的具体色值（镜像 `resources/**/element/color.json`）与相位配色 |
| `views/*.ets` | 四个页签；每个页签自带轮询，`onVisibleAreaChange` 里暂停 |
| `pages/Index.ets` | 唯一 @Entry；头部、核心可用性横幅、Tabs |
| `vpn/VeilVpnAbility.ets` | RPC host：`veil.start`、tun 生命周期、protect、`tun_up/tun_down` |
| `../cpp/napi_init.cpp` | NAPI 壳：`dlopen("libveilcore.so")` + `dlsym`，导出 `start/call/shutdown` |

## 3. 使用的 RPC 方法

生命周期与状态：`status`（1s 轮询）、`start`、`stop`、`version`
节点：`groups`（5s 轮询）、`select`、`delay`、`nodes`
规则/订阅：`config`、`set_mode`、`import`、`sub_add`、`sub_update`、`sub_delete`
运行态：`conns`、`close_conn`、`close_all`、`logs`（1.5s 增量）、`set_config`、`reset_stats`

## 4. 失败与降级

- 连接不是状态：`CoreState`（Idle/Connecting/Ready/Unavailable）只描述**套接字**。
  隧道是否连通永远读 `status.phase`，UI 不会因为按钮点过就显示“已连接”。
- 连接不上 → `Index` 顶部横幅显示真实错误 + “重试”；各页签显示空态，不渲染假数据。
- 任何 RPC 错误 → `toast` 显示核心原文（`errorText()`）。
- 扩展进程 socket 断开 → 1s 后自动重连，`veil.shutdown()` 只在 `onDestroy` 里调用。
