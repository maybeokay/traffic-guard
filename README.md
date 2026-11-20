# TrafficGuard 流量卫士

一个零依赖的网络流量监控与 DDoS 防护反向代理，基于 C# + HttpListener，部署于 Windows Server。

## 功能

- **反向代理**：将外部请求转发到后端网站
- **流量统计**：总请求数、唯一 IP、平均 QPS、总流量、热门页面、Top IP、User-Agent、状态码分布
- **DDoS 防护**：每 IP 滑动窗口限速 + 自动封禁 + 手动封禁/解封
- **监控仪表盘**：`/__guard__/`，3 秒自动刷新
- **请求日志**：CSV 落盘（`C:\traffic-guard\requests.log`）

## 编译部署

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:TrafficGuard.exe TrafficGuard.cs
TrafficGuard.exe 8081 http://127.0.0.1:8080
```

参数：`TrafficGuard.exe <监听端口> <后端地址>`

## 防护参数

- 限速窗口：10 秒
- 单 IP 阈值：100 请求 / 窗口
- 触发后封禁时长：5 分钟（可手动解封）
