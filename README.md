# fw.sh — nftables 防火墙配置脚本

基于 nftables 的防火墙配置脚本，兼容 Docker（iptables-nft 后端），支持 blog / billing / mail 三套系统独立部署。

## 特性

- **Docker 兼容** — 仅操作自定义表 `fw_filter` / `fw_ddos`，不触碰 Docker 的 iptables-nft 规则
- **系统隔离** — 三套系统部署在不同机器上，`init` 时选择系统类型，按需加载规则
- **数据库端口细粒度控制** — 支持 pgsql / redis / es 独立开关，即时生效无需重启
- **SSH 暴力破解防护** — 基于 nftables 动态集合，超限 IP 自动加入黑名单
- **规则持久化** — 自动保存到 `/etc/nftables.conf`，开机自动加载
- **自动备份** — 每次 `init` 前备份当前规则到 `/etc/nftables.backup/`

## 系统要求

- Debian / Ubuntu（需要 `apt` 包管理器）
- nftables（脚本会自动安装）
- root 权限

## 快速开始

```bash
# 1. 根据机器用途初始化防火墙（三选一）
sudo bash fw.sh init blog       # Blog 系统
sudo bash fw.sh init billing    # Billing Center
sudo bash fw.sh init mail       # 邮件系统

# 2. 保持当前 SSH 不断开，另开终端测试 SSH 登录
# SSH 端口自动从 /etc/ssh/sshd_config 读取，无需手动配置
ssh -p <你的SSH端口> user@host

# 3. 查看防火墙状态
sudo bash fw.sh status
```

## 命令一览

| 命令 | 说明 |
|------|------|
| `init <系统>` | 初始化防火墙（blog / billing / mail） |
| `start` | 加载已保存的规则 |
| `stop` | 清除自定义规则（不影响 Docker） |
| `status` | 查看防火墙状态和端口开关情况 |
| `db-open <系统> <服务>` | 开放指定数据库端口 |
| `db-close <系统> <服务>` | 关闭指定数据库端口 |
| `-h, --help` | 显示帮助信息 |

## 各系统初始化规则

### Blog 系统 (`init blog`)

| 方向 | 规则 |
|------|------|
| 入站 | Web (80, 443)、SSH (自动读取 sshd_config)、ICMP、Docker 内网、已建立连接 |
| 转发 | Docker 内网放行；阻断 pgsql (5432)、redis (7002-7007)、es (9200, 9300) |
| 出站 | 全部放行 |

### Billing 系统 (`init billing`)

| 方向 | 规则 |
|------|------|
| 入站 | Web (80, 443)、SSH (自动读取 sshd_config)、ICMP、Docker 内网、已建立连接 |
| 转发 | Docker 内网放行；阻断 pgsql (5433)、redis (8002-8007) |
| 出站 | 全部放行 |

### 邮件系统 (`init mail`)

| 方向 | 规则 |
|------|------|
| 入站 | Web (80, 443)、Mail (25, 143, 465, 587, 993)、SSH (自动读取 sshd_config)、ICMP、Docker 内网、已建立连接 |
| 转发 | Docker 内网放行 |
| 出站 | 全部放行 |

## 数据库端口管理

数据库端口默认**全部关闭**（forward 链 drop），需要维护时手动开放：

```bash
# Blog 系统
sudo bash fw.sh db-open blog pgsql     # 开放 PostgreSQL (5432)
sudo bash fw.sh db-open blog redis     # 开放 Redis (7002-7007)
sudo bash fw.sh db-open blog es        # 开放 Elasticsearch (9200, 9300)
sudo bash fw.sh db-close blog pgsql    # 关闭 PostgreSQL

# Billing 系统
sudo bash fw.sh db-open billing pgsql  # 开放 PostgreSQL (5433)
sudo bash fw.sh db-open billing redis  # 开放 Redis (8002-8007)
sudo bash fw.sh db-close billing redis # 关闭 Redis
```

开关操作通过 `nft add/delete rule` 直接生效，同时自动持久化到配置文件。

## SSH 暴力破解防护

通过独立的 `fw_ddos` 表（优先级 -10）实现：

- 同一 IP 在 1 分钟内超过 5 次 SSH 新连接 → 自动加入黑名单
- 黑名单 IP 封禁 5 分钟，期间所有入站流量丢弃
- 参数可在脚本头部配置：

```bash
SSH_RATE_LIMIT="5/minute"   # 速率限制
SSH_BURST_LIMIT=5            # 突发限制
SSH_BLOCK_TIMEOUT="5m"       # 封禁时长
```

## 配置项

脚本头部的用户配置项：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SSH_PORT` | 自动读取 `/etc/ssh/sshd_config`，未配置时回退到 22 | SSH 端口 |
| `WEB_PORTS` | 80, 443 | Web 服务端口 |
| `MAIL_PORTS` | 25, 143, 465, 587, 993 | 邮件服务端口 |
| `BLOG_DB_PORTS` | 5432 | Blog PostgreSQL 端口 |
| `BLOG_REDIS_PORTS` | 7002-7007 | Blog Redis Cluster 端口 |
| `BLOG_ES_PORTS` | 9200, 9300 | Blog Elasticsearch 端口 |
| `BILLING_DB_PORTS` | 5433 | Billing PostgreSQL 端口 |
| `BILLING_REDIS_PORTS` | 8002-8007 | Billing Redis Cluster 端口 |
| `DOCKER_INTERNAL_SUBNETS` | 172.16.0.0/12, 178.18.x.0/24 | Docker 内部网段 |

## 文件说明

```
fw.sh           # 防火墙配置脚本
fw_test.sh      # 单元测试（74 个测试用例，mock 方式运行，无需 root）
```

运行时生成的文件：

| 路径 | 说明 |
|------|------|
| `/etc/nftables.conf` | 持久化规则（仅自定义表） |
| `/etc/nftables.system_type` | 系统类型标记 |
| `/etc/nftables.backup/` | 规则备份目录 |

## 单元测试

```bash
bash fw_test.sh
```

测试通过 mock 函数模拟 `nft` / `systemctl` 等命令，无需 root 权限，不影响系统规则。

## Docker 兼容说明

脚本**不使用** `systemctl restart/stop nftables`（其 `ExecStop` 会 `flush ruleset` 清掉 Docker 的 iptables-nft 链），而是：

- `init` — 通过 `nft add` 命令直接添加规则（立即生效），仅 `systemctl enable` 确保开机自启
- `stop` — 仅 `nft delete table` 删除自定义表，Docker 规则完全不受影响
- `save_rules` — 仅导出 `fw_filter` 和 `fw_ddos` 两张自定义表

如果因其他原因导致 Docker 网络异常，执行 `sudo systemctl restart docker` 即可恢复。

## 调试

```bash
sudo DEBUG=1 bash fw.sh init blog
```

设置 `DEBUG=1` 会输出每个 nft 命令的详细信息。

## License

Copyright (c) 2025 by jiaopengzi, All Rights Reserved.
