#!/bin/bash
# FilePath    : firewall/fw.sh
# Author      : jiaopengzi
# Blog        : https://jiaopengzi.com
# Copyright   : Copyright (c) 2025 by jiaopengzi, All Rights Reserved.
# Description : nftables 防火墙配置脚本(兼容 Docker), 支持 blog/billing/mail 三套系统.

set -euo pipefail

# =============================================================================
# 用户配置项(请根据实际环境修改)
# =============================================================================

# SSH 端口(自动从 sshd_config 读取, 读取失败回退到默认值 22)
SSH_PORT=$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1)
SSH_PORT="${SSH_PORT:-22}"

# SSH 暴力破解防护参数
SSH_RATE_LIMIT="5/minute"  # 速率限制
SSH_BURST_LIMIT=5          # 突发限制(包)
SSH_BLOCK_TIMEOUT="5m"     # 封禁时长

# Web 服务端口
WEB_PORTS="80, 443"

# 邮件服务端口
MAIL_PORTS="25, 143, 465, 587, 993"

# Blog 系统数据库端口(默认关闭对外访问)
BLOG_DB_PORTS="5432"         # pgsql
BLOG_REDIS_PORTS="7002-7007" # redis cluster
BLOG_ES_PORTS="9200, 9300"   # elasticsearch

# Billing Center 数据库端口(默认关闭对外访问)
BILLING_DB_PORTS="5433"         # pgsql
BILLING_REDIS_PORTS="8002-8007" # redis cluster

# Docker 内部网段(允许内部通信, 逗号分隔)
# 172.16.0.0/12 覆盖 Docker 默认网段; 178.18.x.0/24 为自定义 Docker 网段
DOCKER_INTERNAL_SUBNETS="172.16.0.0/12, 178.18.10.0/24, 178.18.11.0/24, 178.18.12.0/24, 178.18.13.0/24, 178.18.14.0/24, 178.18.15.0/24, 178.18.16.0/24, 178.18.17.0/24, 178.18.18.0/24"

# nftables 配置文件路径
NFTABLES_CONF="/etc/nftables.conf"

# 备份目录
BACKUP_DIR="/etc/nftables.backup"

# =============================================================================
# 内部常量(不建议修改)
# =============================================================================

# nftables 自定义表名
TABLE_FILTER="fw_filter"
TABLE_DDOS="fw_ddos"

# 系统类型标记文件(记录 init 时选择的系统类型)
SYSTEM_TYPE_FILE="/etc/nftables.system_type"

# 规则注释标记(用于查找和删除规则)
BLOG_DB_COMMENT="blog-db-block"
BLOG_REDIS_COMMENT="blog-redis-block"
BLOG_ES_COMMENT="blog-es-block"
BILLING_DB_COMMENT="billing-db-block"
BILLING_REDIS_COMMENT="billing-redis-block"

# 脚本名称
SCRIPT_NAME=$(basename "$0")

# =============================================================================
# 日志函数
# =============================================================================

# 输出信息日志(绿色)
log_info() {
    echo -e "\033[32m[INFO]\033[0m $*"
}

# 输出警告日志(黄色)
log_warn() {
    echo -e "\033[33m[WARN]\033[0m $*"
}

# 输出错误日志(红色)
log_error() {
    echo -e "\033[31m[ERROR]\033[0m $*"
}

# 输出调试日志(青色, 需要 DEBUG=1)
log_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "\033[36m[DEBUG]\033[0m $*"
    fi
}

# =============================================================================
# 检查函数
# =============================================================================

# 检查是否以 root 用户运行
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log_error "请以 root 用户运行此脚本(使用 sudo)"
        exit 1
    fi
}

# 检查 nftables 是否已安装
check_nft_installed() {
    command -v nft &>/dev/null
}

# 安装 nftables(如果未安装)
install_nftables() {
    log_info "检查 nftables 是否已安装..."
    if check_nft_installed; then
        log_info "nftables 已安装, 版本: $(nft --version 2>/dev/null | head -n1)"
        return 0
    fi

    log_info "nftables 未安装, 正在安装..."
    apt update
    apt install -y nftables
    log_info "nftables 安装完成"

    systemctl enable nftables 2>/dev/null || true
}

# =============================================================================
# 备份函数
# =============================================================================

# 备份当前 nftables 规则集
backup_rules() {
    local backup_file
    mkdir -p "$BACKUP_DIR"
    backup_file="$BACKUP_DIR/nftables.backup.$(date +%Y%m%d_%H%M%S)"
    log_info "备份当前规则到 $backup_file"
    nft list ruleset > "$backup_file" 2>/dev/null || true
    echo "$backup_file"
}

# =============================================================================
# 核心 nftables 函数
# =============================================================================

# 删除自定义表(不影响 Docker 自动生成的规则)
delete_custom_tables() {
    log_debug "删除自定义表"
    nft delete table inet "$TABLE_FILTER" 2>/dev/null || true
    nft delete table inet "$TABLE_DDOS" 2>/dev/null || true
}

# 创建主过滤表
create_filter_table() {
    log_debug "创建主过滤表 inet $TABLE_FILTER"
    nft add table inet "$TABLE_FILTER"
}

# 创建 Docker 子网命名集合(用于统一匹配内部网段)
create_docker_subnets_set() {
    log_debug "创建 Docker 子网集合"
    nft add set inet "$TABLE_FILTER" docker_subnets \
        '{' type ipv4_addr \; flags interval \; '}'
    # shellcheck disable=SC2086
    nft add element inet "$TABLE_FILTER" docker_subnets \
        '{' $DOCKER_INTERNAL_SUBNETS '}'
}

# 创建 input 链(默认策略: 丢弃)
create_input_chain() {
    log_debug "创建 input 链"
    nft add chain inet "$TABLE_FILTER" input \
        '{' type filter hook input priority 0 \; policy drop \; '}'
}

# 创建 forward 链(优先级 -1, 高于 Docker 的 iptables 规则; 默认策略: 接受)
create_forward_chain() {
    log_debug "创建 forward 链"
    nft add chain inet "$TABLE_FILTER" forward \
        '{' type filter hook forward priority -1 \; policy accept \; '}'
}

# 创建 output 链(默认策略: 接受)
create_output_chain() {
    log_debug "创建 output 链"
    nft add chain inet "$TABLE_FILTER" output \
        '{' type filter hook output priority 0 \; policy accept \; '}'
}

# 添加 input 链基础规则
add_input_base_rules() {
    log_debug "添加 input 链基础规则"

    # 回环接口无条件放行
    nft add rule inet "$TABLE_FILTER" input iif lo accept

    # 已建立连接和相关连接放行
    nft add rule inet "$TABLE_FILTER" input ct state established,related accept

    # Docker 桥接接口放行
    nft add rule inet "$TABLE_FILTER" input iifname "docker0" accept

    # Docker 内部网段放行(使用命名集合)
    nft add rule inet "$TABLE_FILTER" input ip saddr @docker_subnets accept

    # ICMP(IPv4)放行
    nft add rule inet "$TABLE_FILTER" input ip protocol icmp accept

    # ICMPv6 精细放行(避免过于宽泛)
    nft add rule inet "$TABLE_FILTER" input ip6 nexthdr icmpv6 icmpv6 type \
        '{' destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit '}' accept
}

# 添加 Web 端口放行规则
add_web_port_rules() {
    log_debug "添加 Web 端口规则: $WEB_PORTS"
    # shellcheck disable=SC2086
    nft add rule inet "$TABLE_FILTER" input tcp dport '{' $WEB_PORTS '}' accept
}

# 添加邮件端口放行规则
add_mail_port_rules() {
    log_debug "添加邮件端口规则: $MAIL_PORTS"
    # shellcheck disable=SC2086
    nft add rule inet "$TABLE_FILTER" input tcp dport '{' $MAIL_PORTS '}' accept
}

# 添加 SSH 端口放行规则(兜底规则, DDoS 表优先处理)
add_ssh_port_rules() {
    log_debug "添加 SSH 端口规则: $SSH_PORT"
    nft add rule inet "$TABLE_FILTER" input tcp dport "$SSH_PORT" accept
}

# 添加 input 链末尾显式丢弃规则
add_input_drop_rule() {
    log_debug "添加 input 链末尾 drop 规则"
    nft add rule inet "$TABLE_FILTER" input drop
}

# 添加 forward 链基础规则
add_forward_base_rules() {
    log_debug "添加 forward 链基础规则"

    # 已建立连接放行
    nft add rule inet "$TABLE_FILTER" forward ct state established,related accept

    # Docker 内部网段放行(容器间及容器到外网通信)
    nft add rule inet "$TABLE_FILTER" forward ip saddr @docker_subnets accept
}

# 添加 forward 链 blog 数据库端口阻断规则
add_forward_blog_db_block_rules() {
    log_debug "添加 forward blog 数据库端口阻断规则"
    # shellcheck disable=SC2086
    nft add rule inet "$TABLE_FILTER" forward \
        tcp dport '{' $BLOG_DB_PORTS '}' drop comment "$BLOG_DB_COMMENT"
    # shellcheck disable=SC2086
    nft add rule inet "$TABLE_FILTER" forward \
        tcp dport '{' $BLOG_REDIS_PORTS '}' drop comment "$BLOG_REDIS_COMMENT"
    # shellcheck disable=SC2086
    nft add rule inet "$TABLE_FILTER" forward \
        tcp dport '{' $BLOG_ES_PORTS '}' drop comment "$BLOG_ES_COMMENT"
}

# 添加 forward 链 billing 数据库端口阻断规则
add_forward_billing_db_block_rules() {
    log_debug "添加 forward billing 数据库端口阻断规则"
    # shellcheck disable=SC2086
    nft add rule inet "$TABLE_FILTER" forward \
        tcp dport '{' $BILLING_DB_PORTS '}' drop comment "$BILLING_DB_COMMENT"
    # shellcheck disable=SC2086
    nft add rule inet "$TABLE_FILTER" forward \
        tcp dport '{' $BILLING_REDIS_PORTS '}' drop comment "$BILLING_REDIS_COMMENT"
}

# =============================================================================
# DDoS 防护函数
# =============================================================================

# 创建 DDoS 防护表
create_ddos_table() {
    log_debug "创建 DDoS 防护表 inet $TABLE_DDOS"
    nft add table inet "$TABLE_DDOS"
}

# 创建 DDoS 黑名单集合(支持动态添加和超时)
create_ddos_sets() {
    log_debug "创建黑名单集合"
    nft add set inet "$TABLE_DDOS" blocklist4 \
        '{' type ipv4_addr \; flags timeout, dynamic \; '}'
    nft add set inet "$TABLE_DDOS" blocklist6 \
        '{' type ipv6_addr \; flags timeout, dynamic \; '}'
}

# 创建 DDoS input 链(优先级 -10, 高于主 input 链, 实现黑名单提前拦截)
create_ddos_input_chain() {
    log_debug "创建 DDoS input 链"
    nft add chain inet "$TABLE_DDOS" input \
        '{' type filter hook input priority -10 \; '}'
}

# 添加 DDoS 防护规则
add_ddos_rules() {
    log_debug "添加 DDoS 防护规则"

    # 黑名单中的 IP 直接丢弃
    nft add rule inet "$TABLE_DDOS" input ip saddr @blocklist4 drop
    nft add rule inet "$TABLE_DDOS" input ip6 saddr @blocklist6 drop

    # 已建立连接放行(防止已连接用户被限速规则影响)
    nft add rule inet "$TABLE_DDOS" input ct state established,related accept

    # SSH 暴力破解防护: 超限加入黑名单并丢弃
    nft add rule inet "$TABLE_DDOS" input tcp dport "$SSH_PORT" ct state new \
        limit rate over "$SSH_RATE_LIMIT" burst "$SSH_BURST_LIMIT" packets \
        add @blocklist4 '{' ip saddr timeout "$SSH_BLOCK_TIMEOUT" '}' drop

    # 放行未超限的 SSH 新连接
    nft add rule inet "$TABLE_DDOS" input tcp dport "$SSH_PORT" ct state new accept
}

# =============================================================================
# 规则保存与加载函数
# =============================================================================

# 保存当前规则集到配置文件(仅保存自定义表, 避免与 Docker iptables-nft 规则重复)
save_rules() {
    log_info "保存规则到 $NFTABLES_CONF"
    {
        echo '#!/usr/sbin/nft -f'
        echo ''
        # 先创建空表(如果不存在则创建, 已存在则无操作), 再删除, 确保幂等
        echo "table inet $TABLE_FILTER"
        echo "delete table inet $TABLE_FILTER"
        echo "table inet $TABLE_DDOS"
        echo "delete table inet $TABLE_DDOS"
        echo ''
        nft list table inet "$TABLE_FILTER" 2>/dev/null || true
        nft list table inet "$TABLE_DDOS" 2>/dev/null || true
    } > "$NFTABLES_CONF"
}

# 设置 nftables 开机自启(不重启服务, 避免 flush ruleset 破坏 Docker 规则)
enable_nftables_service() {
    log_debug "设置 nftables 开机自启"
    systemctl enable nftables 2>/dev/null || true
}

# =============================================================================
# 规则查找与删除函数
# =============================================================================

# 删除指定 comment 标记的规则
# 参数: $1=表名, $2=链名, $3=comment 关键字
delete_rules_by_comment() {
    local table="$1"
    local chain="$2"
    local comment="$3"

    if ! nft list chain inet "$table" "$chain" &>/dev/null; then
        log_warn "链 inet $table $chain 未找到, 请先运行 '$SCRIPT_NAME init'"
        return 1
    fi

    local rules handles
    rules=$(nft --handle list chain inet "$table" "$chain")
    handles=$(echo "$rules" | grep "$comment" | awk '{print $NF}') || true

    if [[ -z "$handles" ]]; then
        log_warn "未找到 $comment 相关规则"
        return 0
    fi

    local h
    for h in $handles; do
        log_debug "删除规则句柄: $h ($comment)"
        nft delete rule inet "$table" "$chain" handle "$h"
    done

    log_info "已删除 $comment 相关规则"
}

# 检查指定 comment 标记的规则是否存在
# 参数: $1=表名, $2=链名, $3=comment 关键字
check_rules_exist() {
    local table="$1"
    local chain="$2"
    local comment="$3"

    if ! nft list chain inet "$table" "$chain" &>/dev/null; then
        return 1
    fi

    nft list chain inet "$table" "$chain" 2>/dev/null | grep -q "$comment"
}

# =============================================================================
# 数据库端口管理函数(细粒度: pgsql/redis/es 独立控制)
# =============================================================================

# 通用: 开放指定 comment 对应的端口
# 参数: $1=comment, $2=端口描述
_open_port_by_comment() {
    local comment="$1"
    local desc="$2"

    delete_rules_by_comment "$TABLE_FILTER" "forward" "$comment"
    save_rules
    log_info "$desc 端口已开放"
}

# 通用: 关闭指定 comment 对应的端口
# 参数: $1=comment, $2=端口描述, $3=端口值, $4=drop 注释
_close_port_by_comment() {
    local comment="$1"
    local desc="$2"
    local ports="$3"

    if check_rules_exist "$TABLE_FILTER" "forward" "$comment"; then
        log_warn "$desc 端口已处于关闭状态"
        return 0
    fi

    # shellcheck disable=SC2086
    nft add rule inet "$TABLE_FILTER" forward \
        tcp dport '{' $ports '}' drop comment "$comment"
    save_rules
    log_info "$desc 端口已关闭"
}

# --- Blog 系统 ---

open_blog_pgsql() {
    _open_port_by_comment "$BLOG_DB_COMMENT" "blog pgsql($BLOG_DB_PORTS)"
}

close_blog_pgsql() {
    _close_port_by_comment "$BLOG_DB_COMMENT" "blog pgsql($BLOG_DB_PORTS)" "$BLOG_DB_PORTS"
}

open_blog_redis() {
    _open_port_by_comment "$BLOG_REDIS_COMMENT" "blog redis($BLOG_REDIS_PORTS)"
}

close_blog_redis() {
    _close_port_by_comment "$BLOG_REDIS_COMMENT" "blog redis($BLOG_REDIS_PORTS)" "$BLOG_REDIS_PORTS"
}

open_blog_es() {
    _open_port_by_comment "$BLOG_ES_COMMENT" "blog es($BLOG_ES_PORTS)"
}

close_blog_es() {
    _close_port_by_comment "$BLOG_ES_COMMENT" "blog es($BLOG_ES_PORTS)" "$BLOG_ES_PORTS"
}

# --- Billing 系统 ---

open_billing_pgsql() {
    _open_port_by_comment "$BILLING_DB_COMMENT" "billing pgsql($BILLING_DB_PORTS)"
}

close_billing_pgsql() {
    _close_port_by_comment "$BILLING_DB_COMMENT" "billing pgsql($BILLING_DB_PORTS)" "$BILLING_DB_PORTS"
}

open_billing_redis() {
    _open_port_by_comment "$BILLING_REDIS_COMMENT" "billing redis($BILLING_REDIS_PORTS)"
}

close_billing_redis() {
    _close_port_by_comment "$BILLING_REDIS_COMMENT" "billing redis($BILLING_REDIS_PORTS)" "$BILLING_REDIS_PORTS"
}

# =============================================================================
# 主操作函数
# =============================================================================

# 初始化防火墙(创建所有规则, 首次使用必须执行)
# 参数: $1=系统类型(blog/billing/mail)
fw_init() {
    local system_type="${1:-}"

    if [[ -z "$system_type" ]]; then
        log_error "请指定系统类型: $SCRIPT_NAME init <blog|billing|mail>"
        exit 1
    fi

    case "$system_type" in
        blog|billing|mail) ;;
        *)
            log_error "未知系统类型: '$system_type' (可选: blog, billing, mail)"
            exit 1
            ;;
    esac

    check_root
    install_nftables
    backup_rules

    log_info "开始初始化防火墙(系统: $system_type)..."

    # 删除旧的自定义表(不破坏 Docker 自动生成的规则)
    delete_custom_tables

    # 创建主过滤表和链
    create_filter_table
    create_docker_subnets_set
    create_input_chain
    create_forward_chain
    create_output_chain

    # 添加 input 规则
    add_input_base_rules

    case "$system_type" in
        blog)
            add_web_port_rules
            add_ssh_port_rules
            add_input_drop_rule
            # forward 规则
            add_forward_base_rules
            add_forward_blog_db_block_rules
            ;;
        billing)
            add_web_port_rules
            add_ssh_port_rules
            add_input_drop_rule
            # forward 规则
            add_forward_base_rules
            add_forward_billing_db_block_rules
            ;;
        mail)
            add_web_port_rules
            add_mail_port_rules
            add_ssh_port_rules
            add_input_drop_rule
            # forward 规则
            add_forward_base_rules
            ;;
    esac

    # 创建 DDoS 防护
    create_ddos_table
    create_ddos_sets
    create_ddos_input_chain
    add_ddos_rules

    # 保存系统类型标记
    echo "$system_type" > "$SYSTEM_TYPE_FILE"

    # 保存并设置开机自启(规则已通过 nft 命令生效, 无需 restart 服务)
    save_rules
    enable_nftables_service

    log_info "防火墙初始化完成! (系统: $system_type)"
    log_info "当前规则摘要:"
    nft list ruleset | grep -E "chain (input|forward|output)|tcp dport|limit rate|blocklist|comment" || true

    echo ""
    echo "======================================================"
    echo "⚠️  重要: 请保持当前 SSH 连接不要关闭,"
    echo "    另开一个终端测试 SSH 端口 $SSH_PORT 是否可正常登录."
    echo "    如果测试失败, 请恢复备份规则."
    echo "======================================================"
}

# 启动防火墙(加载已保存的规则)
fw_start() {
    check_root

    if ! check_nft_installed; then
        log_error "nftables 未安装, 请先运行 '$SCRIPT_NAME init'"
        exit 1
    fi

    if [[ ! -f "$NFTABLES_CONF" ]]; then
        log_error "未找到配置文件 $NFTABLES_CONF, 请先运行 '$SCRIPT_NAME init'"
        exit 1
    fi

    log_info "启动防火墙..."
    nft -f "$NFTABLES_CONF"
    enable_nftables_service
    log_info "防火墙已启动"
}

# 停止防火墙(仅清除自定义规则, 不触碰 Docker 规则)
fw_stop() {
    check_root

    log_info "停止防火墙..."
    delete_custom_tables
    log_info "防火墙已停止(自定义规则已清除, Docker 规则保留)"
}

# 查看防火墙状态
fw_status() {
    if ! check_nft_installed; then
        log_error "nftables 未安装"
        exit 1
    fi

    echo "========== nftables 服务状态 =========="
    systemctl is-active nftables 2>/dev/null || echo "inactive"

    echo ""
    echo "========== 当前规则集 =========="
    nft list ruleset 2>/dev/null || echo "无规则"

    echo ""
    echo "========== 端口状态 =========="

    # 读取系统类型标记
    local sys_type="unknown"
    if [[ -f "$SYSTEM_TYPE_FILE" ]]; then
        sys_type=$(cat "$SYSTEM_TYPE_FILE")
    fi
    echo "系统类型: $sys_type"
    echo ""

    if nft list chain inet "$TABLE_FILTER" input &>/dev/null; then
        local input_rules
        input_rules=$(nft list chain inet "$TABLE_FILTER" input 2>/dev/null)

        echo "[入站端口]"
        local _s
        _s="已关闭"; echo "$input_rules" | grep -q "tcp dport.*80" && _s="已开放"
        echo "  Web   ($WEB_PORTS):                $_s"

        if [[ "$sys_type" == "mail" ]]; then
            _s="已关闭"; echo "$input_rules" | grep -q "tcp dport.*25" && _s="已开放"
            echo "  Mail  ($MAIL_PORTS):  $_s"
        fi

        _s="已关闭"; echo "$input_rules" | grep -q "tcp dport.*$SSH_PORT" && _s="已开放"
        echo "  SSH   ($SSH_PORT):                      $_s"
    fi

    if nft list chain inet "$TABLE_FILTER" forward &>/dev/null; then
        local rules
        rules=$(nft list chain inet "$TABLE_FILTER" forward 2>/dev/null)

        case "$sys_type" in
            blog)
                echo ""
                echo "[Blog 数据库端口]"
                local _status
                _status="已关闭"; echo "$rules" | grep -q "$BLOG_DB_COMMENT" || _status="已开放"
                echo "  pgsql ($BLOG_DB_PORTS):       $_status"
                _status="已关闭"; echo "$rules" | grep -q "$BLOG_REDIS_COMMENT" || _status="已开放"
                echo "  redis ($BLOG_REDIS_PORTS):  $_status"
                _status="已关闭"; echo "$rules" | grep -q "$BLOG_ES_COMMENT" || _status="已开放"
                echo "  es    ($BLOG_ES_PORTS):  $_status"
                ;;
            billing)
                echo ""
                echo "[Billing 数据库端口]"
                local _status
                _status="已关闭"; echo "$rules" | grep -q "$BILLING_DB_COMMENT" || _status="已开放"
                echo "  pgsql ($BILLING_DB_PORTS):       $_status"
                _status="已关闭"; echo "$rules" | grep -q "$BILLING_REDIS_COMMENT" || _status="已开放"
                echo "  redis ($BILLING_REDIS_PORTS):  $_status"
                ;;
            mail)
                echo ""
                echo "[Mail 系统无数据库端口管理]"
                ;;
        esac
    else
        echo "防火墙未初始化"
    fi
}

# =============================================================================
# 帮助信息
# =============================================================================

# 显示帮助信息
show_help() {
    cat <<EOF
用法: $SCRIPT_NAME <命令> [参数]

nftables 防火墙配置脚本(兼容 Docker)
支持系统: Blog Web 服务, Billing Center, 邮件服务

命令:
    init <系统>                   初始化防火墙(首次使用必须执行)
    start                         启动防火墙(加载已保存的规则)
    stop                          停止防火墙(清除自定义规则, 保留 Docker 规则)
    status                        查看防火墙状态和规则
    db-open <系统> <服务>         开放指定系统的指定服务端口
    db-close <系统> <服务>        关闭指定系统的指定服务端口(默认状态)
    -h, --help                    显示此帮助信息

系统名称:
    blog                Blog 系统(Web + 数据库服务)
    billing             Billing Center(Web + 数据库服务)
    mail                邮件系统(Web + 邮件服务, 无数据库端口管理)

服务名称:
    pgsql               PostgreSQL  (blog: $BLOG_DB_PORTS, billing: $BILLING_DB_PORTS)
    redis               Redis       (blog: $BLOG_REDIS_PORTS, billing: $BILLING_REDIS_PORTS)
    es                  Elasticsearch(仅 blog: $BLOG_ES_PORTS)

默认开放的服务端口:
    Web:    $WEB_PORTS
    Mail:   $MAIL_PORTS
    SSH:    $SSH_PORT

示例:
    $SCRIPT_NAME init blog                  # 初始化 blog 系统防火墙
    $SCRIPT_NAME init billing               # 初始化 billing 系统防火墙
    $SCRIPT_NAME init mail                  # 初始化邮件系统防火墙
    $SCRIPT_NAME start                      # 启动防火墙
    $SCRIPT_NAME stop                       # 停止防火墙
    $SCRIPT_NAME status                     # 查看状态
    $SCRIPT_NAME db-open blog pgsql         # 开放 blog PostgreSQL 端口
    $SCRIPT_NAME db-open blog redis         # 开放 blog Redis 端口
    $SCRIPT_NAME db-open blog es            # 开放 blog Elasticsearch 端口
    $SCRIPT_NAME db-close blog pgsql        # 关闭 blog PostgreSQL 端口
    $SCRIPT_NAME db-open billing pgsql      # 开放 billing PostgreSQL 端口
    $SCRIPT_NAME db-open billing redis      # 开放 billing Redis 端口
    $SCRIPT_NAME db-close billing redis     # 关闭 billing Redis 端口

注意:
    - 必须以 root 用户运行(init/start/stop/db-open/db-close)
    - 初始化后会自动保存规则到 $NFTABLES_CONF
    - 数据库端口默认关闭, 需要时手动开放
    - 停止防火墙不会清除 Docker 自身的规则
    - 设置 DEBUG=1 环境变量可查看调试信息
EOF
}

# =============================================================================
# 主入口
# =============================================================================

# 主函数, 解析命令行参数并调用对应操作
main() {
    local command="${1:-}"
    local arg="${2:-}"

    case "$command" in
        init)
            fw_init "$arg"
            ;;
        start)
            fw_start
            ;;
        stop)
            fw_stop
            ;;
        status)
            fw_status
            ;;
        db-open)
            check_root
            local service="${3:-}"
            case "$arg" in
                blog)
                    case "$service" in
                        pgsql) open_blog_pgsql ;;
                        redis) open_blog_redis ;;
                        es)    open_blog_es ;;
                        *)     log_error "未知服务: '$service' (可选: pgsql, redis, es)"; exit 1 ;;
                    esac
                    ;;
                billing)
                    case "$service" in
                        pgsql) open_billing_pgsql ;;
                        redis) open_billing_redis ;;
                        *)     log_error "未知服务: '$service' (可选: pgsql, redis)"; exit 1 ;;
                    esac
                    ;;
                *)
                    log_error "未知系统: '$arg' (可选: blog, billing)"
                    exit 1
                    ;;
            esac
            ;;
        db-close)
            check_root
            local service="${3:-}"
            case "$arg" in
                blog)
                    case "$service" in
                        pgsql) close_blog_pgsql ;;
                        redis) close_blog_redis ;;
                        es)    close_blog_es ;;
                        *)     log_error "未知服务: '$service' (可选: pgsql, redis, es)"; exit 1 ;;
                    esac
                    ;;
                billing)
                    case "$service" in
                        pgsql) close_billing_pgsql ;;
                        redis) close_billing_redis ;;
                        *)     log_error "未知服务: '$service' (可选: pgsql, redis)"; exit 1 ;;
                    esac
                    ;;
                *)
                    log_error "未知系统: '$arg' (可选: blog, billing)"
                    exit 1
                    ;;
            esac
            ;;
        -h|--help)
            show_help
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

# 直接运行时执行 main, 被 source 时不执行(便于单元测试)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
