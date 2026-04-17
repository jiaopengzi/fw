#!/bin/bash
# FilePath    : firewall/fw_test.sh
# Author      : jiaopengzi
# Blog        : https://jiaopengzi.com
# Copyright   : Copyright (c) 2025 by jiaopengzi, All Rights Reserved.
# Description : fw.sh 单元测试脚本, 通过 mock 函数模拟 nft/systemctl 等命令进行测试.

# SC2329/SC2317: 测试函数通过变量名间接调用, shellcheck 误报不可达
# SC2034: 测试框架变量在子 shell 或动态场景中使用
# SC1091: source 路径在运行时确定
# shellcheck disable=SC2329,SC2317,SC2034,SC1091

set -euo pipefail

# =============================================================================
# 测试框架
# =============================================================================

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# 测试临时目录
TEST_TMP_DIR=$(mktemp -d)
NFT_CMD_LOG="$TEST_TMP_DIR/nft_commands.log"

# 颜色常量
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
NC='\033[0m'

# Mock 控制变量
MOCK_NFT_HANDLE_OUTPUT=""
MOCK_NFT_LIST_OUTPUT=""
MOCK_CHAIN_EXISTS=1

# =============================================================================
# 测试框架函数
# =============================================================================

# 每个测试前的初始化
setup() {
    true > "$NFT_CMD_LOG"
    rm -f "$TEST_TMP_DIR/system_type"
    MOCK_NFT_HANDLE_OUTPUT=""
    MOCK_NFT_LIST_OUTPUT=""
    MOCK_CHAIN_EXISTS=1
}

# 运行单个测试
run_test() {
    local test_name="$1"
    local test_func="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    setup

    local output
    if output=$($test_func 2>&1); then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}  ✓${NC} $test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS+=("$test_name")
        echo -e "${RED}  ✗${NC} $test_name"
        if [[ -n "$output" ]]; then
            echo -e "    ${RED}$output${NC}"
        fi
    fi
}

# 断言: 期望值等于实际值
assert_eq() {
    local expected="$1"
    local actual="$2"
    local msg="${3:-}"

    if [[ "$expected" != "$actual" ]]; then
        echo "断言失败${msg:+: $msg}
  期望: '$expected'
  实际: '$actual'"
        return 1
    fi
}

# 断言: 字符串包含子串
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="${3:-}"

    if [[ "$haystack" != *"$needle"* ]]; then
        echo "断言失败${msg:+: $msg}
  未找到: '$needle'"
        return 1
    fi
}

# 断言: 字符串不包含子串
assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="${3:-}"

    if [[ "$haystack" == *"$needle"* ]]; then
        echo "断言失败${msg:+: $msg}
  不应包含: '$needle'"
        return 1
    fi
}

# 断言: 文件包含指定文本
assert_file_contains() {
    local file="$1"
    local pattern="$2"
    local msg="${3:-}"

    if ! grep -q "$pattern" "$file" 2>/dev/null; then
        echo "断言失败${msg:+: $msg}
  文件 '$file' 不包含: '$pattern'"
        return 1
    fi
}

# 断言: 文件不包含指定文本
assert_file_not_contains() {
    local file="$1"
    local pattern="$2"
    local msg="${3:-}"

    if grep -q "$pattern" "$file" 2>/dev/null; then
        echo "断言失败${msg:+: $msg}
  文件 '$file' 不应包含: '$pattern'"
        return 1
    fi
}

# =============================================================================
# Mock 函数(在 source fw.sh 之前定义)
# =============================================================================

# Mock nft 命令
nft() {
    echo "nft $*" >> "$NFT_CMD_LOG"

    if [[ "$*" == *"--version"* ]]; then
        echo "nftables v1.0.0 (Lester Gooch #5)"
        return 0
    fi

    if [[ "$*" == *"list chain"* ]]; then
        # 检查是否模拟链不存在
        if [[ "$MOCK_CHAIN_EXISTS" == "0" ]]; then
            echo "Error: No such file or directory" >&2
            return 1
        fi

        # 带 --handle 的列表(返回句柄)
        if [[ "$*" == *"--handle"* ]]; then
            if [[ -n "$MOCK_NFT_HANDLE_OUTPUT" ]]; then
                echo "$MOCK_NFT_HANDLE_OUTPUT"
            else
                echo 'table inet fw_filter {'
                echo '  chain forward {'
                echo '    type filter hook forward priority -1; policy accept;'
                echo '  }'
                echo '}'
            fi
            return 0
        fi

        # 普通列表(用于存在性检查和规则查找)
        if [[ -n "$MOCK_NFT_LIST_OUTPUT" ]]; then
            echo "$MOCK_NFT_LIST_OUTPUT"
        else
            echo 'table inet fw_filter {'
            echo '  chain forward {'
            echo '    type filter hook forward priority -1; policy accept;'
            echo '  }'
            echo '}'
        fi
        return 0
    fi

    if [[ "$*" == *"list ruleset"* ]]; then
        echo "# mock ruleset"
        return 0
    fi

    return 0
}

# Mock systemctl 命令
systemctl() {
    echo "systemctl $*" >> "$NFT_CMD_LOG"
    case "$*" in
        "is-active nftables"*)
            echo "active"
            ;;
    esac
    return 0
}

# Mock apt 命令
apt() {
    echo "apt $*" >> "$NFT_CMD_LOG"
    return 0
}

# =============================================================================
# 加载被测脚本
# =============================================================================

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Source fw.sh(不会执行 main, 因为 BASH_SOURCE[0] != $0)
# shellcheck source=fw.sh
source "$SCRIPT_DIR/fw.sh"

# 覆盖配置(使用临时目录避免写入系统文件, 必须在 source 之后)
NFTABLES_CONF="$TEST_TMP_DIR/nftables.conf"
BACKUP_DIR="$TEST_TMP_DIR/backup"
SYSTEM_TYPE_FILE="$TEST_TMP_DIR/system_type"

# 覆盖 SSH_PORT(测试环境可能无 sshd_config, 统一设为 2222)
SSH_PORT=2222

# 覆盖 check_root(测试环境不需要 root 权限)
check_root() {
    return 0
}

# =============================================================================
# 测试用例: 日志函数
# =============================================================================

test_log_info_format() {
    local output
    output=$(log_info "test message")
    assert_contains "$output" "[INFO]" "log_info 应包含 [INFO] 标记"
    assert_contains "$output" "test message" "log_info 应包含消息内容"
}

test_log_warn_format() {
    local output
    output=$(log_warn "warning message")
    assert_contains "$output" "[WARN]" "log_warn 应包含 [WARN] 标记"
    assert_contains "$output" "warning message" "log_warn 应包含消息内容"
}

test_log_error_format() {
    local output
    output=$(log_error "error message")
    assert_contains "$output" "[ERROR]" "log_error 应包含 [ERROR] 标记"
    assert_contains "$output" "error message" "log_error 应包含消息内容"
}

test_log_debug_off() {
    local output
    DEBUG=0
    output=$(log_debug "debug message")
    assert_eq "" "$output" "DEBUG=0 时 log_debug 不应输出"
}

test_log_debug_on() {
    local output
    DEBUG=1
    output=$(log_debug "debug message")
    DEBUG=0
    assert_contains "$output" "[DEBUG]" "DEBUG=1 时 log_debug 应包含 [DEBUG] 标记"
    assert_contains "$output" "debug message" "DEBUG=1 时 log_debug 应包含消息内容"
}

# =============================================================================
# 测试用例: 帮助信息
# =============================================================================

test_show_help_contains_usage() {
    local output
    output=$(show_help)
    assert_contains "$output" "用法:" "帮助信息应包含 '用法:'"
}

test_show_help_contains_commands() {
    local output
    output=$(show_help)
    assert_contains "$output" "init" "帮助信息应包含 init 命令"
    assert_contains "$output" "start" "帮助信息应包含 start 命令"
    assert_contains "$output" "stop" "帮助信息应包含 stop 命令"
    assert_contains "$output" "status" "帮助信息应包含 status 命令"
    assert_contains "$output" "db-open" "帮助信息应包含 db-open 命令"
    assert_contains "$output" "db-close" "帮助信息应包含 db-close 命令"
}

test_show_help_contains_systems() {
    local output
    output=$(show_help)
    assert_contains "$output" "blog" "帮助信息应包含 blog 系统"
    assert_contains "$output" "billing" "帮助信息应包含 billing 系统"
    assert_contains "$output" "mail" "帮助信息应包含 mail 系统"
}

test_show_help_contains_ports() {
    local output
    output=$(show_help)
    assert_contains "$output" "80, 443" "帮助信息应包含 Web 端口"
    assert_contains "$output" "25, 143, 465, 587, 993" "帮助信息应包含邮件端口"
    assert_contains "$output" "$SSH_PORT" "帮助信息应包含 SSH 端口"
}

# =============================================================================
# 测试用例: 检查函数
# =============================================================================

test_check_nft_installed_with_mock() {
    # nft 已被 mock 为函数, command -v 应能找到
    if check_nft_installed; then
        return 0
    fi
    echo "check_nft_installed 应返回 0(nft 函数已定义)"
    return 1
}

# =============================================================================
# 测试用例: 核心 nftables 函数
# =============================================================================

test_delete_custom_tables() {
    delete_custom_tables >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft delete table inet $TABLE_FILTER" \
        "应调用 nft delete table 删除 $TABLE_FILTER"
    assert_file_contains "$NFT_CMD_LOG" "nft delete table inet $TABLE_DDOS" \
        "应调用 nft delete table 删除 $TABLE_DDOS"
}

test_create_filter_table() {
    create_filter_table >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft add table inet $TABLE_FILTER" \
        "应调用 nft add table 创建 $TABLE_FILTER"
}

test_create_input_chain() {
    create_input_chain >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft add chain inet $TABLE_FILTER input" \
        "应调用 nft add chain 创建 input 链"
    assert_file_contains "$NFT_CMD_LOG" "policy drop" \
        "input 链默认策略应为 drop"
}

test_create_forward_chain() {
    create_forward_chain >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft add chain inet $TABLE_FILTER forward" \
        "应调用 nft add chain 创建 forward 链"
    assert_file_contains "$NFT_CMD_LOG" "priority -1" \
        "forward 链优先级应为 -1"
    assert_file_contains "$NFT_CMD_LOG" "policy accept" \
        "forward 链默认策略应为 accept"
}

test_create_output_chain() {
    create_output_chain >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft add chain inet $TABLE_FILTER output" \
        "应调用 nft add chain 创建 output 链"
    assert_file_contains "$NFT_CMD_LOG" "policy accept" \
        "output 链默认策略应为 accept"
}

test_create_docker_subnets_set() {
    create_docker_subnets_set >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft add set inet $TABLE_FILTER docker_subnets" \
        "应创建 docker_subnets 集合"
    assert_file_contains "$NFT_CMD_LOG" "nft add element inet $TABLE_FILTER docker_subnets" \
        "应向 docker_subnets 集合添加元素"
}

test_add_input_base_rules() {
    add_input_base_rules >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "iif lo accept" \
        "应放行回环接口"
    assert_file_contains "$NFT_CMD_LOG" "ct state established,related accept" \
        "应放行已建立连接"
    assert_file_contains "$NFT_CMD_LOG" 'iifname "docker0" accept' \
        "应放行 docker0 接口"
    assert_file_contains "$NFT_CMD_LOG" "@docker_subnets accept" \
        "应放行 Docker 内部网段"
    assert_file_contains "$NFT_CMD_LOG" "ip protocol icmp accept" \
        "应放行 ICMP"
}

test_add_web_port_rules() {
    add_web_port_rules >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "tcp dport" \
        "应添加 TCP 端口规则"
    assert_file_contains "$NFT_CMD_LOG" "80" \
        "应包含端口 80"
    assert_file_contains "$NFT_CMD_LOG" "443" \
        "应包含端口 443"
}

test_add_mail_port_rules() {
    add_mail_port_rules >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "25" "应包含端口 25"
    assert_file_contains "$NFT_CMD_LOG" "143" "应包含端口 143"
    assert_file_contains "$NFT_CMD_LOG" "465" "应包含端口 465"
    assert_file_contains "$NFT_CMD_LOG" "587" "应包含端口 587"
    assert_file_contains "$NFT_CMD_LOG" "993" "应包含端口 993"
}

test_add_ssh_port_rules() {
    add_ssh_port_rules >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "tcp dport $SSH_PORT accept" \
        "应添加 SSH 端口 $SSH_PORT 放行规则"
}

test_add_input_drop_rule() {
    add_input_drop_rule >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "input drop" \
        "应在 input 链末尾添加 drop 规则"
}

test_add_forward_base_rules() {
    add_forward_base_rules >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "forward ct state established,related accept" \
        "forward 链应放行已建立连接"
    assert_file_contains "$NFT_CMD_LOG" "forward ip saddr @docker_subnets accept" \
        "forward 链应放行 Docker 内部网段"
}

test_add_forward_blog_db_block_rules() {
    add_forward_blog_db_block_rules >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BLOG_DB_COMMENT" \
        "应包含 blog-db-block 注释"
    assert_file_contains "$NFT_CMD_LOG" "$BLOG_REDIS_COMMENT" \
        "应包含 blog-redis-block 注释"
    assert_file_contains "$NFT_CMD_LOG" "$BLOG_ES_COMMENT" \
        "应包含 blog-es-block 注释"
    assert_file_contains "$NFT_CMD_LOG" "5432" \
        "应包含 pgsql 端口 5432"
    assert_file_contains "$NFT_CMD_LOG" "7002-7007" \
        "应包含 redis 端口 7002-7007"
    assert_file_contains "$NFT_CMD_LOG" "9200" \
        "应包含 es 端口 9200"
}

test_add_forward_billing_db_block_rules() {
    add_forward_billing_db_block_rules >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BILLING_DB_COMMENT" \
        "应包含 billing-db-block 注释"
    assert_file_contains "$NFT_CMD_LOG" "$BILLING_REDIS_COMMENT" \
        "应包含 billing-redis-block 注释"
    assert_file_contains "$NFT_CMD_LOG" "5433" \
        "应包含 pgsql 端口 5433"
    assert_file_contains "$NFT_CMD_LOG" "8002-8007" \
        "应包含 redis 端口 8002-8007"
}

# =============================================================================
# 测试用例: DDoS 防护函数
# =============================================================================

test_create_ddos_table() {
    create_ddos_table >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft add table inet $TABLE_DDOS" \
        "应创建 DDoS 防护表"
}

test_create_ddos_sets() {
    create_ddos_sets >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "blocklist4" "应创建 IPv4 黑名单集合"
    assert_file_contains "$NFT_CMD_LOG" "blocklist6" "应创建 IPv6 黑名单集合"
}

test_create_ddos_input_chain() {
    create_ddos_input_chain >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft add chain inet $TABLE_DDOS input" \
        "应创建 DDoS input 链"
    assert_file_contains "$NFT_CMD_LOG" "priority -10" \
        "DDoS input 链优先级应为 -10"
}

test_add_ddos_rules() {
    add_ddos_rules >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "@blocklist4 drop" \
        "应添加 IPv4 黑名单丢弃规则"
    assert_file_contains "$NFT_CMD_LOG" "@blocklist6 drop" \
        "应添加 IPv6 黑名单丢弃规则"
    assert_file_contains "$NFT_CMD_LOG" "limit rate over" \
        "应添加速率限制规则"
    assert_file_contains "$NFT_CMD_LOG" "tcp dport $SSH_PORT ct state new accept" \
        "应添加 SSH 新连接放行规则"
}

# =============================================================================
# 测试用例: 规则查找与删除函数
# =============================================================================

test_delete_rules_by_comment_found() {
    MOCK_NFT_HANDLE_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
    tcp dport { 5432 } drop comment "blog-db-block" # handle 10
    tcp dport { 7002-7007 } drop comment "blog-redis-block" # handle 11
  }
}'
    delete_rules_by_comment "$TABLE_FILTER" "forward" "$BLOG_DB_COMMENT" >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft delete rule inet $TABLE_FILTER forward handle 10" \
        "应删除句柄为 10 的规则"
}

test_delete_rules_by_comment_not_found() {
    MOCK_NFT_HANDLE_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
  }
}'
    local output
    output=$(delete_rules_by_comment "$TABLE_FILTER" "forward" "nonexistent-comment" 2>&1)
    assert_contains "$output" "未找到" "未找到规则时应输出警告"
    assert_file_not_contains "$NFT_CMD_LOG" "delete rule" \
        "未找到规则时不应调用 delete rule"
}

test_delete_rules_by_comment_chain_not_exist() {
    MOCK_CHAIN_EXISTS=0
    local result=0
    delete_rules_by_comment "$TABLE_FILTER" "forward" "$BLOG_DB_COMMENT" >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "链不存在时应返回 1"
}

test_check_rules_exist_found() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    tcp dport { 5432 } drop comment "blog-db-block"
  }
}'
    if check_rules_exist "$TABLE_FILTER" "forward" "$BLOG_DB_COMMENT"; then
        return 0
    fi
    echo "规则存在时 check_rules_exist 应返回 0"
    return 1
}

test_check_rules_exist_not_found() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
  }
}'
    if check_rules_exist "$TABLE_FILTER" "forward" "$BLOG_DB_COMMENT"; then
        echo "规则不存在时 check_rules_exist 应返回 1"
        return 1
    fi
    return 0
}

test_check_rules_exist_chain_not_exist() {
    MOCK_CHAIN_EXISTS=0
    if check_rules_exist "$TABLE_FILTER" "forward" "$BLOG_DB_COMMENT"; then
        echo "链不存在时 check_rules_exist 应返回 1"
        return 1
    fi
    return 0
}

# =============================================================================
# 测试用例: 数据库端口管理函数(细粒度)
# =============================================================================

# --- Blog pgsql ---

test_open_blog_pgsql() {
    MOCK_NFT_HANDLE_OUTPUT='table inet fw_filter {
  chain forward {
    tcp dport { 5432 } drop comment "blog-db-block" # handle 10
  }
}'
    open_blog_pgsql >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "delete rule" \
        "open_blog_pgsql 应删除阻断规则"
    assert_file_contains "$NFT_CMD_LOG" "nft list table inet $TABLE_FILTER" \
        "open_blog_pgsql 应保存规则"
}

test_close_blog_pgsql_when_open() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
  }
}'
    close_blog_pgsql >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BLOG_DB_COMMENT" \
        "close_blog_pgsql 应添加 blog-db-block 规则"
}

test_close_blog_pgsql_already_closed() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    tcp dport { 5432 } drop comment "blog-db-block"
  }
}'
    local output
    output=$(close_blog_pgsql 2>&1)
    assert_contains "$output" "已处于关闭状态" \
        "端口已关闭时应提示已处于关闭状态"
}

# --- Blog redis ---

test_open_blog_redis() {
    MOCK_NFT_HANDLE_OUTPUT='table inet fw_filter {
  chain forward {
    tcp dport { 7002-7007 } drop comment "blog-redis-block" # handle 11
  }
}'
    open_blog_redis >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "delete rule" \
        "open_blog_redis 应删除阻断规则"
}

test_close_blog_redis_when_open() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
  }
}'
    close_blog_redis >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BLOG_REDIS_COMMENT" \
        "close_blog_redis 应添加 blog-redis-block 规则"
}

# --- Blog es ---

test_open_blog_es() {
    MOCK_NFT_HANDLE_OUTPUT='table inet fw_filter {
  chain forward {
    tcp dport { 9200, 9300 } drop comment "blog-es-block" # handle 12
  }
}'
    open_blog_es >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "delete rule" \
        "open_blog_es 应删除阻断规则"
}

test_close_blog_es_when_open() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
  }
}'
    close_blog_es >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BLOG_ES_COMMENT" \
        "close_blog_es 应添加 blog-es-block 规则"
}

# --- Billing pgsql ---

test_open_billing_pgsql() {
    MOCK_NFT_HANDLE_OUTPUT='table inet fw_filter {
  chain forward {
    tcp dport { 5433 } drop comment "billing-db-block" # handle 13
  }
}'
    open_billing_pgsql >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "delete rule" \
        "open_billing_pgsql 应删除阻断规则"
}

test_close_billing_pgsql_when_open() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
  }
}'
    close_billing_pgsql >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BILLING_DB_COMMENT" \
        "close_billing_pgsql 应添加 billing-db-block 规则"
}

# --- Billing redis ---

test_open_billing_redis() {
    MOCK_NFT_HANDLE_OUTPUT='table inet fw_filter {
  chain forward {
    tcp dport { 8002-8007 } drop comment "billing-redis-block" # handle 14
  }
}'
    open_billing_redis >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "delete rule" \
        "open_billing_redis 应删除阻断规则"
}

test_close_billing_redis_when_open() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
  }
}'
    close_billing_redis >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BILLING_REDIS_COMMENT" \
        "close_billing_redis 应添加 billing-redis-block 规则"
}

# --- 主函数命令解析: db-open/db-close 细粒度 ---

test_main_db_open_blog_pgsql() {
    MOCK_NFT_HANDLE_OUTPUT='table inet fw_filter {
  chain forward {
    tcp dport { 5432 } drop comment "blog-db-block" # handle 10
  }
}'
    main "db-open" "blog" "pgsql" >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "delete rule" \
        "main db-open blog pgsql 应删除规则"
}

test_main_db_close_blog_redis() {
    MOCK_NFT_LIST_OUTPUT='table inet fw_filter {
  chain forward {
    type filter hook forward priority -1; policy accept;
  }
}'
    main "db-close" "blog" "redis" >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BLOG_REDIS_COMMENT" \
        "main db-close blog redis 应添加阻断规则"
}

test_main_db_open_blog_unknown_service() {
    local result=0
    (main "db-open" "blog" "unknown") >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "未知服务时应退出码为 1"
}

test_main_db_open_billing_unknown_service() {
    local result=0
    (main "db-open" "billing" "unknown") >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "未知服务时应退出码为 1"
}

test_main_db_open_billing_es_invalid() {
    local result=0
    (main "db-open" "billing" "es") >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "billing 系统不支持 es 时应退出码为 1"
}

# =============================================================================
# 测试用例: 主操作函数
# =============================================================================

test_fw_init_blog_calls_blog_steps() {
    fw_init blog >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft delete table inet $TABLE_FILTER" \
        "fw_init blog 应删除旧的 filter 表"
    assert_file_contains "$NFT_CMD_LOG" "nft add table inet $TABLE_FILTER" \
        "fw_init blog 应创建 filter 表"
    assert_file_contains "$NFT_CMD_LOG" "nft add table inet $TABLE_DDOS" \
        "fw_init blog 应创建 DDoS 表"
    assert_file_contains "$NFT_CMD_LOG" "nft add chain inet $TABLE_FILTER input" \
        "fw_init blog 应创建 input 链"
    assert_file_contains "$NFT_CMD_LOG" "nft add chain inet $TABLE_FILTER forward" \
        "fw_init blog 应创建 forward 链"
    assert_file_contains "$NFT_CMD_LOG" "$BLOG_DB_COMMENT" \
        "fw_init blog 应添加 blog 数据库阻断规则"
    assert_file_not_contains "$NFT_CMD_LOG" "$BILLING_DB_COMMENT" \
        "fw_init blog 不应添加 billing 规则"
    assert_file_not_contains "$NFT_CMD_LOG" "$MAIL_PORTS" \
        "fw_init blog 不应添加邮件端口规则"
    assert_file_contains "$NFT_CMD_LOG" "systemctl enable nftables" \
        "fw_init blog 应设置 nftables 开机自启"
    assert_file_contains "$SYSTEM_TYPE_FILE" "blog" \
        "fw_init blog 应记录系统类型为 blog"
}

test_fw_init_billing_calls_billing_steps() {
    fw_init billing >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$BILLING_DB_COMMENT" \
        "fw_init billing 应添加 billing 数据库阻断规则"
    assert_file_not_contains "$NFT_CMD_LOG" "$BLOG_DB_COMMENT" \
        "fw_init billing 不应添加 blog 规则"
    assert_file_not_contains "$NFT_CMD_LOG" "$MAIL_PORTS" \
        "fw_init billing 不应添加邮件端口规则"
    assert_file_contains "$SYSTEM_TYPE_FILE" "billing" \
        "fw_init billing 应记录系统类型为 billing"
}

test_fw_init_mail_calls_mail_steps() {
    fw_init mail >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "$MAIL_PORTS" \
        "fw_init mail 应添加邮件端口规则"
    assert_file_not_contains "$NFT_CMD_LOG" "$BLOG_DB_COMMENT" \
        "fw_init mail 不应添加 blog 规则"
    assert_file_not_contains "$NFT_CMD_LOG" "$BILLING_DB_COMMENT" \
        "fw_init mail 不应添加 billing 规则"
    assert_file_contains "$SYSTEM_TYPE_FILE" "mail" \
        "fw_init mail 应记录系统类型为 mail"
}

test_fw_init_no_system_type_exits() {
    local result=0
    (fw_init) >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "未指定系统类型时应退出码为 1"
}

test_fw_init_unknown_system_type_exits() {
    local result=0
    (fw_init unknown) >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "未知系统类型时应退出码为 1"
}

test_fw_stop_deletes_tables() {
    fw_stop >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft delete table inet $TABLE_FILTER" \
        "fw_stop 应删除 filter 表"
    assert_file_contains "$NFT_CMD_LOG" "nft delete table inet $TABLE_DDOS" \
        "fw_stop 应删除 DDoS 表"
    assert_file_not_contains "$NFT_CMD_LOG" "systemctl stop nftables" \
        "fw_stop 不应停止 nftables 服务(避免破坏 Docker 规则)"
}

test_fw_start_loads_rules() {
    # 创建模拟配置文件
    echo "# mock rules" > "$NFTABLES_CONF"
    fw_start >/dev/null 2>&1
    assert_file_contains "$NFT_CMD_LOG" "nft -f $NFTABLES_CONF" \
        "fw_start 应加载配置文件"
    assert_file_contains "$NFT_CMD_LOG" "systemctl enable nftables" \
        "fw_start 应设置开机自启"
    assert_file_not_contains "$NFT_CMD_LOG" "systemctl start nftables" \
        "fw_start 不应通过 systemctl 启动(避免重复加载)"
}

test_fw_status_output() {
    # 模拟已初始化 mail 系统
    echo "mail" > "$SYSTEM_TYPE_FILE"
    local output
    output=$(fw_status 2>&1)
    assert_contains "$output" "nftables 服务状态" "应显示服务状态标题"
    assert_contains "$output" "当前规则集" "应显示规则集标题"
    assert_contains "$output" "端口状态" "应显示端口状态标题"
    assert_contains "$output" "系统类型: mail" "应显示系统类型为 mail"
    assert_contains "$output" "Mail 系统无数据库端口管理" "应显示 mail 无数据库管理"
}

# =============================================================================
# 测试用例: 主函数命令解析
# =============================================================================

test_main_help_flag() {
    local output
    output=$(main -h 2>&1)
    assert_contains "$output" "用法:" "main -h 应显示帮助信息"
}

test_main_help_long_flag() {
    local output
    output=$(main --help 2>&1)
    assert_contains "$output" "用法:" "main --help 应显示帮助信息"
}

test_main_no_args_shows_help() {
    local result=0
    (main) >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "无参数时应退出码为 1"
}

test_main_unknown_command() {
    local result=0
    (main "unknown-cmd") >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "未知命令时应退出码为 1"
}

test_main_db_open_unknown_system() {
    local result=0
    (main "db-open" "unknown") >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "未知系统时应退出码为 1"
}

test_main_db_close_unknown_system() {
    local result=0
    (main "db-close" "unknown") >/dev/null 2>&1 || result=$?
    assert_eq "1" "$result" "未知系统时应退出码为 1"
}

# =============================================================================
# 测试用例: 备份函数
# =============================================================================

test_backup_rules_creates_file() {
    mkdir -p "$BACKUP_DIR"
    local backup_file
    backup_file=$(backup_rules 2>/dev/null | tail -n1)
    if [[ -z "$backup_file" ]]; then
        echo "backup_rules 应返回备份文件路径"
        return 1
    fi
    if [[ ! -f "$backup_file" ]]; then
        echo "备份文件应被创建: $backup_file"
        return 1
    fi
}

# =============================================================================
# 测试用例: 保存规则
# =============================================================================

test_save_rules_creates_config() {
    save_rules >/dev/null 2>&1
    if [[ ! -f "$NFTABLES_CONF" ]]; then
        echo "save_rules 应创建配置文件: $NFTABLES_CONF"
        return 1
    fi
    assert_file_contains "$NFT_CMD_LOG" "nft list table inet $TABLE_FILTER" \
        "save_rules 应调用 nft list table 保存自定义表"
    assert_file_contains "$NFT_CMD_LOG" "nft list table inet $TABLE_DDOS" \
        "save_rules 应调用 nft list table 保存 DDoS 表"
}

# =============================================================================
# 测试用例: 配置变量
# =============================================================================

test_config_ssh_port() {
    assert_eq "2222" "$SSH_PORT" "SSH 端口应为 2222(测试覆盖值)"
}

test_config_ssh_port_auto_read() {
    # 模拟 sshd_config 文件
    local mock_sshd_config="$TEST_TMP_DIR/sshd_config"
    echo "Port 3322" > "$mock_sshd_config"
    local result
    result=$(grep -E '^\s*Port\s+' "$mock_sshd_config" 2>/dev/null | awk '{print $2}' | head -n1)
    result="${result:-22}"
    assert_eq "3322" "$result" "应从 sshd_config 读取到端口 3322"
}

test_config_ssh_port_fallback() {
    # 不存在的文件应回退到默认值 22
    local result
    result=$(grep -E '^\s*Port\s+' "/nonexistent/sshd_config" 2>/dev/null | awk '{print $2}' | head -n1)
    result="${result:-22}"
    assert_eq "22" "$result" "sshd_config 不存在时应回退到 22"
}

test_config_web_ports() {
    assert_contains "$WEB_PORTS" "80" "Web 端口应包含 80"
    assert_contains "$WEB_PORTS" "443" "Web 端口应包含 443"
}

test_config_mail_ports() {
    assert_contains "$MAIL_PORTS" "25" "邮件端口应包含 25"
    assert_contains "$MAIL_PORTS" "993" "邮件端口应包含 993"
}

test_config_blog_db_ports() {
    assert_eq "5432" "$BLOG_DB_PORTS" "Blog pgsql 端口应为 5432"
    assert_eq "7002-7007" "$BLOG_REDIS_PORTS" "Blog redis 端口应为 7002-7007"
    assert_contains "$BLOG_ES_PORTS" "9200" "Blog es 端口应包含 9200"
}

test_config_billing_db_ports() {
    assert_eq "5433" "$BILLING_DB_PORTS" "Billing pgsql 端口应为 5433"
    assert_eq "8002-8007" "$BILLING_REDIS_PORTS" "Billing redis 端口应为 8002-8007"
}

test_config_docker_subnets() {
    assert_contains "$DOCKER_INTERNAL_SUBNETS" "172.16.0.0/12" "应包含 Docker 默认网段"
    assert_contains "$DOCKER_INTERNAL_SUBNETS" "178.18.11.0/24" "应包含 pgsql 网段"
    assert_contains "$DOCKER_INTERNAL_SUBNETS" "178.18.13.0/24" "应包含 redis 网段"
}

# =============================================================================
# 运行所有测试
# =============================================================================

echo ""
echo "=========================================="
echo "  fw.sh 单元测试"
echo "=========================================="
echo ""

echo "--- 日志函数 ---"
run_test "log_info 输出格式正确" test_log_info_format
run_test "log_warn 输出格式正确" test_log_warn_format
run_test "log_error 输出格式正确" test_log_error_format
run_test "log_debug DEBUG=0 时无输出" test_log_debug_off
run_test "log_debug DEBUG=1 时有输出" test_log_debug_on

echo ""
echo "--- 帮助信息 ---"
run_test "帮助信息包含用法说明" test_show_help_contains_usage
run_test "帮助信息包含所有命令" test_show_help_contains_commands
run_test "帮助信息包含系统名称" test_show_help_contains_systems
run_test "帮助信息包含端口信息" test_show_help_contains_ports

echo ""
echo "--- 检查函数 ---"
run_test "check_nft_installed 检测 mock nft" test_check_nft_installed_with_mock

echo ""
echo "--- 配置变量 ---"
run_test "SSH 端口配置正确" test_config_ssh_port
run_test "SSH 端口自动读取 sshd_config" test_config_ssh_port_auto_read
run_test "SSH 端口回退默认值 22" test_config_ssh_port_fallback
run_test "Web 端口配置正确" test_config_web_ports
run_test "邮件端口配置正确" test_config_mail_ports
run_test "Blog 数据库端口配置正确" test_config_blog_db_ports
run_test "Billing 数据库端口配置正确" test_config_billing_db_ports
run_test "Docker 子网配置正确" test_config_docker_subnets

echo ""
echo "--- 核心 nftables 函数 ---"
run_test "delete_custom_tables 删除正确的表" test_delete_custom_tables
run_test "create_filter_table 创建过滤表" test_create_filter_table
run_test "create_input_chain 创建 input 链" test_create_input_chain
run_test "create_forward_chain 创建 forward 链" test_create_forward_chain
run_test "create_output_chain 创建 output 链" test_create_output_chain
run_test "create_docker_subnets_set 创建子网集合" test_create_docker_subnets_set
run_test "add_input_base_rules 添加基础规则" test_add_input_base_rules
run_test "add_web_port_rules 添加 Web 端口规则" test_add_web_port_rules
run_test "add_mail_port_rules 添加邮件端口规则" test_add_mail_port_rules
run_test "add_ssh_port_rules 添加 SSH 端口规则" test_add_ssh_port_rules
run_test "add_input_drop_rule 添加末尾丢弃规则" test_add_input_drop_rule
run_test "add_forward_base_rules 添加 forward 基础规则" test_add_forward_base_rules
run_test "add_forward_blog_db_block_rules 添加 blog 阻断规则" test_add_forward_blog_db_block_rules
run_test "add_forward_billing_db_block_rules 添加 billing 阻断规则" test_add_forward_billing_db_block_rules

echo ""
echo "--- DDoS 防护函数 ---"
run_test "create_ddos_table 创建 DDoS 表" test_create_ddos_table
run_test "create_ddos_sets 创建黑名单集合" test_create_ddos_sets
run_test "create_ddos_input_chain 创建 DDoS input 链" test_create_ddos_input_chain
run_test "add_ddos_rules 添加 DDoS 防护规则" test_add_ddos_rules

echo ""
echo "--- 规则查找与删除 ---"
run_test "delete_rules_by_comment 找到并删除规则" test_delete_rules_by_comment_found
run_test "delete_rules_by_comment 未找到规则时警告" test_delete_rules_by_comment_not_found
run_test "delete_rules_by_comment 链不存在时返回 1" test_delete_rules_by_comment_chain_not_exist
run_test "check_rules_exist 规则存在时返回 0" test_check_rules_exist_found
run_test "check_rules_exist 规则不存在时返回 1" test_check_rules_exist_not_found
run_test "check_rules_exist 链不存在时返回 1" test_check_rules_exist_chain_not_exist

echo ""
echo "--- 数据库端口管理(细粒度) ---"
run_test "open_blog_pgsql 删除阻断规则并保存" test_open_blog_pgsql
run_test "close_blog_pgsql 端口开放时添加阻断规则" test_close_blog_pgsql_when_open
run_test "close_blog_pgsql 端口已关闭时跳过" test_close_blog_pgsql_already_closed
run_test "open_blog_redis 删除阻断规则" test_open_blog_redis
run_test "close_blog_redis 端口开放时添加阻断规则" test_close_blog_redis_when_open
run_test "open_blog_es 删除阻断规则" test_open_blog_es
run_test "close_blog_es 端口开放时添加阻断规则" test_close_blog_es_when_open
run_test "open_billing_pgsql 删除阻断规则" test_open_billing_pgsql
run_test "close_billing_pgsql 端口开放时添加阻断规则" test_close_billing_pgsql_when_open
run_test "open_billing_redis 删除阻断规则" test_open_billing_redis
run_test "close_billing_redis 端口开放时添加阻断规则" test_close_billing_redis_when_open

echo ""
echo "--- 主操作函数 ---"
run_test "fw_init blog 调用 blog 初始化步骤" test_fw_init_blog_calls_blog_steps
run_test "fw_init billing 调用 billing 初始化步骤" test_fw_init_billing_calls_billing_steps
run_test "fw_init mail 调用 mail 初始化步骤" test_fw_init_mail_calls_mail_steps
run_test "fw_init 未指定系统类型退出码为 1" test_fw_init_no_system_type_exits
run_test "fw_init 未知系统类型退出码为 1" test_fw_init_unknown_system_type_exits
run_test "fw_stop 删除自定义表并停止服务" test_fw_stop_deletes_tables
run_test "fw_start 加载配置并启动服务" test_fw_start_loads_rules
run_test "fw_status 输出包含各状态段" test_fw_status_output

echo ""
echo "--- 主函数命令解析 ---"
run_test "main -h 显示帮助" test_main_help_flag
run_test "main --help 显示帮助" test_main_help_long_flag
run_test "main 无参数退出码为 1" test_main_no_args_shows_help
run_test "main 未知命令退出码为 1" test_main_unknown_command
run_test "main db-open 未知系统退出码为 1" test_main_db_open_unknown_system
run_test "main db-close 未知系统退出码为 1" test_main_db_close_unknown_system
run_test "main db-open blog pgsql 正确调用" test_main_db_open_blog_pgsql
run_test "main db-close blog redis 正确调用" test_main_db_close_blog_redis
run_test "main db-open blog 未知服务退出码为 1" test_main_db_open_blog_unknown_service
run_test "main db-open billing 未知服务退出码为 1" test_main_db_open_billing_unknown_service
run_test "main db-open billing es 不支持退出码为 1" test_main_db_open_billing_es_invalid

echo ""
echo "--- 备份与保存 ---"
run_test "backup_rules 创建备份文件" test_backup_rules_creates_file
run_test "save_rules 创建配置文件" test_save_rules_creates_config

# =============================================================================
# 测试结果汇总
# =============================================================================

echo ""
echo "=========================================="
echo "  测试结果"
echo "=========================================="
echo -e "  总计: $TESTS_RUN"
echo -e "  ${GREEN}通过: $TESTS_PASSED${NC}"
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "  ${RED}失败: $TESTS_FAILED${NC}"
    echo ""
    echo "  失败的测试:"
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "    ${RED}✗${NC} $t"
    done
else
    echo -e "  ${GREEN}失败: 0${NC}"
fi
echo "=========================================="

# 清理临时目录
rm -rf "$TEST_TMP_DIR"

# 以失败测试数量作为退出码
exit "$TESTS_FAILED"
