#!/bin/bash

# Deadpool 代理池启动脚本
# 支持后台运行、自动重启、日志记录

PROGRAM_NAME="deadpool"
PROGRAM_PATH="./Deadpool"
PID_FILE="./deadpool.pid"
LOG_FILE="./deadpool.log"
CONFIG_FILE="./config.toml"
MAX_RESTARTS=10
RESTART_DELAY=5

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查程序是否存在
check_program() {
    if [ ! -f "$PROGRAM_PATH" ]; then
        echo -e "${RED}错误: 程序文件 $PROGRAM_PATH 不存在${NC}"
        exit 1
    fi
}

# 检查程序是否运行
is_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            return 0
        else
            rm -f "$PID_FILE"
        fi
    fi
    return 1
}

# 启动程序
start_program() {
    if is_running; then
        echo -e "${YELLOW}程序已经在运行中 (PID: $(cat $PID_FILE))${NC}"
        return 0
    fi

    echo -e "${GREEN}启动 Deadpool 代理池...${NC}"

    # 创建日志目录
    mkdir -p "$(dirname "$LOG_FILE")"

    # 后台启动程序
    nohup "$PROGRAM_PATH" -c "$CONFIG_FILE" >> "$LOG_FILE" 2>&1 &
    PID=$!

    # 保存PID
    echo $PID > "$PID_FILE"

    # 检查启动是否成功
    sleep 2
    if is_running; then
        echo -e "${GREEN}程序启动成功 (PID: $PID)${NC}"
        echo "日志文件: $LOG_FILE"
        echo "PID文件: $PID_FILE"
    else
        echo -e "${RED}程序启动失败，请检查日志文件 $LOG_FILE${NC}"
        rm -f "$PID_FILE"
        exit 1
    fi
}

# 停止程序
stop_program() {
    if ! is_running; then
        echo -e "${YELLOW}程序未运行${NC}"
        return 0
    fi

    PID=$(cat "$PID_FILE")
    echo -e "${YELLOW}停止程序 (PID: $PID)...${NC}"

    # 发送TERM信号
    kill -TERM "$PID" 2>/dev/null

    # 等待程序退出
    for i in {1..10}; do
        if ! ps -p "$PID" > /dev/null 2>&1; then
            echo -e "${GREEN}程序已停止${NC}"
            rm -f "$PID_FILE"
            return 0
        fi
        sleep 1
    done

    # 如果程序没有响应，强制杀死
    echo -e "${YELLOW}强制停止程序...${NC}"
    kill -KILL "$PID" 2>/dev/null
    rm -f "$PID_FILE"
    echo -e "${GREEN}程序已强制停止${NC}"
}

# 重启程序
restart_program() {
    stop_program
    sleep 2
    start_program
}

# 查看状态
status_program() {
    if is_running; then
        PID=$(cat "$PID_FILE")
        echo -e "${GREEN}程序正在运行 (PID: $PID)${NC}"

        # 显示运行时间
        if command -v ps >/dev/null 2>&1; then
            START_TIME=$(ps -p "$PID" -o lstart= 2>/dev/null)
            if [ -n "$START_TIME" ]; then
                echo "启动时间: $START_TIME"
            fi
        fi

        # 显示内存使用
        if command -v ps >/dev/null 2>&1; then
            MEMORY=$(ps -p "$PID" -o rss= 2>/dev/null)
            if [ -n "$MEMORY" ]; then
                MEMORY_MB=$((MEMORY / 1024))
                echo "内存使用: ${MEMORY_MB}MB"
            fi
        fi

        # 显示代理数量
        if [ -f "lastData.txt" ]; then
            PROXY_COUNT=$(wc -l < "lastData.txt" 2>/dev/null || echo "0")
            echo "代理数量: $PROXY_COUNT"
        fi
    else
        echo -e "${RED}程序未运行${NC}"
    fi
}

# 查看日志
view_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo -e "${RED}日志文件不存在: $LOG_FILE${NC}"
    fi
}

# 守护进程模式
daemon_mode() {
    echo -e "${GREEN}进入守护进程模式...${NC}"
    echo "程序崩溃时将自动重启，按 Ctrl+C 退出"

    RESTART_COUNT=0

    while true; do
        if ! is_running; then
            if [ $RESTART_COUNT -ge $MAX_RESTARTS ]; then
                echo -e "${RED}程序重启次数超过限制 ($MAX_RESTARTS)，退出守护模式${NC}"
                exit 1
            fi

            RESTART_COUNT=$((RESTART_COUNT + 1))
            echo -e "${YELLOW}程序未运行，尝试重启 (第 $RESTART_COUNT 次)...${NC}"

            start_program
            sleep $RESTART_DELAY
        else
            # 重置重启计数器
            RESTART_COUNT=0
        fi

        sleep 5
    done
}

# 清理
cleanup() {
    stop_program
    rm -f "$PID_FILE"
    echo -e "${GREEN}清理完成${NC}"
}

# 显示帮助
show_help() {
    echo "Deadpool 代理池管理脚本"
    echo ""
    echo "用法: $0 {start|stop|restart|status|logs|daemon|cleanup|help}"
    echo ""
    echo "命令:"
    echo "  start   - 启动程序"
    echo "  stop    - 停止程序"
    echo "  restart - 重启程序"
    echo "  status  - 查看运行状态"
    echo "  logs    - 查看实时日志"
    echo "  daemon  - 守护进程模式 (自动重启)"
    echo "  cleanup - 停止并清理"
    echo "  help    - 显示此帮助信息"
}

# 主逻辑
check_program

case "$1" in
    start)
        start_program
        ;;
    stop)
        stop_program
        ;;
    restart)
        restart_program
        ;;
    status)
        status_program
        ;;
    logs)
        view_logs
        ;;
    daemon)
        daemon_mode
        ;;
    cleanup)
        cleanup
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}错误: 未知命令 '$1'${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac