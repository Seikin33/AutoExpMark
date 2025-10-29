#!/bin/bash

# 定时器脚本 timer.sh

# 检查是否提供了时间参数
if [ $# -ne 2 ]; then
    echo "使用方法: $0 <时间> <要执行的python文件>"
    echo "示例: $0 5m my_script.py"
    echo "时间格式支持:"
    echo "  s - 秒 (例如 30s)"
    echo "  m - 分钟 (例如 5m)"
    echo "  h - 小时 (例如 2h)"
    exit 1
fi

# 获取时间参数
time_input=$1
python_file=$2

# 解析时间单位
unit=${time_input: -1}
value=${time_input%?}

# 验证输入格式
if ! [[ $unit =~ ^[smh]$ ]] || ! [[ $value =~ ^[0-9]+$ ]]; then
    echo "错误: 无效的时间格式"
    exit 1
fi

# 转换为秒数
case $unit in
    s) seconds=$value ;;
    m) seconds=$((value * 60)) ;;
    h) seconds=$((value * 3600)) ;;
esac

# 检查python文件是否存在
if [ ! -f "$python_file" ]; then
    echo "错误: 当前目录下找不到 $python_file 文件"
    exit 1
fi

echo "定时器已设置，将在 $time_input 后运行 $python_file"

# 使用sleep命令等待指定时间后运行python脚本
sleep $seconds && python3 "$python_file"
