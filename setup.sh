#!/bin/bash
set -e
echo '=== auto-get 一键部署 ==='

# 1. 安装系统依赖
apt-get update -qq
apt-get install -y -qq python3-pip chromium 2>&1 | tail -3

# 2. 安装 Python 依赖
pip3 install -r requirements.txt --break-system-packages -q 2>&1 | tail -3

# 3. 安装 Playwright 浏览器
python3 -m playwright install chromium 2>&1 | tail -3

# 4. 首次运行测试
python3 crawler.py

# 5. 设置定时任务（每日 17:00 HK Time = 09:00 UTC）
echo '0 9 * * * /usr/bin/python3 /root/auto-get/crawler.py >> /root/auto-get/cron.log 2>&1' | crontab -

echo '=== 部署完成 ==='
echo '定时任务已设置：每日 17:00 HK Time 自动运行'
echo '输出目录：/CloudNAS/AI/'
crontab -l
