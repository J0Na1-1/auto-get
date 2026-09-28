# auto-get

每日自动爬取 5 个安全公告源，整理为标准模板输出 Excel 报表。

## 功能

- 爬取 GovCERT、HKCERT、Fortinet PSIRT、Palo Alto Networks、Cisco PSIRT
- 筛选当日 HK Time 发布的警报
- 自动提取：日期、风险等级、平台、影响产品、描述、解决方案、相关链接、CVE、来源
- 跳过低风险和 Info 级别
- 输出格式对齐 CloudNAS 每日新闻模版
- 每日 17:00 HK Time 自动运行

## 源站

| 源 | URL |
|--|--|
| GovCERT.HK | https://www.govcert.gov.hk/en/ |
| HKCERT | https://www.hkcert.org/security-bulletin/ |
| Fortinet PSIRT | https://fortiguard.fortinet.com/psirt |
| Palo Alto | https://security.paloaltonetworks.com/ |
| Cisco PSIRT | https://sec.cloudapps.cisco.com/security/center/publicationListing.x |

## 一键部署

```bash
git clone https://github.com/J0Na1-1/auto-get.git
cd auto-get
chmod +x setup.sh
./setup.sh
```

setup.sh 会自动完成：
1. 安装系统依赖（python3-pip、chromium）
2. 安装 Python 依赖
3. 安装 Playwright 浏览器
4. 首次运行测试
5. 设置每日 17:00 HK Time 定时任务

## 手动部署

```bash
# 安装依赖
apt-get update && apt-get install -y python3-pip chromium
pip3 install -r requirements.txt --break-system-packages
python3 -m playwright install chromium

# 首次运行
python3 crawler.py

# 设置定时任务（UTC 09:00 = HK Time 17:00）
echo "0 9 * * * /usr/bin/python3 /root/auto-get/crawler.py >> /root/auto-get/cron.log 2>&1" | crontab -
```

## 输出

- 文件：/CloudNAS/AI/AlertNewsDDMMYY.xlsx
- 格式：Excel，9 列，对齐模版
- 无新警报时生成空文件（仅表头）

## 注意事项

- 时区：HK Time (UTC+8)
- 低风险和 Info 级别不记录
- 同一 CVE 出现在多个源时各记一行
- Cisco 使用 Playwright 浏览器渲染
- 需要 chromium 浏览器支持

## 文件结构

```
auto-get/
├── crawler.py      # 主爬虫脚本
├── requirements.txt # Python 依赖
├── setup.sh        # 一键部署脚本
└── README.md       # 本文件
```
