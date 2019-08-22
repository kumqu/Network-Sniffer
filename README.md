## 环境：
  Ubuntu 17.0

## 功能：
1. 使用libpcap库捕获局域网中的所有数据包
2. 支持IP协议、TCP协议和UDP协议分析
3. 打印协议类型、IP地址、MAC地址、端口和16进制与ASCII数据信息等

## 用法：
1. gcc sniffer.c -o sniffer -lpcap
2. ./sniffer

