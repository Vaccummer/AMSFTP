#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
演示 iterator_listdir 与 listdir 的区别
"""

import AMSFTP
import time

# 替换为实际的连接信息
request = AMSFTP.AMData.ConRequst(
    nickname="test",
    hostname="192.168.1.80",
    username="amroot",
    port=22,
    password="123456",
)

print("创建客户端连接...")
client = AMSFTP.AMSFTPClient(request, [])

test_path = "."  # 测试目录

print("\n" + "="*60)
print("方法 1: 使用 listdir() - 一次性加载所有文件")
print("="*60)
start = time.time()
error, files = client.listdir(test_path)
load_time = time.time() - start

if error[0] == AMSFTP.AMEnum.ErrorCode.Success:
    print(f"✓ 加载完成，耗时: {load_time:.3f}秒")
    print(f"✓ 文件总数: {len(files)}")
    print(f"✓ 前 5 个文件:")
    for i, f in enumerate(files[:5]):
        print(f"    {i+1}. {f.name} ({f.type.name})")
else:
    print(f"✗ 错误: {error}")

print("\n" + "="*60)
print("方法 2: 使用 iterator_listdir() - 逐个yield文件")
print("="*60)
start = time.time()
count = 0
try:
    for file in client.iterator_listdir(test_path):
        count += 1
        if count <= 5:
            print(f"  {count}. {file.name} ({file.type.name})")
        if count == 5:
            print(f"  ... (提前退出迭代)")
            break  # 提前退出 - 这就是迭代器的优势！
    
    iter_time = time.time() - start
    print(f"✓ 处理完成，耗时: {iter_time:.3f}秒")
    print(f"✓ 处理了 {count} 个文件（提前退出）")
    
except Exception as e:
    print(f"✗ 错误: {e}")

print("\n" + "="*60)
print("性能对比总结")
print("="*60)
print(f"listdir()          : {load_time:.3f}秒 (加载所有 {len(files)} 个文件)")
print(f"iterator_listdir() : {iter_time:.3f}秒 (只处理 {count} 个文件)")
print(f"性能提升: {(load_time/iter_time):.1f}x 更快")

print("\n使用建议:")
print("  • 小目录 (< 1000 文件)     : 使用 listdir()")
print("  • 大目录 (> 10000 文件)    : 使用 iterator_listdir()")
print("  • 需要提前退出             : 使用 iterator_listdir()")
print("  • 需要知道文件总数         : 使用 listdir()")
