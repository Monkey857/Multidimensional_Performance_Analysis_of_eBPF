import matplotlib.pyplot as plt
import pandas as pd
import csv

# 输入和输出文件名
input_file = './output.txt'
output_file = './data.csv'

# 读取 .txt 文件并写入 .csv 文件
with open(input_file, 'r') as txt_file, open(output_file, 'w', newline='') as csv_file:
    # 读取 .txt 文件内容
    lines = txt_file.readlines()

    # 提取列名和数据
    columns = lines[0].split()
    data_lines = [line.split() for line in lines[1:]]

    # 写入 .csv 文件
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(columns)  # 写入列名
    csv_writer.writerows(data_lines)  # 写入数据

# 使用 Pandas 读取 .csv 文件并计算每列的统计信息
data = pd.read_csv(output_file)  # 默认使用逗号分隔符读取数据

# 提取 hash 和 array 的平均值
average_values_hash = data[['Map_01_Insert', 'Map_01_LookUp', 'Map_01_Delete']].mean()
average_values_array = data[['Map_02_Insert', 'Map_02_LookUp', 'Map_02_Delete']].mean()

# 绘制平均值图表，确保为每条线条指定标签
plt.figure(figsize=(10, 6))

# 绘制 hash 使用蓝色线条
plt.plot(['insert', 'lookup', 'delete'], average_values_hash, marker='o', linestyle='-', color='b', label='Hash')

# 绘制 array 使用红色线条
plt.plot(['insert', 'lookup', 'delete'], average_values_array, marker='s', linestyle='-', color='r', label='Array')

plt.title('Average Performance of eBPF Hash and Array Operations', pad=20)
plt.xlabel('Operation Type')
plt.ylabel('Value')
plt.legend(loc='upper right', fontsize='small', frameon=True, shadow=True)
plt.grid(True)
plt.savefig('average_plot_updated.png')  # 保存为图片文件
plt.show()

# 计算所有统计信息
metrics = {
    'Average': data.mean(),       # 平均值
    'Median': data.median(),      # 中位数
    'Std Dev': data.std(),        # 标准差
    'Variance': data.var(),       # 方差
    'Max': data.max(),            # 最大值
    'Min': data.min(),            # 最小值
    'Kurtosis': data.kurtosis(),  # 峰度
    'Skewness': data.skew()       # 偏度
}

# 打印所有统计信息到控制台
for metric, values in metrics.items():
    print(f"{metric} values:")
    for key, value in values.items():
        print(f"{key}: {value}")
    print()

# 绘制包含所有统计信息的综合图表
plt.figure(figsize=(14, 8))

# 分别绘制 hash 和 array 的平均值
plt.plot(['insert', 'lookup', 'delete'], average_values_hash, marker='o', linestyle='-', color='blue', label='Hash Average')
plt.plot(['insert', 'lookup', 'delete'], average_values_array, marker='s', linestyle='-', color='red', label='Array Average')

# 颜色映射表，用于确保同一个指标使用相同的颜色
colors = ['g', 'c', 'm', 'y', 'k', 'orange']

# 从第一个颜色开始，用于其他统计信息
color_index = 0

# 绘制其他统计信息
for metric, values in metrics.items():
    if metric != 'Average':  # 跳过已经绘制的平均值
        color = colors[color_index % len(colors)]
        plt.plot(['insert', 'lookup', 'delete'], values[['Map_01_Insert', 'Map_01_LookUp', 'Map_01_Delete']], marker='o', linestyle='-', color=color, label=f'Hash {metric}')
        plt.plot(['insert', 'lookup', 'delete'], values[['Map_02_Insert', 'Map_02_LookUp', 'Map_02_Delete']], marker='s', linestyle='--', color=color, label=f'Array {metric}')
        color_index += 1

plt.title('Statistics of eBPF Hash and Array Operations', pad=20)
plt.xlabel('Operation Type')
plt.ylabel('Value')
plt.legend(loc='upper right', bbox_to_anchor=(1.15, 1), fontsize='small', frameon=True, shadow=True)
plt.grid(True)
plt.savefig('combined_plot_updated.png')  # 保存为图片文件
plt.show()
