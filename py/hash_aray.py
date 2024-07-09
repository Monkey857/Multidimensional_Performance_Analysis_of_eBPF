import matplotlib.pyplot as plt
import pandas as pd
import csv

# 输入文件名和输出文件名
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

print(f"Successfully converted {input_file} to {output_file}")

# 使用 Pandas 读取 .csv 文件并计算每列的平均值
data = pd.read_csv(output_file)  # 默认使用逗号分隔符读取数据
average_values = data.mean()

print("\nAverage values:")
print(average_values)

# 重新组织数据
hash_values = average_values[['hash_ins', 'hash_look', 'hash_del']]
arr_values = average_values[['arr_ins', 'arr_look', 'arr_clear']]
labels = ['insert', 'lookup', 'delete']

# 绘制折线图
plt.figure(figsize=(10, 6))

# 绘制hash相关的折线
plt.plot(labels, hash_values, marker='o', linestyle='-', color='b', label='Hash')

# 绘制array相关的折线
plt.plot(labels, arr_values, marker='o', linestyle='-', color='g', label='Array')

# 添加标题和标签
plt.title('Average Values Line Plot')
plt.xlabel('Operations')
plt.ylabel('Average Value (seconds)')
plt.legend()
plt.grid(True)

# 保存并显示图表
plt.savefig('line_plot.png')  # 保存为图片文件
plt.show()

# 绘制柱状图
plt.figure(figsize=(10, 6))
bar_width = 0.35
index = range(len(labels))

plt.bar(index, hash_values, bar_width, color='b', label='Hash')
plt.bar([i + bar_width for i in index], arr_values, bar_width, color='g', label='Array')

# 添加标题和标签
plt.title('Average Values Bar Plot')
plt.xlabel('Operations')
plt.ylabel('Average Value (seconds)')
plt.xticks([i + bar_width / 2 for i in index], labels)
plt.legend()
plt.grid(axis='y')

# 保存并显示图表
plt.savefig('bar_plot.png')  # 保存为图片文件
plt.show()
