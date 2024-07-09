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
