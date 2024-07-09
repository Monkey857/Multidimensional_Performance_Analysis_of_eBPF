# eBPF多维度分析

## 一、工具使用说明：

### 1.环境准备：

1.1ebpf运行环境：

```shell
#在Summer_of_Open_Source/目录下执行：
make deps
```

1.2python环境：

```shell
#下载python3
sudo apt install python3
#检查是否下载成功：
python3 --version
#下载pandas库
sudo pip3 install pandas -i https://pypi.tuna.tsinghua.edu.cn/simple
```

2.运行：

```shell
#在Summer_of_Open_Source/目录下运行shell脚本：
#此脚本用来比较Map类型中hash和array在时间层面进行增删改查操作的差异
sudo bash run_ebpf_and_process.sh
```



