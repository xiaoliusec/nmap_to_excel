# nmap_to_excel
脚本功能：将nmap扫描结果转换为可视化excel表格。

在企业中，经常会用到nmap工具收集内网资产，但整理nmap扫描结果相当麻烦，故诞生此工具，提高生产效率。

使用方法：
```
pip install openpyxl
```
```
python3 Nmap_to_excel.py
```

![image-20240827145948419](https://github.com/user-attachments/assets/36d1b67f-a1c1-4e02-8589-458e3b82f3ea)

选择nmap扫描结果生成的xml文件即可，如需要转换多个，把xml文件放在同一文件夹下，选中文件夹即可。

![image-20240827150158703](https://github.com/user-attachments/assets/d3c0d6ca-d752-4b08-8f97-1fb9f92fe20f)
![image](https://github.com/user-attachments/assets/d346c25c-cc8f-4d4c-a14d-706e403b80b5)

