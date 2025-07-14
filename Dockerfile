FROM opengauss/opengauss:7.0.0-RC2.B010-openEuler20.03

# 安装 Python3 和 pip
RUN yum install -y python3 python3-pip && yum clean all

# 设置工作目录
WORKDIR /workspace

# 复制当前目录下所有内容到容器内
COPY . /workspace

# 可选：安装 Python 依赖
# RUN pip install -r requirements.txt

CMD ["tail", "-f", "/dev/null"]