FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV XDG_RUNTIME_DIR /run/user/1000

RUN apt-get update && apt-get install -y expect python3-pip \
                                        python3-pyqt5 \
                                        sudo \
                                        ssh \
                                        xterm \
                                        && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir cryptography

RUN adduser --quiet qtuser && usermod -aG video qtuser && usermod -aG sudo qtuser
RUN echo 'root:root' | chpasswd
RUN echo 'qtuser:root' | chpasswd
RUN mkdir -p /run/user/1000 && chmod 700 /run/user/1000 && chown qtuser /run/user/1000
RUN mkdir -p /run/user/0 && chmod 700 /run/user/0

COPY ./app /var/lib/encryptzia
COPY ./build/launcher.sh /usr/bin/encryptzia
RUN touch /var/log/encryptzia.log && chmod 777 /var/log/encryptzia.log && chmod +x /usr/bin/encryptzia
WORKDIR /var/lib/encryptzia

EXPOSE 8080
EXPOSE 5678

CMD [ "encryptzia" ]