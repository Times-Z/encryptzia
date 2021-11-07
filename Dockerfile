FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV XDG_RUNTIME_DIR /run/user/1000

RUN apt-get update && apt-get install -y python3-pip \
                                        python3-pyqt5 \
                                        sudo \
                                        && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir cryptography

RUN adduser --quiet qtuser && usermod -aG video qtuser && usermod -aG sudo qtuser
RUN echo 'root:root' | chpasswd
RUN echo 'qtuser:root' | chpasswd
RUN mkdir -p /run/user/1000 && chmod 700 /run/user/1000 && chown qtuser /run/user/1000
RUN mkdir -p /run/user/0 && chmod 700 /run/user/0

COPY ./app /var/lib/sshmanager
COPY ./build/launcher.sh /usr/bin/sshmanager
RUN touch /var/log/sshmanager.log && chmod 777 /var/log/sshmanager.log && chmod +x /usr/bin/sshmanager
WORKDIR /var/lib/sshmanager

EXPOSE 8080
EXPOSE 5678

CMD [ "sshmanager" ]