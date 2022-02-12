FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV XDG_RUNTIME_DIR=/run/user/1000
ENV PYTEST_QT_API=pyqt5

COPY ./app /var/lib/encryptzia
COPY ./build/launcher.sh /usr/bin/encryptzia

RUN apt-get update \
 && apt-get install -y expect \
                        python3-pip \
                        python3-pyqt5 \
                        sudo \
                        ssh \
                        xterm \
                        && rm -rf /var/lib/apt/lists/* \
                        && pip3 install --no-cache-dir cryptography pytest-qt \
                        && adduser --quiet qtuser \
                        && usermod -aG video qtuser \
                        && usermod -aG sudo qtuser \
                        && echo 'root:root' | chpasswd \
                        && echo 'qtuser:root' | chpasswd \
                        && mkdir -p /run/user/1000 \
                        && chmod 700 /run/user/1000 \
                        && chown qtuser /run/user/1000 \
                        && mkdir -p /run/user/0 \
                        && chmod 700 /run/user/0 \
                        && touch /var/log/encryptzia.log \
                        && chmod 777 /var/log/encryptzia.log \
                        && chmod +x /usr/bin/encryptzia

WORKDIR /var/lib/encryptzia

EXPOSE 8080
EXPOSE 5678

CMD [ "encryptzia" ]