# Encryptzia

![python version](https://img.shields.io/badge/python-3.9%2B-blue)
![python QT version](https://img.shields.io/badge/pyqt5-5.15.2-blue)

Encryptzia is a Python builed ssh manager.

![dark theme preview](.images/encryptzia01.png)
![light theme preview](.images/encryptzia02.png)
![add preview](.images/encryptzia03.png)
![edit and open preview](.images/encryptzia04.png)

## Standard installation

You can download the debian package from [here](https://github.com/Crash-Zeus/encryptzia/releases) and run it with your package manager

```shell
sudo apt install $HOME/Download/encryptzia.deb
```

## Development installation

For development usage [x11](https://wikipedia.org/wiki/X_Window_System), [docker](https://docs.docker.com/get-docker/) and [docker-compose](https://docs.docker.com/compose/gettingstarted/) are required.

First of all build the dev image :
```shell
docker build -t registry.jonas.domains/timesz/encryptzia:stable .
```

Next run the compose :
```shell
docker-compose up -d
```

You can now exec into the container and run application :
```shell
docker exec -it encryptzia bash
```

In container :
```shell
encryptzia
#or
python3 main.py 
```

## Contributing
Pull requests are welcome.
## License
[MIT](./LICENSE)
