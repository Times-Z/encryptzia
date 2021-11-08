#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys, os, base64, json
from PyQt5.QtWidgets import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from PyQt5 import QtCore, QtGui
from classes import Display
from classes import Logger

class App(QApplication):
    """
        Main class
        - Run the main window and the manager
    """

    messageBoxIcons = {
        'critical': QMessageBox.Critical,
        'warning': QMessageBox.Warning,
        'info': QMessageBox.Information,
        'question': QMessageBox.Question,
        'None': QMessageBox.NoIcon
    }

    messageBoxBtn = {
        'ok': QMessageBox.Ok,
        'open': QMessageBox.Open,
        'save': QMessageBox.Save,
        'cancel': QMessageBox.Cancel,
        'close': QMessageBox.Close,
        'discard': QMessageBox.Discard,
        'apply': QMessageBox.Apply,
        'reset': QMessageBox.Reset,
        'default': QMessageBox.RestoreDefaults,
        'help': QMessageBox.Help,
        'no': QMessageBox.No,
        'yes': QMessageBox.Yes,
        'abort': QMessageBox.Abort,
        'retry': QMessageBox.Retry,
        'ignore': QMessageBox.Ignore,
    }


    def __init__(self, sys_argv):
        super(App, self).__init__(sys_argv)
        self.rootPath = os.path.dirname(os.path.realpath(__file__))
        self.logPath = '/var/log/sshmanager.log'
        self.configPath = os.environ.get('HOME')+'/.config/sshmanager/user.json'
        self.currentSelected = None
        self.display = Display.Instance({'app': self, 'rootPath': self.rootPath})
        self.logger = Logger.Instance()
        self.logger.config(self.logPath)
        self.logger.debug('Os : ' + sys.platform)
        self.logger.debug('Python version ' + str(sys.version_info.major)
            + '.' + str(sys.version_info.micro) + '.' + str(sys.version_info.minor)
        )
        self.logger.info('Starting app')
        self.run()

    def run(self) -> QWidget:
        """
            Build main widget
        """
        self.display.ask_password_ui()
        return self.display.main_ui()

    def genOneTimeKey(self, passwd):
        self.logger.info('Gen one time key')
        password = passwd.encode()
        salt = b'8qRA9Y8Q6z'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def save(self):
        """
            save configuration
        """
        encrypted = self.fernet.encrypt((json.dumps(self.config)).encode("utf-8"))
        with open(self.configPath, "wb") as f:
                f.write(encrypted)
        self.logger.info('saved')

    def load_connection(self, params):
        passwd = (params.get('field')).text()
        key = self.genOneTimeKey(passwd)
        self.fernet = Fernet(key)
        if not os.path.exists(os.path.dirname(self.configPath)):
            self.logger.info('Creating ' + self.configPath)
            os.makedirs(os.path.dirname(self.configPath))
            with open(self.configPath, "wb") as f:
                encrypted = self.fernet.encrypt(b'{"entries": []}')
                f.write(encrypted)
        try:
            with open(self.configPath, "rb") as f:
                data = f.read()
            self.config = json.loads(self.fernet.decrypt(data))
            self.logger.info('Decrypt data ok')
        except InvalidToken:
            exit(0)
        return (params.get('ui')).close()

    def add_connection_process(self, params):
        data = {
            "name": params.get('name').text(),
            "username": params.get('username').text(),
            "ip": params.get('ip').text(),
            "port": (params.get('port').text()) if (params.get('port').text()) != "" else "22",
            "password": params.get('password').text()
        }
        self.config['entries'].append(data)
        self.display.refresh_connection_list()
        (params.get('ui')).close()

    def edit_connection_process(self, params):
        self.logger.debug(str(params))
        (params.get('ui')).close()

    def defineCurrentItem(self, item):
        self.currentSelected = item
        self.logger.info('Current item : ' + item.text())
    
    def openSshWindow(self, item):
        self.logger.info('Open ssh window for ' + item.text())
        connection = self.getDataByItem(self.currentSelected)
        command = self.rootPath + '/run.sh ' + connection['username'] + ' ' + connection['ip'] + ' ' + connection['port'] + ' ' + connection['password']
        os.system("xterm -e 'bash -c \""+command+";\"'")

    def getDataByItem(self, item):
        for entrie in self.config['entries']:
            if entrie['name'] == item.text():
                data = entrie
                break
        return data

if __name__ == '__main__':
    app = App(sys.argv)
    app.setWindowIcon(QtGui.QIcon(app.rootPath + '/assets/imgs/icon.png'))
    sys.exit(app.exec_())