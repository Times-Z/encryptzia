#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import shutil
import sys

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5 import QtGui
from PyQt5.QtWidgets import (QApplication, QCheckBox, QListWidgetItem,
                             QMessageBox, QWidget)

from classes import Display, Logger


class App(QApplication):
    """
        Main class
        - Run the main window and the manager
    """

    def __init__(self, sys_argv):
        super(App, self).__init__(sys_argv)
        self.programName = 'Maxi Manager'
        self.programVersion = "0.1.0"
        self.rootPath = os.path.dirname(os.path.realpath(__file__))
        self.logPath = '/var/log/sshmanager.log'
        self.configPath = os.environ.get('HOME')+'/.config/sshmanager/user.json'
        self.currentSelected = None
        self.display = Display.Instance({'app': self})
        self.logger = Logger.Instance()
        self.logger.config(self.logPath)
        self.logger.debug('Os : ' + sys.platform)
        self.logger.debug('Python version ' + str(sys.version_info.major)
            + '.' + str(sys.version_info.micro) + '.' + str(sys.version_info.minor)
        )
        self.logger.info('Starting app')

    def run(self) -> QWidget:
        """
            Build main widget
        """
        self.display.ask_password_ui()
        return self.display.main_ui()

    def gen_one_time_key(self, passwd: str) -> bytes:
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

    def save(self) -> bool:
        """
            save configuration
        """
        try:
            encrypted = self.fernet.encrypt((json.dumps(self.config)).encode("utf-8"))
            with open(self.configPath, "wb") as f:
                    f.write(encrypted)
            self.logger.info('saved')
            return True
        except:
            return False

    def load_connection(self, params: dict) -> bool:
        passwd = (params.get('field')).text()
        key = self.gen_one_time_key(passwd)
        self.fernet = Fernet(key)
        self.create_config()
        try:
            with open(self.configPath, "rb") as f:
                data = f.read()
            self.config = json.loads(self.fernet.decrypt(data))
            self.logger.info('Decrypt data ok')
        except InvalidToken:
            exit(0)
        return (params.get('ui')).close()

    def add_connection_process(self, params: dict) -> bool:
        data = {
            "name": params.get('name').text(),
            "username": params.get('username').text(),
            "ip": params.get('ip').text(),
            "port": (params.get('port').text()) if (params.get('port').text()) != "" else "22",
            "password": params.get('password').text()
        }
        self.config['entries'].append(data)
        self.display.refresh_connection_list()
        if self.config['autoSave'] == "True":
            self.save()
        return (params.get('ui')).close()

    def edit_connection_process(self, params: dict) -> bool:
        self.logger.debug(str(params))
        return (params.get('ui')).close()

    def delete_connection_process(self, action: int, item: QListWidgetItem) -> bool:
        if action == QMessageBox.Yes:
            i=0
            for entrie in self.config['entries']:
                if entrie['name'] == item.text():
                    break
                i+=1
            del self.config['entries'][i]
            self.logger.info('Deleted entrie number ' + str(i))
            if self.config['autoSave'] == "True":
                self.save()
            return True
        else:
            return False

    def delete_config_process(self, action) -> int:
        if action == QMessageBox.Yes:
            shutil.rmtree(os.environ.get('HOME') + '/.config/sshmanager')
            self.config = None
            self.create_config()
            if self.config['autoSave'] == "True":
                self.save()
            return True
        else:
            return False

    def define_current_item(self, item: QListWidgetItem) -> QListWidgetItem:
        self.currentSelected = item
        self.logger.info('Current item : ' + item.text())
        return self.currentSelected
    
    def open_ssh_window(self, item: QListWidgetItem):
        self.logger.info('Open ssh window for ' + item.text())
        connection = self.get_data_by_item(item)
        command = self.rootPath + '/run.sh ' + connection['username'] + ' ' + connection['ip'] + ' ' + connection['port'] + ' ' + connection['password']
        os.system("xterm -e 'bash -c \""+command+";\"'")

    def get_data_by_item(self, item: QListWidgetItem) -> dict:
        for entrie in self.config['entries']:
            if entrie['name'] == item.text():
                data = entrie
                break
        return data

    def create_config(self) -> bool:
        if not os.path.exists(os.path.dirname(self.configPath)):
            self.logger.info('Creating ' + self.configPath)
            os.makedirs(os.path.dirname(self.configPath))
            with open(self.configPath, "wb") as f:
                self.config = {"autoSave": "True", "entries": []}
                encrypted = self.fernet.encrypt(b'{"autoSave": "True", "entries": []}')
                f.write(encrypted)
        return True

    def toogle_auto_save(self, checkbox: QCheckBox) -> bool:
        actual = self.config['autoSave']
        if checkbox.isChecked():
            self.config['autoSave'] = True
        else:
            self.config['autoSave'] = False
        self.logger.info(
            'AutoSave from ' + str(actual) + ' to ' + str(self.config['autoSave'])
        )
        self.save()
        return self.config['autoSave']

if __name__ == '__main__':
    app = App(sys.argv)
    app.setWindowIcon(QtGui.QIcon(app.rootPath + '/assets/imgs/icon.png'))
    app.run()
    sys.exit(app.exec_())
