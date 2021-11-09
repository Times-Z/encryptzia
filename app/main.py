#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import shutil
import sys
import uuid

from PyQt5.QtCore import Qt

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5 import QtGui
from PyQt5.QtWidgets import (QApplication, QCheckBox, QListWidgetItem,
                             QMessageBox, QRadioButton, QWidget)

from classes import Display, Logger


class App(QApplication):
    """
        Main class
        - Run the main window and the manager
    """

    def __init__(self, sys_argv):
        super(App, self).__init__(sys_argv)
        self.programName = 'NaN named'
        self.programVersion = "Alpha 0.1.0"
        self.defaultPalette = QtGui.QGuiApplication.palette()
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
        self.logger.info(self.programName + ' v.' + self.programVersion)

    def run(self) -> QWidget:
        firstSet = self.check_config()
        if firstSet:
            self.load_connection({}, True)
        else:
            self.display.ask_password_ui()
        self.set_style(self.config['uiTheme'])
        return self.display.main_ui()

    def set_style(self, theme) -> QtGui.QPalette:
        self.setStyle("Fusion")
        palette = QtGui.QPalette()
        if theme == 'Dark':
            palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.WindowText, Qt.white)
            palette.setColor(QtGui.QPalette.Base, QtGui.QColor(35, 35, 35))
            palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.ToolTipBase, QtGui.QColor(25, 25, 25))
            palette.setColor(QtGui.QPalette.ToolTipText, Qt.white)
            palette.setColor(QtGui.QPalette.Text, Qt.white)
            palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.ButtonText, Qt.white)
            palette.setColor(QtGui.QPalette.BrightText, Qt.red)
            palette.setColor(QtGui.QPalette.Link, QtGui.QColor(42, 130, 218))
            palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(42, 130, 218))
            palette.setColor(QtGui.QPalette.HighlightedText, Qt.black)
        else:
            palette = self.defaultPalette
        self.config['uiTheme'] = theme
        self.logger.info('Set palette ' + theme)
        if self.config['autoSave'] == "True":
            self.save(False)
        return self.setPalette(palette)

    def check_config(self) -> bool:
        return self.create_config()

    def gen_one_time_key(self, passwd: str) -> bytes:
        password = passwd.encode()
        salt = bytes(str(uuid.getnode()).encode("utf-8"))
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.logger.info('Gen one time key')
        return key

    def save(self, notify=True) -> bool:
        """
            save configuration
        """
        try:
            encrypted = self.fernet.encrypt((json.dumps(self.config)).encode("utf-8"))
            with open(self.configPath, "wb") as f:
                    f.write(encrypted)
            if notify:
                self.display.notify('Saved', 'ok')
            self.logger.info('Saved')
            return True
        except:
            return False

    def load_connection(self, params: dict, firstSet=False) -> bool:
        if not firstSet:
            passwd = (params.get('field')).text()
            key = self.gen_one_time_key(passwd)
            self.fernet = Fernet(key)
        try:
            with open(self.configPath, "rb") as f:
                data = f.read()
            self.config = json.loads(self.fernet.decrypt(data))
            self.logger.info('Unlocked vault')
        except InvalidToken:
            self.logger.info('Unlocked vault failed')
            exit(0)
        if not firstSet:
            returned = (params.get('ui')).close()
        else:
            returned = True
        return returned

    def add_connection_process(self, params: dict) -> bool:
        data = {
            "uuid": str(uuid.uuid4()),
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
        data = {
            "uuid": params.get('uuid'),
            "name": params.get('name').text(),
            "username": params.get('username').text(),
            "ip": params.get('ip').text(),
            "port": (params.get('port').text()) if (params.get('port').text()) != "" else "22",
            "password": params.get('password').text()
        }
        i = self.get_item_config_position(params.get('uuid'))
        self.config['entries'][i] = data
        if self.config['autoSave'] == "True":
            self.save()
        self.display.refresh_connection_list()
        return (params.get('ui')).close()

    def delete_connection_process(self, action: int, item: QListWidgetItem) -> bool:
        if action == QMessageBox.Yes:
            i = self.get_item_config_position(item.data(999))
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
        self.logger.info('Current item : ' + item.data(999))
        return self.currentSelected

    def get_item_config_position(self, uuid: str) -> int:
        i=0
        for entrie in self.config['entries']:
            if entrie['uuid'] == uuid:
                break
            i+=1
        return i

    def open_ssh_window(self, item: QListWidgetItem):
        connection = self.get_data_by_item(item)
        self.logger.info('Open ssh window for ' + connection['uuid'])
        command = self.rootPath + '/run.sh ' + connection['username'] + ' ' + connection['ip'] + ' ' + connection['port'] + ' ' + connection['password'] + ' ' + self.config['sshTimeout']
        os.system("xterm -e 'bash -c \""+command+";\"'")

    def get_data_by_item(self, item: QListWidgetItem) -> dict:
        for entrie in self.config['entries']:
            if entrie['uuid'] == item.data(999):
                data = entrie
                break
        return data

    def create_config(self) -> bool:
        created = False
        if not os.path.exists(os.path.dirname(self.configPath)):
            self.logger.info('Creating ' + str(os.path.dirname(self.configPath)))
            os.makedirs(os.path.dirname(self.configPath))
            created = True
        if not os.path.isfile(self.configPath):
            self.display.change_password_ui(True)
            try:
                self.config = {
                    "autoSave": "True",
                    "sshTimeout": "10",
                    "uiTheme": "Dark",
                    "entries": []
                }
                encrypted = self.fernet.encrypt(
                    b'{"autoSave": "True", "sshTimeout": "10", "uiTheme": "Dark", "entries": []}'
                )
            except:
                self.logger.crit('Failed to encrypt str ' + str(self.config))
                exit(1)
            with open(self.configPath, "wb") as f:
                f.write(encrypted)
            created = True
            self.logger.info('Creating ' + self.configPath)
        return created

    def set_password(self, params: dict):
        if (params.get('password')).text() == (params.get('repassword')).text():
            key = self.gen_one_time_key(params.get('password').text())
            self.fernet = Fernet(key)
            self.save(False)
            self.display.notify('Password changed', 'ok')
            return (params.get('ui')).close()
        else:
            self.display.notify('Both password not matched', 'error')

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
