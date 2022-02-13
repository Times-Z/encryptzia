#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import shutil
import sys
import traceback
import uuid
import subprocess
import threading
import time

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5 import QtGui
from PyQt5.QtWidgets import (QApplication, QCheckBox, QLineEdit,
                             QListWidgetItem, QMessageBox, QWidget)

from classes import Display, Logger


class Encryptzia(QApplication):
    """
        Main class
        - Run the program
        - Check and create config
        - Do process
    """

    def __init__(self, sys_argv):
        super(Encryptzia, self).__init__(sys_argv)
        self.program_name = 'Encryptzia'
        self.version = (open("version.dat", "r")).read()
        self.default_palette = QtGui.QGuiApplication.palette()
        self.root_path = os.path.dirname(os.path.realpath(__file__))
        self.log_path = '/var/log/encryptzia.log'
        self.config_path = os.environ.get(
            'HOME') + '/.config/encryptzia/user.json'
        self.current_selected = None
        self.display = Display(self)
        self.logger = Logger()
        self.logger.config(self.log_path)
        self.logger.debug('Os : ' + sys.platform)
        self.logger.debug('Python version ' + str(sys.version_info.major)
                          + '.' + str(sys.version_info.micro) +
                          '.' + str(sys.version_info.minor)
                          )
        self.logger.info(self.program_name + ' ' + self.version)

    def run(self) -> QWidget:
        """
            Run the program
        """
        first_set = self.check_config()
        if first_set:
            self.load_configuration({}, True)
        else:
            self.display.ask_password_ui()
        self.display.set_style(self.config['uiTheme'], True)
        return self.display.main_ui()

    def check_config(self) -> bool:
        """
            Check the configuration

            (to do : check running program)
        """
        return self.create_config()

    def gen_one_time_key(self, passwd: str) -> bytes:
        """
            Generate one time key from password to encrypte / decrypte file
        """
        password = passwd.encode()
        salt = bytes(str(uuid.getnode()).encode("utf-8")) if (os.environ.get('ENCRYPTZIA_DEV_MODE')
                                                              is None or os.environ.get('ENCRYPTZIA_DEV_MODE') == 'false') else bytes(("devSaltIsNotSecure").encode("utf-8"))
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
            Save configuration
        """
        try:
            encrypted = self.fernet.encrypt(
                (json.dumps(self.config)).encode("utf-8"))
            with open(self.config_path, "wb") as f:
                f.write(encrypted)
            if notify:
                self.display.notify('Saved', 'ok')
            self.logger.info('Saved')
            return True
        except Exception:
            log = traceback.format_exc()
            self.logger.crit(log)
            return False

    def load_configuration(self, params: dict, first_set=False) -> bool:
        """
            Decrypt file and load configuration
        """
        if not first_set:
            passwd = (params.get('field')).text()
            key = self.gen_one_time_key(passwd)
            self.fernet = Fernet(key)
        try:
            with open(self.config_path, "rb") as f:
                data = f.read()
            self.config = json.loads(self.fernet.decrypt(data))
            self.logger.info('Unlocked vault')
        except InvalidToken:
            self.logger.info('Unlocked vault failed')
            exit(0)
        if not first_set:
            returned = (params.get('ui')).close()
        else:
            returned = True
        return returned

    def add_edit_connection_process(self, params: dict) -> bool:
        """
            Store data for add or edit connection ui

            Save data if auto saved is on
        """
        data = {
            "uuid": params.get('uuid') if params.get('uuid') else str(uuid.uuid4()),
            "name": params.get('name').text(),
            "username": params.get('username').text(),
            "ip": params.get('ip').text(),
            "port": (params.get('port').text()) if (params.get('port').text()) != "" else "22",
            "password": params.get('password').text()
        }
        if params.get('uuid'):
            i = self.get_item_config_position(params.get('uuid'))
            self.config['entries'][i] = data
        else:
            self.config['entries'].append(data)
        if self.config['autoSave'] == "True":
            self.save()
        self.display.refresh_connection_list()
        return (params.get('ui').close())

    def delete_connection_process(self, action: int, item: QListWidgetItem) -> bool:
        """
            Delete connection for connection ui

            Save data if auto saved is on
        """
        if action == QMessageBox.Yes:
            i = self.get_item_config_position(item.data(999))
            del self.config['entries'][i]
            self.logger.info('Deleted entrie number ' + str(i))
            if self.config['autoSave'] == "True":
                self.save()
            return True
        else:
            return False

    def delete_config_process(self, action) -> bool:
        """
            Delete $HOME/.config/encryptzia and exit program
        """
        if action == QMessageBox.Yes:
            shutil.rmtree(os.environ.get('HOME') + '/.config/encryptzia')
            self.logger.info('Removed $HOME/.config/encryptzia')
            exit(0)
        else:
            return False

    def define_current_item(self, item: QListWidgetItem) -> QListWidgetItem:
        """
            Store item clicked in variable
        """
        self.current_selected = item
        return self.current_selected

    def get_item_config_position(self, uuid: str) -> int:
        """
            Get item position in configuration by unique id

            Used for editing or removing object from configuration
        """
        i = 0
        for entrie in self.config['entries']:
            if entrie['uuid'] == uuid:
                break
            i += 1
        return i

    def open_ssh_window(self, item: QListWidgetItem) -> threading.Thread:
        """
            Create a thread and open an ssh window on it
        """
        connection = self.get_data_by_item(item)
        self.logger.info(f'Open {self.config["shell"]} ssh window')
        base_64_password = base64.b64encode(
            bytes(connection['password'], "utf-8"))
        command = (
            self.root_path
            + '/run.sh'
            + ' ' + connection['username']
            + ' ' + connection['ip']
            + ' ' + connection['port']
            + ' ' + base_64_password.decode("utf-8")
            + ' ' + self.config['sshTimeout']
        )
        thread = threading.Thread(
            target=self.execute_command_on_thread, args=(command, item)
        )
        thread.start()
        return thread

    def execute_command_on_thread(self, command: str, item: QListWidgetItem) -> int:
        """
            Execute command and get return code for a subprocess in a thread
        """
        process = subprocess.Popen(
            self.config['shell'] + " -e bash -c '" + command + "';", shell=True
        )
        thread_name = threading.current_thread().getName()
        self.logger.info(f'{thread_name} running for item {item.data(999)}')
        while process.poll() is None:
            time.sleep(0.1)
        self.logger.info(f'{thread_name} stop with code {str(process.poll())}')
        return process.poll()

    def get_data_by_item(self, item: QListWidgetItem) -> dict:
        """
            Get data from item by unique id
        """
        for entrie in self.config['entries']:
            if entrie['uuid'] == item.data(999):
                data = entrie
                break
        return data

    def create_config(self) -> bool:
        """
            Create configuration if not exist
        """
        created = False
        if not os.path.exists(os.path.dirname(self.config_path)):
            self.logger.info(
                'Creating ' + str(os.path.dirname(self.config_path)))
            os.makedirs(os.path.dirname(self.config_path))
            created = True
        if not os.path.isfile(self.config_path):
            self.display.change_password_ui(True)
            try:
                self.config = {
                    "autoSave": "True",
                    "sshTimeout": "10",
                    "uiTheme": "Light",
                    "shell": "xterm -fg white -bg black -fa 'DejaVu Sans Mono' -fs 12",
                    "entries": []
                }
                encrypted = self.fernet.encrypt(
                    bytes(json.dumps(self.config), encoding='utf-8')
                )
            except Exception:
                log = traceback.format_exc()
                self.logger.crit(log)
                self.logger.crit('No password specified, exiting')
                exit(1)
            with open(self.config_path, "wb") as f:
                f.write(encrypted)
            created = True
            self.logger.info('Creating ' + self.config_path)
        return created

    def set_password(self, params: dict):
        """
            Set or edit the main password of app
        """
        if (params.get('password')).text() == (params.get('repassword')).text():
            key = self.gen_one_time_key(params.get('password').text())
            self.fernet = Fernet(key)
            if hasattr(self, 'config'):
                self.save(False)
                self.display.notify('Password changed', 'ok')
            else:
                self.display.notify('Password set', 'ok')
            return (params.get('ui')).close()
        else:
            self.display.notify('Both password not matched', 'error')

    def toogle_auto_save(self, checkbox: QCheckBox) -> bool:
        """
            Toogle auto save
        """
        actual = self.config['autoSave']
        if checkbox.isChecked():
            self.config['autoSave'] = "True"
        else:
            self.config['autoSave'] = "False"
        self.logger.info(
            'AutoSave from ' + str(actual) + ' to ' +
            str(self.config['autoSave'])
        )
        self.save(False)
        return self.config['autoSave']

    def change_shell_emulator(self, item: QLineEdit) -> bool:
        if item.isModified:
            self.config['shell'] = item.text()
            return self.save(False)


if __name__ == '__main__':
    app = Encryptzia(sys.argv)
    app.setWindowIcon(QtGui.QIcon(app.root_path + '/assets/imgs/icon.png'))
    app.run()
    sys.exit(app.exec_())
