#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import json
import os
from pathlib import Path
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
from PyQt5.QtWidgets import (QApplication, QMessageBox, QWidget)

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
        self.default_palette = QtGui.QGuiApplication.palette()
        self.root_path = os.path.dirname(os.path.realpath(__file__))
        with open(self.root_path + "/version.dat", "r") as f:
            self.version = f.read()
        self.log_path = '/var/log/encryptzia.log'
        self.config_path = os.environ.get(
            'HOME') + '/.config/encryptzia/user.json'
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
        config_exist = self.check_config()
        if config_exist:
            self.display.ask_password_ui()
        else:
            self.display.change_password_ui(True)
            self.create_config()
            self.load_configuration()
        try:
            self.display.set_style(self.config['uiTheme'], True)
        except AttributeError:
            log = traceback.format_exc()
            self.logger.crit(log)
            self.logger.crit('No password specified')
            sys.exit(1)
        return self.display.main_ui()

    def check_config(self) -> bool:
        """
            Check if the configuration exist
        """
        if not os.path.isfile(self.config_path):
            self.logger.warn('config path not existing' + self.config_path)
            return False
        return True

    def gen_one_time_key(self, passwd: str) -> bytes:
        """
            Generate one time key from password to encrypte / decrypte file
        """
        password = passwd.encode()
        salt = bytes(str(uuid.getnode()).encode("utf-8")) if (os.environ.get('ENCRYPTZIA_DEV_MODE')
                                                              is None or os.environ.get('ENCRYPTZIA_DEV_MODE') == 'false') else bytes(("devSaltIsNotSecure").encode("utf-8"))
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512,
            length=32,
            salt=salt,
            iterations=500000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.fernet = Fernet(key)
        self.logger.info('Gen one time key')
        return key

    def save(self) -> bool:
        """
            Save configuration
        """
        try:
            encrypted = self.fernet.encrypt(
                (json.dumps(self.config)).encode("utf-8"))
            with open(self.config_path, "wb") as f:
                f.write(encrypted)
            self.logger.info('Saved')
            return True
        except Exception:
            log = traceback.format_exc()
            self.logger.crit(log)
            return False

    def load_configuration(self, password: str = None) -> bool:
        """
            Decrypt file and load configuration
        """
        if password:
            self.gen_one_time_key(password)
        try:
            with open(self.config_path, "rb") as f:
                data = f.read()
            self.config = json.loads(self.fernet.decrypt(data))
            self.logger.info('Unlocked vault')
        except InvalidToken:
            self.logger.info('Unlocked vault failed')
            sys.exit(0)
        return True

    def add_edit_connection_process(self, params: dict) -> bool:
        """
            Store data from add/edit connection ui

            Save data if auto saved is on
        """
        data = {
            "uuid": params.get('uuid') if params.get('uuid') else str(uuid.uuid4()),
            "name": params.get('name'),
            "username": params.get('username'),
            "ip": params.get('ip'),
            "port": (params.get('port')) if (params.get('port')) != "" else "22",
            "password": params.get('password')
        }

        if params.get('uuid'):
            i = self.get_item_config_position(params.get('uuid'))
            self.config['entries'][i] = data
        else:
            self.config['entries'].append(data)

        return self.save() if self.config['autoSave'] == 'True' else True

    def delete_connection_process(self, action: int, uuid: str) -> bool:
        """
            Delete connection for connection ui

            Save data if auto saved is on
        """
        if action == QMessageBox.Yes:
            i = self.get_item_config_position(uuid)
            del self.config['entries'][i]
            self.logger.info('Deleted entrie number ' + str(i) +
                             ' of ' + str(len(self.config['entries'])))
            if self.config['autoSave'] == "True":
                self.save()
            return True
        else:
            return False

    def delete_config_process(self, action: int) -> bool:
        """
            Delete $HOME/.config/encryptzia and exit program
        """
        if action == QMessageBox.Yes:
            path = Path(self.config_path)
            if path.parent.absolute() == self.program_name:
                shutil.rmtree(os.environ.get('HOME') + '/.config/encryptzia')
                self.logger.info(
                    'Removed '+os.environ.get("HOME")+'/.config/encryptzia')
            else:
                os.unlink(self.config_path)
                self.logger.info('Removed ' + self.config_path)
            return True
        else:
            return False

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

    def open_ssh_window(self, data: dict) -> threading.Thread:
        """
            Create a thread and open an ssh window on it
        """
        self.logger.info(f'Open {self.config["shell"]} ssh window')
        base_64_password = base64.b64encode(
            bytes(data['password'], "utf-8"))
        command = (
            self.root_path
            + '/run.sh'
            + ' ' + data['username']
            + ' ' + data['ip']
            + ' ' + data['port']
            + ' ' + base_64_password.decode("utf-8")
            + ' ' + self.config['sshTimeout']
        )
        thread = threading.Thread(
            target=self.execute_command_on_thread, args=(command, data['uuid'])
        )
        thread.start()
        return thread

    def execute_command_on_thread(self, command: str, uuid: str) -> int:
        """
            Execute command and get return code for a subprocess in a thread
        """
        process = subprocess.Popen(
            self.config['shell'] + " -e bash -c '" + command + "';", shell=True
        )
        thread_name = threading.current_thread().getName()
        self.logger.info(f'{thread_name} running for item {uuid}')
        while process.poll() is None:
            time.sleep(0.1)
        self.logger.info(f'{thread_name} stop with code {str(process.poll())}')
        return process.poll()

    def get_data_by_item(self, itemId: int) -> dict:
        """
            Get data from item by unique id
        """
        for entrie in self.config['entries']:
            if entrie['uuid'] == itemId:
                data = entrie
                break
        return data

    def create_config(self) -> dict:
        """
            Create configuration
        """
        if not os.path.exists(os.path.dirname(self.config_path)):
            self.logger.info(
                'Creating ' + str(os.path.dirname(self.config_path)))
            os.makedirs(os.path.dirname(self.config_path))
        try:
            self.config = {
                "autoSave": "True",
                "sshTimeout": "10",
                "uiTheme": "Light",
                "shell": "xterm -fg white -bg black -fa 'DejaVu Sans Mono' -fs 12",
                "entries": []
            }
            saved = self.save()
            if not saved:
                raise Exception('No password specified')
        except Exception as e:
            self.logger.crit(str(e))
            sys.exit(1)
        self.logger.info('Creating ' + self.config_path)
        return self.config

    def set_password(self, password: str, repassword: str):
        """
            Set or edit the main password of app
        """
        if password == repassword:
            self.gen_one_time_key(password)
            return True
        else:
            return False

    def toogle_auto_save(self, checkbox: bool) -> str:
        """
            Toogle auto save
        """
        actual = self.config['autoSave']
        if checkbox:
            self.config['autoSave'] = "True"
        else:
            self.config['autoSave'] = "False"
        self.logger.info(
            'AutoSave from ' + str(actual) + ' to ' +
            str(self.config['autoSave'])
        )
        self.save()
        return self.config['autoSave']

    def change_shell_emulator(self, text: str, modified: bool) -> bool:
        if modified:
            self.config['shell'] = text
            return self.save()
        return False


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'DEBUG':
        os.environ['DEBUG'] = 'true'
        import debugpy
        print('Waiting debug session...')
        debugpy.listen(('0.0.0.0', 5678))
        debugpy.wait_for_client()
    app = Encryptzia(sys.argv)
    app.setWindowIcon(QtGui.QIcon(app.root_path + '/assets/imgs/icon.png'))
    app.run()
    sys.exit(app.exec_())