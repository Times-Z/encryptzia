#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
from getopt import getopt
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
        self.NAME: str = 'Encryptzia'
        self.ROOT_PATH: str = os.path.dirname(os.path.realpath(__file__))
        with open(self.ROOT_PATH + "/version.dat", "r") as f:
            self.VERSION: str = f.read()
        self.LOG_PATH: str = '/var/log/encryptzia.log'
        self.CONFIG_PATH: str = os.environ.get(
            'HOME') + '/.config/encryptzia/user.json'
        self.display: Display = Display(self)
        self.logger: Logger = Logger()
        self.logger.config(self.LOG_PATH)
        self.logger.debug('Os : ' + sys.platform)
        self.logger.debug('Python version ' + str(sys.version_info.major) +
                          '.' + str(sys.version_info.minor)
                          + '.' + str(sys.version_info.micro)
                          )
        self.logger.info(self.NAME + ' ' + self.VERSION)

    def run(self) -> QWidget:
        """
            Run the program
        """
        config_exist: bool = self.check_config()
        if config_exist:
            self.display.ask_password_ui()
        else:
            self.display.change_password_ui(True)
            self.create_config()
            self.load_configuration()
        try:
            self.display.set_style(self.config['uiTheme'], True)
        except AttributeError:
            log: str = traceback.format_exc()
            self.logger.crit(log)
            self.logger.crit('No password specified')
            sys.exit(1)
        return self.display.main_ui()

    def check_config(self) -> bool:
        """
            Check if the configuration exist
        """
        if not os.path.isfile(self.CONFIG_PATH):
            self.logger.warn('config path not existing' + self.CONFIG_PATH)
            return False
        return True

    def gen_one_time_key(self, passwd: str) -> bytes:
        """
            Generate one time key from password to encrypte / decrypte file
        """
        password: bytes = passwd.encode()
        salt: bytes = bytes(str(uuid.getnode()).encode("utf-8")) if (os.environ.get('ENCRYPTZIA_DEV_MODE')
                                                                     is None or os.environ.get('ENCRYPTZIA_DEV_MODE') == 'false') else bytes(("devSaltIsNotSecure").encode("utf-8"))
        kdf: PBKDF2HMAC = PBKDF2HMAC(
            algorithm=hashes.SHA512,
            length=32,
            salt=salt,
            iterations=500000,
            backend=default_backend()
        )
        key: bytes = base64.urlsafe_b64encode(kdf.derive(password))
        self.fernet = Fernet(key)
        self.logger.info('Gen one time key')
        return key

    def save(self) -> bool:
        """
            Save configuration
        """
        try:
            encrypted: bytes = self.fernet.encrypt(
                (json.dumps(self.config)).encode("utf-8"))
            with open(self.CONFIG_PATH, "wb") as f:
                f.write(encrypted)
            self.logger.info('Saved')
            return True
        except Exception:
            log: str = traceback.format_exc()
            self.logger.crit(log)
            return False

    def load_configuration(self, password: str = None) -> bool:
        """
            Decrypt file and load configuration
        """
        if password:
            self.gen_one_time_key(password)
        try:
            with open(self.CONFIG_PATH, "rb") as f:
                data: bytes = f.read()
            self.config: dict = json.loads(self.fernet.decrypt(data))
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
        data: dict[str, str] = {
            "uuid": params.get('uuid') if params.get('uuid') else str(uuid.uuid4()),
            "name": params.get('name'),
            "username": params.get('username'),
            "ip": params.get('ip'),
            "port": (params.get('port')) if (params.get('port')) != "" else "22",
            "password": params.get('password')
        }

        if params.get('uuid'):
            i: int = self.get_item_config_position(params.get('uuid'))
            self.config['entries'][i] = data
        else:
            self.config['entries'].append(data)

        return self.save() if self.config['autoSave'] == 'True' else True

    def delete_connection_process(self, action: bool, uuid: str) -> bool:
        """
            Delete connection for connection ui

            Save data if auto saved is on
        """
        if action:
            i: int = self.get_item_config_position(uuid)
            del self.config['entries'][i]
            self.logger.info('Deleted entrie number ' + str(i) +
                             ' of ' + str(len(self.config['entries'])))
            if self.config['autoSave'] == "True":
                self.save()
            return True
        else:
            return False

    def delete_config_process(self, action: bool) -> bool:
        """
            Delete $HOME/.config/encryptzia and exit program
        """
        if action:
            path: Path = Path(self.CONFIG_PATH)
            if path.parent.absolute() == self.NAME:
                shutil.rmtree(os.environ.get('HOME') + '/.config/encryptzia')
                self.logger.info(
                    'Removed '+os.environ.get("HOME")+'/.config/encryptzia')
            else:
                os.unlink(self.CONFIG_PATH)
                self.logger.info('Removed ' + self.CONFIG_PATH)
            return True
        else:
            return False

    def get_item_config_position(self, uuid: str) -> int:
        """
            Get item position in configuration by unique id

            Used for editing or removing object from configuration
        """
        i: int = 0
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
        base_64_password: bytes = base64.b64encode(
            bytes(data['password'], "utf-8"))
        command: str = (
            self.ROOT_PATH
            + '/assets/scripts/ssh.sh'
            + ' ' + data['username']
            + ' ' + data['ip']
            + ' ' + data['port']
            + ' ' + base_64_password.decode("utf-8")
            + ' ' + self.config['sshTimeout']
        )
        thread: threading.Thread = threading.Thread(
            target=self.execute_command_on_thread, args=(command, data['uuid'])
        )
        thread.start()
        return thread

    def execute_command_on_thread(self, command: str, uuid: str) -> int:
        """
            Execute command and get return code for a subprocess in a thread
        """
        process: subprocess.Popen = subprocess.Popen(
            self.config['shell'] + " -e bash -c '" + command + "';", shell=True
        )
        thread_name: str = threading.current_thread().getName()
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
                data: dict[str, str] = entrie
                break
        return data

    def create_config(self) -> dict:
        """
            Create configuration
        """
        if not os.path.exists(os.path.dirname(self.CONFIG_PATH)):
            self.logger.info(
                'Creating ' + str(os.path.dirname(self.CONFIG_PATH)))
            os.makedirs(os.path.dirname(self.CONFIG_PATH))
        try:
            self.config: dict[str, str] = {
                "autoSave": "True",
                "sshTimeout": "10",
                "uiTheme": "Light",
                "shell": "xterm -fg white -bg black -fa 'DejaVu Sans Mono' -fs 12",
                "entries": []
            }
            saved: bool = self.save()
            if not saved:
                raise Exception('No password specified')
        except Exception as e:
            self.logger.crit(str(e))
            sys.exit(1)
        self.logger.info('Creating ' + self.CONFIG_PATH)
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
        actual: str = self.config['autoSave']
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
    argv = sys.argv[1:]
    try:
        mode: str = 'gui'
        debug: bool = False
        opts, args = getopt(argv, 'm:d:', [
            "mode=",
            "debug="
        ])

        for opt, arg in opts:
            if opt in ['-m', '--mode']:
                mode = arg
            elif opt in ['-d', '--debug']:
                debug = arg

        if debug:
            import debugpy
            print('Waiting debug session...')
            debugpy.listen(('0.0.0.0', 5678))
            debugpy.wait_for_client()
        if mode == 'gui':
            app = Encryptzia(sys.argv)
            app.setWindowIcon(QtGui.QIcon(
                app.ROOT_PATH + '/assets/imgs/icon.png'))
            app.run()
            sys.exit(app.exec_())
        elif mode == 'tui':
            print('TUI is not currently available')
            sys.exit(0)
        raise Exception('Missing argument')
    except Exception as e:
        print(e)
        sys.exit(1)
