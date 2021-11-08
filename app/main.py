#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys, os, base64, json
from PyQt5.QtWidgets import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from PyQt5 import QtCore, QtGui
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
        self.logger = Logger.Instance()
        self.logger.config(self.logPath)
        self.logger.debug('Os : ' + sys.platform)
        self.logger.debug('Python version ' + str(sys.version_info.major)
            + '.' + str(sys.version_info.micro) + '.' + str(sys.version_info.minor)
        )
        self.logger.info('Starting app')
        self.build_ui()

    def build_ui(self) -> QWidget:
        """
            Build main widget
        """
        # Define all widget
        self.askPass()

        self.main_window = QWidget()
        with open(self.rootPath + '/assets/style.css','r') as styleSheet:
            self.main_window.setStyleSheet(styleSheet.read())
        self.main_window.setWindowTitle("SSH Manager")
        self.menuBar = QMenuBar(self.main_window)
        fileMenu = self.menuBar.addMenu('File')
        editMenu = self.menuBar.addMenu('Edit')
        self.layout = QGridLayout()
        self.connectionList = QListWidget()
        self.refreshConnectionList()
        self.connectionList.itemClicked.connect(self.defineCurrentItem)
        self.connectionList.itemDoubleClicked.connect(self.openSshWindow)

        addButton = QPushButton('Add ssh connection')
        deleteButton = QPushButton('Delete ssh connection')

        self.layout.addWidget(self.menuBar)
        self.layout.addWidget(self.connectionList)
        self.layout.addWidget(addButton)
        self.layout.addWidget(deleteButton)

        saveAction = QAction('Save', self)
        exitAction = QAction('Exit', self)
        aboutAction = QAction('About', self)
        editAction = QAction('Edit selected connection', self)

        saveAction.triggered.connect(self.save)
        fileMenu.addAction(saveAction)
        exitAction.triggered.connect(QtCore.QCoreApplication.quit)
        fileMenu.addAction(exitAction)
        editAction.triggered.connect(self.edit_connection_window)
        editMenu.addAction(editAction)
        aboutAction.triggered.connect(self.showAbout)
        self.menuBar.addAction(aboutAction)

        self.main_window.setLayout(self.layout)

        addButton.clicked.connect(self.add_connection_window)
        deleteButton.clicked.connect(self.delete_connection)
        self.main_window.show()
        self.main_window.move(0,0)
        self.logger.info('Build main ui')

        return self.main_window

    def askPass(self):
        """
            Load connections from encrypted file
        """
        self.logger.info('Build password ask ui')
        self.askPasswordWindow = QDialog()
        layout = QGridLayout()
        pwdField = QLineEdit()
        self.askPasswordWindow.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)
        acceptBtn = QPushButton('unlock')
        self.askPasswordWindow.setWindowTitle("Unlock manager")
        pwdField.setPlaceholderText('Your password')
        pwdField.setEchoMode(QLineEdit.Password)

        layout.addWidget(pwdField)
        layout.addWidget(acceptBtn)
        self.askPasswordWindow.setLayout(layout)
        acceptBtn.clicked.connect(lambda: self.load_connection(pwdField))
        self.askPasswordWindow.exec_()

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

    def load_connection(self, field):
        passwd = field.text()
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
        return self.askPasswordWindow.close()

    def add_connection_window(self):
        """
            add ssh connection
        """
        self.logger.info('Build add ssh connection ui')
        self.addConnectionWindow = QDialog()
        self.addConnectionWindow.setWindowTitle('New ssh connection')
        layout = QFormLayout()
        nameField = QLineEdit()
        usernameFied = QLineEdit()
        ipField = QLineEdit()
        portField = QLineEdit('22')
        passwordField = QLineEdit()
        addBtn = QPushButton('add')

        nameField.setPlaceholderText('Common name')
        usernameFied.setPlaceholderText('Username')
        ipField.setPlaceholderText('192.168.1.9')
        portField.setPlaceholderText('22 (default)')
        passwordField.setPlaceholderText('123456')

        layout.addWidget(nameField)
        layout.addWidget(usernameFied)
        layout.addWidget(ipField)
        layout.addWidget(portField)
        layout.addWidget(passwordField)
        layout.addWidget(addBtn)

        addBtn.clicked.connect(lambda: self.add_connection_process({
                "name": nameField,
                "username": usernameFied,
                "ip": ipField,
                "port": portField,
                "password": passwordField
            }))
        self.addConnectionWindow.setLayout(layout)
        self.addConnectionWindow.exec_()

    def add_connection_process(self, params):
        data = {
            "name": params.get('name').text(),
            "username": params.get('username').text(),
            "ip": params.get('ip').text(),
            "port": (params.get('port').text()) if (params.get('port').text()) != "" else "22",
            "password": params.get('password').text()
        }
        self.config['entries'].append(data)
        self.refreshConnectionList()
        self.addConnectionWindow.close()

    def edit_connection_window(self):
        if self.currentSelected:
            self.logger.info('Build edit ssh connection ui for item ' + self.currentSelected.text())
            self.editConnectionWindow = QDialog()
            self.editConnectionWindow.setWindowTitle('New ssh connection')
            data = self.getDataByItem(self.currentSelected)
            layout = QFormLayout()
            nameField = QLineEdit(data['name'])
            usernameFied = QLineEdit(data['username'])
            ipField = QLineEdit(data['ip'])
            portField = QLineEdit(data['port'])
            passwordField = QLineEdit(data['password'])
            addBtn = QPushButton('edit')

            layout.addWidget(nameField)
            layout.addWidget(usernameFied)
            layout.addWidget(ipField)
            layout.addWidget(portField)
            layout.addWidget(passwordField)
            layout.addWidget(addBtn)

            addBtn.clicked.connect(lambda: self.add_connection_process({
                    "name": nameField,
                    "username": usernameFied,
                    "ip": ipField,
                    "port": portField,
                    "password": passwordField
                }))
            self.editConnectionWindow.setLayout(layout)
            self.editConnectionWindow.exec_()

    def refreshConnectionList(self):
        self.connectionList.clear()
        for entrie in self.config['entries']:
            item = QListWidgetItem(entrie['name'])
            item.setToolTip('IP : '+ entrie['ip'])
            self.connectionList.addItem(item)
            
        self.logger.info('Refresh connection list')

    def delete_connection(self):
        """
            delete ssh connection
        """
        self.logger.debug('delete ssh connection')

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

    def showAbout(self):
        self.logger.info('Build about ui')
        w = QMessageBox()
        w.setWindowTitle('About')
        w.setText("""
            <div>Program write by Jonas Bertin</div>
            <div>2021</div>
        """)
        w.resize(100, 100)
        w.exec_()

if __name__ == '__main__':
    app = App(sys.argv)
    app.setWindowIcon(QtGui.QIcon(app.rootPath + '/assets/imgs/icon.png'))
    sys.exit(app.exec_())