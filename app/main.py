#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys, os
from PyQt5.QtWidgets import *
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
        self.logger = Logger.Instance()
        self.logger.config(self.logPath)
        self.logger.debug('Os : ' + sys.platform)
        self.logger.debug('Python version ' + str(sys.version_info.major)
            + '.' + str(sys.version_info.micro) + '.' + str(sys.version_info.minor)
        )
        self.logger.info('starting app')
        self.build_ui()

    def build_ui(self) -> QWidget:
        """
            Build main widget
        """
        self.main_window = QWidget()
        self.main_window.setWindowTitle("SSH Manager")
        self.main_window.setWindowFlags(QtCore.Qt.MSWindowsOwnDC)

        with open(self.rootPath + '/assets/style.css','r') as styleSheet:
            self.main_window.setStyleSheet(styleSheet.read())

        self.layout = QGridLayout()

        # connection list & buttons
        self.connectionList = QListWidget()
        self.init()
        self.addButton = QPushButton('Add ssh connection')
        self.deleteButton = QPushButton('Delete ssh connection')

        self.layout.addWidget(self.connectionList)
        self.layout.addWidget(self.addButton)
        self.layout.addWidget(self.deleteButton)
        self.main_window.setLayout(self.layout)

        self.addButton.clicked.connect(self.add_connection)
        self.deleteButton.clicked.connect(self.delete_connection)
        self.main_window.show()
        self.main_window.move(0,0)
        self.logger.info('Build ui')

        return self.main_window

    def init(self):
        """
            Load connections from encrypted file
        """
        first=False
        if not os.path.exists(os.path.dirname(self.configPath)):
            first=True
            self.logger.info('Creating ' + self.configPath)
            os.makedirs(os.path.dirname(self.configPath))
            with open(self.configPath, "w") as f:
                f.write('')

        dialog = QDialog()
        layout = QGridLayout()
        pwdField = QLineEdit()
        dialog.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)

        if first:
            retypePwdField = QLineEdit()
            acceptBtn = QPushButton('create')
            dialog.setWindowTitle("Set password")
            pwdField.setPlaceholderText('Your password')
            pwdField.setEchoMode(QLineEdit.Password)
            retypePwdField.setPlaceholderText('Retrype your password')
            retypePwdField.setEchoMode(QLineEdit.Password)

            layout.addWidget(pwdField)
            layout.addWidget(retypePwdField)
            layout.addWidget(acceptBtn)
            dialog.setLayout(layout)
            acceptBtn.clicked.connect(lambda: self.setPswd(pwdField))
            dialog.exec_()
        else:
            acceptBtn = QPushButton('unlock')
            dialog.setWindowTitle("Unlock manager")
            pwdField.setPlaceholderText('Your password')
            pwdField.setEchoMode(QLineEdit.Password)

            layout.addWidget(pwdField)
            layout.addWidget(acceptBtn)
            dialog.setLayout(layout)
            acceptBtn.clicked.connect(lambda: self.load_connection(pwdField))
            dialog.exec_()


    def setPswd(self, field):
        passwd = field.text()
        self.logger.debug(passwd)


    def load_connection(self, field):
        passwd = field.text()
        self.logger.debug(passwd)

    def add_connection(self):
        """
            add ssh connection
        """
        self.logger.debug('add ssh connection')

    def delete_connection(self):
        """
            delete ssh connection
        """
        self.logger.debug('delete ssh connection')

if __name__ == '__main__':
    app = App(sys.argv)
    app.setWindowIcon(QtGui.QIcon(app.rootPath + '/assets/imgs/icon.png'))
    sys.exit(app.exec_())