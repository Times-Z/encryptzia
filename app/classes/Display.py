# -*- coding: utf-8 -*-
from PyQt5 import QtCore
from PyQt5.QtWidgets import QAction, QDialog, QFormLayout, QGridLayout, QLineEdit, QListWidget, QListWidgetItem, QMenuBar, QMessageBox, QPushButton, QWidget

from .Singleton import Singleton

@Singleton
class Display():
    """
        Display class
    """
    
    def __init__(self, params):
        self.App = params.get('app')

    def ask_password_ui(self) -> QDialog:
        askPasswordWindow = QDialog()
        layout = QGridLayout()
        pwdField = QLineEdit()
        askPasswordWindow.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)
        acceptBtn = QPushButton('unlock')
        askPasswordWindow.setWindowTitle("Unlock manager")
        pwdField.setPlaceholderText('Your password')
        pwdField.setEchoMode(QLineEdit.Password)

        layout.addWidget(pwdField)
        layout.addWidget(acceptBtn)
        askPasswordWindow.setLayout(layout)

        self.App.logger.debug('Build ask password ui')
        acceptBtn.clicked.connect(lambda: self.App.load_connection({
            'ui': askPasswordWindow,
            'field': pwdField
        }))
        return askPasswordWindow.exec_()

    def main_ui(self) -> QWidget:
        self.main_window = QWidget()
        with open(self.App.rootPath + '/assets/style.css','r') as styleSheet:
            self.main_window.setStyleSheet(styleSheet.read())
        self.main_window.setWindowTitle("SSH Manager")
        menuBar = QMenuBar(self.main_window)
        fileMenu = menuBar.addMenu('File')
        editMenu = menuBar.addMenu('Edit')
        layout = QGridLayout()
        self.connectionList = QListWidget()
        self.refresh_connection_list()
        self.connectionList.itemClicked.connect(self.App.defineCurrentItem)
        self.connectionList.itemDoubleClicked.connect(self.App.openSshWindow)

        addButton = QPushButton('Add ssh connection')
        deleteButton = QPushButton('Delete ssh connection')

        layout.addWidget(menuBar)
        layout.addWidget(self.connectionList)
        layout.addWidget(addButton)
        layout.addWidget(deleteButton)

        saveAction = QAction('Save', self.App)
        exitAction = QAction('Exit', self.App)
        aboutAction = QAction('About', self.App)
        editAction = QAction('Edit selected connection', self.App)
        deleteAction = QAction('Delete selected connection', self.App)
        deleteConfig = QAction('Delete all configuration', self.App)

        saveAction.triggered.connect(self.App.save)
        fileMenu.addAction(saveAction)
        exitAction.triggered.connect(QtCore.QCoreApplication.quit)
        fileMenu.addAction(exitAction)

        editAction.triggered.connect(self.edit_connection_ui)
        editMenu.addAction(editAction)
        deleteAction.triggered.connect(self.delete_connection_ui)
        editMenu.addAction(deleteAction)
        deleteConfig.triggered.connect(self.delete_config_ui)
        editMenu.addAction(deleteConfig)

        aboutAction.triggered.connect(self.about_ui)
        menuBar.addAction(aboutAction)

        self.main_window.setLayout(layout)

        addButton.clicked.connect(self.add_connection_ui)
        deleteButton.clicked.connect(self.delete_connection_ui)
        self.main_window.show()
        self.main_window.move(0,0)
        self.App.logger.info('Build main ui')

        return self.main_window

    def add_connection_ui(self) -> QDialog:
        addConnectionWindow = QDialog()
        addConnectionWindow.setWindowTitle('New ssh connection')

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

        addBtn.clicked.connect(lambda: self.App.add_connection_process({
                "ui": addConnectionWindow,
                "name": nameField,
                "username": usernameFied,
                "ip": ipField,
                "port": portField,
                "password": passwordField
            }))
        addConnectionWindow.setLayout(layout)
        self.App.logger.info('Build add ssh connection ui')
        return addConnectionWindow.exec_()

    def edit_connection_ui(self) -> QDialog:
        if self.App.currentSelected:
            editConnectionWindow = QDialog()
            editConnectionWindow.setWindowTitle('New ssh connection')
            data = self.App.getDataByItem(self.App.currentSelected)
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

            addBtn.clicked.connect(lambda: self.App.edit_connection_process({
                    "ui": editConnectionWindow,
                    "name": nameField,
                    "username": usernameFied,
                    "ip": ipField,
                    "port": portField,
                    "password": passwordField
                }))
            editConnectionWindow.setLayout(layout)
            self.App.logger.info(
                'Build edit ssh connection ui for item ' + self.App.currentSelected.text()
            )
            return editConnectionWindow.exec_()

    def delete_connection_ui(self):
        self.App.logger.debug('Build delete ssh warning')

    def delete_config_ui(self):
        self.App.logger.debug('Build delete config warning')

    def about_ui(self) -> QMessageBox:
        window = QMessageBox()
        window.setWindowTitle('About')
        window.setText("""
            <div>{0} - V.{1}</div>
            <div>Write by <span style="color:red">Jonas Bertin</span></div>
            <div>2021</div>
        """.format(self.App.programName, self.App.programVersion))
        window.resize(100, 100)
        self.App.logger.info('Build about ui')
        return window.exec_()

    def refresh_connection_list(self) -> None:
        self.connectionList.clear()
        for entrie in self.App.config['entries']:
            item = QListWidgetItem(entrie['name'])
            item.setToolTip('IP : '+ entrie['ip'])
            self.connectionList.addItem(item)
        self.App.logger.info('Refresh connection list')
