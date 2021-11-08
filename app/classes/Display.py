# -*- coding: utf-8 -*-
from PyQt5 import QtCore
from PyQt5.QtWidgets import QAction, QCheckBox, QDial, QDialog, QFormLayout, QGridLayout, QLineEdit, QListWidget, QListWidgetItem, QMenuBar, QMessageBox, QPushButton, QWidget

from .Singleton import Singleton

@Singleton
class Display():
    """
        Display class
    """
    
    def __init__(self, params):
        self.App = params.get('app')

    def ask_password_ui(self) -> QDialog:
        window = QDialog()
        layout = QGridLayout()
        pwdField = QLineEdit()
        window.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)
        acceptBtn = QPushButton('unlock')
        window.setWindowTitle("Unlock manager")
        pwdField.setPlaceholderText('Your password')
        pwdField.setEchoMode(QLineEdit.Password)
        pwdField.textEdited.connect(lambda: self.toogle_echo_password(pwdField))

        layout.addWidget(pwdField)
        layout.addWidget(acceptBtn)
        window.setLayout(layout)

        self.App.logger.info('Build ask password ui')
        acceptBtn.clicked.connect(lambda: self.App.load_connection({
            'ui': window,
            'field': pwdField
        }))
        return window.exec_()

    def main_ui(self) -> QWidget:
        self.mainWindow = QWidget()
        with open(self.App.rootPath + '/assets/style.css','r') as styleSheet:
            self.mainWindow.setStyleSheet(styleSheet.read())
        self.mainWindow.setWindowTitle("SSH Manager")
        menuBar = QMenuBar(self.mainWindow)
        fileMenu = menuBar.addMenu('File')
        editMenu = menuBar.addMenu('Edition')
        layout = QGridLayout()
        self.connectionList = QListWidget()
        self.refresh_connection_list()
        self.connectionList.itemClicked.connect(self.App.define_current_item)
        self.connectionList.itemDoubleClicked.connect(self.App.open_ssh_window)

        addButton = QPushButton('Add ssh connection')
        deleteButton = QPushButton('Delete ssh connection')

        layout.addWidget(menuBar)
        layout.addWidget(self.connectionList)
        layout.addWidget(addButton)
        layout.addWidget(deleteButton)

        saveAction = QAction('Save', self.App)
        exitAction = QAction('Exit', self.App)
        settingsAction = QAction('Settings', self.App)
        aboutAction = QAction('About', self.App)
        editAction = QAction('Edit selected connection', self.App)
        deleteAction = QAction('Delete selected connection', self.App)

        saveAction.triggered.connect(self.App.save)
        fileMenu.addAction(saveAction)
        exitAction.triggered.connect(QtCore.QCoreApplication.quit)
        fileMenu.addAction(exitAction)

        editAction.triggered.connect(self.edit_connection_ui)
        editMenu.addAction(editAction)
        deleteAction.triggered.connect(self.delete_connection_ui)
        editMenu.addAction(deleteAction)

        settingsAction.triggered.connect(self.settings_ui)
        menuBar.addAction(settingsAction)
        aboutAction.triggered.connect(self.about_ui)
        menuBar.addAction(aboutAction)

        self.mainWindow.setLayout(layout)

        addButton.clicked.connect(self.add_connection_ui)
        deleteButton.clicked.connect(self.delete_connection_ui)
        self.mainWindow.show()
        self.mainWindow.move(0,0)
        self.App.logger.info('Build main ui')

        return self.mainWindow

    def add_connection_ui(self) -> QDialog:
        window = QDialog()
        window.setWindowTitle('New ssh connection')

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
                "ui": window,
                "name": nameField,
                "username": usernameFied,
                "ip": ipField,
                "port": portField,
                "password": passwordField
            }))
        window.setLayout(layout)
        self.App.logger.info('Build add ssh connection ui')
        return window.exec_()

    def edit_connection_ui(self) -> QDialog:
        if self.App.currentSelected:
            window = QDialog()
            window.setWindowTitle('New ssh connection')
            data = self.App.get_data_by_item(self.App.currentSelected)
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
                    "ui": window,
                    "name": nameField,
                    "username": usernameFied,
                    "ip": ipField,
                    "port": portField,
                    "password": passwordField
                }))
            window.setLayout(layout)
            self.App.logger.info(
                'Build edit ssh connection ui for item ' + self.App.currentSelected.text()
            )
            return window.exec_()

    def delete_connection_ui(self) -> None:
        item = self.App.currentSelected
        window = QMessageBox()
        window.setIcon(QMessageBox.Warning)
        window.setWindowTitle('WARNING')
        window.setText("""
        <div style="color:red">Deleting {0}</div>
        <div>Are you sure ?</div>
        """.format(
            item.text()
        ))
        window.addButton(QMessageBox.Yes)
        window.addButton(QMessageBox.No)

        self.App.logger.debug('Build delete ssh warning')
        result = window.exec_()
        self.App.delete_connection_process(result, item)
        self.refresh_connection_list()

    def delete_config_ui(self) -> None:
        window = QMessageBox()
        window.setIcon(QMessageBox.Warning)
        window.setWindowTitle('WARNING')
        window.setText("""
        <div style="color:red">Deleting all the configuration</div>
        <div>Are you sure ?</div>
        """)
        window.addButton(QMessageBox.Yes)
        window.addButton(QMessageBox.No)

        self.App.logger.debug('Build delete config warning')
        result = window.exec_()
        self.App.delete_config_process(result)
        self.refresh_connection_list()

    def settings_ui(self) -> QDialog:
        window = QDialog()
        window.setWindowTitle('Settings')
        window.setFixedSize(400, 400)

        layout = QGridLayout()

        autoSaveCheckbox = QCheckBox('Auto save')
        deleteConfigBtn = QPushButton('Delete all configuration')
        changePasswordBtn = QPushButton('Change password')

        autoSaveCheckbox.setChecked(bool(self.App.config['autoSave']))

        autoSaveCheckbox.stateChanged.connect(lambda:
        self.App.toogle_auto_save(autoSaveCheckbox)
        )
        deleteConfigBtn.clicked.connect(self.delete_config_ui)
        changePasswordBtn.clicked.connect(self.change_password_ui)

        window.setLayout(layout)

        layout.addWidget(autoSaveCheckbox)
        layout.addWidget(deleteConfigBtn)
        layout.addWidget(changePasswordBtn)

        self.App.logger.info('Build settings ui')
        return window.exec_()

    def change_password_ui(self) -> QDialog:
        window = QDialog()
        layout = QGridLayout()
        window.setWindowTitle('Set password')

        password = QLineEdit()
        repassword = QLineEdit()
        password.setEchoMode(QLineEdit.Password)
        repassword.setEchoMode(QLineEdit.Password)

        layout.addWidget(password)
        layout.addWidget(repassword)

        window.setLayout(layout)

        return window.exec_()

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
        if self.App.config is not None:
            for entrie in self.App.config['entries']:
                item = QListWidgetItem(entrie['name'])
                item.setToolTip('IP : '+ entrie['ip'])
                self.connectionList.addItem(item)
        self.App.logger.info('Refresh connection list')

    def toogle_echo_password(self, item):
        item.setEchoMode(QLineEdit.Normal)
        QtCore.QTimer.singleShot(500, lambda: item.setEchoMode(QLineEdit.Password))
