# -*- coding: utf-8 -*-
from PyQt5 import QtCore
from PyQt5.QtWidgets import (QAction, QCheckBox, QDialog, QFormLayout,
                             QGridLayout, QLabel, QLayout, QLineEdit, QListWidget,
                             QListWidgetItem, QMenuBar, QMessageBox,
                             QPushButton, QRadioButton, QWidget)

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
        acceptBtn = QPushButton('unlock')

        window.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)
        window.setWindowTitle("Unlock manager")

        pwdField.setPlaceholderText('Your password')
        pwdField.setEchoMode(QLineEdit.Password)
        pwdField.textChanged.connect(lambda: self.toogle_echo_password(pwdField))

        self.add_widgets(layout, [
            pwdField,
            acceptBtn
        ])

        window.setLayout(layout)

        self.App.logger.info('Build ask password ui')
        acceptBtn.clicked.connect(lambda: self.App.load_connection({
            'ui': window,
            'field': pwdField
        }))
        return window.exec_()

    def main_ui(self) -> QWidget:

        self.mainWindow = QWidget()
        menuBar = QMenuBar(self.mainWindow)
        layout = QGridLayout()
        self.connectionList = QListWidget()
        label = QLabel('Shortcut')
        addButton = QPushButton('Add ssh connection')
        editButton = QPushButton('Edit selected connection')
        deleteButton = QPushButton('Delete selected connection')

        self.refresh_connection_list()

        with open(self.App.rootPath + '/assets/style.css','r') as styleSheet:
            self.mainWindow.setStyleSheet(styleSheet.read())

        self.mainWindow.setWindowTitle(
            self.App.programName + ' - ' + self.App.programVersion
        )

        fileMenu = menuBar.addMenu('File')
        editMenu = menuBar.addMenu('Edition')

        self.connectionList.sortItems(QtCore.Qt.SortOrder.AscendingOrder)
        self.connectionList.itemClicked.connect(self.App.define_current_item)
        self.connectionList.itemDoubleClicked.connect(self.App.open_ssh_window)

        label.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter)

        self.add_widgets(layout, [
            menuBar,
            self.connectionList,
            label,
            addButton,
            editButton,
            deleteButton
        ])

        saveAction = QAction('Save', self.App)
        exitAction = QAction('Exit', self.App)
        settingsAction = QAction('Settings', self.App)
        aboutAction = QAction('About', self.App)
        editAction = QAction('Edit selected connection', self.App)
        deleteAction = QAction('Delete selected connection', self.App)

        saveAction.triggered.connect(lambda: self.App.save(True))
        exitAction.triggered.connect(QtCore.QCoreApplication.quit)
        self.add_actions(fileMenu, [
            saveAction,
            exitAction
        ])

        editAction.triggered.connect(self.edit_connection_ui)
        deleteAction.triggered.connect(self.delete_connection_ui)
        self.add_actions(editMenu, [
            editAction,
            deleteAction
        ])

        settingsAction.triggered.connect(self.settings_ui)
        aboutAction.triggered.connect(self.about_ui)
        self.add_actions(menuBar, [
            settingsAction,
            aboutAction
        ])

        self.mainWindow.setLayout(layout)

        addButton.clicked.connect(self.add_connection_ui)
        editButton.clicked.connect(self.edit_connection_ui)
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

        self.add_widgets(layout, [
            nameField,
            usernameFied,
            ipField,
            portField,
            passwordField,
            addBtn
        ])

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
            data = self.App.get_data_by_item(self.App.currentSelected)
            window.setWindowTitle('Edit ' + data['name'])
            layout = QFormLayout()

            nameField = QLineEdit(data['name'])
            usernameFied = QLineEdit(data['username'])
            ipField = QLineEdit(data['ip'])
            portField = QLineEdit(data['port'])
            passwordField = QLineEdit(data['password'])
            showPasswordBtn = QPushButton('Show password')
            addBtn = QPushButton('Edit')

            passwordField.setEchoMode(QLineEdit.Password)
            showPasswordBtn.clicked.connect(
                lambda: self.toogle_echo_password(passwordField, 2000)
            )

            self.add_widgets(layout, [
                nameField,
                usernameFied,
                ipField,
                portField,
                passwordField,
                showPasswordBtn,
                addBtn
            ])

            addBtn.clicked.connect(lambda: self.App.edit_connection_process({
                    "ui": window,
                    "uuid": data['uuid'],
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
        if self.App.currentSelected is not None:
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

        css = """
            QLabel {
                max-height: 10px
            }
            padding: 0px
            margin: 0px
            top: 0px
        """

        themeLabel = QLabel('Theme')
        themeLabel.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter)
        darkTheme = QRadioButton('Dark', window)
        lightTheme = QRadioButton('Light', window)

        themeLabel.setStyleSheet(css)
        darkTheme.setStyleSheet(css)
        lightTheme.setStyleSheet(css)

        darkTheme.setChecked((self.App.config['uiTheme'] == 'Dark'))
        lightTheme.setChecked((self.App.config['uiTheme'] == 'Light'))

        autoSaveCheckbox = QCheckBox('Auto save')
        deleteConfigBtn = QPushButton('Delete all configuration')
        changePasswordBtn = QPushButton('Change password')

        autoSaveCheckbox.setChecked(bool(self.App.config['autoSave']))

        autoSaveCheckbox.stateChanged.connect(lambda:
        self.App.toogle_auto_save(autoSaveCheckbox)
        )
        deleteConfigBtn.clicked.connect(self.delete_config_ui)
        changePasswordBtn.clicked.connect(self.change_password_ui)
        darkTheme.clicked.connect(lambda: self.App.set_style(darkTheme.text()))
        lightTheme.clicked.connect(lambda: self.App.set_style(lightTheme.text()))

        window.setLayout(layout)

        self.add_widgets(layout, [
            themeLabel,
            darkTheme,
            lightTheme,
            autoSaveCheckbox,
            deleteConfigBtn,
            changePasswordBtn
        ])

        self.App.logger.info('Build settings ui')
        return window.exec_()

    def change_password_ui(self, firstSet=False) -> QDialog:
        window = QDialog()
        layout = QGridLayout()
        if firstSet:
            title = 'Create password'
        else:
            title = 'Set new password'
        window.setWindowTitle(title)

        passwordField = QLineEdit()
        repasswordField = QLineEdit()
        passwordField.setPlaceholderText('Your password')
        repasswordField.setPlaceholderText('Retype password')
        validateBtn = QPushButton('Validate')
        passwordField.setEchoMode(QLineEdit.Password)
        repasswordField.setEchoMode(QLineEdit.Password)

        passwordField.textChanged.connect(lambda: self.toogle_echo_password(passwordField))
        repasswordField.textChanged.connect(lambda: self.toogle_echo_password(repasswordField))
        validateBtn.clicked.connect(
            lambda: self.App.set_password({
                "ui": window,
                "password": passwordField,
                "repassword": repasswordField
            })
        )

        self.add_widgets(layout, [
            passwordField,
            repasswordField,
            validateBtn
        ])

        window.setLayout(layout)
        self.App.logger.info('Build set/change password ui')
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
        try:
            if self.App.config is not None:
                for entrie in self.App.config['entries']:
                    item = QListWidgetItem(entrie['name'])
                    item.setData(999, entrie['uuid'])
                    item.setToolTip('IP : '+ entrie['ip'])
                    self.connectionList.addItem(item)
        except:
            exit(1)
        self.connectionList.sortItems(QtCore.Qt.SortOrder.AscendingOrder)
        self.App.logger.info('Refresh connection list')

    def toogle_echo_password(self, item: QLineEdit, msec=500) -> QtCore.QTimer:
        item.setEchoMode(QLineEdit.Normal)
        return QtCore.QTimer.singleShot(msec, lambda: item.setEchoMode(QLineEdit.Password))

    def notify(self, text: str, type: str) -> QMessageBox:
        icons = {
            'error': QMessageBox.Critical,
            'ok': QMessageBox.Information
        }
        window = QMessageBox()
        window.setWindowTitle('Information')
        window.setText(text)
        window.setIcon(icons.get(type))
        QtCore.QTimer.singleShot(1000, lambda: window.close())
        self.App.logger.info('Notify ' + type)
        return window.exec_()

    def add_widgets(self, layout: QLayout, widgets: list) -> QLayout:
        for widget in widgets:
            layout.addWidget(widget)
        return layout
    
    def add_actions(self, menu: QMenuBar, actions: list) -> QMenuBar:
        for action in actions:
            menu.addAction(action)
        return menu
