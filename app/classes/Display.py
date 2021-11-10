# -*- coding: utf-8 -*-
import traceback
from datetime import datetime

from PyQt5 import QtCore
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import (QAction, QCheckBox, QDialog, QFormLayout,
                             QGridLayout, QHBoxLayout, QLabel, QLayout,
                             QLineEdit, QListWidget, QListWidgetItem, QMenuBar,
                             QMessageBox, QPushButton, QRadioButton,
                             QSpacerItem, QVBoxLayout, QWidget)

from .Singleton import Singleton


@Singleton
class Display():
    """
        Display class
    """
    
    def __init__(self, params):
        self.app = params.get('app')
        self.timer_running = False

    def ask_password_ui(self) -> QDialog:
        window = QDialog()
        layout = QGridLayout()
        password_field = QLineEdit()
        accept_btn = QPushButton('unlock')

        window.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)
        window.setWindowTitle("Unlock manager")

        password_field.setPlaceholderText('Your password')
        password_field.setEchoMode(QLineEdit.Password)
        password_field.textChanged.connect(lambda: self.toogle_echo_password(password_field))

        self.add_widgets(layout, [
            password_field,
            accept_btn
        ])

        window.setLayout(layout)

        self.app.logger.info('Build ask password ui')
        accept_btn.clicked.connect(lambda: self.app.load_connection({
            'ui': window,
            'field': password_field
        }))
        return window.exec_()

    def main_ui(self) -> QWidget:

        self.main_window = QWidget()
        menu_bar = QMenuBar(self.main_window)
        layout = QGridLayout()
        self.connection_list = QListWidget()
        label = QLabel('Shortcut')
        add_btn = QPushButton('Add ssh connection')
        edit_btn = QPushButton('Edit selected connection')
        delete_btn = QPushButton('Delete selected connection')

        self.refresh_connection_list()

        self.main_window.setWindowTitle(self.app.program_name)

        file_menu = menu_bar.addMenu('File')
        edit_menu = menu_bar.addMenu('Edition')

        self.connection_list.sortItems(QtCore.Qt.SortOrder.AscendingOrder)
        self.connection_list.itemClicked.connect(self.app.define_current_item)
        self.connection_list.itemDoubleClicked.connect(self.app.open_ssh_window)

        label.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter)

        self.add_widgets(layout, [
            menu_bar,
            self.connection_list,
            label,
            add_btn,
            edit_btn,
            delete_btn
        ])

        save_action = QAction('Save', self.app)
        exit_action = QAction('Exit', self.app)
        settings_action = QAction('Settings', self.app)
        about_action = QAction('About', self.app)
        edit_action = QAction('Edit selected connection', self.app)
        delete_action = QAction('Delete selected connection', self.app)

        save_action.triggered.connect(lambda: self.app.save(True))
        exit_action.triggered.connect(QtCore.QCoreApplication.quit)
        self.add_actions(file_menu, [
            save_action,
            exit_action
        ])

        edit_action.triggered.connect(self.edit_connection_ui)
        delete_action.triggered.connect(self.delete_connection_ui)
        self.add_actions(edit_menu, [
            edit_action,
            delete_action
        ])

        settings_action.triggered.connect(self.settings_ui)
        about_action.triggered.connect(self.about_ui)
        self.add_actions(menu_bar, [
            settings_action,
            about_action
        ])

        self.main_window.setLayout(layout)

        add_btn.clicked.connect(self.add_connection_ui)
        edit_btn.clicked.connect(self.edit_connection_ui)
        delete_btn.clicked.connect(self.delete_connection_ui)

        self.main_window.show()
        self.main_window.move(0,0)
        self.app.logger.info('Build main ui')

        return self.main_window

    def add_connection_ui(self) -> QDialog:
        window = QDialog()
        window.setWindowTitle('New ssh connection')

        main_layout = QVBoxLayout()
        form_layout = QFormLayout()
        name_field = QLineEdit()
        username_field = QLineEdit()
        ip_field = QLineEdit()
        port_field = QLineEdit('22')
        password_field = QLineEdit()
        add_btn = QPushButton('add')

        self.set_regex(
            "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            ip_field
        )
        self.set_regex(
            "^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
            port_field
        )

        self.add_rows(form_layout, [
            {'label': 'Common name', 'widget': name_field},
            {'label': 'User name', 'widget': username_field},
            {'label': 'Ip', 'widget': ip_field},
            {'label': 'Port', 'widget': port_field},
            {'label': 'Password', 'widget': password_field},
        ])

        main_layout.addLayout(form_layout)
        main_layout.addWidget(add_btn)

        add_btn.clicked.connect(lambda: self.app.add_connection_process({
                "ui": window,
                "name": name_field,
                "username": username_field,
                "ip": ip_field,
                "port": port_field,
                "password": password_field
            }))

        window.setLayout(main_layout)
        self.app.logger.info('Build add ssh connection ui')
        return window.exec_()

    def edit_connection_ui(self) -> QDialog:
        if self.app.current_selected:
            window = QDialog()
            data = self.app.get_data_by_item(self.app.current_selected)
            window.setWindowTitle('Edit ' + data['name'])
            main_layout = QVBoxLayout()
            form_layout = QFormLayout()

            name_field = QLineEdit(data['name'])
            username_field = QLineEdit(data['username'])
            ip_field = QLineEdit(data['ip'])
            port_field = QLineEdit(data['port'])
            password_field = QLineEdit(data['password'])
            show_password_btn = QPushButton('Show password')
            add_btn = QPushButton('Edit')

            password_field.setEchoMode(QLineEdit.Password)
            show_password_btn.clicked.connect(
                lambda: self.toogle_echo_password(password_field, 2000)
            )

            self.add_rows(form_layout, [
                {'label': 'Common name', 'widget': name_field},
                {'label': 'User name', 'widget': username_field},
                {'label': 'Ip', 'widget': ip_field},
                {'label': 'Port', 'widget': port_field},
                {'label': 'Password', 'widget': password_field},
            ])

            main_layout.addLayout(form_layout)

            self.add_widgets(main_layout, [
                show_password_btn,
                add_btn
            ])

            add_btn.clicked.connect(lambda: self.app.edit_connection_process({
                    "ui": window,
                    "uuid": data['uuid'],
                    "name": name_field,
                    "username": username_field,
                    "ip": ip_field,
                    "port": port_field,
                    "password": password_field
                }))

            window.setLayout(main_layout)
            self.app.logger.info(
                'Build edit ssh connection ui for item ' + self.app.current_selected.text()
            )
            return window.exec_()

    def delete_connection_ui(self) -> None:
        if self.app.current_selected is not None:
            item = self.app.current_selected
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

            self.app.logger.info('Build delete ssh warning')
            result = window.exec_()
            self.app.delete_connection_process(result, item)
            self.refresh_connection_list()

    def delete_config_ui(self) -> None:
        window = QMessageBox()
        window.setIcon(QMessageBox.Warning)
        window.setWindowTitle('WARNING')
        window.setText("""
        <div style="color:red">Deleting all the configuration</div>
        <div>Are you sure ?</div>
        <div>{0} exit after pressing yes button</div>
        """.format(self.app.program_name))
        window.addButton(QMessageBox.Yes)
        window.addButton(QMessageBox.No)

        self.app.logger.info('Build delete config warning')
        result = window.exec_()
        self.app.delete_config_process(result)
        self.refresh_connection_list()

    def settings_ui(self) -> QDialog:
        window = QDialog()
        window.setWindowTitle('Settings')
        window.setFixedSize(400, 400)

        main_layout = QHBoxLayout()
        left_layout = QFormLayout()
        theme_layout = QFormLayout()
        right_layout = QFormLayout()

        dark_theme = QRadioButton('Dark', window)
        light_theme = QRadioButton('Light', window)

        dark_theme.setChecked((self.app.config['uiTheme'] == 'Dark'))
        light_theme.setChecked((self.app.config['uiTheme'] == 'Light'))

        auto_save_checkbox = QCheckBox('Auto save')
        delete_conf_btn = QPushButton('Delete all configuration')
        change_password_btn = QPushButton('Change password')

        auto_save_checkbox.setChecked(bool(self.app.config['autoSave']))

        auto_save_checkbox.stateChanged.connect(lambda:
        self.app.toogle_auto_save(auto_save_checkbox)
        )
        delete_conf_btn.clicked.connect(self.delete_config_ui)
        change_password_btn.clicked.connect(self.change_password_ui)
        dark_theme.clicked.connect(lambda: self.app.set_style(dark_theme.text()))
        light_theme.clicked.connect(lambda: self.app.set_style(light_theme.text()))

        left_layout.addRow('Theme', theme_layout)
        self.add_widgets(theme_layout, [
            dark_theme,
            light_theme
        ])
        left_layout.addItem(QSpacerItem(100, 10))
        left_layout.addWidget(auto_save_checkbox)
        main_layout.addLayout(left_layout)

        self.add_widgets(right_layout, [
            delete_conf_btn,
            change_password_btn
        ])
        main_layout.addLayout(right_layout)

        window.setLayout(main_layout)
        self.app.logger.info('Build settings ui')
        return window.exec_()

    def change_password_ui(self, first_set=False) -> QDialog:
        window = QDialog()
        layout = QGridLayout()
        if first_set:
            title = 'Create password'
        else:
            title = 'Set new password'
        window.setWindowTitle(title)

        password_field = QLineEdit()
        re_password_field = QLineEdit()
        password_field.setPlaceholderText('Your password')
        re_password_field.setPlaceholderText('Retype password')
        validate_btn = QPushButton('Validate')
        password_field.setEchoMode(QLineEdit.Password)
        re_password_field.setEchoMode(QLineEdit.Password)

        password_field.textEdited.connect(lambda: self.toogle_echo_password(password_field, 3000))
        re_password_field.textChanged.connect(lambda: self.toogle_echo_password(re_password_field, 3000))

        validate_btn.clicked.connect(
            lambda: self.app.set_password({
                "ui": window,
                "password": password_field,
                "repassword": re_password_field
            })
        )

        self.add_widgets(layout, [
            password_field,
            re_password_field,
            validate_btn
        ])

        window.setLayout(layout)
        self.app.logger.info('Build set/change password ui')
        return window.exec_()

    def about_ui(self) -> QMessageBox:
        window = QMessageBox()
        window.setWindowTitle('About')
        window.setText("""
            <div>{0} - version {1}</div>
            <div>2021 - {2}</div>
        """.format(
            self.app.program_name,
            self.app.version,
            (datetime.now()).year
            ))
        window.resize(100, 100)
        self.app.logger.info('Build about ui')
        return window.exec_()

    def refresh_connection_list(self) -> None:
        self.connection_list.clear()
        try:
            if self.app.config is not None:
                for entrie in self.app.config['entries']:
                    item = QListWidgetItem(entrie['name'])
                    item.setData(999, entrie['uuid'])
                    item.setToolTip('IP : '+ entrie['ip'])
                    self.connection_list.addItem(item)
        except Exception:
            log = traceback.format_exc()
            self.logger.crit(log)
            exit(1)
        self.connection_list.sortItems(QtCore.Qt.SortOrder.AscendingOrder)
        self.app.logger.info('Refresh connection list')

    def toogle_echo_password(self, item: QLineEdit, msec=500) -> None:
        if item.echoMode() == QLineEdit.Password:
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
        self.app.logger.info('Notify ' + type)
        return window.exec_()

    def add_rows(self, layout: QFormLayout, rows: list) -> QFormLayout:
        for row in rows:
            layout.addRow((row.get('label')), row.get('widget'))
        return layout

    def add_widgets(self, layout: QLayout, widgets: list) -> QLayout:
        for widget in widgets:
            layout.addWidget(widget)
        return layout
    
    def add_actions(self, menu: QMenuBar, actions: list) -> QMenuBar:
        for action in actions:
            menu.addAction(action)
        return menu

    def set_regex(self, regex: str, input: QLineEdit) -> QLineEdit:
        reg_ex = QtCore.QRegExp(regex)
        input_validator = QRegExpValidator(reg_ex, input)
        input.setValidator(input_validator)
        return input