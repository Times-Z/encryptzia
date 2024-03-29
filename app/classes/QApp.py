# -*- coding: utf-8 -*-
import os
import psutil
from threading import Thread
from PyQt5.QtWidgets import (QAction, QCheckBox, QDialog,
                             QFormLayout, QGridLayout, QHBoxLayout, QLabel,
                             QLayout, QLineEdit, QListWidget, QListWidgetItem,
                             QMenu, QMenuBar, QMessageBox, QPushButton, QRadioButton,
                             QSpacerItem, QVBoxLayout, QWidget)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QRegExpValidator, QCursor
from PyQt5 import QtCore, QtGui
import platform


class QApp():
    """
        Display class
        - Used for display management
    """

    def __init__(self, app):
        self.app = app
        self.default_palette: QtGui.QPalette = QtGui.QGuiApplication.palette()
        self.current_selected: QListWidgetItem = None
        self.show_pass: bool = False

    def ask_password_ui(self) -> QDialog:
        """
            Build ask password ui
            - QDialog
            - QGridLayout
        """
        window = QDialog()
        main_layout = QGridLayout()
        layout = QHBoxLayout()
        password_field = QLineEdit()
        show_password_checkbox = QCheckBox('show')
        accept_btn = QPushButton('unlock')

        window.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)
        window.setWindowTitle("Unlock manager")

        password_field.setPlaceholderText('Your password')
        password_field.setEchoMode(QLineEdit.Password)

        self.add_widgets(layout, [
            password_field,
            show_password_checkbox
        ])

        main_layout.addLayout(layout, 1, 0)
        main_layout.addWidget(accept_btn)
        window.setLayout(main_layout)

        accept_btn.clicked.connect(
            lambda: self.wrapper_load_configuration(password_field.text(), window))

        show_password_checkbox.setChecked(bool(
            True if self.show_pass else False)
        )

        show_password_checkbox.stateChanged.connect(
            lambda: self.toogle_echo_password({password_field})
        )

        self.app.logger.info('Build ask password ui')
        return window.exec_()

    def main_ui(self) -> QWidget:
        """
            Build main window ui
            - Qwidget
                - QMenuBar
            - QGridLayout
            - QListWidget
        """
        self.main_window = QWidget()
        menu_bar = QMenuBar(self.main_window)
        layout = QGridLayout()
        self.connection_list = QListWidget()
        label = QLabel('Shortcut')
        add_btn = QPushButton('Add ssh connection')
        edit_btn = QPushButton('Edit selected connection')
        delete_btn = QPushButton('Delete selected connection')

        self.refresh_connection_list()

        self.main_window.setWindowTitle(self.app.NAME)
        self.connection_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.connection_list.customContextMenuRequested.connect(
            self.context_menu)

        file_menu: QMenu = menu_bar.addMenu('File')
        edit_menu: QMenu = menu_bar.addMenu('Edition')

        self.connection_list.sortItems(QtCore.Qt.SortOrder.AscendingOrder)
        self.connection_list.itemClicked.connect(self.define_current_item)
        self.connection_list.itemDoubleClicked.connect(
            self.wrapper_open_ssh_window)

        label.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter)

        self.add_widgets(layout, [
            menu_bar,
            self.connection_list,
            label,
            add_btn,
            edit_btn,
            delete_btn
        ])

        save_action = QAction('Save', self.app.qapp)
        exit_action = QAction('Exit', self.app.qapp)
        settings_action = QAction('Settings', self.app.qapp)
        about_action = QAction('About', self.app.qapp)
        edit_action = QAction('Edit selected connection', self.app.qapp)
        delete_action = QAction('Delete selected connection', self.app.qapp)

        save_action.triggered.connect(lambda: self.wrapper_save(True))
        exit_action.triggered.connect(QtCore.QCoreApplication.quit)
        self.add_actions(file_menu, [
            save_action,
            exit_action
        ])

        edit_action.triggered.connect(
            lambda: self.add_edit_connection_ui('edit'))
        delete_action.triggered.connect(self.delete_ui)
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

        add_btn.clicked.connect(lambda: self.add_edit_connection_ui())
        edit_btn.clicked.connect(lambda: self.add_edit_connection_ui('edit'))
        delete_btn.clicked.connect(self.delete_ui)

        self.main_window.show()
        self.main_window.move(0, 0)
        self.app.logger.info('Build main ui')

        return self.main_window

    def add_edit_connection_ui(self, mode: str = 'add') -> QDialog:
        """
            Build add and edit connection ui
            - QDialog
            - QVBoxLayout
            - QFormLayout
        """
        window = QDialog()
        window.setWindowTitle(mode + ' connection')
        data: dict = None

        if mode == 'edit' and self.current_selected:
            data: dict = self.app.get_data_by_item(self.current_selected.data(999))

        main_layout = QVBoxLayout()
        form_layout = QFormLayout()

        name_field = QLineEdit(data['name'] if data else None)
        username_field = QLineEdit(data['username'] if data else None)
        ip_field = QLineEdit(data['ip'] if data else None)
        port_field = QLineEdit(data['port'] if data else '22')
        password_field = QLineEdit(data['password'] if data else None)
        show_password_checkbox = QCheckBox('show password')
        edit_add_btn = QPushButton('add' if mode == 'add' else 'edit')

        password_field.setEchoMode(
            QLineEdit.Normal if self.show_pass else QLineEdit.Password)

        show_password_checkbox.setChecked(bool(
            True if self.show_pass else False)
        )
        show_password_checkbox.stateChanged.connect(
            lambda: self.toogle_echo_password({password_field}))

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
        main_layout.addWidget(show_password_checkbox)
        main_layout.addWidget(edit_add_btn)

        edit_add_btn.clicked.connect(lambda: self.wrapper_add_edit_connection_process({
            "ui": window,
            "uuid": data['uuid'] if data else None,
            "name": name_field,
            "username": username_field,
            "ip": ip_field,
            "port": port_field,
            "password": password_field
        }))

        window.setLayout(main_layout)
        log_line = f'Build {mode} ssh connection ui'
        if data is not None:
            log_line += f' for item ' + data['uuid']
        if mode == 'edit' and self.current_selected is None:
            return window.destroy()
        self.app.logger.info(
            log_line
        )
        return window.exec_()

    def delete_ui(self, delete_all: bool = False) -> None:
        """
            Build delete connection or delete configuration ui
            - QMessageBox
        """
        window = QMessageBox()
        window.setIcon(QMessageBox.Warning)
        window.setWindowTitle('WARNING')
        window.addButton(QMessageBox.Yes)
        window.addButton(QMessageBox.No)
        if not delete_all:
            if self.current_selected is not None:
                item = self.current_selected
                window.setText("""
                <div style="color:red">Deleting {0}</div>
                <div>Are you sure ?</div>
                """.format(
                    item.text()
                ))

                self.app.logger.info('Build delete ssh warning ui')
                result = window.exec_()
                self.app.delete_connection_process((True if result == QMessageBox.Yes else False), item.data(999))
                return self.refresh_connection_list()

        window.setText("""
        <div style="color:red">Deleting all the configuration</div>
        <div>Are you sure ?</div>
        <div>{0} exit after pressing yes button</div>
        """.format(self.app.NAME))
        self.app.logger.info('Build delete config warning ui')
        result = window.exec_()
        self.app.delete_config_process((True if result == QMessageBox.Yes else False))
        return QtCore.QCoreApplication.quit() if result == QMessageBox.Yes else self.refresh_connection_list()

    def settings_ui(self) -> QDialog:
        """
            Build setting ui
            - QDialog
                - QGridLayout
                - QHBoxLayout
                - QFormLayout
        """
        window = QDialog()
        window.setWindowTitle('Settings')
        window.setFixedSize(400, 400)

        main_layout = QGridLayout()
        top_layout = QHBoxLayout()
        left_layout = QFormLayout()
        theme_layout = QFormLayout()
        right_layout = QFormLayout()
        bottom_layout = QFormLayout()

        dark_theme = QRadioButton('Dark', window)
        light_theme = QRadioButton('Light', window)

        dark_theme.setChecked((self.app.config['uiTheme'] == 'Dark'))
        light_theme.setChecked((self.app.config['uiTheme'] == 'Light'))

        auto_save_checkbox = QCheckBox('Auto save')
        delete_conf_btn = QPushButton('Delete all configuration')
        change_password_btn = QPushButton('Change password')

        auto_save_checkbox.setChecked(bool(
            True if self.app.config['autoSave'] == 'True' else False)
        )

        auto_save_checkbox.stateChanged.connect(lambda:
                                                self.app.toogle_auto_save(
                                                    auto_save_checkbox.isChecked())
                                                )
        delete_conf_btn.clicked.connect(lambda: self.delete_ui(True))
        change_password_btn.clicked.connect(self.change_password_ui)
        dark_theme.clicked.connect(lambda: self.set_style(dark_theme.text()))
        light_theme.clicked.connect(lambda: self.set_style(light_theme.text()))

        left_layout.addRow('Theme', theme_layout)
        self.add_widgets(theme_layout, [
            dark_theme,
            light_theme
        ])
        left_layout.addItem(QSpacerItem(100, 10))
        left_layout.addWidget(auto_save_checkbox)
        top_layout.addLayout(left_layout)

        self.add_widgets(right_layout, [
            delete_conf_btn,
            change_password_btn
        ])
        top_layout.addLayout(right_layout)

        shell_choice = QLineEdit(self.app.config['shell'])
        shell_choice.textEdited.connect(
            lambda: self.app.change_shell_emulator(shell_choice.text(), shell_choice.isModified()))
        bottom_layout.addRow(
            'Terminal emulator', shell_choice
        )

        main_layout.addLayout(top_layout, 0, 0)
        main_layout.addLayout(bottom_layout, 1, 0,
                              QtCore.Qt.AlignmentFlag.AlignTop)
        window.setLayout(main_layout)
        self.app.logger.info('Build settings ui')
        return window.exec_()

    def change_password_ui(self, first_set: bool = False) -> QDialog:
        """
            Build change password ui
            - QDialog
                - QGridLayout
        """
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
        show_password_checkbox = QCheckBox('Show password')

        password_field.setEchoMode(
            QLineEdit.Normal if self.show_pass else QLineEdit.Password)
        re_password_field.setEchoMode(
            QLineEdit.Normal if self.show_pass else QLineEdit.Password)

        show_password_checkbox.setChecked(bool(
            True if self.show_pass else False)
        )

        show_password_checkbox.stateChanged.connect(
            lambda: self.toogle_echo_password({password_field, re_password_field}))

        validate_btn.clicked.connect(
            lambda: self.wrapper_set_password(
                password_field, re_password_field, window)
        )

        self.add_widgets(layout, [
            password_field,
            re_password_field,
            show_password_checkbox,
            validate_btn
        ])

        window.setLayout(layout)
        self.app.logger.info('Build set/change password ui')
        return window.exec_()

    def about_ui(self) -> QMessageBox:
        """
            Build about ui
            - QMessageBox
        """
        window = QMessageBox()
        window.setObjectName("about_ui")
        window.setProperty("cssClass", "about")
        window.setWindowTitle('About')
        current_usage = round(psutil.Process(
            os.getpid()).memory_info().rss / (1024 * 1024))
        window.setText("""
            <div>{0} - version <span id="version">{1}</span></div>
            <div>Release date : {2}</div>
            <div>Python version : {3}</div>
            <div>Qt version : {4}</div>
            <div>Author: <a href="https://github.com/Crash-Zeus">Crash-Zeus</a></div>
            <div>Current ram usage : {5} mb</div>
        """.format(
            self.app.NAME,
            self.app.VERSION,
            self.app.RELEASE_DATE,
            platform.python_version(),
            QtCore.QT_VERSION_STR,
            str(current_usage)
        ))
        window.resize(100, 100)
        self.app.logger.info('Build about ui')
        return window.exec_()

    def context_menu(self) -> QAction:
        """
            Build context menu with actions
        """
        menu = QMenu(self.main_window)
        add_action = QAction("Add connection")
        edit_action = QAction("Edit connection")
        delete_action = QAction("Delete connection")

        add_action.triggered.connect(
            lambda: self.add_edit_connection_ui('add'))
        edit_action.triggered.connect(
            lambda: self.add_edit_connection_ui('edit'))
        delete_action.triggered.connect(lambda: self.delete_ui())

        self.add_actions(menu, [
            add_action,
            edit_action,
            delete_action
        ])

        return menu.exec_(QCursor.pos())

    def refresh_connection_list(self) -> None:
        """
            Clear and load QListWidgetItems for main window
        """
        self.connection_list.clear()
        if self.app.config is not None:
            for entrie in self.app.config['entries']:
                item = QListWidgetItem(entrie['name'])
                item.setData(999, entrie['uuid'])
                item.setToolTip('IP : ' + entrie['ip'])
                self.connection_list.addItem(item)
        self.connection_list.sortItems(QtCore.Qt.SortOrder.AscendingOrder)
        self.app.logger.info('Refresh connection list')

    def toogle_echo_password(self, items: dict) -> None:
        """
            Toogle echo mode for item
        """
        if self.show_pass:
            mode = QLineEdit.Password
            self.show_pass = False
        else:
            mode = QLineEdit.Normal
            self.show_pass = True

        for item in items:
            item.setEchoMode(mode)

        return None

    def notify(self, text: str, type: str) -> QMessageBox:
        """
            Create a QMessageBox to notify user

            Auto close after 1 seconde

            - QMessageBox
        """
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
        """
            Add multiple row in QFormLayout from list
        """
        for row in rows:
            layout.addRow((row.get('label')), row.get('widget'))
        return layout

    def add_widgets(self, layout: QLayout, widgets: list) -> QLayout:
        """
            Add multiple widget to QLayout from list
        """
        for widget in widgets:
            layout.addWidget(widget)
        return layout

    def add_actions(self, menu: QMenuBar, actions: list) -> QMenuBar:
        """
            Add multiple action to QmenuBar from list
        """
        for action in actions:
            menu.addAction(action)
        return menu

    def set_style(self, theme: str, init: bool = False) -> QtGui.QPalette:
        """
            Set application style from configuration

            Default is light theme
        """
        self.app.qapp.setStyle("Fusion")
        if theme == 'Dark':
            palette = QtGui.QPalette()
            palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.WindowText, Qt.white)
            palette.setColor(QtGui.QPalette.Base, QtGui.QColor(35, 35, 35))
            palette.setColor(QtGui.QPalette.AlternateBase,
                             QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.ToolTipBase,
                             QtGui.QColor(25, 25, 25))
            palette.setColor(QtGui.QPalette.ToolTipText, Qt.white)
            palette.setColor(QtGui.QPalette.Text, Qt.white)
            palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.ButtonText, Qt.white)
            palette.setColor(QtGui.QPalette.BrightText, Qt.red)
            palette.setColor(QtGui.QPalette.Link, QtGui.QColor(42, 130, 218))
            palette.setColor(QtGui.QPalette.Highlight,
                             QtGui.QColor(42, 130, 218))
            palette.setColor(QtGui.QPalette.HighlightedText, Qt.black)
        else:
            palette = self.default_palette
        self.app.config['uiTheme'] = theme
        self.app.logger.info('Set palette ' + theme)
        if not init:
            if self.app.config['autoSave'] == "True":
                self.wrapper_save(False)
        return self.app.qapp.setPalette(palette)

    def set_regex(self, regex: str, input: QLineEdit) -> QLineEdit:
        """
            Define regex to a QLineEdit
        """
        reg_ex = QtCore.QRegExp(regex)
        input_validator = QRegExpValidator(reg_ex, input)
        input.setValidator(input_validator)
        return input

    def define_current_item(self, item: QListWidgetItem) -> QListWidgetItem:
        """
            Store last item clicked in a variable
        """
        self.current_selected = item
        return self.current_selected

    def wrapper_load_configuration(self, password: str, ui: QDialog) -> bool:
        """
            Passthrough to Encryptzia class
            Load config and close window
        """
        self.app.load_configuration(password)
        return ui.close()

    def wrapper_open_ssh_window(self, item: QListWidgetItem) -> Thread:
        """
            Passthrough to Encryptzia class
            Get data by item
            Open ssh terminal on a thread
        """
        data = self.app.get_data_by_item(item.data(999))
        return self.app.open_ssh_window(data)

    def wrapper_save(self, notify: bool = True) -> bool:
        if self.app.save():
            if notify:
                self.notify('Saved', 'ok')
            return True
        else:
            return False

    def wrapper_add_edit_connection_process(self, params: dict) -> bool:
        data = {
            "uuid": params.get('uuid') if params.get('uuid') else None,
            "name": params.get('name').text(),
            "username": params.get('username').text(),
            "ip": params.get('ip').text(),
            "port": (params.get('port').text()),
            "password": params.get('password').text()
        }

        self.app.add_edit_connection_process(data)
        self.refresh_connection_list()
        return (params.get('ui').close())

    def wrapper_set_password(self, password: QLineEdit, repassword: QLineEdit, ui: QDialog) -> bool:
        set = self.app.set_password(password.text(), repassword.text())
        if not set:
            self.notify('Password not match', 'error')
            return False
        if hasattr(self.app, 'config'):
            self.wrapper_save(False)
            self.notify('Password changed', 'ok')
        else:
            self.notify('Password set', 'ok')
        return ui.close()
