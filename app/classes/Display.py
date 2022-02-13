# -*- coding: utf-8 -*-
import traceback
from datetime import datetime

from PyQt5 import QtCore, QtGui
from PyQt5.QtGui import QRegExpValidator, QCursor
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QAction, QApplication, QCheckBox, QDialog,
                             QFormLayout, QGridLayout, QHBoxLayout, QLabel,
                             QLayout, QLineEdit, QListWidget, QListWidgetItem,
                             QMenu, QMenuBar, QMessageBox, QPushButton, QRadioButton,
                             QSpacerItem, QVBoxLayout, QWidget)


class Display():
    """
        Display class
        - Used for display management
    """

    def __init__(self, app: QApplication):
        self.app = app
        self.show_pass = False

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

        self.app.logger.info('Build ask password ui')
        accept_btn.clicked.connect(lambda: self.app.load_configuration({
            'ui': window,
            'field': password_field
        }))
        show_password_checkbox.setChecked(bool(
            True if self.show_pass else False)
        )
        show_password_checkbox.stateChanged.connect(
            lambda: self.toogle_echo_password({password_field})
        )

        return window.exec_()

    def main_ui(self) -> QWidget:
        """
            Build main window ui
            - Qwidget
            - QGridLayout
            - QMenuBar
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

        self.main_window.setWindowTitle(self.app.program_name)
        self.connection_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.connection_list.customContextMenuRequested.connect(
            self.context_menu)

        file_menu = menu_bar.addMenu('File')
        edit_menu = menu_bar.addMenu('Edition')

        self.connection_list.sortItems(QtCore.Qt.SortOrder.AscendingOrder)
        self.connection_list.itemClicked.connect(self.app.define_current_item)
        self.connection_list.itemDoubleClicked.connect(
            self.app.open_ssh_window)

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

    def add_edit_connection_ui(self, mode='add') -> QDialog:
        """
            Build add and edit connection ui
            - QDialog
            - QVBoxLayout
            - QFormLayout
        """
        window = QDialog()
        window.setWindowTitle(mode + ' connection')
        data = None

        if mode == 'edit' and self.app.current_selected:
            data = self.app.get_data_by_item(self.app.current_selected)

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

        edit_add_btn.clicked.connect(lambda: self.app.add_edit_connection_process({
            "ui": window,
            "uuid": data['uuid'] if data else None,
            "name": name_field,
            "username": username_field,
            "ip": ip_field,
            "port": port_field,
            "password": password_field
        }))

        window.setLayout(main_layout)
        log_line = f'Build {mode} ssh connection ui '
        if data is not None:
            log_line += f'for item ' + data['uuid']
        if mode == 'edit' and self.app.current_selected is None:
            return window.destroy()
        self.app.logger.info(
            log_line
        )
        return window.exec_()

    def delete_ui(self, delete_all=False) -> None:
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
            if self.app.current_selected is not None:
                item = self.app.current_selected
                window.setText("""
                <div style="color:red">Deleting {0}</div>
                <div>Are you sure ?</div>
                """.format(
                    item.text()
                ))

                self.app.logger.info('Build delete ssh warning ui')
                result = window.exec_()
                self.app.delete_connection_process(result, item)
                return self.refresh_connection_list()

        window.setText("""
        <div style="color:red">Deleting all the configuration</div>
        <div>Are you sure ?</div>
        <div>{0} exit after pressing yes button</div>
        """.format(self.app.program_name))
        self.app.logger.info('Build delete config warning ui')
        result = window.exec_()
        self.app.delete_config_process(result)
        return self.refresh_connection_list()

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
                                                    auto_save_checkbox)
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
            lambda: self.app.change_shell_emulator(shell_choice))
        bottom_layout.addRow(
            'Terminal emulator', shell_choice
        )

        main_layout.addLayout(top_layout, 0, 0)
        main_layout.addLayout(bottom_layout, 1, 0,
                              QtCore.Qt.AlignmentFlag.AlignTop)
        window.setLayout(main_layout)
        self.app.logger.info('Build settings ui')
        return window.exec_()

    def change_password_ui(self, first_set=False) -> QDialog:
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
            lambda: self.app.set_password({
                "ui": window,
                "password": password_field,
                "repassword": re_password_field
            })
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
        window.setWindowTitle('About')
        window.setText("""
            <div>{0} - version {1}</div>
            <div>2021 - {2}</div>
            <div>Author: <a href="https://github.com/Crash-Zeus">Crash-Zeus</a></div>
        """.format(
            self.app.program_name,
            self.app.version,
            (datetime.now()).year
        ))
        window.resize(100, 100)
        self.app.logger.info('Build about ui')
        return window.exec_()

    def refresh_connection_list(self) -> None:
        """
            Clear and load QListWidgetItems for main window
        """
        self.connection_list.clear()
        try:
            if self.app.config is not None:
                for entrie in self.app.config['entries']:
                    item = QListWidgetItem(entrie['name'])
                    item.setData(999, entrie['uuid'])
                    item.setToolTip('IP : ' + entrie['ip'])
                    self.connection_list.addItem(item)
        except Exception:
            log = traceback.format_exc()
            self.logger.crit(log)
            exit(1)
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

    def set_style(self, theme: str, init=False) -> QtGui.QPalette:
        """
            Set application style from configuration

            Default is light theme
        """
        self.app.setStyle("Fusion")
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
            palette = self.app.default_palette
        self.app.config['uiTheme'] = theme
        self.app.logger.info('Set palette ' + theme)
        if not init:
            if self.app.config['autoSave'] == "True":
                self.app.save(False)
        return self.app.setPalette(palette)

    def set_regex(self, regex: str, input: QLineEdit) -> QLineEdit:
        """
            Define regex to a QLineEdit
        """
        reg_ex = QtCore.QRegExp(regex)
        input_validator = QRegExpValidator(reg_ex, input)
        input.setValidator(input_validator)
        return input
