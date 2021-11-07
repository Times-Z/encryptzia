#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys, os
from PyQt5.QtWidgets import *
from PyQt5 import QtCore, QtGui
from classes import Logger

class App(QApplication):
    """
        Main class
        - Run the main window and the window
    """

    def __init__(self, sys_argv):
        super(App, self).__init__(sys_argv)
        self.rootPath = os.path.dirname(os.path.realpath(__file__))
        self.logPath = '/var/log/pyrpg.log'
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

        # # Start button
        # self.startBtn = QPushButton("Start")
        # self.exitBtn = QPushButton("Exit")
        # self.startBtn.clicked.connect(self.start_game)
        # self.exitBtn.clicked.connect(exit)

        # self.layout.addWidget(self.startBtn)
        # self.layout.addWidget(self.exitBtn)
        # self.main_window.setLayout(self.layout)
        self.main_window.show()
        self.main_window.move(0,0)
        self.logger.info('Build ui')

        return self.main_window

if __name__ == '__main__':
    app = App(sys.argv)
    app.setWindowIcon(QtGui.QIcon(app.rootPath + '/assets/imgs/icon.svg'))
    sys.exit(app.exec_())