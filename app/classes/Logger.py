# -*- coding: utf-8 -*-
import datetime
import os
import sys

from .Singleton import Singleton


@Singleton
class Logger():
    """
        Logger class log in file
            - debug
            - info
            - warning
            - critical
    """
    
    def __init__(self):
        self.INFO = "[INFO]"
        self.WARN = "[WARN]"
        self.CRIT = "[CRITICAL]"
        self.DEBUG = "[DEBUG]"

    def config(self, filename='app.log', level=None):
        if level is None:
            level = self.INFO
        self.filename = filename
        self.defaultLevel = level
        open(self.filename, 'w').close()

    def info(self, log):
        self.defaultLevel = self.INFO
        self.__writeInFile(log)

    def warn(self, log):
        self.defaultLevel = self.WARN
        self.__writeInFile(log)

    def debug(self, log):
        self.defaultLevel = self.DEBUG
        self.__writeInFile(log)

    def crit(self, log):
        self.defaultLevel = self.CRIT
        self.__writeInFile(log)

    def __writeInFile(self, log):
        f = open(self.filename, 'a')
        f.write(str(datetime.datetime.now().strftime('%H:%M:%S')) + ' ' + self.defaultLevel + ' ' + log + '\n')
        f.close()
