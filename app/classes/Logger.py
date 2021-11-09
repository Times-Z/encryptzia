# -*- coding: utf-8 -*-
import datetime

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
        self.INFORMATION = "[INFO]"
        self.WARNING = "[WARN]"
        self.CRITICAL = "[CRITICAL]"
        self.DEBUGGER = "[DEBUG]"

    def config(self, filename='app.log', level=None):
        if level is None:
            level = self.INFORMATION
        self.filename = filename
        self.default_level = level
        open(self.filename, 'w').close()

    def info(self, log):
        self.default_level = self.INFORMATION
        self.__write_in_file(log)

    def warn(self, log):
        self.default_level = self.WARNING
        self.__write_in_file(log)

    def debug(self, log):
        self.default_level = self.DEBUGGER
        self.__write_in_file(log)

    def crit(self, log):
        self.default_level = self.CRITICAL
        self.__write_in_file(log)

    def __write_in_file(self, log):
        f = open(self.filename, 'a')
        f.write(str(datetime.datetime.now().strftime('%H:%M:%S')) + ' ' + self.default_level + ' ' + log + '\n')
        f.close()
