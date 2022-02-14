from random import randint
import secrets
import pytest
import sys
from PyQt5.QtWidgets import QLineEdit
sys.path.append("..")
from main import Encryptzia


@pytest.fixture
def default_config():
    return {
        "autoSave": "True",
        "sshTimeout": "10",
        "uiTheme": "Light",
        "shell": "xterm -fg white -bg black -fa 'DejaVu Sans Mono' -fs 12",
        "entries": []
    }


@pytest.fixture
def config_with_entries():
    return {
        "autoSave": "True",
        "sshTimeout": "10",
        "uiTheme": "Light",
        "shell": "xterm -fg white -bg black -fa 'DejaVu Sans Mono' -fs 12",
        "entries": [
            {
                    "uuid": "c0373984-7505-4a20-b683-7ba4663a5ed6",
                    "name": "test",
                    "username": "usertest",
                    "ip": "127.0.0.1",
                    "port": "9872",
                    "password": "123456"
            },
            {
                "uuid": "c0373984-8888-4a20-b683-7ba4663a5ed6",
                "name": "test2",
                "username": "usertest2",
                "ip": "127.0.0.1",
                "port": "4222",
                "password": "12345678910"
            }
        ]
    }


@pytest.fixture
def app():
    app = Encryptzia([])
    app.config_path = '/tmp/' + secrets.token_urlsafe(randint(5, 10)) + '.json'

    print('Encryptzia' + ' version ' + app.version)
    print('Conf :' + app.config_path)

    return app


def test_check_config_false(app: Encryptzia):
    result = app.check_config()
    assert type(result) == bool and result == False


def test_gen_one_time_key(app: Encryptzia):
    result = app.gen_one_time_key(secrets.token_urlsafe(randint(5, 10)))
    assert type(result) == bytes


def test_create_config(app: Encryptzia, default_config: dict):
    test_gen_one_time_key(app)
    result = app.create_config()
    assert type(result) == dict and result == default_config


def test_check_config_true(app: Encryptzia, default_config: dict):
    test_create_config(app, default_config)
    result = app.check_config()
    assert type(result) == bool and result == True


def test_load_configuration(app: Encryptzia, default_config: dict):
    test_create_config(app, default_config)
    result = app.load_configuration({}, True)
    assert type(
        result) == bool and result == True and app.config == default_config


def test_save(app: Encryptzia, default_config: dict, config_with_entries: dict):
    test_create_config(app, default_config)
    app.config = config_with_entries
    result = app.save(False)
    assert type(result) == bool and result == True


def test_configuration_with_entries(app: Encryptzia, default_config: dict, config_with_entries: dict):
    test_create_config(app, default_config)
    app.config = config_with_entries
    app.save(False)
    app.load_configuration({}, True)
    assert type(app.config) == dict and app.config == config_with_entries


def test_get_item_config_position(app: Encryptzia, default_config: dict, config_with_entries: dict):
    test_configuration_with_entries(app, default_config, config_with_entries)
    result = app.get_item_config_position(
        "c0373984-8888-4a20-b683-7ba4663a5ed6")
    assert type(result) == int and result == 1


def test_change_shell_emulator(app: Encryptzia, default_config: dict):
    test_create_config(app, default_config)
    widget = QLineEdit('unit')
    widget.setModified(True)
    result = app.change_shell_emulator(widget)
    assert type(result) == bool and app.config['shell'] == 'unit'
