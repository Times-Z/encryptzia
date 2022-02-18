from random import randint
import secrets
import time
import pytest
import sys
import os
import gc
from PyQt5.QtWidgets import QMessageBox
sys.path.append("..")
from main import Encryptzia


@pytest.fixture(autouse=True)
def time_between_test():
    yield
    time.sleep(1)
    gc.collect()


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


def create_payload(app: Encryptzia) -> str:
    payload = secrets.token_urlsafe(randint(1, 20))
    app.gen_one_time_key(payload)
    app.create_config()
    return payload


@pytest.fixture
def app():
    app = Encryptzia([])
    app.config_path = '/tmp/' + secrets.token_urlsafe(randint(1, 20)) + '.json'

    print('Encryptzia' + ' version ' + app.VERSION)
    print('Conf : ' + app.config_path)

    return app


def test_check_config_false(app: Encryptzia):
    result = app.check_config()
    assert type(result) == bool and not result


def test_gen_one_time_key(app: Encryptzia):
    result = app.gen_one_time_key(secrets.token_urlsafe(randint(5, 10)))
    assert type(result) == bytes


def test_create_config(app: Encryptzia, default_config: dict):
    test_gen_one_time_key(app)
    result = app.create_config()
    assert type(result) == dict and result == default_config


def test_check_config_true(app: Encryptzia):
    create_payload(app)
    result = app.check_config()
    assert type(result) == bool and result


def test_load_configuration_first_set(app: Encryptzia, default_config: dict):
    create_payload(app)
    result = app.load_configuration()
    assert type(
        result) == bool and result and app.config == default_config


def test_load_configuration_with_password(app: Encryptzia, default_config: dict):
    payload = create_payload(app)
    result = app.load_configuration(payload)
    assert type(
        result) == bool and result and app.config == default_config


def test_save(app: Encryptzia, config_with_entries: dict):
    create_payload(app)
    app.config = config_with_entries
    result = app.save()
    assert type(result) == bool and result


def test_configuration_with_entries(app: Encryptzia, config_with_entries: dict):
    payload = create_payload(app)
    app.config = config_with_entries
    app.save()
    app.load_configuration(payload)
    assert type(app.config) == dict and app.config == config_with_entries


def test_get_item_config_position(app: Encryptzia, config_with_entries: dict):
    create_payload(app)
    app.config = config_with_entries
    app.save()
    result = app.get_item_config_position(
        config_with_entries["entries"][1]["uuid"])
    assert type(result) == int and result == 1


def test_get_data_by_item(app: Encryptzia, config_with_entries: dict):
    create_payload(app)
    app.config = config_with_entries
    app.save()
    result = app.get_data_by_item(config_with_entries["entries"][1]["uuid"])
    assert type(result) == dict and result == config_with_entries['entries'][1]


def test_change_shell_emulator_modified_true(app: Encryptzia):
    create_payload(app)
    result = app.change_shell_emulator('unit', True)
    assert type(
        result) == bool and result and app.config['shell'] == 'unit'


def test_change_shell_emulator_modified_false(app: Encryptzia, default_config: dict):
    create_payload(app)
    result = app.change_shell_emulator('unit', False)
    assert type(
        result) == bool and not result and app.config['shell'] == default_config['shell']


def test_set_password_ok(app: Encryptzia):
    create_payload(app)
    result = app.set_password('random_pass', 'random_pass')
    assert type(result) == bool and result


def test_set_password_not_ok(app: Encryptzia):
    create_payload(app)
    random_pass = secrets.token_urlsafe(randint(5, 10))
    result = app.set_password(random_pass, 'toto')
    assert type(result) and not result


def test_toogle_auto_save_true(app: Encryptzia):
    create_payload(app)
    result = app.toogle_auto_save(True)
    assert type(result) == str and result == 'True'


def test_toogle_auto_save_false(app: Encryptzia):
    create_payload(app)
    result = app.toogle_auto_save(False)
    assert type(result) == str and result == 'False'


def test_delete_config_process_false(app: Encryptzia):
    create_payload(app)
    result = app.delete_config_process(QMessageBox.No)
    assert type(result) == bool and not result and os.path.exists(
        app.config_path)


def test_delete_config_process_true(app: Encryptzia):
    create_payload(app)
    result = app.delete_config_process(QMessageBox.Yes)
    assert type(result) == bool and result and not os.path.exists(
        app.config_path)


def test_delete_connection_process_true(app: Encryptzia, config_with_entries: dict):
    create_payload(app)
    excepted = len(config_with_entries['entries'])
    app.config = config_with_entries
    result = app.delete_connection_process(
        QMessageBox.Yes, 'c0373984-7505-4a20-b683-7ba4663a5ed6')
    assert type(result) == bool and result and (
        len(app.config['entries']) < excepted)


def test_delete_connection_process_false(app: Encryptzia, config_with_entries: dict):
    create_payload(app)
    excepted = len(config_with_entries['entries'])
    app.config = config_with_entries
    result = app.delete_connection_process(
        QMessageBox.No, 'c0373984-7505-4a20-b683-7ba4663a5ed6')
    assert type(result) == bool and not result and (
        len(app.config['entries']) == excepted)


def test_add_edit_connection_process_add(app: Encryptzia):
    create_payload(app)
    data = {
        "name": secrets.token_urlsafe(randint(1, 20)),
        "username": secrets.token_urlsafe(3),
        "ip": '.'.join('%s' % randint(0, 255) for i in range(4)),
        "port": randint(0, 1023),
        "password": secrets.token_urlsafe(randint(1, 20))
    }
    result = app.add_edit_connection_process(data)
    assert type(
        result) == bool and result and app.config["entries"][0]["name"] == data["name"]


def test_add_edit_connection_process_edit(app: Encryptzia, config_with_entries: dict):
    create_payload(app)
    excepted = config_with_entries["entries"][1]["uuid"]
    app.config = config_with_entries
    data = {
        "uuid": excepted,
        "name": secrets.token_urlsafe(randint(1, 20)),
        "username": secrets.token_urlsafe(3),
        "ip": '.'.join('%s' % randint(0, 255) for i in range(4)),
        "port": randint(0, 1023),
        "password": secrets.token_urlsafe(randint(1, 20))
    }
    result = app.add_edit_connection_process(data)
    assert type(
        result) == bool and result and app.config["entries"][1]["uuid"] == excepted
