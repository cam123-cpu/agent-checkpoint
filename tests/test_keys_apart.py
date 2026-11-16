"""Secrets can live apart from the data, so a copy of the data folder can't be read or re-signed."""
import os

import pytest

from agent_checkpoint.cli import main
from agent_checkpoint.tenancy import Registry


def test_new_install_keeps_keys_out_of_the_data_folder(tmp_path):
    reg = Registry(str(tmp_path / "data"), str(tmp_path / "keys"))
    reg.create_org("acme", "Acme")
    reg.accounts()
    assert reg.secrets_beside_data() == []
    assert os.path.exists(tmp_path / "keys" / "acme" / "data.key")
    assert reg.gateway("acme").org.ledger.verify()[0]


def test_move_keys_then_everything_still_opens(tmp_path, capsys):
    data, keys = str(tmp_path / "data"), str(tmp_path / "keys")
    Registry(data).create_org("acme", "Acme")
    assert main(["--home", data, "doctor"]) == 1
    assert "inside the data folder" in capsys.readouterr().out
    assert main(["--home", data, "--keys", keys, "move-keys"]) == 0
    assert Registry(data).secrets_beside_data() == []
    reg = Registry(data, keys)
    assert reg.gateway("acme").org.ledger.verify()[0]
    assert main(["--home", data, "--keys", keys, "doctor"]) == 0


def test_keys_folder_inside_the_data_folder_is_refused(tmp_path):
    data = str(tmp_path / "data")
    Registry(data).create_org("acme", "Acme")
    with pytest.raises(ValueError):
        Registry(data, os.path.join(data, "keys")).move_secrets()
