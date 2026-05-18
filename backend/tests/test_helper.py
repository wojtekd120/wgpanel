import importlib.machinery
import importlib.util
from pathlib import Path

import pytest


def load_helper():
    helper_path = Path(__file__).resolve().parents[2] / "helper" / "wgpanel-helper"
    loader = importlib.machinery.SourceFileLoader("wgpanel_helper", str(helper_path))
    spec = importlib.util.spec_from_loader("wgpanel_helper", loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_helper_rejects_paths_outside_run_dir(tmp_path, monkeypatch):
    helper = load_helper()
    run_dir = tmp_path / "run" / "wgpanel"
    outside = tmp_path / "outside.conf"
    run_dir.mkdir(parents=True)
    outside.write_text("[Interface]\n", encoding="utf-8")
    monkeypatch.setattr(helper, "RUN_DIR", run_dir)

    with pytest.raises(SystemExit):
        helper.validate_config_path(str(outside))


def test_helper_accepts_conf_inside_run_dir(tmp_path, monkeypatch):
    helper = load_helper()
    run_dir = tmp_path / "run" / "wgpanel"
    config = run_dir / "wg0.test.conf"
    run_dir.mkdir(parents=True)
    config.write_text("[Interface]\n", encoding="utf-8")
    monkeypatch.setattr(helper, "RUN_DIR", run_dir)

    assert helper.validate_config_path(str(config)) == config.resolve()


def test_helper_backup_paths_are_persistent_and_private(tmp_path, monkeypatch):
    helper = load_helper()
    backup_dir = tmp_path / "etc" / "wireguard" / "backups"
    monkeypatch.setattr(helper, "BACKUP_DIR", backup_dir)

    assert str(helper.BACKUP_DIR).endswith("backups")
    assert "/run" not in str(helper.BACKUP_DIR).replace("\\", "/")


def test_helper_rejects_invalid_interface_names():
    helper = load_helper()
    for name in ["../wg0", "/etc/passwd", "wg0;rm -rf", "bad/name"]:
        with pytest.raises(SystemExit):
            helper.validate_interface(name)


def test_helper_rejects_backup_outside_backup_dir(tmp_path, monkeypatch):
    helper = load_helper()
    backup_dir = tmp_path / "etc" / "wireguard" / "backups"
    backup_dir.mkdir(parents=True)
    outside = tmp_path / "wg0.conf.20260101-120000.bak"
    outside.write_text("[Interface]\n", encoding="utf-8")
    monkeypatch.setattr(helper, "BACKUP_DIR", backup_dir)

    with pytest.raises(SystemExit):
        helper.validate_backup_path(str(outside), "wg0")


def test_helper_self_test_does_not_modify_config_or_backup_dirs(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    run_dir = tmp_path / "run" / "wgpanel"
    backup_dir = tmp_path / "etc" / "wireguard" / "backups"
    monkeypatch.setattr(helper, "RUN_DIR", run_dir)
    monkeypatch.setattr(helper, "BACKUP_DIR", backup_dir)
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0, raising=False)

    helper.self_test()

    assert "self-test ok" in capsys.readouterr().out
    assert not run_dir.exists()
    assert not backup_dir.exists()
