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
