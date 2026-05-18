from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_backend_dependency_files_exist_and_are_split():
    runtime = ROOT / "backend" / "requirements.txt"
    dev = ROOT / "backend" / "requirements-dev.txt"

    assert runtime.is_file()
    assert dev.is_file()
    runtime_text = runtime.read_text(encoding="utf-8")
    dev_text = dev.read_text(encoding="utf-8")
    assert "fastapi" in runtime_text
    assert "uvicorn" in runtime_text
    assert "pytest" not in runtime_text
    assert "-r requirements.txt" in dev_text
    assert "pytest" in dev_text


def test_systemd_installer_has_repo_preflight_and_copy_excludes():
    script = (ROOT / "scripts" / "install-systemd.sh").read_text(encoding="utf-8")

    assert 'require_repo_file "backend/requirements.txt"' in script
    assert 'require_repo_file "backend/app"' in script
    assert 'require_repo_file "frontend/package.json"' in script
    assert 'require_repo_file "helper/wgpanel-helper"' in script
    assert '--exclude node_modules' in script
    assert '--exclude .venv' in script
    assert '--exclude .env' in script
    assert '"$install_path/backend/.venv/bin/pip" install -r "$install_path/backend/requirements.txt"' in script


def test_dark_theme_uses_neutral_surfaces():
    css = (ROOT / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")
    dark_block = css.split('[data-theme="dark"]', 1)[1].split("}", 1)[0]

    assert "--surface: #161b22" in dark_block
    assert "--surface-muted: #202731" in dark_block
    assert "#1a231f" not in dark_block
    assert "#243029" not in dark_block
