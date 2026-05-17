import os
import subprocess
import tempfile
import threading
from pathlib import Path

APPLY_LOCK = threading.Lock()


def apply_config_with_helper(helper_path: Path, run_dir: Path, config_text: str, dry_run: bool, interface: str = "wg0") -> str:
    with APPLY_LOCK:
        run_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix="wg0.", suffix=".conf", dir=run_dir, text=True)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(config_text)
            os.chmod(temp_path, 0o640)
            if dry_run:
                return str(temp_path)
            subprocess.run(
                ["sudo", str(helper_path), "apply", "--interface", interface, "--config", str(temp_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
            return str(temp_path)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
