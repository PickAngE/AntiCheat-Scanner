import logging
import subprocess
from typing import List, Optional

logger = logging.getLogger(__name__)


def run_cmd(args: List[str], timeout: int = 60) -> Optional[str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="ignore",
        )
        if proc.returncode != 0:
            logger.debug(
                "%s failed (rc=%s): %s",
                args[0],
                proc.returncode,
                (proc.stderr or proc.stdout or "")[:200],
            )
            return None
        return proc.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("%s error: %s", args[0], exc)
        return None
