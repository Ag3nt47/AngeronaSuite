"""Fixed Ollama serve launcher with retained server/runner Job custody."""
from angerona.core.windows_child_job import (
    OwnedWindowsChild as OwnedOllamaProcess,
    WindowsChildJob as OwnedOllamaJob,
    launch_windows_child,
)

__all__ = ["OwnedOllamaProcess", "OwnedOllamaJob", "launch_owned_ollama"]


def launch_owned_ollama(image, environment, *, deadline, check_cancelled=None):
    return launch_windows_child(
        [str(image), "serve"], environment, cwd=str(image.parent),
        deadline=deadline, check_cancelled=check_cancelled, kill_on_close=True,
    )
