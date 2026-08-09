from __future__ import annotations

import json
import os
from pathlib import Path

from vpn_service.node_agent.models import AgentState, SnapshotCredential

AUTH_FILE_MODE = 0o640
PRIVATE_FILE_MODE = 0o600


def render_auth_file(
    credentials: list[SnapshotCredential],
    *,
    canary_username: str,
    canary_password: str,
    canary_version: str,
) -> bytes:
    lines = [
        "# managed by vpn-node-sync; manual changes are overwritten",
        f"# canary-version {canary_version}",
        f"{canary_username} {canary_password}",
    ]
    lines.extend(f"{item.proxy_username} {item.proxy_password}" for item in credentials)
    return ("\n".join(lines) + "\n").encode("ascii")


class AtomicFiles:
    def __init__(self, active_path: Path, staging_path: Path, state_path: Path) -> None:
        self.active_path = active_path
        self.staging_path = staging_path
        self.state_path = state_path
        self.backup_path = active_path.with_name(active_path.name + ".last-good")

    def verify_same_filesystem(self) -> None:
        self.active_path.parent.mkdir(parents=True, exist_ok=True)
        self.staging_path.parent.mkdir(parents=True, exist_ok=True)
        active_device = self.active_path.parent.stat().st_dev
        staging_device = self.staging_path.parent.stat().st_dev
        if active_device != staging_device:
            raise RuntimeError("GOST active and staging paths must share a filesystem")

    def replace_auth(self, content: bytes) -> bytes | None:
        previous = self.active_path.read_bytes() if self.active_path.exists() else None
        if previous is not None:
            self._atomic_write(self.backup_path, previous, mode=AUTH_FILE_MODE)
        self._atomic_write(self.staging_path, content, mode=AUTH_FILE_MODE)
        os.replace(self.staging_path, self.active_path)
        self._fsync_directory(self.active_path.parent)
        return previous

    def restore_auth(self, previous: bytes | None) -> None:
        content = previous if previous is not None else b""
        self._atomic_write(self.staging_path, content, mode=AUTH_FILE_MODE)
        os.replace(self.staging_path, self.active_path)
        self._fsync_directory(self.active_path.parent)

    def load_state(self) -> AgentState:
        if not self.state_path.exists():
            return AgentState()
        return AgentState.model_validate_json(self.state_path.read_bytes())

    def save_state(self, state: AgentState) -> None:
        payload = json.dumps(
            state.model_dump(mode="json"),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        self._atomic_write(self.state_path, payload, mode=PRIVATE_FILE_MODE)

    @staticmethod
    def _atomic_write(path: Path, content: bytes, *, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
            AtomicFiles._fsync_directory(path.parent)
        except BaseException:
            try:
                temporary.unlink(missing_ok=True)
            finally:
                raise

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
