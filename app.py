import hashlib
import importlib.util
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import zipfile
import tkinter as tk
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tkinter import (
    BOTH,
    END,
    IntVar,
    LEFT,
    RIGHT,
    VERTICAL,
    W,
    BooleanVar,
    StringVar,
    Tk,
    Toplevel,
    filedialog,
    messagebox,
)
from tkinter import ttk

try:
    import tomllib
except Exception:
    try:
        import tomli as tomllib  # type: ignore[import-not-found]
    except Exception:
        tomllib = None

try:
    import winsound
except ImportError:
    winsound = None

try:
    import pystray  # type: ignore[import-not-found]
    from PIL import Image, ImageDraw  # type: ignore[import-not-found]
except Exception:
    pystray = None
    Image = None
    ImageDraw = None


SCAN_INTERVAL_SECONDS = 2.0
MAX_RECENT_CRASHES = 200
MAX_RECENT_ISSUES = 300
MAX_PERSISTED_HISTORY = 1000

STATE_FILE_NAME = "session_state.json"
HISTORY_FILE_NAME = "crash_history.json"
APP_DIR_NAME = "CrashReader"

ANSI_RESET = "\033[0m"
ANSI_PURPLE = "\033[95m"
ANSI_LIGHT_PURPLE = "\033[38;5;183m"

COLOR_BG = "#111115"
COLOR_PANEL = "#1B1B22"
COLOR_TEXT = "#E8E8F6"
COLOR_MUTED = "#B9B9C9"
COLOR_PURPLE = "#8B5CF6"
COLOR_PURPLE_LIGHT = "#B79CFF"
COLOR_BORDER = "#323244"

SLEEPCAST_ART = r"""
  _____ _      ______ ______ _____   _____          _____ _______
 / ____| |    |  ____|  ____|  __ \ / ____|   /\   / ____|__   __|
| (___ | |    | |__  | |__  | |__) | |       /  \ | (___    | |
 \___ \| |    |  __| |  __| |  ___/| |      / /\ \ \___ \   | |
 ____) | |____| |____| |____| |    | |____ / ____ \____) |  | |
|_____/|______|______|______|_|     \_____/_/    \_\_____/  |_|
"""

SLEEPCAST_FOOTER = [
        "Made By SoullessEyes",
        "Sleepcast 2025-2026 ©",
]


def _is_frozen_build() -> bool:
    return bool(getattr(sys, "frozen", False))


def _project_root() -> Path:
    if _is_frozen_build():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _default_user_save_folder() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / APP_DIR_NAME / "save"
    return Path.home() / ".crashreader" / "save"


@dataclass
class CrashEvent:
    file_path: Path
    created_at: float
    summary: str
    suspected_mods: list[str]
    confidence: str
    severity: str
    loader_profile: str
    signature: str
    evidence: dict[str, list[str]]

    def to_dict(self) -> dict:
        return {
            "file_path": str(self.file_path),
            "created_at": self.created_at,
            "summary": self.summary,
            "suspected_mods": self.suspected_mods,
            "confidence": self.confidence,
            "severity": self.severity,
            "loader_profile": self.loader_profile,
            "signature": self.signature,
            "evidence": self.evidence,
        }

    @staticmethod
    def from_dict(payload: dict) -> "CrashEvent":
        return CrashEvent(
            file_path=Path(payload.get("file_path", "unknown")),
            created_at=float(payload.get("created_at", time.time())),
            summary=str(payload.get("summary", "No crash details available")),
            suspected_mods=list(payload.get("suspected_mods", ["No clear mod detected"])),
            confidence=str(payload.get("confidence", "Low")),
            severity=str(payload.get("severity", "Minor")),
            loader_profile=str(payload.get("loader_profile", "Unknown")),
            signature=str(payload.get("signature", "")),
            evidence=dict(payload.get("evidence", {})),
        )


@dataclass
class LogIssueEvent:
    file_path: Path
    created_at: float
    level: str
    log_type: str
    log_meaning: str
    mod_hint: str
    message: str
    signature: str

    @staticmethod
    def build_signature(level: str, log_type: str, mod_hint: str, message: str) -> str:
        normalized = re.sub(r"\s+", " ", message.lower()).strip()
        basis = f"{level.lower()}|{log_type.lower()}|{mod_hint.lower()}|{normalized[:180]}"
        return hashlib.sha1(basis.encode("utf-8", errors="ignore")).hexdigest()[:16]


class CrashAnalyzer:
    """Parses Minecraft crash reports and estimates likely culprit mods."""

    FORGE_MOD_HEADER = re.compile(r"--\s*MOD\s+([a-zA-Z0-9_.-]+)\s*--")
    SUSPECTED_MODS_LINE = re.compile(r"Suspected Mods?:\s*(.+)", re.IGNORECASE)
    MODFILE_LINE = re.compile(r"Mod File:\s*(.+)", re.IGNORECASE)
    CAUSED_BY_LINE = re.compile(r"Caused by:\s*(.+)", re.IGNORECASE)

    def __init__(self, modpack_root: Path) -> None:
        self.modpack_root = modpack_root
        self.known_mod_names = self._discover_mod_names()

    def _discover_mod_names(self) -> set[str]:
        names: set[str] = set()
        mods_dir = self.modpack_root / "mods"
        if not mods_dir.exists() or not mods_dir.is_dir():
            return names

        for jar_path in mods_dir.glob("*.jar"):
            base = jar_path.stem.lower()
            names.add(base)
            simplified = re.sub(r"[-_]?\d+[\w.-]*$", "", base)
            if simplified:
                names.add(simplified)
        return names

    def analyze_file(self, crash_file: Path) -> CrashEvent:
        text = crash_file.read_text(encoding="utf-8", errors="ignore")
        lower = text.lower()
        candidates: dict[str, int] = {}
        evidence: dict[str, list[str]] = {}
        loader_profile = self._detect_loader_profile(lower)
        weights = self._loader_weights(loader_profile)

        # Strong hints from Forge/Fabric report sections.
        for mod_id in self.FORGE_MOD_HEADER.findall(text):
            self._register(candidates, evidence, mod_id, weights["header"], "Found in -- MOD <id> -- section")

        for suspected_line in self.SUSPECTED_MODS_LINE.findall(text):
            for token in re.split(r"[,;\s]+", suspected_line):
                token = token.strip(".()[]{}\"' ")
                if token:
                    self._register(candidates, evidence, token, weights["suspected"], "Found in Suspected Mods line")

        for mod_file in self.MODFILE_LINE.findall(text):
            token = Path(mod_file.strip()).stem
            if token:
                self._register(candidates, evidence, token, weights["modfile"], "Found in Mod File entry")

        # Medium hints from exception sections.
        for caused_by in self.CAUSED_BY_LINE.findall(text):
            for token in self._tokens_from_line(caused_by):
                self._register(candidates, evidence, token, weights["causedby"], "Referenced in Caused by chain")

        # Match known jar names that appear in the crash report.
        for mod_name in self.known_mod_names:
            if not mod_name or len(mod_name) < 3:
                continue
            if mod_name in lower:
                penalty = 0
                if "mod list" in lower and lower.count(mod_name) == 1:
                    penalty = 1
                self._register(
                    candidates,
                    evidence,
                    mod_name,
                    max(1, weights["known_match"] - penalty),
                    "Matched installed mod jar name in crash text",
                )

        ranked = sorted(candidates.items(), key=lambda x: x[1], reverse=True)
        suspected = [name for name, _score in ranked[:5]]

        if not suspected:
            suspected = ["No clear mod detected"]
            confidence = "Low"
        else:
            top_score = ranked[0][1]
            if top_score >= 9:
                confidence = "High"
            elif top_score >= 5:
                confidence = "Medium"
            else:
                confidence = "Low"

        summary = self._build_summary(text)
        severity = self._determine_severity(crash_file.name.lower(), lower)
        signature = self._build_signature(summary, suspected, loader_profile)
        return CrashEvent(
            file_path=crash_file,
            created_at=crash_file.stat().st_mtime,
            summary=summary,
            suspected_mods=suspected,
            confidence=confidence,
            severity=severity,
            loader_profile=loader_profile,
            signature=signature,
            evidence=evidence,
        )

    @staticmethod
    def _add_score(candidates: dict[str, int], token: str, score: int) -> None:
        clean = token.lower().strip()
        clean = re.sub(r"[^a-z0-9_.-]", "", clean)
        if not clean:
            return
        candidates[clean] = candidates.get(clean, 0) + score

    @classmethod
    def _register(
        cls,
        candidates: dict[str, int],
        evidence: dict[str, list[str]],
        token: str,
        score: int,
        reason: str,
    ) -> None:
        clean = token.lower().strip()
        clean = re.sub(r"[^a-z0-9_.-]", "", clean)
        if not clean:
            return
        candidates[clean] = candidates.get(clean, 0) + score
        if clean not in evidence:
            evidence[clean] = []
        if reason not in evidence[clean]:
            evidence[clean].append(reason)

    @staticmethod
    def _tokens_from_line(line: str) -> list[str]:
        tokens = re.split(r"[^a-zA-Z0-9_.-]+", line)
        out: list[str] = []
        for token in tokens:
            token = token.strip(". ")
            if len(token) >= 3:
                out.append(token)
        return out

    @staticmethod
    def _build_summary(text: str) -> str:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if not lines:
            return "No crash details available"

        for line in lines:
            lower = line.lower()
            if "exception" in lower or "error" in lower or "failed" in lower:
                return line[:220]

        return lines[0][:220]

    @staticmethod
    def _detect_loader_profile(lower_text: str) -> str:
        if "neoforge" in lower_text:
            return "NeoForge"
        if "fabric-loader" in lower_text or "net.fabricmc" in lower_text or "mixin" in lower_text:
            return "Fabric"
        if "quilt_loader" in lower_text or "org.quiltmc" in lower_text:
            return "Quilt"
        if "modlauncher" in lower_text or "-- mod " in lower_text or "forge" in lower_text:
            return "Forge"
        return "Unknown"

    @staticmethod
    def _loader_weights(loader_profile: str) -> dict[str, int]:
        if loader_profile == "Fabric":
            return {
                "header": 7,
                "suspected": 10,
                "modfile": 6,
                "causedby": 4,
                "known_match": 3,
            }
        if loader_profile in {"Forge", "NeoForge"}:
            return {
                "header": 9,
                "suspected": 10,
                "modfile": 7,
                "causedby": 3,
                "known_match": 2,
            }
        if loader_profile == "Quilt":
            return {
                "header": 7,
                "suspected": 9,
                "modfile": 6,
                "causedby": 4,
                "known_match": 3,
            }
        return {
            "header": 6,
            "suspected": 8,
            "modfile": 6,
            "causedby": 3,
            "known_match": 2,
        }

    @staticmethod
    def _determine_severity(file_name_lower: str, crash_text_lower: str) -> str:
        if file_name_lower.startswith("hs_err_pid"):
            return "Critical"
        if "a fatal error has been detected by the java runtime environment" in crash_text_lower:
            return "Critical"
        if "outofmemoryerror" in crash_text_lower:
            return "Critical"
        if "failed to start" in crash_text_lower or "mod loading has failed" in crash_text_lower:
            return "Major"
        if "exception" in crash_text_lower or "error" in crash_text_lower:
            return "Major"
        return "Minor"

    @staticmethod
    def _build_signature(summary: str, suspected_mods: list[str], loader_profile: str) -> str:
        mod_basis = "|".join(suspected_mods[:3]).lower()
        summary_basis = re.sub(r"\s+", " ", summary.lower()).strip()
        basis = f"{loader_profile}|{summary_basis}|{mod_basis}"
        return hashlib.sha1(basis.encode("utf-8", errors="ignore")).hexdigest()[:16]


class CrashWatcher(threading.Thread):
    """Polls crash-report folders and emits newly detected crash files."""

    def __init__(self, root_path: Path, event_queue: queue.Queue[Path], stop_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self.root_path = root_path
        self.event_queue = event_queue
        self.stop_event = stop_event
        self.seen: set[str] = set()

        # Seed with existing crash files so startup doesn't re-alert historical reports.
        try:
            for crash_file in self._candidate_crash_files():
                key = f"{crash_file}:{crash_file.stat().st_mtime}"
                self.seen.add(key)
        except Exception:
            pass

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                for crash_file in self._candidate_crash_files():
                    key = f"{crash_file}:{crash_file.stat().st_mtime}"
                    if key in self.seen:
                        continue
                    self.seen.add(key)
                    self.event_queue.put(crash_file)

                if len(self.seen) > 5000:
                    # Keep memory bounded for long sessions.
                    self.seen = set(list(self.seen)[-2500:])
            except Exception:
                # Ignore transient IO issues while folders/files are changing.
                pass

            time.sleep(SCAN_INTERVAL_SECONDS)

    def _candidate_crash_files(self) -> list[Path]:
        folders = [
            self.root_path / "crash-reports",
            self.root_path / ".minecraft" / "crash-reports",
            self.root_path,
        ]

        candidates: list[Path] = []
        for folder in folders:
            if not folder.exists() or not folder.is_dir():
                continue

            for path in folder.glob("crash-*.txt"):
                candidates.append(path)
            for path in folder.glob("hs_err_pid*.log"):
                candidates.append(path)

        candidates.sort(key=lambda p: p.stat().st_mtime)
        return candidates


class LogWatcher(threading.Thread):
    """Tails Minecraft log files and emits ERROR/FATAL mod issues."""

    ERROR_LEVEL_RE = re.compile(r"\b(ERROR|FATAL)\b", re.IGNORECASE)
    MODID_RE = re.compile(r"\bmod(?:id)?\s*[:=]\s*([a-zA-Z0-9_.-]+)", re.IGNORECASE)
    LOGGER_RE = re.compile(r"\[([a-zA-Z0-9_.-]+)(?:/[^\]]*)?\]")
    LOG_TYPE_RULES: list[tuple[str, tuple[str, ...], str]] = [
        (
            "Rendering",
            ("render", "shader", "opengl", "glerror", "framebuffer", "embeddium", "oculus", "iris"),
            "Graphics or shader pipeline issue. Check renderer mods, shader packs, and GPU-related settings.",
        ),
        (
            "Mixin",
            ("mixin", "inject", "apply failed", "transformer", "failed injection"),
            "Code injection conflict between mods. Usually a mod-version mismatch or incompatible pair.",
        ),
        (
            "Dependency",
            ("no such method", "classnotfound", "nosuchfielderror", "missing", "dependency"),
            "Missing or incompatible dependency/API. Verify required libraries and exact mod versions.",
        ),
        (
            "Config",
            ("config", "toml", "json", "parse", "invalid value", "malformed"),
            "Configuration parse or value issue. Review recent config edits and restore backups if needed.",
        ),
        (
            "Memory",
            ("outofmemory", "gc overhead", "heap space", "direct buffer memory"),
            "Memory pressure. Adjust Java memory allocation and reduce heavy mods/shaders.",
        ),
        (
            "Networking",
            ("disconnect", "handshake", "packet", "channel", "timeout", "connection"),
            "Network or protocol mismatch. Check client/server mod parity and network stability.",
        ),
        (
            "World IO",
            ("region", "chunk", "nbt", "save", "level.dat", "ioexception"),
            "World data read/write issue. Validate world integrity and storage availability.",
        ),
        (
            "Startup",
            ("failed to start", "mod loading has failed", "boot", "initialization", "entrypoint"),
            "Startup initialization failure. Usually appears before entering world and points to mod loading.",
        ),
    ]
    IGNORE_HINTS = {
        "main",
        "render thread",
        "server thread",
        "worker-main",
        "minecraft",
        "net.minecraft",
        "forge",
        "neoforge",
        "fabric",
        "quilt",
    }

    def __init__(self, root_path: Path, event_queue: queue.Queue[LogIssueEvent], stop_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self.root_path = root_path
        self.event_queue = event_queue
        self.stop_event = stop_event
        self.file_offsets: dict[str, int] = {}

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                for log_file in self._candidate_log_files():
                    self._tail_and_parse(log_file)

                if len(self.file_offsets) > 100:
                    # Bound memory if many transient logs appear.
                    self.file_offsets = dict(list(self.file_offsets.items())[-50:])
            except Exception:
                # Ignore transient IO issues while logs rotate.
                pass

            time.sleep(1.0)

    def _candidate_log_files(self) -> list[Path]:
        folders = [
            self.root_path / "logs",
            self.root_path / ".minecraft" / "logs",
        ]

        candidates: list[Path] = []
        for folder in folders:
            if not folder.exists() or not folder.is_dir():
                continue
            for path in folder.glob("*.log"):
                candidates.append(path)

        candidates.sort(key=lambda p: p.stat().st_mtime)
        return candidates

    def _tail_and_parse(self, log_file: Path) -> None:
        key = str(log_file.resolve())
        size = log_file.stat().st_size
        start = self.file_offsets.get(key, 0)

        if size < start:
            # Log got truncated/rotated; start from beginning.
            start = 0
        if size == start:
            return

        with log_file.open("r", encoding="utf-8", errors="ignore") as f:
            f.seek(start)
            chunk = f.read()
            self.file_offsets[key] = f.tell()

        created_at = log_file.stat().st_mtime
        for raw_line in chunk.splitlines():
            issue = self._issue_from_line(log_file, created_at, raw_line)
            if issue is not None:
                self.event_queue.put(issue)

    @classmethod
    def _issue_from_line(cls, log_file: Path, created_at: float, line: str) -> LogIssueEvent | None:
        if not line.strip():
            return None

        level_match = cls.ERROR_LEVEL_RE.search(line)
        if level_match is None:
            return None

        lower_line = line.lower()
        if "error" not in lower_line and "fatal" not in lower_line:
            return None

        mod_hint = cls._extract_mod_hint(line)
        level = level_match.group(1).upper()
        message = line.strip()
        log_type, log_meaning = cls._classify_log_type(message)
        signature = LogIssueEvent.build_signature(level, log_type, mod_hint, message)

        return LogIssueEvent(
            file_path=log_file,
            created_at=created_at,
            level=level,
            log_type=log_type,
            log_meaning=log_meaning,
            mod_hint=mod_hint,
            message=message[:260],
            signature=signature,
        )

    @classmethod
    def _classify_log_type(cls, message: str) -> tuple[str, str]:
        lower = message.lower()
        for log_type, needles, meaning in cls.LOG_TYPE_RULES:
            for token in needles:
                if token in lower:
                    return log_type, meaning
        return (
            "General Runtime",
            "General runtime error/fatal event. Review full stack context and nearby lines for root cause.",
        )

    @classmethod
    def _extract_mod_hint(cls, line: str) -> str:
        explicit = cls.MODID_RE.search(line)
        if explicit is not None:
            return explicit.group(1).lower()

        for hit in cls.LOGGER_RE.findall(line):
            lowered = hit.strip().lower()
            if not lowered:
                continue
            if lowered in cls.IGNORE_HINTS:
                continue
            if len(lowered) < 3:
                continue
            if " " in lowered:
                continue
            return lowered

        return "unknown-mod"


class CrashReaderApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("CrashReader - Mod Crash Popup")
        self.root.geometry("1100x700")
        self.root.minsize(900, 500)
        self.root.resizable(True, True)
        self.root.configure(bg=COLOR_BG)

        self.current_path = StringVar(value="No folder selected")
        self.save_path = StringVar(value=str(self._default_save_folder()))
        self.status_var = StringVar(value="Pick a modpack folder to begin")
        self.sound_enabled = BooleanVar(value=True)
        self.tray_enabled = BooleanVar(value=False)
        self.popup_enabled = BooleanVar(value=True)
        self.popup_on_repeat = BooleanVar(value=True)
        self.popup_cooldown_seconds = IntVar(value=0)
        self.fullscreen = False
        self.tray_icon = None
        self._tray_running = False
        self.last_popup_at: dict[str, float] = {}
        self.last_popup_global_at = 0.0
        self.last_crash_file_seen = "None"
        self.last_crash_seen_at = 0.0
        self.last_issue_file_seen = "None"
        self.last_issue_seen_at = 0.0
        self.issue_sort_column: str = "time"
        self.issue_sort_desc: bool = True

        self.config_status_var = StringVar(value="Choose a modpack folder to manage configs")
        self.config_selected_file_var = StringVar(value="Selected config: none")
        self.config_backup_status_var = StringVar(value="Original backup: not created")
        self.config_filter_var = StringVar(value="")
        self.config_edit_key_var = StringVar(value="")
        self.config_edit_value_var = StringVar(value="")
        self.selected_config_file: Path | None = None
        self.selected_config_kv_item: str | None = None
        self.config_kv_line_by_item: dict[str, int] = {}

        self.diag_watchers_var = StringVar(value="Watchers: idle")
        self.diag_queues_var = StringVar(value="Queues: crash=0, logs=0")
        self.diag_last_crash_var = StringVar(value="Last crash file seen: none")
        self.diag_last_issue_var = StringVar(value="Last live log issue: none")
        self.diag_last_popup_var = StringVar(value="Last popup: none")
        self.diag_counts_var = StringVar(value="Tracked items: crashes=0, issues=0, signatures=0")
        self.verify_score_var = StringVar(value="CrashReader Stability Score: --/100")
        self.verify_cert_var = StringVar(value="Certification: not verified")
        self.verify_data_var = StringVar(value="Evidence: run verification to calculate stability signals")
        self.verify_status_var = StringVar(value="Verify Files checks not run yet")

        self.queue: queue.Queue[Path] = queue.Queue()
        self.log_queue: queue.Queue[LogIssueEvent] = queue.Queue()
        self.stop_event = threading.Event()
        self.watcher: CrashWatcher | None = None
        self.log_watcher: LogWatcher | None = None
        self.analyzer: CrashAnalyzer | None = None
        self.rows_by_item: dict[str, CrashEvent] = {}
        self.signature_to_item: dict[str, str] = {}
        self.signature_count: Counter[str] = Counter()
        self.issue_by_item: dict[str, LogIssueEvent] = {}
        self.issue_signature_to_item: dict[str, str] = {}
        self.issue_signature_count: Counter[str] = Counter()
        self.conflict_by_item: dict[str, tuple[str, str]] = {}
        self.conflict_pairs: Counter[tuple[str, str]] = Counter()
        self.event_history: list[CrashEvent] = []

        self._configure_theme()
        self._build_ui()
        self._load_state()
        self._bind_shortcuts()
        self.root.after(800, self._refresh_diagnostics)
        self.root.after(600, self._pump_queue)

    def _configure_theme(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background=COLOR_BG)
        style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT)
        style.configure("TLabelframe", background=COLOR_PANEL, foreground=COLOR_PURPLE_LIGHT, bordercolor=COLOR_BORDER)
        style.configure("TLabelframe.Label", background=COLOR_PANEL, foreground=COLOR_PURPLE_LIGHT)
        style.configure(
            "TButton",
            background=COLOR_PURPLE,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            focusthickness=1,
            focuscolor=COLOR_PURPLE_LIGHT,
            padding=6,
        )
        style.map("TButton", background=[("active", COLOR_PURPLE_LIGHT), ("pressed", COLOR_PURPLE)])
        style.configure("TCheckbutton", background=COLOR_BG, foreground=COLOR_TEXT)

        style.configure("TNotebook", background=COLOR_BG, bordercolor=COLOR_BORDER)
        style.configure("TNotebook.Tab", background=COLOR_PANEL, foreground=COLOR_MUTED, padding=(10, 6))
        style.map("TNotebook.Tab", background=[("selected", COLOR_PURPLE)], foreground=[("selected", COLOR_TEXT)])

        style.configure(
            "Treeview",
            background=COLOR_PANEL,
            fieldbackground=COLOR_PANEL,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            rowheight=23,
        )
        style.map("Treeview", background=[("selected", COLOR_PURPLE)], foreground=[("selected", COLOR_TEXT)])
        style.configure("Treeview.Heading", background="#242433", foreground=COLOR_PURPLE_LIGHT, bordercolor=COLOR_BORDER)
        style.configure("Vertical.TScrollbar", background=COLOR_PANEL, troughcolor=COLOR_BG, bordercolor=COLOR_BORDER)

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=BOTH, expand=True)

        notebook = ttk.Notebook(main)
        notebook.pack(fill=BOTH, expand=True)

        monitor_tab = ttk.Frame(notebook, padding=4)
        live_logs_tab = ttk.Frame(notebook, padding=10)
        mods_tab = ttk.Frame(notebook, padding=10)
        config_tab = ttk.Frame(notebook, padding=10)
        diagnostics_tab = ttk.Frame(notebook, padding=10)
        verify_files_tab = ttk.Frame(notebook, padding=10)
        settings_tab = ttk.Frame(notebook, padding=10)
        notebook.add(monitor_tab, text="Crash Monitor")
        notebook.add(live_logs_tab, text="Live Logs")
        notebook.add(mods_tab, text="Mods")
        notebook.add(config_tab, text="Config")
        notebook.add(diagnostics_tab, text="Diagnostics")
        notebook.add(verify_files_tab, text="Verify Files")
        notebook.add(settings_tab, text="Settings")

        self._build_monitor_tab(monitor_tab)
        self._build_live_logs_tab(live_logs_tab)
        self._build_mods_tab(mods_tab)
        self._build_config_tab(config_tab)
        self._build_diagnostics_tab(diagnostics_tab)
        self._build_verify_files_tab(verify_files_tab)
        self._build_settings_tab(settings_tab)

    def _build_monitor_tab(self, parent: ttk.Frame) -> None:
        main = parent

        top = ttk.Frame(main)
        top.pack(fill="x")

        ttk.Button(top, text="Choose Modpack Folder", command=self.choose_folder).pack(side=LEFT)
        ttk.Button(top, text="Choose Save Folder", command=self.choose_save_folder).pack(side=LEFT, padx=(8, 0))
        ttk.Button(top, text="Toggle Fullscreen (F11)", command=self.toggle_fullscreen).pack(side=LEFT, padx=(8, 0))
        ttk.Checkbutton(top, text="Alert sound", variable=self.sound_enabled).pack(side=LEFT, padx=(8, 0))
        ttk.Checkbutton(top, text="Minimize to tray", variable=self.tray_enabled).pack(side=LEFT, padx=(8, 0))
        ttk.Label(top, textvariable=self.status_var).pack(side=RIGHT)

        path_row = ttk.Frame(main)
        path_row.pack(fill="x", pady=(8, 10))
        ttk.Label(path_row, text="Watching:").pack(side=LEFT)
        ttk.Label(path_row, textvariable=self.current_path).pack(side=LEFT, padx=(6, 0))

        save_row = ttk.Frame(main)
        save_row.pack(fill="x", pady=(0, 8))
        ttk.Label(save_row, text="Save Folder:").pack(side=LEFT)
        ttk.Label(save_row, textvariable=self.save_path).pack(side=LEFT, padx=(6, 0))

        columns = ("time", "file", "mods", "confidence", "severity", "count", "loader")
        self.tree = ttk.Treeview(main, columns=columns, show="headings", height=14)
        self.tree.heading("time", text="Time")
        self.tree.heading("file", text="Crash Report File")
        self.tree.heading("mods", text="Likely Culprit Mods")
        self.tree.heading("confidence", text="Confidence")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("count", text="Count")
        self.tree.heading("loader", text="Loader")

        self.tree.column("time", width=150, anchor=W)
        self.tree.column("file", width=230, anchor=W)
        self.tree.column("mods", width=300, anchor=W)
        self.tree.column("confidence", width=85, anchor=W)
        self.tree.column("severity", width=85, anchor=W)
        self.tree.column("count", width=70, anchor=W)
        self.tree.column("loader", width=90, anchor=W)

        scrollbar = ttk.Scrollbar(main, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill="y")

        detail_frame = ttk.LabelFrame(main, text="Details", padding=8)
        detail_frame.pack(fill=BOTH, expand=True, pady=(10, 0))

        self.detail_text = ttk.Treeview(detail_frame, columns=("value",), show="tree", height=8)
        self.detail_text.pack(fill=BOTH, expand=True)

        conflicts_frame = ttk.LabelFrame(main, text="Top Conflict Pairs", padding=8)
        conflicts_frame.pack(fill=BOTH, expand=False, pady=(10, 0))

        self.conflict_tree = ttk.Treeview(conflicts_frame, columns=("pair", "hits"), show="headings", height=5)
        self.conflict_tree.heading("pair", text="Likely Mod Conflict Pair")
        self.conflict_tree.heading("hits", text="Occurrences")
        self.conflict_tree.column("pair", width=500, anchor=W)
        self.conflict_tree.column("hits", width=120, anchor=W)
        self.conflict_tree.pack(fill=BOTH, expand=True)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.conflict_tree.bind("<<TreeviewSelect>>", self._on_conflict_select)

    def _build_live_logs_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Potential Crash List (Live Log Errors)", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        ttk.Label(
            parent,
            text="Live ERROR/FATAL events from logs. Select a row to view details.",
            wraplength=860,
        ).pack(anchor=W, pady=(6, 10))
        ttk.Label(
            parent,
            text="Tip: click a column header to sort. Click again to toggle more-to-less or less-to-more.",
            wraplength=860,
        ).pack(anchor=W, pady=(0, 8))

        issue_frame = ttk.LabelFrame(parent, text="Live Log Events", padding=8)
        issue_frame.pack(fill=BOTH, expand=True)

        issue_columns = ("time", "file", "level", "type", "mod", "message", "count")
        self.issue_tree = ttk.Treeview(issue_frame, columns=issue_columns, show="headings", height=15)
        self.issue_tree.heading("time", text="Time", command=lambda: self._sort_issue_tree("time"))
        self.issue_tree.heading("file", text="Log File", command=lambda: self._sort_issue_tree("file"))
        self.issue_tree.heading("level", text="Level", command=lambda: self._sort_issue_tree("level"))
        self.issue_tree.heading("type", text="Type", command=lambda: self._sort_issue_tree("type"))
        self.issue_tree.heading("mod", text="Mod Hint", command=lambda: self._sort_issue_tree("mod"))
        self.issue_tree.heading("message", text="Message", command=lambda: self._sort_issue_tree("message"))
        self.issue_tree.heading("count", text="Count", command=lambda: self._sort_issue_tree("count"))

        self.issue_tree.column("time", width=150, anchor=W)
        self.issue_tree.column("file", width=170, anchor=W)
        self.issue_tree.column("level", width=70, anchor=W)
        self.issue_tree.column("type", width=130, anchor=W)
        self.issue_tree.column("mod", width=120, anchor=W)
        self.issue_tree.column("message", width=400, anchor=W)
        self.issue_tree.column("count", width=70, anchor=W)

        issue_scrollbar = ttk.Scrollbar(issue_frame, orient=VERTICAL, command=self.issue_tree.yview)
        self.issue_tree.configure(yscrollcommand=issue_scrollbar.set)

        self.issue_tree.pack(side=LEFT, fill=BOTH, expand=True)
        issue_scrollbar.pack(side=RIGHT, fill="y")

        detail_frame = ttk.LabelFrame(parent, text="Live Log Details", padding=8)
        detail_frame.pack(fill=BOTH, expand=True, pady=(10, 0))
        self.issue_detail_text = ttk.Treeview(detail_frame, columns=("value",), show="tree", height=8)
        self.issue_detail_text.pack(fill=BOTH, expand=True)

        self.issue_tree.bind("<<TreeviewSelect>>", self._on_issue_select)

    def _build_config_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Config Manager", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        ttk.Label(
            parent,
            text="Manage modpack config files with one original backup and one-click restore.",
            wraplength=860,
        ).pack(anchor=W, pady=(6, 10))

        controls = ttk.Frame(parent)
        controls.pack(fill="x", pady=(0, 8))
        ttk.Button(controls, text="Refresh Config Files", command=self._refresh_config_files).pack(side=LEFT)
        ttk.Button(controls, text="Create Original Backup", command=self._create_original_config_backup).pack(side=LEFT, padx=(8, 0))
        ttk.Button(controls, text="Restore Original", command=self._restore_original_config_backup).pack(side=LEFT, padx=(8, 0))
        ttk.Button(controls, text="Open Backup Folder", command=self._open_config_backup_folder).pack(side=LEFT, padx=(8, 0))
        ttk.Button(controls, text="Save Current File", command=self._save_selected_config_file).pack(side=LEFT, padx=(8, 0))

        ttk.Label(parent, textvariable=self.config_status_var).pack(anchor=W)
        ttk.Label(parent, textvariable=self.config_backup_status_var).pack(anchor=W, pady=(2, 8))

        center = ttk.Frame(parent)
        center.pack(fill=BOTH, expand=True)

        left_panel = ttk.LabelFrame(center, text="Config Files", padding=8)
        left_panel.pack(side=LEFT, fill=BOTH, expand=False)

        filter_row = ttk.Frame(left_panel)
        filter_row.pack(fill="x", pady=(0, 6))
        ttk.Label(filter_row, text="Filter:").pack(side=LEFT)
        filter_entry = ttk.Entry(filter_row, textvariable=self.config_filter_var, width=30)
        filter_entry.pack(side=LEFT, padx=(6, 0))
        filter_entry.bind("<KeyRelease>", lambda _event: self._refresh_config_files())

        self.config_files_tree = ttk.Treeview(left_panel, columns=("path",), show="headings", height=22)
        self.config_files_tree.heading("path", text="Path")
        self.config_files_tree.column("path", width=320, anchor=W)

        file_scroll = ttk.Scrollbar(left_panel, orient=VERTICAL, command=self.config_files_tree.yview)
        self.config_files_tree.configure(yscrollcommand=file_scroll.set)
        self.config_files_tree.pack(side=LEFT, fill=BOTH, expand=True)
        file_scroll.pack(side=RIGHT, fill="y")
        self.config_files_tree.bind("<<TreeviewSelect>>", self._on_config_file_select)

        right_panel = ttk.Frame(center)
        right_panel.pack(side=LEFT, fill=BOTH, expand=True, padx=(10, 0))

        ttk.Label(right_panel, textvariable=self.config_selected_file_var).pack(anchor=W)

        kv_frame = ttk.LabelFrame(right_panel, text="Detected Configurable Keys", padding=8)
        kv_frame.pack(fill=BOTH, expand=False, pady=(8, 8))
        self.config_kv_tree = ttk.Treeview(kv_frame, columns=("key", "value"), show="headings", height=8)
        self.config_kv_tree.heading("key", text="Key")
        self.config_kv_tree.heading("value", text="Value")
        self.config_kv_tree.column("key", width=280, anchor=W)
        self.config_kv_tree.column("value", width=360, anchor=W)
        self.config_kv_tree.pack(fill=BOTH, expand=True)
        self.config_kv_tree.bind("<<TreeviewSelect>>", self._on_config_key_select)

        kv_edit_row = ttk.Frame(right_panel)
        kv_edit_row.pack(fill="x", pady=(0, 8))
        ttk.Label(kv_edit_row, text="Key:").pack(side=LEFT)
        ttk.Entry(kv_edit_row, textvariable=self.config_edit_key_var, width=34, state="readonly").pack(side=LEFT, padx=(6, 8))
        ttk.Label(kv_edit_row, text="Value:").pack(side=LEFT)
        ttk.Entry(kv_edit_row, textvariable=self.config_edit_value_var, width=34).pack(side=LEFT, padx=(6, 8))
        ttk.Button(kv_edit_row, text="Apply Value", command=self._apply_config_key_value_to_editor).pack(side=LEFT)

        editor_frame = ttk.LabelFrame(right_panel, text="File Editor", padding=8)
        editor_frame.pack(fill=BOTH, expand=True)
        self.config_editor = tk.Text(editor_frame, wrap="none", bg=COLOR_PANEL, fg=COLOR_TEXT, insertbackground=COLOR_TEXT)
        editor_scroll_y = ttk.Scrollbar(editor_frame, orient=VERTICAL, command=self.config_editor.yview)
        self.config_editor.configure(yscrollcommand=editor_scroll_y.set)
        self.config_editor.pack(side=LEFT, fill=BOTH, expand=True)
        editor_scroll_y.pack(side=RIGHT, fill="y")

    def _build_mods_tab(self, parent: ttk.Frame) -> None:
        self.mods_status_var = StringVar(value="Choose a modpack folder to list mods")

        ttk.Label(parent, text="Modpack Mods", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        ttk.Label(
            parent,
            text="Shows detected mod jar files and best-effort version parsing.",
            wraplength=860,
        ).pack(anchor=W, pady=(6, 10))

        controls = ttk.Frame(parent)
        controls.pack(fill="x", pady=(0, 8))
        ttk.Button(controls, text="Refresh Mod List", command=self._refresh_mods_list).pack(side=LEFT)
        ttk.Label(controls, textvariable=self.mods_status_var).pack(side=LEFT, padx=(10, 0))

        mods_frame = ttk.LabelFrame(parent, text="Detected Mods", padding=8)
        mods_frame.pack(fill=BOTH, expand=True)

        columns = ("mod", "version", "jar")
        self.mods_tree = ttk.Treeview(mods_frame, columns=columns, show="headings", height=18)
        self.mods_tree.heading("mod", text="Mod")
        self.mods_tree.heading("version", text="Version")
        self.mods_tree.heading("jar", text="Jar File")
        self.mods_tree.column("mod", width=260, anchor=W)
        self.mods_tree.column("version", width=180, anchor=W)
        self.mods_tree.column("jar", width=440, anchor=W)

        scrollbar = ttk.Scrollbar(mods_frame, orient=VERTICAL, command=self.mods_tree.yview)
        self.mods_tree.configure(yscrollcommand=scrollbar.set)

        self.mods_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill="y")

    def _build_diagnostics_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Runtime Diagnostics", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        ttk.Label(
            parent,
            text="Live internal status to verify watchers and alerts are working.",
            wraplength=860,
        ).pack(anchor=W, pady=(6, 10))

        status_frame = ttk.LabelFrame(parent, text="Status", padding=8)
        status_frame.pack(fill=BOTH, expand=False)

        ttk.Label(status_frame, textvariable=self.diag_watchers_var).pack(anchor=W, pady=(2, 2))
        ttk.Label(status_frame, textvariable=self.diag_queues_var).pack(anchor=W, pady=(2, 2))
        ttk.Label(status_frame, textvariable=self.diag_last_crash_var, wraplength=860).pack(anchor=W, pady=(2, 2))
        ttk.Label(status_frame, textvariable=self.diag_last_issue_var, wraplength=860).pack(anchor=W, pady=(2, 2))
        ttk.Label(status_frame, textvariable=self.diag_last_popup_var).pack(anchor=W, pady=(2, 2))
        ttk.Label(status_frame, textvariable=self.diag_counts_var).pack(anchor=W, pady=(2, 2))

        controls = ttk.Frame(parent)
        controls.pack(fill="x", pady=(10, 0))
        ttk.Button(controls, text="Refresh Now", command=lambda: self._refresh_diagnostics(reschedule=False)).pack(side=LEFT)

    def _build_verify_files_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Verify Files and Stability", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        ttk.Label(
            parent,
            text=(
                "Run integrity and stability checks for the selected modpack folder. "
                "This creates a clear, shareable health score and certification state."
            ),
            wraplength=860,
        ).pack(anchor=W, pady=(6, 10))

        controls = ttk.Frame(parent)
        controls.pack(fill="x", pady=(0, 8))
        ttk.Button(controls, text="Run Verification", command=self._run_verify_files_check).pack(side=LEFT)
        ttk.Button(
            controls,
            text="Refresh Diagnostics",
            command=lambda: self._refresh_diagnostics(reschedule=False),
        ).pack(side=LEFT, padx=(8, 0))

        score_frame = ttk.LabelFrame(parent, text="Certification Summary", padding=8)
        score_frame.pack(fill=BOTH, expand=False)
        ttk.Label(score_frame, textvariable=self.verify_score_var, font=("Segoe UI", 11, "bold")).pack(anchor=W, pady=(2, 2))
        ttk.Label(score_frame, textvariable=self.verify_cert_var).pack(anchor=W, pady=(2, 2))
        ttk.Label(score_frame, textvariable=self.verify_data_var, wraplength=860).pack(anchor=W, pady=(2, 2))
        ttk.Label(score_frame, textvariable=self.verify_status_var, wraplength=860).pack(anchor=W, pady=(2, 2))

        checks_frame = ttk.LabelFrame(parent, text="Verification Checks", padding=8)
        checks_frame.pack(fill=BOTH, expand=True, pady=(10, 0))

        columns = ("check", "status", "points", "details")
        self.verify_tree = ttk.Treeview(checks_frame, columns=columns, show="headings", height=14)
        self.verify_tree.heading("check", text="Check")
        self.verify_tree.heading("status", text="Status")
        self.verify_tree.heading("points", text="Points")
        self.verify_tree.heading("details", text="Details")

        self.verify_tree.column("check", width=220, anchor=W)
        self.verify_tree.column("status", width=140, anchor=W)
        self.verify_tree.column("points", width=80, anchor=W)
        self.verify_tree.column("details", width=520, anchor=W)

        scrollbar = ttk.Scrollbar(checks_frame, orient=VERTICAL, command=self.verify_tree.yview)
        self.verify_tree.configure(yscrollcommand=scrollbar.set)
        self.verify_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill="y")

    def _run_verify_files_check(self, selected_path: Path | None = None) -> None:
        if not hasattr(self, "verify_tree"):
            return

        for item in self.verify_tree.get_children():
            self.verify_tree.delete(item)

        modpack_path = selected_path or self._modpack_path()
        if modpack_path is None:
            self.verify_score_var.set("CrashReader Stability Score: --/100")
            self.verify_cert_var.set("Certification: not verified")
            self.verify_data_var.set("Evidence: choose a valid modpack folder first")
            self.verify_status_var.set("Verify Files could not run: no modpack selected")
            return

        score = 0
        checks: list[tuple[str, str, int, str]] = []

        mods_dir = modpack_path / "mods"
        jars = sorted(mods_dir.glob("*.jar"), key=lambda p: p.name.lower()) if mods_dir.exists() and mods_dir.is_dir() else []
        mods_points = 15 if jars else 0
        checks.append(
            (
                "Mods folder and jars",
                "Pass" if jars else "Fail",
                mods_points,
                f"Detected {len(jars)} jar file(s)" if jars else "mods folder missing or contains no jars",
            )
        )
        score += mods_points

        config_dir = modpack_path / "config"
        config_points = 10 if config_dir.exists() and config_dir.is_dir() else 0
        checks.append(
            (
                "Config folder",
                "Pass" if config_points else "Fail",
                config_points,
                "Config folder detected" if config_points else "Config folder not found",
            )
        )
        score += config_points

        backup_dir = self._original_config_backup_path(modpack_path)
        backup_ready = bool(backup_dir is not None and backup_dir.exists() and backup_dir.is_dir())
        backup_points = 10 if backup_ready else 0
        checks.append(
            (
                "Original config backup",
                "Pass" if backup_ready else "Fail",
                backup_points,
                "Backup is available for restore" if backup_ready else "Original backup not found",
            )
        )
        score += backup_points

        readable_points = 0
        broken_count = 0
        if jars:
            sample = jars[:50]
            for jar_path in sample:
                try:
                    with zipfile.ZipFile(jar_path, "r") as archive:
                        archive.testzip()
                except Exception:
                    broken_count += 1
            if broken_count == 0:
                readable_points = 15
                status = "Pass"
            elif broken_count <= 2:
                readable_points = 8
                status = "Warn"
            else:
                readable_points = 0
                status = "Fail"
            checks.append(
                (
                    "Jar readability",
                    status,
                    readable_points,
                    f"Checked {len(sample)} jar(s); unreadable={broken_count}",
                )
            )
        else:
            checks.append(("Jar readability", "Fail", 0, "No jars available to validate"))
        score += readable_points

        duplicate_points = 0
        duplicate_buckets: dict[str, list[str]] = {}
        if jars:
            by_mod: dict[str, list[str]] = {}
            for jar_path in jars:
                mod_name, _version = self._mod_name_version_from_jar(jar_path)
                key = re.sub(r"[^a-z0-9]+", "", mod_name.lower())
                if not key:
                    key = re.sub(r"[^a-z0-9]+", "", jar_path.stem.lower())
                if not key:
                    continue
                by_mod.setdefault(key, []).append(jar_path.name)
            duplicate_buckets = {k: v for k, v in by_mod.items() if len(v) > 1}

            if not duplicate_buckets:
                duplicate_points = 10
                dup_status = "Pass"
                dup_detail = "No duplicate-looking mod jars detected"
            else:
                duplicate_points = 3
                dup_status = "Warn"
                dup_detail = f"Potential duplicate mod groups: {len(duplicate_buckets)}"
            checks.append(("Duplicate mod scan", dup_status, duplicate_points, dup_detail))
        else:
            checks.append(("Duplicate mod scan", "Fail", 0, "No jars available for duplicate analysis"))
        score += duplicate_points

        total_events = len(self.event_history)
        unique_signatures = len(self.signature_count)
        repeated_events = max(0, total_events - unique_signatures)
        if total_events == 0:
            recurrence_points = 10
            recurrence_status = "Neutral"
            recurrence_detail = "No crash history captured yet"
        else:
            recurrence_ratio = repeated_events / max(1, total_events)
            if recurrence_ratio <= 0.05:
                recurrence_points = 20
                recurrence_status = "Pass"
            elif recurrence_ratio <= 0.20:
                recurrence_points = 12
                recurrence_status = "Warn"
            else:
                recurrence_points = 4
                recurrence_status = "Fail"
            recurrence_detail = (
                f"Events={total_events}, unique signatures={unique_signatures}, repeats={repeated_events}"
            )
        checks.append(("Recurring fatal signatures", recurrence_status, recurrence_points, recurrence_detail))
        score += recurrence_points

        critical_events = sum(1 for event in self.event_history if event.severity.lower() == "critical")
        if total_events == 0:
            critical_points = 8
            critical_status = "Neutral"
            critical_detail = "No severity history captured yet"
        else:
            critical_ratio = critical_events / max(1, total_events)
            if critical_ratio == 0:
                critical_points = 15
                critical_status = "Pass"
            elif critical_ratio <= 0.15:
                critical_points = 9
                critical_status = "Warn"
            else:
                critical_points = 3
                critical_status = "Fail"
            critical_detail = f"Critical events={critical_events} of {total_events}"
        checks.append(("Critical crash ratio", critical_status, critical_points, critical_detail))
        score += critical_points

        live_issue_count = len(self.issue_by_item)
        if live_issue_count == 0:
            issue_points = 5
            issue_status = "Pass"
        elif live_issue_count <= 5:
            issue_points = 3
            issue_status = "Warn"
        else:
            issue_points = 1
            issue_status = "Fail"
        checks.append(("Active live-log issues", issue_status, issue_points, f"Current tracked issues: {live_issue_count}"))
        score += issue_points

        for check_name, status, points, details in checks:
            self.verify_tree.insert("", END, values=(check_name, status, points, details))

        score = max(0, min(100, score))
        if total_events >= 25 and score >= 90:
            cert = "Certified Stable"
        elif score >= 75:
            cert = "Provisionally Stable"
        elif score >= 55:
            cert = "Needs Review"
        else:
            cert = "At Risk"

        self.verify_score_var.set(f"CrashReader Stability Score: {score}/100")
        self.verify_cert_var.set(f"Certification: {cert}")
        self.verify_data_var.set(
            (
                f"Evidence: crashes={total_events}, signatures={unique_signatures}, "
                f"critical={critical_events}, live issues={live_issue_count}"
            )
        )
        self.verify_status_var.set(
            f"Last verification run: {time.strftime('%Y-%m-%d %H:%M:%S')} | Modpack: {modpack_path.name}"
        )

    def _build_settings_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Alert and Behavior Settings", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        ttk.Label(
            parent,
            text="Tune popup behavior and test notifications without waiting for a real crash.",
            wraplength=860,
        ).pack(anchor=W, pady=(6, 12))

        alert_frame = ttk.LabelFrame(parent, text="Popup Alerts", padding=8)
        alert_frame.pack(fill=BOTH, expand=False)

        ttk.Checkbutton(alert_frame, text="Enable popup alerts", variable=self.popup_enabled).pack(anchor=W, pady=(2, 2))
        ttk.Checkbutton(
            alert_frame,
            text="Show popup for repeated crash signatures",
            variable=self.popup_on_repeat,
        ).pack(anchor=W, pady=(2, 2))

        cooldown_row = ttk.Frame(alert_frame)
        cooldown_row.pack(fill="x", pady=(4, 2))
        ttk.Label(cooldown_row, text="Popup cooldown (seconds):").pack(side=LEFT)
        ttk.Spinbox(
            cooldown_row,
            from_=0,
            to=3600,
            width=8,
            textvariable=self.popup_cooldown_seconds,
        ).pack(side=LEFT, padx=(8, 0))
        ttk.Label(cooldown_row, text="0 = no cooldown").pack(side=LEFT, padx=(8, 0))

        behavior_frame = ttk.LabelFrame(parent, text="Other Behavior", padding=8)
        behavior_frame.pack(fill=BOTH, expand=False, pady=(10, 0))
        ttk.Checkbutton(behavior_frame, text="Enable alert sound", variable=self.sound_enabled).pack(anchor=W, pady=(2, 2))
        ttk.Checkbutton(behavior_frame, text="Minimize to tray", variable=self.tray_enabled).pack(anchor=W, pady=(2, 2))

        actions_frame = ttk.LabelFrame(parent, text="Actions", padding=8)
        actions_frame.pack(fill=BOTH, expand=True, pady=(10, 0))

        buttons_row = ttk.Frame(actions_frame)
        buttons_row.pack(fill="x")
        ttk.Button(buttons_row, text="Test Popup", command=self._test_popup).pack(side=LEFT)
        ttk.Button(buttons_row, text="Test Sound", command=self._test_sound).pack(side=LEFT, padx=(8, 0))
        ttk.Button(buttons_row, text="Clear Lists", command=self._clear_runtime_lists).pack(side=LEFT, padx=(8, 0))
        ttk.Button(buttons_row, text="Save Settings", command=self._apply_settings).pack(side=LEFT, padx=(8, 0))

        ttk.Label(
            actions_frame,
            text=(
                "Clear Lists resets the in-app crash table, live log issue list, details panel, and conflict pairs. "
                "It does not stop monitoring."
            ),
            wraplength=860,
        ).pack(anchor=W, pady=(10, 0))

    def _refresh_mods_list(self, selected_path: Path | None = None) -> None:
        if not hasattr(self, "mods_tree"):
            return

        for item in self.mods_tree.get_children():
            self.mods_tree.delete(item)

        if selected_path is None:
            raw_path = self.current_path.get().strip()
            if not raw_path or raw_path == "No folder selected":
                self.mods_status_var.set("Choose a modpack folder first")
                return
            selected_path = Path(raw_path)

        mods_dir = selected_path / "mods"
        if not mods_dir.exists() or not mods_dir.is_dir():
            self.mods_status_var.set("No mods folder found in selected modpack")
            return

        jars = sorted(mods_dir.glob("*.jar"), key=lambda p: p.name.lower())
        if not jars:
            self.mods_status_var.set("mods folder found, but no .jar files were detected")
            return

        inserted = 0
        for jar_path in jars:
            mod_name, version = self._mod_name_version_from_jar(jar_path)
            self.mods_tree.insert("", END, values=(mod_name, version, jar_path.name))
            inserted += 1

        self.mods_status_var.set(f"Detected {inserted} mod(s)")

    @staticmethod
    def _mod_name_version_from_jar(jar_path: Path) -> tuple[str, str]:
        display_name = jar_path.stem
        version = "Unknown"

        file_name, file_version = CrashReaderApp._split_mod_name_version(jar_path.stem)
        if file_name:
            display_name = file_name
        if file_version:
            version = file_version

        try:
            with zipfile.ZipFile(jar_path, "r") as archive:
                if "fabric.mod.json" in archive.namelist():
                    payload = json.loads(archive.read("fabric.mod.json").decode("utf-8", errors="ignore"))
                    name = str(payload.get("name", "")).strip()
                    ver = str(payload.get("version", "")).strip()
                    if name:
                        display_name = name
                    if ver:
                        version = ver
        except Exception:
            pass

        return display_name, version

    @staticmethod
    def _split_mod_name_version(stem: str) -> tuple[str, str]:
        if not stem:
            return "unknown", "Unknown"

        parts = re.split(r"[-_]+", stem)
        if len(parts) == 1:
            return stem, "Unknown"

        split_idx = -1
        for idx, part in enumerate(parts):
            if re.search(r"\d", part):
                split_idx = idx
                break

        if split_idx <= 0:
            return stem, "Unknown"

        name = "-".join(parts[:split_idx]).strip("-")
        version = "-".join(parts[split_idx:]).strip("-")
        if not name:
            name = stem
        if not version:
            version = "Unknown"
        return name, version

    def _modpack_path(self) -> Path | None:
        raw_path = self.current_path.get().strip()
        if not raw_path or raw_path == "No folder selected":
            return None
        path = Path(raw_path)
        if not path.exists() or not path.is_dir():
            return None
        return path

    def _config_folder_path(self, modpack_path: Path | None = None) -> Path | None:
        modpack = modpack_path or self._modpack_path()
        if modpack is None:
            return None
        config_dir = modpack / "config"
        if not config_dir.exists() or not config_dir.is_dir():
            return None
        return config_dir

    def _original_config_backup_path(self, modpack_path: Path | None = None) -> Path | None:
        _modpack = modpack_path or self._modpack_path()
        if _modpack is None:
            return None
        return self._active_save_folder() / "config backup"

    def _refresh_config_files(self, selected_path: Path | None = None) -> None:
        if not hasattr(self, "config_files_tree"):
            return

        for item in self.config_files_tree.get_children():
            self.config_files_tree.delete(item)

        self.selected_config_file = None
        self.config_selected_file_var.set("Selected config: none")
        self.config_editor.delete("1.0", END)
        self._clear_config_key_values()

        config_dir = self._config_folder_path(selected_path)
        if config_dir is None:
            self.config_status_var.set("No config folder found in selected modpack")
            self._refresh_config_backup_status(selected_path)
            return

        filter_text = self.config_filter_var.get().strip().lower()
        extensions = {".toml", ".json", ".cfg", ".conf", ".properties", ".ini", ".txt", ".yaml", ".yml"}
        candidates: list[Path] = []
        for path in config_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in extensions:
                continue
            rel = str(path.relative_to(config_dir)).replace("\\", "/")
            if filter_text and filter_text not in rel.lower():
                continue
            candidates.append(path)

        candidates.sort(key=lambda p: str(p).lower())
        for path in candidates:
            rel = str(path.relative_to(config_dir)).replace("\\", "/")
            self.config_files_tree.insert("", END, values=(rel,))

        self.config_status_var.set(f"Loaded {len(candidates)} config file(s)")
        self._refresh_config_backup_status(selected_path)

    def _refresh_config_backup_status(self, selected_path: Path | None = None) -> None:
        backup_dir = self._original_config_backup_path(selected_path)
        if backup_dir is None or not backup_dir.exists() or not backup_dir.is_dir():
            self.config_backup_status_var.set("Original backup: not created")
            return

        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(backup_dir.stat().st_mtime))
        self.config_backup_status_var.set(f"Original backup: ready at {backup_dir} ({stamp})")

    def _create_original_config_backup(self) -> None:
        config_dir = self._config_folder_path()
        backup_dir = self._original_config_backup_path()
        if config_dir is None or backup_dir is None:
            self.config_status_var.set("Select a valid modpack with a config folder first")
            return

        if backup_dir.exists():
            self.config_status_var.set("Original backup already exists")
            self._refresh_config_backup_status()
            return

        backup_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(config_dir, backup_dir)
        self.config_status_var.set(f"Original config backup created at {backup_dir}")
        self._refresh_config_backup_status()

    def _ensure_original_backup_exists(self) -> bool:
        backup_dir = self._original_config_backup_path()
        if backup_dir is None:
            return False
        if backup_dir.exists():
            return True
        self._create_original_config_backup()
        return backup_dir.exists()

    def _restore_original_config_backup(self) -> None:
        modpack = self._modpack_path()
        config_dir = self._config_folder_path(modpack)
        backup_dir = self._original_config_backup_path(modpack)
        if modpack is None or backup_dir is None:
            self.config_status_var.set("Select a valid modpack first")
            return
        if not backup_dir.exists() or not backup_dir.is_dir():
            self.config_status_var.set("Original backup does not exist yet")
            return

        confirmed = messagebox.askyesno(
            "Restore Original Config",
            "Replace current config folder with the original backup?\nThis will overwrite current config changes.",
        )
        if not confirmed:
            return

        target_config = modpack / "config"
        if target_config.exists() and target_config.is_dir():
            shutil.rmtree(target_config)
        shutil.copytree(backup_dir, target_config)

        self.config_status_var.set(f"Config folder restored from original backup at {backup_dir}")
        self._refresh_config_files(modpack)

    def _open_config_backup_folder(self) -> None:
        backup_dir = self._original_config_backup_path()
        if backup_dir is None:
            self.config_status_var.set("Select a valid modpack first")
            return

        backup_dir.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt" and hasattr(os, "startfile"):
                os.startfile(str(backup_dir))
            else:
                subprocess.Popen(["xdg-open", str(backup_dir)])
            self.config_status_var.set(f"Opened backup folder: {backup_dir}")
        except Exception as ex:
            self.config_status_var.set(f"Could not open backup folder: {ex}")

    def _on_config_file_select(self, _event=None) -> None:
        selected = self.config_files_tree.selection()
        if not selected:
            return

        config_dir = self._config_folder_path()
        if config_dir is None:
            return

        rel = self.config_files_tree.item(selected[0], "values")[0]
        file_path = config_dir / rel
        if not file_path.exists() or not file_path.is_file():
            self.config_status_var.set("Selected config file is no longer available")
            return

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as ex:
            self.config_status_var.set(f"Failed to read file: {ex}")
            return

        self.selected_config_file = file_path
        self.config_selected_file_var.set(f"Selected config: {rel}")
        self.config_editor.delete("1.0", END)
        self.config_editor.insert("1.0", content)
        self.selected_config_kv_item = None
        self.config_edit_key_var.set("")
        self.config_edit_value_var.set("")
        self._populate_config_key_values(file_path, content)

    def _on_config_key_select(self, _event=None) -> None:
        selected = self.config_kv_tree.selection()
        if not selected:
            return
        self.selected_config_kv_item = selected[0]
        values = self.config_kv_tree.item(self.selected_config_kv_item, "values")
        if not values or len(values) < 2:
            return
        self.config_edit_key_var.set(str(values[0]))
        self.config_edit_value_var.set(str(values[1]))

    def _apply_config_key_value_to_editor(self) -> None:
        if self.selected_config_file is None:
            self.config_status_var.set("Select a config file first")
            return

        if not self._ensure_original_backup_exists():
            self.config_status_var.set("Could not create original backup")
            return

        key = self.config_edit_key_var.get().strip()
        if not key:
            self.config_status_var.set("Select a key from the list first")
            return

        new_value_raw = self.config_edit_value_var.get()
        content = self.config_editor.get("1.0", "end-1c")
        suffix = self.selected_config_file.suffix.lower()

        if suffix == ".json":
            try:
                data = json.loads(content)
                path_tokens = self._parse_key_path(key)
                coerced = self._coerce_value(new_value_raw)
                if not self._set_nested_value(data, path_tokens, coerced):
                    self.config_status_var.set("Could not apply key path in JSON")
                    return
                updated = json.dumps(data, indent=2, ensure_ascii=False)
            except Exception as ex:
                self.config_status_var.set(f"Could not update JSON value: {ex}")
                return
        else:
            updated = None
            if self.selected_config_kv_item is not None and self.selected_config_kv_item in self.config_kv_line_by_item:
                line_idx = self.config_kv_line_by_item[self.selected_config_kv_item]
                updated = self._replace_key_assignment_at_line(content, line_idx, key, new_value_raw)
            if updated is None:
                updated = self._replace_key_assignment_in_text(content, key, new_value_raw)
            if updated is None:
                self.config_status_var.set("Could not find key assignment to update in editor text")
                return

        if not self._write_selected_config_content(updated):
            return

        self.config_editor.delete("1.0", END)
        self.config_editor.insert("1.0", updated)
        self._populate_config_key_values(self.selected_config_file, updated)
        self.config_status_var.set(f"Updated and saved value for key: {key}")

    def _save_selected_config_file(self) -> None:
        if self.selected_config_file is None:
            self.config_status_var.set("Select a config file first")
            return

        if not self._ensure_original_backup_exists():
            self.config_status_var.set("Could not create original backup")
            return

        content = self.config_editor.get("1.0", "end-1c")
        if not self._write_selected_config_content(content):
            return

        self.config_status_var.set(f"Config file saved: {self.selected_config_file.name}")
        self._populate_config_key_values(self.selected_config_file, content)

    def _write_selected_config_content(self, content: str) -> bool:
        if self.selected_config_file is None:
            self.config_status_var.set("Select a config file first")
            return False

        if not self._validate_config_content(self.selected_config_file, content):
            return False

        try:
            self.selected_config_file.write_text(content, encoding="utf-8")
        except Exception as ex:
            self.config_status_var.set(f"Save failed: {ex}")
            return False

        return True

    def _validate_config_content(self, file_path: Path, content: str) -> bool:
        suffix = file_path.suffix.lower()
        try:
            if suffix == ".json":
                json.loads(content)
            elif suffix == ".toml" and tomllib is not None:
                tomllib.loads(content)
        except Exception as ex:
            self.config_status_var.set(f"Validation failed: {ex}")
            return False
        return True

    def _clear_config_key_values(self) -> None:
        if not hasattr(self, "config_kv_tree"):
            return
        for item in self.config_kv_tree.get_children():
            self.config_kv_tree.delete(item)
        self.config_kv_line_by_item.clear()
        self.selected_config_kv_item = None
        self.config_edit_key_var.set("")
        self.config_edit_value_var.set("")

    def _populate_config_key_values(self, file_path: Path, content: str) -> None:
        self._clear_config_key_values()
        suffix = file_path.suffix.lower()

        extracted: list[tuple[str, str]] = []
        if suffix == ".json":
            try:
                data = json.loads(content)
                self._flatten_config_values(data, "", extracted)
            except Exception:
                pass
        elif suffix == ".toml" and tomllib is not None:
            try:
                data = tomllib.loads(content)
                self._flatten_config_values(data, "", extracted)
            except Exception:
                pass
        else:
            for line_idx, raw_line in enumerate(content.splitlines()):
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    extracted.append((key.strip(), value.strip(), line_idx))
                elif ":" in line:
                    key, value = line.split(":", 1)
                    extracted.append((key.strip(), value.strip(), line_idx))

        for row in extracted[:1000]:
            if len(row) == 3:
                key, value, line_idx = row
                item_id = self.config_kv_tree.insert("", END, values=(key, value))
                self.config_kv_line_by_item[item_id] = line_idx
            else:
                key, value = row
                self.config_kv_tree.insert("", END, values=(key, value))

    def _flatten_config_values(self, data, prefix: str, out: list[tuple[str, str]]) -> None:
        if isinstance(data, dict):
            for key, value in data.items():
                next_prefix = f"{prefix}.{key}" if prefix else str(key)
                self._flatten_config_values(value, next_prefix, out)
            return
        if isinstance(data, list):
            for idx, value in enumerate(data):
                next_prefix = f"{prefix}[{idx}]"
                self._flatten_config_values(value, next_prefix, out)
            return

        out.append((prefix or "value", str(data)))

    @staticmethod
    def _parse_key_path(path: str) -> list[str | int]:
        tokens: list[str | int] = []
        for hit in re.finditer(r"([^.\[\]]+)|\[(\d+)\]", path):
            name = hit.group(1)
            index = hit.group(2)
            if name is not None:
                tokens.append(name)
            elif index is not None:
                tokens.append(int(index))
        return tokens

    @staticmethod
    def _coerce_value(value: str):
        stripped = value.strip()
        lower = stripped.lower()
        if lower in {"true", "false"}:
            return lower == "true"
        if lower in {"none", "null"}:
            return None
        if re.fullmatch(r"-?\d+", stripped):
            try:
                return int(stripped)
            except Exception:
                pass
        if re.fullmatch(r"-?\d+\.\d+", stripped):
            try:
                return float(stripped)
            except Exception:
                pass
        if (stripped.startswith('"') and stripped.endswith('"')) or (stripped.startswith("'") and stripped.endswith("'")):
            return stripped[1:-1]
        return stripped

    @staticmethod
    def _set_nested_value(data, tokens: list[str | int], value) -> bool:
        if not tokens:
            return False

        cursor = data
        for token in tokens[:-1]:
            if isinstance(token, int):
                if not isinstance(cursor, list) or token < 0 or token >= len(cursor):
                    return False
                cursor = cursor[token]
            else:
                if not isinstance(cursor, dict) or token not in cursor:
                    return False
                cursor = cursor[token]

        last = tokens[-1]
        if isinstance(last, int):
            if not isinstance(cursor, list) or last < 0 or last >= len(cursor):
                return False
            cursor[last] = value
            return True

        if not isinstance(cursor, dict):
            return False
        cursor[last] = value
        return True

    @staticmethod
    def _replace_key_assignment_in_text(content: str, key: str, value: str) -> str | None:
        candidates = [key]
        if "." in key:
            candidates.append(key.split(".")[-1])

        lines = content.splitlines(keepends=True)
        for candidate in candidates:
            if not candidate:
                continue
            pattern = re.compile(rf"^(\s*{re.escape(candidate)}\s*[:=]\s*)(.*?)(\s*(?:[#;].*)?)(\r?\n?)$")
            for idx, line in enumerate(lines):
                match = pattern.match(line)
                if match is None:
                    continue
                prefix = match.group(1)
                suffix = match.group(3)
                newline = match.group(4)
                lines[idx] = f"{prefix}{value}{suffix}{newline}"
                return "".join(lines)

        return None

    @staticmethod
    def _replace_key_assignment_at_line(content: str, line_idx: int, key: str, value: str) -> str | None:
        lines = content.splitlines(keepends=True)
        if line_idx < 0 or line_idx >= len(lines):
            return None

        line = lines[line_idx]
        pattern = re.compile(rf"^(\s*{re.escape(key)}\s*[:=]\s*)(.*?)(\s*(?:[#;].*)?)(\r?\n?)$")
        match = pattern.match(line)
        if match is None:
            fallback = re.compile(r"^(\s*[^:=\s]+\s*[:=]\s*)(.*?)(\s*(?:[#;].*)?)(\r?\n?)$")
            match = fallback.match(line)
            if match is None:
                return None

        prefix = match.group(1)
        suffix = match.group(3)
        newline = match.group(4)
        lines[line_idx] = f"{prefix}{value}{suffix}{newline}"
        return "".join(lines)

    def _bind_shortcuts(self) -> None:
        self.root.bind("<F11>", lambda _event: self.toggle_fullscreen())
        self.root.bind("<Escape>", lambda _event: self.exit_fullscreen())
        self.root.bind("<Unmap>", self._maybe_minimize_to_tray)

    def _refresh_diagnostics(self, reschedule: bool = True) -> None:
        watcher_state = "running" if (self.watcher is not None and self.watcher.is_alive()) else "stopped"
        log_watcher_state = "running" if (self.log_watcher is not None and self.log_watcher.is_alive()) else "stopped"
        self.diag_watchers_var.set(f"Watchers: crash={watcher_state}, logs={log_watcher_state}")

        self.diag_queues_var.set(f"Queues: crash={self.queue.qsize()}, logs={self.log_queue.qsize()}")

        crash_ts = self._format_timestamp(self.last_crash_seen_at)
        issue_ts = self._format_timestamp(self.last_issue_seen_at)
        popup_ts = self._format_timestamp(self.last_popup_global_at)

        self.diag_last_crash_var.set(f"Last crash file seen: {self.last_crash_file_seen} ({crash_ts})")
        self.diag_last_issue_var.set(f"Last live log issue: {self.last_issue_file_seen} ({issue_ts})")
        self.diag_last_popup_var.set(f"Last popup: {popup_ts}")
        self.diag_counts_var.set(
            f"Tracked items: crashes={len(self.rows_by_item)}, issues={len(self.issue_by_item)}, signatures={len(self.signature_to_item)}"
        )

        if reschedule:
            self.root.after(1200, self._refresh_diagnostics)

    @staticmethod
    def _format_timestamp(ts: float) -> str:
        if ts <= 0:
            return "none"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    def choose_folder(self) -> None:
        picked = filedialog.askdirectory(title="Choose your modpack root folder")
        if not picked:
            return

        path = Path(picked)
        if not path.exists():
            messagebox.showerror("Invalid Folder", "That folder does not exist.")
            return

        previous_raw = self.current_path.get().strip()
        previous_path = Path(previous_raw) if previous_raw and previous_raw != "No folder selected" else None
        switched_modpack = previous_path is not None and previous_path.resolve() != path.resolve()

        if switched_modpack:
            self._clear_runtime_lists()
            self._delete_original_config_backup()

        self.current_path.set(str(path))
        self._run_startup_health_check(path)
        self.status_var.set("Watching for new crash reports...")
        self._start_watching(path)
        self._refresh_mods_list(path)
        self._refresh_config_files(path)
        self._run_verify_files_check(path)

        if switched_modpack:
            self._create_original_config_backup()

        self._save_state()

    def _delete_original_config_backup(self) -> None:
        backup_dir = self._original_config_backup_path()
        if backup_dir is None:
            return
        if backup_dir.exists() and backup_dir.is_dir():
            shutil.rmtree(backup_dir)

    def choose_save_folder(self) -> None:
        picked = filedialog.askdirectory(title="Choose save folder for JSON session files")
        if not picked:
            return

        path = Path(picked)
        if not path.exists():
            messagebox.showerror("Invalid Folder", "That save folder does not exist.")
            return

        self.save_path.set(str(path))
        self.status_var.set("Save folder updated")
        self._save_state()

    def _start_watching(self, path: Path, clear_existing: bool = True) -> None:
        self._stop_watching()
        self.analyzer = CrashAnalyzer(path)
        if clear_existing:
            self.signature_to_item.clear()
            self.signature_count.clear()
            self.conflict_pairs.clear()
            self.rows_by_item.clear()
            self.issue_by_item.clear()
            self.issue_signature_to_item.clear()
            self.issue_signature_count.clear()
            self.conflict_by_item.clear()
            self.event_history.clear()

            for item in self.tree.get_children():
                self.tree.delete(item)
            for item in self.detail_text.get_children():
                self.detail_text.delete(item)
            for item in self.conflict_tree.get_children():
                self.conflict_tree.delete(item)
            for item in self.issue_tree.get_children():
                self.issue_tree.delete(item)

        self.stop_event = threading.Event()
        self.watcher = CrashWatcher(path, self.queue, self.stop_event)
        self.watcher.start()
        self.log_watcher = LogWatcher(path, self.log_queue, self.stop_event)
        self.log_watcher.start()

    def _stop_watching(self) -> None:
        if self.watcher and self.watcher.is_alive():
            self.stop_event.set()
            self.watcher.join(timeout=1.5)
        if self.log_watcher and self.log_watcher.is_alive():
            self.stop_event.set()
            self.log_watcher.join(timeout=1.5)

    def _pump_queue(self) -> None:
        processed = 0
        issues_processed = 0
        while True:
            try:
                crash_file = self.queue.get_nowait()
            except queue.Empty:
                break

            self._handle_crash_file(crash_file)
            processed += 1

        while True:
            try:
                issue_event = self.log_queue.get_nowait()
            except queue.Empty:
                break

            self._record_log_issue(issue_event)
            issues_processed += 1

        if processed and issues_processed:
            self.status_var.set(f"Detected {processed} crash file(s) and {issues_processed} potential issue(s)")
        elif processed:
            self.status_var.set(f"Detected {processed} new crash report(s)")
        elif issues_processed:
            self.status_var.set(f"Detected {issues_processed} potential issue(s) from live logs")

        self.root.after(600, self._pump_queue)

    def _record_log_issue(self, event: LogIssueEvent) -> None:
        self.last_issue_file_seen = event.file_path.name
        self.last_issue_seen_at = time.time()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.created_at))
        existing = self.issue_signature_to_item.get(event.signature)
        self.issue_signature_count[event.signature] += 1

        if existing:
            self.issue_tree.item(
                existing,
                values=(
                    timestamp,
                    event.file_path.name,
                    event.level,
                    event.log_type,
                    event.mod_hint,
                    event.message,
                    self.issue_signature_count[event.signature],
                ),
            )
            self.issue_by_item[existing] = event
            self._resort_issue_tree_if_needed()
            return

        item_id = self.issue_tree.insert(
            "",
            0,
            values=(
                timestamp,
                event.file_path.name,
                event.level,
                event.log_type,
                event.mod_hint,
                event.message,
                self.issue_signature_count[event.signature],
            ),
        )
        self.issue_by_item[item_id] = event
        self.issue_signature_to_item[event.signature] = item_id
        self._resort_issue_tree_if_needed()

        children = self.issue_tree.get_children()
        if len(children) > MAX_RECENT_ISSUES:
            to_remove = children[MAX_RECENT_ISSUES:]
            for item in to_remove:
                old_event = self.issue_by_item.get(item)
                if old_event and self.issue_signature_to_item.get(old_event.signature) == item:
                    self.issue_signature_to_item.pop(old_event.signature, None)
                self.issue_tree.delete(item)
                self.issue_by_item.pop(item, None)

    def _handle_crash_file(self, crash_file: Path) -> None:
        if not self.analyzer:
            return

        self.last_crash_file_seen = crash_file.name
        self.last_crash_seen_at = time.time()

        try:
            event = self.analyzer.analyze_file(crash_file)
        except Exception as ex:
            self.status_var.set(f"Could not parse {crash_file.name}: {ex}")
            return

        self._record_event(event, notify=True, persist=True)

    def _record_event(self, event: CrashEvent, notify: bool, persist: bool) -> None:
        self.event_history.append(event)
        if len(self.event_history) > MAX_PERSISTED_HISTORY:
            self.event_history = self.event_history[-MAX_PERSISTED_HISTORY:]

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.created_at))
        mods = ", ".join(event.suspected_mods)

        self.signature_count[event.signature] += 1
        existing = self.signature_to_item.get(event.signature)

        if existing:
            self.tree.item(
                existing,
                values=(
                    timestamp,
                    event.file_path.name,
                    mods,
                    event.confidence,
                    event.severity,
                    self.signature_count[event.signature],
                    event.loader_profile,
                ),
            )
            self.rows_by_item[existing] = event
            if notify:
                self.status_var.set(
                    f"Repeated crash signature detected ({self.signature_count[event.signature]}x): {event.file_path.name}"
                )
                self._maybe_alert_for_event(event, is_repeat=True)
        else:
            item_id = self.tree.insert(
                "",
                0,
                values=(
                    timestamp,
                    event.file_path.name,
                    mods,
                    event.confidence,
                    event.severity,
                    self.signature_count[event.signature],
                    event.loader_profile,
                ),
            )
            self.rows_by_item[item_id] = event
            self.signature_to_item[event.signature] = item_id
            if notify:
                self._maybe_alert_for_event(event, is_repeat=False)

        self._update_conflict_pairs(event)
        self._refresh_conflict_tree()

        # Keep table size under control for long running sessions.
        children = self.tree.get_children()
        if len(children) > MAX_RECENT_CRASHES:
            to_remove = children[MAX_RECENT_CRASHES:]
            for item in to_remove:
                old_event = self.rows_by_item.get(item)
                if old_event and self.signature_to_item.get(old_event.signature) == item:
                    self.signature_to_item.pop(old_event.signature, None)
                self.tree.delete(item)
                self.rows_by_item.pop(item, None)

        if persist:
            self._save_state()

    def _show_popup(self, event: CrashEvent) -> None:
        popup = Toplevel(self.root)
        popup.title("Crash Detected")
        popup.geometry("620x320+80+80")
        popup.attributes("-topmost", True)
        popup.configure(bg=COLOR_BG)

        frame = ttk.Frame(popup, padding=12)
        frame.pack(fill=BOTH, expand=True)

        ttk.Label(frame, text="New Crash Report Detected", font=("Segoe UI", 12, "bold")).pack(anchor=W)
        ttk.Label(frame, text=f"File: {event.file_path.name}").pack(anchor=W, pady=(6, 0))
        ttk.Label(frame, text=f"Confidence: {event.confidence}").pack(anchor=W, pady=(3, 0))
        ttk.Label(frame, text=f"Severity: {event.severity}").pack(anchor=W, pady=(3, 0))
        ttk.Label(frame, text=f"Loader profile: {event.loader_profile}").pack(anchor=W, pady=(3, 0))

        ttk.Label(frame, text="Likely culprit mods:", font=("Segoe UI", 10, "bold")).pack(anchor=W, pady=(8, 0))
        ttk.Label(frame, text=", ".join(event.suspected_mods), wraplength=580).pack(anchor=W, pady=(2, 0))

        if event.suspected_mods and event.suspected_mods[0] in event.evidence:
            reason = event.evidence[event.suspected_mods[0]][0]
            ttk.Label(frame, text=f"Top evidence: {reason}", wraplength=580).pack(anchor=W, pady=(3, 0))

        ttk.Label(frame, text="Summary:", font=("Segoe UI", 10, "bold")).pack(anchor=W, pady=(8, 0))
        ttk.Label(frame, text=event.summary, wraplength=580).pack(anchor=W, pady=(2, 0))

        ttk.Button(frame, text="Close", command=popup.destroy).pack(anchor=W, pady=(12, 0))

        # Auto-close after 18 seconds so multiple crashes do not flood windows.
        popup.after(18000, popup.destroy)

    def _maybe_alert_for_event(self, event: CrashEvent, is_repeat: bool) -> None:
        if not self.popup_enabled.get():
            return
        if is_repeat and not self.popup_on_repeat.get():
            return

        cooldown = self._popup_cooldown_seconds()
        last = self.last_popup_at.get(event.signature, 0.0)
        now = time.time()
        if cooldown > 0 and (now - last) < cooldown:
            return

        self.last_popup_at[event.signature] = now
        self.last_popup_global_at = now
        self._show_popup(event)
        self._play_alert_sound(event.severity)

    def _popup_cooldown_seconds(self) -> int:
        try:
            value = int(self.popup_cooldown_seconds.get())
        except Exception:
            value = 0
        return max(0, value)

    def _test_popup(self) -> None:
        event = CrashEvent(
            file_path=Path("test-crash-report.txt"),
            created_at=time.time(),
            summary="Test popup from Settings tab",
            suspected_mods=["examplemod"],
            confidence="High",
            severity="Major",
            loader_profile="Unknown",
            signature=LogIssueEvent.build_signature("TEST", "General Runtime", "examplemod", "settings-popup-test"),
            evidence={"examplemod": ["Manual test from Settings tab"]},
        )
        self._show_popup(event)
        self.status_var.set("Popup test shown")

    def _test_sound(self) -> None:
        if winsound is not None:
            sound_type = winsound.MB_ICONEXCLAMATION
            winsound.MessageBeep(sound_type)
        else:
            try:
                self.root.bell()
            except Exception:
                pass
        self.status_var.set("Sound test played")

    def _clear_runtime_lists(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item in self.issue_tree.get_children():
            self.issue_tree.delete(item)
        for item in self.conflict_tree.get_children():
            self.conflict_tree.delete(item)
        for item in self.detail_text.get_children():
            self.detail_text.delete(item)
        if hasattr(self, "issue_detail_text"):
            for item in self.issue_detail_text.get_children():
                self.issue_detail_text.delete(item)

        self.rows_by_item.clear()
        self.signature_to_item.clear()
        self.signature_count.clear()
        self.issue_by_item.clear()
        self.issue_signature_to_item.clear()
        self.issue_signature_count.clear()
        self.conflict_by_item.clear()
        self.conflict_pairs.clear()
        self.event_history.clear()
        self.last_popup_at.clear()

        self._save_state()
        self._run_verify_files_check()
        self.status_var.set("Cleared in-memory crash and log lists")

    def _apply_settings(self) -> None:
        # Normalize cooldown input before saving.
        self.popup_cooldown_seconds.set(self._popup_cooldown_seconds())
        self._save_state()
        self.status_var.set("Settings saved")

    def _on_tree_select(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return

        item = selected[0]
        event = self.rows_by_item.get(item)
        if not event:
            return

        self._clear_detail_panel()
        self.detail_text.insert("", END, text="Source: Crash Reports")
        self.detail_text.insert("", END, text=f"File: {event.file_path}")
        self.detail_text.insert("", END, text=f"Signature: {event.signature}")
        self.detail_text.insert("", END, text=f"Confidence: {event.confidence}")
        self.detail_text.insert("", END, text=f"Severity: {event.severity}")
        self.detail_text.insert("", END, text=f"Loader: {event.loader_profile}")
        self.detail_text.insert("", END, text=f"Likely Mods: {', '.join(event.suspected_mods)}")
        self.detail_text.insert("", END, text=f"Summary: {event.summary}")

        self.detail_text.insert("", END, text="Evidence:")
        for mod in event.suspected_mods:
            reasons = event.evidence.get(mod, [])
            if not reasons:
                continue
            self.detail_text.insert("", END, text=f"  {mod}")
            for reason in reasons:
                self.detail_text.insert("", END, text=f"    - {reason}")

    def _on_issue_select(self, _event=None) -> None:
        selected = self.issue_tree.selection()
        if not selected:
            return

        item = selected[0]
        event = self.issue_by_item.get(item)
        if not event:
            return

        self._clear_issue_detail_panel()
        occurrences = self.issue_signature_count.get(event.signature, 1)
        self.issue_detail_text.insert("", END, text="Source: Live Logs")
        self.issue_detail_text.insert("", END, text=f"Log File: {event.file_path}")
        self.issue_detail_text.insert("", END, text=f"Level: {event.level}")
        self.issue_detail_text.insert("", END, text=f"Type: {event.log_type}")
        self.issue_detail_text.insert("", END, text=f"What it means: {event.log_meaning}")
        self.issue_detail_text.insert("", END, text=f"Mod Hint: {event.mod_hint}")
        self.issue_detail_text.insert("", END, text=f"Occurrences: {occurrences}")
        self.issue_detail_text.insert("", END, text=f"Signature: {event.signature}")
        self.issue_detail_text.insert("", END, text=f"Message: {event.message}")
        self.issue_detail_text.insert(
            "",
            END,
            text="Reason: Added because this line contains ERROR/FATAL and was categorized to help triage and teach likely impact.",
        )

    def _sort_issue_tree(self, column: str) -> None:
        if not hasattr(self, "issue_tree"):
            return

        if self.issue_sort_column == column:
            self.issue_sort_desc = not self.issue_sort_desc
        else:
            self.issue_sort_column = column
            self.issue_sort_desc = column in {"time", "count", "level"}

        self._resort_issue_tree_if_needed()

    def _resort_issue_tree_if_needed(self) -> None:
        if not hasattr(self, "issue_tree"):
            return

        children = list(self.issue_tree.get_children(""))
        if not children:
            return

        level_weight = {"FATAL": 2, "ERROR": 1}

        def key_for(item_id: str):
            event = self.issue_by_item.get(item_id)
            if event is None:
                return ""

            column = self.issue_sort_column
            if column == "time":
                return event.created_at
            if column == "file":
                return event.file_path.name.lower()
            if column == "level":
                return level_weight.get(event.level.upper(), 0)
            if column == "type":
                return event.log_type.lower()
            if column == "mod":
                return event.mod_hint.lower()
            if column == "message":
                return event.message.lower()
            if column == "count":
                return self.issue_signature_count.get(event.signature, 1)
            return ""

        ordered = sorted(children, key=key_for, reverse=self.issue_sort_desc)
        for idx, item_id in enumerate(ordered):
            self.issue_tree.move(item_id, "", idx)

    def _on_conflict_select(self, _event=None) -> None:
        selected = self.conflict_tree.selection()
        if not selected:
            return

        item = selected[0]
        pair = self.conflict_by_item.get(item)
        if not pair:
            return

        hits = self.conflict_pairs.get(pair, 0)
        reason = self._build_conflict_reason(pair, hits)

        self._clear_detail_panel()
        self.detail_text.insert("", END, text="Source: Likely Mod Conflict Pairs")
        self.detail_text.insert("", END, text=f"Conflict Pair: {pair[0]} <-> {pair[1]}")
        self.detail_text.insert("", END, text=f"Occurrences: {hits}")
        self.detail_text.insert("", END, text=f"Reason: {reason}")

    def _clear_detail_panel(self) -> None:
        for node in self.detail_text.get_children():
            self.detail_text.delete(node)

    def _clear_issue_detail_panel(self) -> None:
        if not hasattr(self, "issue_detail_text"):
            return
        for node in self.issue_detail_text.get_children():
            self.issue_detail_text.delete(node)

    def _update_conflict_pairs(self, event: CrashEvent) -> None:
        mods = [m for m in event.suspected_mods if m != "No clear mod detected"]
        if len(mods) < 2:
            return

        top_mods = mods[:4]
        for i in range(len(top_mods)):
            for j in range(i + 1, len(top_mods)):
                pair = tuple(sorted((top_mods[i], top_mods[j])))
                self.conflict_pairs[pair] += 1

    def _refresh_conflict_tree(self) -> None:
        for item in self.conflict_tree.get_children():
            self.conflict_tree.delete(item)
        self.conflict_by_item.clear()

        for pair, hits in self.conflict_pairs.most_common(8):
            item_id = self.conflict_tree.insert("", END, values=(f"{pair[0]} <-> {pair[1]}", hits))
            self.conflict_by_item[item_id] = pair

    def _build_conflict_reason(self, pair: tuple[str, str], hits: int) -> str:
        mod_a, mod_b = pair
        shared_events = [
            event
            for event in self.event_history
            if mod_a in event.suspected_mods and mod_b in event.suspected_mods
        ]
        if not shared_events:
            return "This pair repeatedly appears together in the top suspected mods for recent crashes."

        loader_counts = Counter(event.loader_profile for event in shared_events)
        severity_counts = Counter(event.severity for event in shared_events)
        common_loader = loader_counts.most_common(1)[0][0] if loader_counts else "Unknown"
        common_severity = severity_counts.most_common(1)[0][0] if severity_counts else "Unknown"

        reason_count = Counter()
        for event in shared_events:
            for reason in event.evidence.get(mod_a, []):
                reason_count[reason] += 1
            for reason in event.evidence.get(mod_b, []):
                reason_count[reason] += 1

        top_reason = reason_count.most_common(1)[0][0] if reason_count else "Both mods are repeatedly co-flagged in crash analysis"
        return (
            f"Seen together in {hits} conflict occurrence(s); common loader={common_loader}, "
            f"typical severity={common_severity}; strongest shared signal: {top_reason}."
        )

    def _run_startup_health_check(self, path: Path) -> None:
        warnings: list[str] = []
        notes: list[str] = []

        mods_dir = path / "mods"
        crash_dir = path / "crash-reports"
        dot_crash_dir = path / ".minecraft" / "crash-reports"

        if not mods_dir.exists():
            warnings.append("No mods folder was found at this root")
        else:
            jar_count = len(list(mods_dir.glob("*.jar")))
            notes.append(f"Detected {jar_count} mod jar(s)")
            if jar_count == 0:
                warnings.append("mods folder exists but has no .jar files")

        if not crash_dir.exists() and not dot_crash_dir.exists():
            warnings.append("No crash-reports folder found yet (it will still monitor root for hs_err_pid logs)")
        else:
            notes.append("Crash report folder detected")

        loader_note = self._infer_loader_from_files(path)
        if loader_note:
            notes.append(f"Likely loader profile: {loader_note}")

        if warnings:
            messagebox.showwarning(
                "Startup Health Check",
                "Warnings:\n- " + "\n- ".join(warnings) + "\n\nNotes:\n- " + "\n- ".join(notes or ["None"]),
            )
        elif notes:
            self.status_var.set("Health check OK: " + "; ".join(notes[:2]))

    @staticmethod
    def _infer_loader_from_files(path: Path) -> str:
        if (path / "neoforge-server-launcher.jar").exists():
            return "NeoForge"
        if (path / "fabric-loader-server-launch.jar").exists() or (path / "fabric-server-launch.jar").exists():
            return "Fabric"
        if (path / "quilt-server-launch.jar").exists():
            return "Quilt"

        config_dir = path / "config"
        if config_dir.exists() and (config_dir / "fml.toml").exists():
            return "Forge"
        return "Unknown"

    def _play_alert_sound(self, severity: str) -> None:
        if not self.sound_enabled.get():
            return
        if winsound is not None:
            sound_type = winsound.MB_ICONEXCLAMATION
            if severity == "Critical":
                sound_type = winsound.MB_ICONHAND
            elif severity == "Major":
                sound_type = winsound.MB_ICONEXCLAMATION
            else:
                sound_type = winsound.MB_OK
            winsound.MessageBeep(sound_type)
        else:
            try:
                self.root.bell()
            except Exception:
                pass

    def _maybe_minimize_to_tray(self, _event=None) -> None:
        if not self.tray_enabled.get():
            return
        if self._tray_running:
            return
        if self.root.state() != "iconic":
            return

        if pystray is None or Image is None or ImageDraw is None:
            self.status_var.set("Tray integration requested, but pystray/Pillow is not installed.")
            return

        self.root.withdraw()
        self._start_tray_icon()

    def _start_tray_icon(self) -> None:
        if self._tray_running:
            return

        icon_image = self._build_tray_image()
        menu = pystray.Menu(
            pystray.MenuItem("Open CrashReader", self._tray_restore),
            pystray.MenuItem("Exit", self._tray_exit),
        )
        self.tray_icon = pystray.Icon("CrashReader", icon_image, "CrashReader", menu)
        self._tray_running = True

        thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        thread.start()

    @staticmethod
    def _build_tray_image():
        image = Image.new("RGB", (64, 64), color=(36, 36, 36))
        draw = ImageDraw.Draw(image)
        draw.rectangle((8, 8, 56, 56), outline=(243, 106, 59), width=4)
        draw.line((16, 40, 30, 48, 48, 20), fill=(243, 106, 59), width=4)
        return image

    def _tray_restore(self, _icon=None, _item=None) -> None:
        self.root.after(0, self._restore_from_tray)

    def _restore_from_tray(self) -> None:
        self.root.deiconify()
        self.root.state("normal")
        self.root.lift()
        self.root.focus_force()
        self._stop_tray_icon()

    def _tray_exit(self, _icon=None, _item=None) -> None:
        self.root.after(0, self.root.destroy)

    def _stop_tray_icon(self) -> None:
        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
        self.tray_icon = None
        self._tray_running = False

    def toggle_fullscreen(self) -> None:
        self.fullscreen = not self.fullscreen
        self.root.attributes("-fullscreen", self.fullscreen)
        self._save_state()

    def exit_fullscreen(self) -> None:
        self.fullscreen = False
        self.root.attributes("-fullscreen", False)
        self._save_state()

    def shutdown(self) -> None:
        self._save_state()
        self._stop_tray_icon()
        self._stop_watching()

    def _default_save_folder(self) -> Path:
        if _is_frozen_build():
            return _default_user_save_folder()
        return _project_root() / "save"

    def _active_save_folder(self) -> Path:
        configured = self.save_path.get().strip()
        if configured:
            return Path(configured)
        return self._default_save_folder()

    def _state_file_path(self) -> Path:
        return self._active_save_folder() / STATE_FILE_NAME

    def _history_file_path(self) -> Path:
        return self._active_save_folder() / HISTORY_FILE_NAME

    def _ensure_save_folder(self) -> Path:
        folder = self._active_save_folder()
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def _save_state(self) -> None:
        try:
            self._ensure_save_folder()
            default_folder = self._default_save_folder()
            default_folder.mkdir(parents=True, exist_ok=True)

            state_payload = {
                "modpack_folder": self.current_path.get() if self.current_path.get() != "No folder selected" else "",
                "save_folder": self.save_path.get(),
                "sound_enabled": bool(self.sound_enabled.get()),
                "tray_enabled": bool(self.tray_enabled.get()),
                "popup_enabled": bool(self.popup_enabled.get()),
                "popup_on_repeat": bool(self.popup_on_repeat.get()),
                "popup_cooldown_seconds": self._popup_cooldown_seconds(),
                "fullscreen": bool(self.fullscreen),
            }

            with self._state_file_path().open("w", encoding="utf-8") as f:
                json.dump(state_payload, f, indent=2)

            # Keep a bootstrap copy in default save so custom save paths can be rediscovered on next launch.
            with (default_folder / STATE_FILE_NAME).open("w", encoding="utf-8") as f:
                json.dump(state_payload, f, indent=2)

            history_payload = [event.to_dict() for event in self.event_history[-MAX_PERSISTED_HISTORY:]]
            with self._history_file_path().open("w", encoding="utf-8") as f:
                json.dump(history_payload, f, indent=2)
        except Exception:
            pass

    def _load_state(self) -> None:
        default_folder = self._default_save_folder()
        default_folder.mkdir(parents=True, exist_ok=True)

        state_file = default_folder / STATE_FILE_NAME
        if state_file.exists():
            try:
                payload = json.loads(state_file.read_text(encoding="utf-8"))
                configured_save = str(payload.get("save_folder", "")).strip()
                if configured_save:
                    self.save_path.set(configured_save)
                self.sound_enabled.set(bool(payload.get("sound_enabled", True)))
                self.tray_enabled.set(bool(payload.get("tray_enabled", False)))
                self.popup_enabled.set(bool(payload.get("popup_enabled", True)))
                self.popup_on_repeat.set(bool(payload.get("popup_on_repeat", True)))
                cooldown_raw = payload.get("popup_cooldown_seconds", 0)
                try:
                    cooldown_value = int(cooldown_raw)
                except Exception:
                    cooldown_value = 0
                self.popup_cooldown_seconds.set(max(0, cooldown_value))
                self.fullscreen = bool(payload.get("fullscreen", False))
                self.root.attributes("-fullscreen", self.fullscreen)

                restored_modpack = str(payload.get("modpack_folder", "")).strip()
                if restored_modpack and Path(restored_modpack).exists():
                    self.current_path.set(restored_modpack)
            except Exception:
                pass

        history_file = self._history_file_path()
        if history_file.exists():
            try:
                history = json.loads(history_file.read_text(encoding="utf-8"))
                if isinstance(history, list):
                    for item in history[-MAX_PERSISTED_HISTORY:]:
                        if not isinstance(item, dict):
                            continue
                        event = CrashEvent.from_dict(item)
                        self._record_event(event, notify=False, persist=False)
                    self.status_var.set(f"Restored {len(self.event_history)} crash event(s) from save folder")
            except Exception:
                pass

        restored_path = self.current_path.get().strip()
        if restored_path and restored_path != "No folder selected":
            path = Path(restored_path)
            if path.exists():
                self.status_var.set("Resumed previous modpack folder monitoring")
                self._start_watching(path, clear_existing=False)
                self._refresh_mods_list(path)
                self._refresh_config_files(path)
                self._run_verify_files_check(path)


def main() -> None:
    if "--gui-only" in sys.argv[1:]:
        _run_gui()
        return

    if "--auto-bootstrap" in sys.argv[1:]:
        _auto_bootstrap_and_launch()
        return

    if not _startup_requirements_gate():
        return

    _run_gui()


def _run_gui() -> None:
    root = Tk()
    app = CrashReaderApp(root)

    def on_close() -> None:
        app.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


def _auto_bootstrap_and_launch() -> None:
    if _is_frozen_build():
        _run_gui()
        return

    _show_sleepcast_banner()
    _clear_terminal()

    missing = _missing_requirements()
    if missing:
        print("Missing requirements detected:")
        for req in missing:
            print(f"- {req}")
        answer = _prompt_install()
        if answer != "y":
            print("Install declined. Exiting launcher.")
            raise SystemExit(130)

        print("Installing requirements now...")
        success = _install_requirements_file()
        if not success:
            print("Requirement install failed. App will not start.")
            raise SystemExit(1)
        print("Requirements installed. Launching app...")
    else:
        print("Requirements already installed. Launching in 5 seconds...")
        time.sleep(5)

    if not _launch_gui_detached():
        print("Detached launch failed. Starting in this terminal instead.")
        _run_gui()


def _launch_gui_detached() -> bool:
    if _is_frozen_build():
        try:
            subprocess.Popen([str(Path(sys.executable).resolve()), "--gui-only"], close_fds=True)
            return True
        except Exception:
            return False

    script_path = Path(__file__).resolve()
    project_root = script_path.parent

    py_exec = Path(sys.executable)
    pyw_exec = py_exec
    if os.name == "nt":
        candidate = py_exec.with_name("pythonw.exe")
        if candidate.exists():
            pyw_exec = candidate

    cmd = [str(pyw_exec), str(script_path), "--gui-only"]

    kwargs = {
        "cwd": str(project_root),
        "close_fds": True,
    }

    if os.name == "nt":
        detached_process = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        create_new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        kwargs["creationflags"] = detached_process | create_new_group

    try:
        subprocess.Popen(cmd, **kwargs)
        return True
    except Exception:
        return False


def _startup_requirements_gate() -> bool:
    if _is_frozen_build():
        return True

    _show_sleepcast_banner()
    _clear_terminal()

    missing = _missing_requirements()
    if not missing:
        return True

    print("Missing requirements detected:")
    for req in missing:
        print(f"- {req}")

    answer = _prompt_install()
    if answer == "n":
        print("Installation declined. Stopping process (Ctrl+C behavior).")
        raise KeyboardInterrupt

    print("Installing requirements now...")
    success = _install_requirements_file()
    if not success:
        print("Requirement install failed. App will not start.")
        return False

    print("Requirements installed. Starting app...")
    return True


def _show_sleepcast_banner() -> None:
    _enable_ansi_colors()
    rows = [line.rstrip("\n") for line in SLEEPCAST_ART.strip("\n").splitlines()]
    for row in rows:
        _print_row_slowly(row, char_delay=0.002, color=ANSI_PURPLE)
        print()
        time.sleep(0.04)

    print()
    widest = max((len(r) for r in rows), default=0)
    for footer in SLEEPCAST_FOOTER:
        _print_row_slowly(footer.center(widest), char_delay=0.004, color=ANSI_LIGHT_PURPLE)
        print()

    time.sleep(10.0)


def _print_row_slowly(text: str, char_delay: float = 0.003, color: str | None = None) -> None:
    if color:
        print(color, end="", flush=True)
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(char_delay)
    if color:
        print(ANSI_RESET, end="", flush=True)


def _enable_ansi_colors() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _clear_terminal() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _missing_requirements() -> list[str]:
    missing: list[str] = []
    module_map = {
        "pystray": "pystray",
        "Pillow": "PIL",
    }
    for package_name, module_name in module_map.items():
        if importlib.util.find_spec(module_name) is None:
            missing.append(package_name)
    return missing


def _prompt_install() -> str:
    while True:
        response = input("Install missing requirements now? (Y/N): ").strip().lower()
        if response in {"y", "n"}:
            return response
        print("Please enter Y or N.")


def _install_requirements_file() -> bool:
    if _is_frozen_build():
        print("Bundled executable mode detected; dependency install is not required.")
        return True

    project_root = _project_root()
    req_file = project_root / "requirements.txt"
    if not req_file.exists():
        print("requirements.txt not found.")
        return False

    cmd = [sys.executable, "-m", "pip", "install", "-r", str(req_file)]
    result = subprocess.run(cmd, cwd=str(project_root), check=False)
    return result.returncode == 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("^C")
        raise SystemExit(130)
