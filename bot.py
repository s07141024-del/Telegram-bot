from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import hmac
import html
import inspect
import io
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

import httpx
import xlrd
from openpyxl import Workbook, load_workbook
from openpyxl.utils import get_column_letter
from telegram import (
    Bot,
    BotCommand,
    ChatMember,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    Update,
)
from telegram.constants import ChatAction, ParseMode
from telegram.error import (
    BadRequest,
    Forbidden,
    NetworkError,
    RetryAfter,
    TelegramError,
    TimedOut,
)
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ==============================================================================
# CORE CONSTANTS & SYSTEM METADATA (NO HARDCODED BOT NAME)
# ==============================================================================

BOT_ENGINE_VERSION = "5.0.0"
DB_SCHEMA_VERSION = 5
DEFAULT_BOT_TOKEN_PLACEHOLDER = "YOUR_BOT_TOKEN_HERE"
FALLBACK_BOT_TOKEN = "9062022809:AAGA-QelWNRrvRyK4gunxTWfxR6cFAXFTqU"

DEFAULT_MAIN_ADMIN_ID = 8882139752
DEFAULT_SUPPORT_USERNAME = "@alman_Op"
DEFAULT_FORCE_JOIN_CHANNEL = "@filesubmit999"
DEFAULT_TASK_FS_REVIEW_CHANNEL = -1004422832745
DEFAULT_FINANCE_REVIEW_CHANNEL = -1004418032153
DEFAULT_PAYOUT_ORDER_CHANNEL = -1004376755344
DEFAULT_LEADERBOARD_CHANNEL = -1003707368957
DEFAULT_AUTO_BACKUP_CHANNEL = -1004498787785

MAX_TELEGRAM_MESSAGE_LEN = 4096
MAX_TELEGRAM_CAPTION_LEN = 1024
MAX_CALLBACK_DATA_BYTES = 64

OFFICIAL_BUTTON_STYLES: Tuple[str, ...] = ("default", "primary", "success", "danger")
STYLE_EMOJI_MAP: Dict[str, str] = {
    "default": "⚪",
    "primary": "🔵",
    "success": "🟢",
    "danger": "🔴",
}

FORBIDDEN_EXECUTABLE_EXTENSIONS: Set[str] = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js", ".jar", ".msi",
    ".apk", ".bin", ".dll", ".so", ".php", ".py", ".rb", ".pl", ".cgi",
}

BASE_DIR = Path(__file__).resolve().parent
DATA_DIRS: Dict[str, Path] = {
    "database": BASE_DIR / "database",
    "exports": BASE_DIR / "exports",
    "source_files": BASE_DIR / "source_files",
    "product_stock": BASE_DIR / "product_stock",
    "user_files": BASE_DIR / "user_files",
    "otp_numbers": BASE_DIR / "otp_numbers",
    "backups": BASE_DIR / "backups",
    "logs": BASE_DIR / "logs",
    "temp": BASE_DIR / "database" / "tmp",
}
DB_PATH = DATA_DIRS["database"] / "bot_platform.db"
ERROR_LOG_PATH = DATA_DIRS["logs"] / "errors.log"
APP_LOG_PATH = DATA_DIRS["logs"] / "bot.log"


def ensure_directories() -> None:
    for path in DATA_DIRS.values():
        path.mkdir(parents=True, exist_ok=True)


def get_dhaka_tz() -> timezone:
    if ZoneInfo is not None:
        try:
            return ZoneInfo("Asia/Dhaka")  # type: ignore[return-value]
        except Exception:
            pass
    return timezone(timedelta(hours=6))


DHAKA_TZ = get_dhaka_tz()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_dhaka() -> datetime:
    return datetime.now(DHAKA_TZ)


def now_utc_iso() -> str:
    return now_utc().strftime("%Y-%m-%d %H:%M:%S")


def now_dhaka_iso() -> str:
    return now_dhaka().strftime("%Y-%m-%d %H:%M:%S")


def dhaka_today_str() -> str:
    return now_dhaka().strftime("%Y-%m-%d")


def parse_iso_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(raw[:19], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def format_dhaka_dt(value: Optional[str]) -> str:
    dt = parse_iso_dt(value)
    if dt is None:
        return str(value or "-")
    return dt.astimezone(DHAKA_TZ).strftime("%Y-%m-%d %I:%M:%S %p")


# ==============================================================================
# SECRET MASKING FILTER & LOGGING SETUP (RULE 42, 43, 56)
# ==============================================================================

class SecretMaskingFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._secrets: Set[str] = set()

    def register_secret(self, secret: Optional[str]) -> None:
        if not secret:
            return
        cleaned = str(secret).strip()
        if len(cleaned) >= 8 and cleaned != DEFAULT_BOT_TOKEN_PLACEHOLDER:
            with self._lock:
                self._secrets.add(cleaned)

    def mask_text(self, text: str) -> str:
        if not text:
            return text
        masked = text
        with self._lock:
            secrets_snapshot = sorted(self._secrets, key=len, reverse=True)
        for sec in secrets_snapshot:
            if sec in masked:
                masked = masked.replace(sec, "***MASKED_SECRET***")
        masked = re.sub(r"\b\d{6,14}:[A-Za-z0-9_-]{20,}\b", "***MASKED_TOKEN***", masked)
        return masked

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = self.mask_text(record.msg)
            if record.args:
                if isinstance(record.args, tuple):
                    record.args = tuple(
                        self.mask_text(a) if isinstance(a, str) else a
                        for a in record.args
                    )
                elif isinstance(record.args, dict):
                    record.args = {
                        k: (self.mask_text(v) if isinstance(v, str) else v)
                        for k, v in record.args.items()
                    }
            if record.exc_text:
                record.exc_text = self.mask_text(record.exc_text)
        except Exception:
            pass
        return True


SECRET_FILTER = SecretMaskingFilter()


def setup_logging() -> logging.Logger:
    ensure_directories()
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    for existing in list(root_logger.handlers):
        root_logger.removeHandler(existing)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(fmt)
    stream_handler.addFilter(SECRET_FILTER)

    app_file_handler = logging.FileHandler(APP_LOG_PATH, encoding="utf-8")
    app_file_handler.setLevel(logging.INFO)
    app_file_handler.setFormatter(fmt)
    app_file_handler.addFilter(SECRET_FILTER)

    err_file_handler = logging.FileHandler(ERROR_LOG_PATH, encoding="utf-8")
    err_file_handler.setLevel(logging.ERROR)
    err_file_handler.setFormatter(fmt)
    err_file_handler.addFilter(SECRET_FILTER)

    root_logger.addHandler(stream_handler)
    root_logger.addHandler(app_file_handler)
    root_logger.addHandler(err_file_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.INFO)
    return logging.getLogger("bot_platform")


_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_first_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        res = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
        if res:
            return res
    except socket.gaierror:
        pass
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_first_getaddrinfo

LOGGER = setup_logging()


def load_bot_token() -> str:
    env_token = os.environ.get("BOT_TOKEN", "").strip()
    token = env_token if env_token else FALLBACK_BOT_TOKEN.strip()
    if not token or token == DEFAULT_BOT_TOKEN_PLACEHOLDER:
        raise RuntimeError(
            "BOT_TOKEN পাওয়া যায়নি বা Placeholder অপরিবর্তিত রয়েছে। "
            "Environment Variable BOT_TOKEN সেট করুন অথবা কোডে আসল BotFather টোকেন দিন।"
        )
    if ":" not in token or len(token) < 20:
        raise RuntimeError(
            "অবৈধ BOT_TOKEN ফরম্যাট! টোকেনে অবশ্যই ':' থাকতে হবে এবং দৈর্ঘ্য ২০+ অক্ষরের হতে হবে।"
        )
    SECRET_FILTER.register_secret(token)
    return token


# ==============================================================================
# SANITIZERS, FORMATTERS & SECURITY HELPERS
# ==============================================================================

def escape_html(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def truncate_text(text: str, max_len: int = MAX_TELEGRAM_MESSAGE_LEN) -> str:
    s = str(text or "")
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 3)] + "..."


def apply_message_size_style(
    text_html: str,
    size_mode: str,
    divider: str = "━━━━━━━━━━━━━━━━━━━━",
    preserve_full_lines: bool = False,
) -> str:
    mode = str(size_mode or "current").strip().lower()
    if mode in ("current", "large", "big", ""):
        return text_html

    out = str(text_html or "")
    esc_div = escape_html(divider)
    for d in {divider, esc_div}:
        if d:
            out = out.replace(f"\n{d}\n", "\n").replace(f"{d}\n", "").replace(d, "")

    out = out.replace("<blockquote>", "").replace("</blockquote>", "")

    if mode == "medium":
        lines = [ln for ln in out.splitlines() if ln.strip()]
        return "\n".join(lines)

    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not preserve_full_lines:
        compact: List[str] = []
        for ln in lines:
            if re.fullmatch(r"(?:[^\w<]{0,6}\s*)?<i>[^<]*</i>", ln):
                continue
            compact.append(ln)
        if compact:
            lines = compact
    return "\n".join(lines)


def sanitize_excel_cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    stripped_leading = text.lstrip(" ")
    if stripped_leading.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def sanitize_filename(name: str, fallback: str = "file") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "").strip())
    cleaned = cleaned.strip("._")
    return cleaned or fallback


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_uid(prefix: str, length: int = 8) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    token = "".join(secrets.choice(alphabet) for _ in range(length))
    stamp = now_dhaka().strftime("%y%m%d")
    return f"{prefix}-{stamp}-{token}"


def generate_internal_test_code(length: int = 16) -> str:
    target_len = 32 if length >= 32 else 16
    base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    raw = "".join(secrets.choice(base32_chars) for _ in range(target_len))
    groups = [raw[i : i + 4] for i in range(0, len(raw), 4)]
    return "-".join(groups)


def normalize_bd_phone(raw_phone: str) -> Tuple[bool, str, str]:
    cleaned = re.sub(r"[\s\-()]+", "", str(raw_phone or "").strip())
    if cleaned.startswith("+88"):
        cleaned = cleaned[3:]
    elif cleaned.startswith("88") and len(cleaned) == 13:
        cleaned = cleaned[2:]
    if not re.fullmatch(r"01[3-9]\d{8}", cleaned):
        return False, cleaned, "Invalid BD mobile number (must be 11 digits starting with 013-019)."
    body = cleaned[2:]
    if len(set(body)) <= 2 or body in {"000000000", "111111111", "123456789", "987654321"}:
        return False, cleaned, "Dummy/repeated mobile number pattern is not allowed."
    return True, cleaned, ""


def mask_phone_or_account(value: str) -> str:
    raw = str(value or "").strip()
    if len(raw) <= 4:
        return "****"
    if len(raw) <= 8:
        return raw[:2] + "*" * (len(raw) - 4) + raw[-2:]
    return raw[:4] + "*" * max(3, len(raw) - 7) + raw[-3:]


def mask_display_name(full_name: Optional[str], user_id: int) -> str:
    name = str(full_name or "").strip()
    if not name:
        return f"User#{str(user_id)[-4:]}"
    if len(name) <= 2:
        return name[0] + "*"
    if len(name) <= 5:
        return name[:2] + "*" * (len(name) - 2)
    return name[:3] + "***" + name[-1:]


def format_money(amount: Union[int, float], currency: str = "৳") -> str:
    val = round(float(amount or 0.0), 4)
    if abs(val - round(val)) < 1e-6:
        return f"{currency}{int(round(val))}"
    formatted = f"{val:.2f}".rstrip("0").rstrip(".")
    return f"{currency}{formatted}"


def parse_positive_float(raw: str) -> Optional[float]:
    try:
        cleaned = str(raw or "").strip().replace(",", "")
        val = float(cleaned)
        if not (val >= 0.0) or val != val or val == float("inf"):
            return None
        return round(val, 4)
    except Exception:
        return None


def parse_positive_int(raw: str) -> Optional[int]:
    try:
        val = int(str(raw or "").strip())
        if val < 0:
            return None
        return val
    except Exception:
        return None


def format_duration_seconds(seconds: int, lang: str = "bn") -> str:
    secs = max(0, int(seconds))
    if secs < 60:
        return f"{secs} সেকেন্ড" if lang == "bn" else f"{secs}s"
    mins, rem_s = divmod(secs, 60)
    if mins < 60:
        if rem_s == 0:
            return f"{mins} মিনিট" if lang == "bn" else f"{mins}m"
        return f"{mins} মিঃ {rem_s} সেঃ" if lang == "bn" else f"{mins}m {rem_s}s"
    hours, rem_m = divmod(mins, 60)
    if rem_m == 0:
        return f"{hours} ঘণ্টা" if lang == "bn" else f"{hours}h"
    return f"{hours} ঘঃ {rem_m} মিঃ" if lang == "bn" else f"{hours}h {rem_m}m"


def parse_duration_input(raw: str) -> Optional[int]:
    """Parse inputs like '30s', '2m', '1h', or integer seconds/minutes."""
    text = str(raw or "").strip().lower()
    if not text:
        return None
    m = re.fullmatch(r"(\d+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)?", text)
    if not m:
        return None
    qty = int(m.group(1))
    unit = m.group(2) or "s"
    if unit.startswith("s"):
        return qty
    if unit.startswith("m"):
        return qty * 60
    if unit.startswith("h"):
        return qty * 3600
    return None


def check_callback_size(callback_data: str) -> str:
    encoded = callback_data.encode("utf-8")
    if len(encoded) > MAX_CALLBACK_DATA_BYTES:
        raise ValueError(f"Callback data exceeds 64 bytes: {callback_data}")
    return callback_data


def safe_json_loads(raw: Optional[str], default: Any = None) -> Any:
    if not raw:
        return {} if default is None else default
    try:
        return json.loads(raw)
    except Exception:
        return {} if default is None else default


def safe_json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False)


# ==============================================================================
# PTB BUTTON COLOR ADAPTER (RULE 88: PTB 22.5 + 22.7+ COMPATIBLE)
# ==============================================================================

class PTBButtonAdapter:
    """
    Supports official Telegram Bot API 9.4+ button styles:
    default, primary, success, danger.
    Automatically detects native 'style' parameter (PTB 22.7+) vs 'api_kwargs' (PTB 22.5).
    """

    def __init__(self) -> None:
        inline_params = inspect.signature(InlineKeyboardButton.__init__).parameters
        reply_params = inspect.signature(KeyboardButton.__init__).parameters
        self._inline_native_style = "style" in inline_params
        self._reply_native_style = "style" in reply_params

    @staticmethod
    def validate_style(style: Optional[str]) -> str:
        cleaned = str(style or "default").strip().lower()
        return cleaned if cleaned in OFFICIAL_BUTTON_STYLES else "default"

    def make_inline_button(
        self,
        text: str,
        callback_data: Optional[str] = None,
        url: Optional[str] = None,
        style: Optional[str] = "default",
        colors_enabled: bool = True,
    ) -> InlineKeyboardButton:
        kwargs: Dict[str, Any] = {"text": str(text)}
        if callback_data is not None:
            kwargs["callback_data"] = check_callback_size(callback_data)
        elif url is not None:
            kwargs["url"] = url
        resolved_style = self.validate_style(style)
        if colors_enabled and resolved_style != "default":
            if self._inline_native_style:
                kwargs["style"] = resolved_style
            else:
                kwargs["api_kwargs"] = {"style": resolved_style}
        return InlineKeyboardButton(**kwargs)

    def make_reply_button(
        self,
        text: str,
        style: Optional[str] = "default",
        colors_enabled: bool = True,
    ) -> KeyboardButton:
        kwargs: Dict[str, Any] = {"text": str(text)}
        resolved_style = self.validate_style(style)
        if colors_enabled and resolved_style != "default":
            if self._reply_native_style:
                kwargs["style"] = resolved_style
            else:
                kwargs["api_kwargs"] = {"style": resolved_style}
        return KeyboardButton(**kwargs)


BUTTON_ADAPTER = PTBButtonAdapter()


# ==============================================================================
# CHANNEL MESSAGE & MEDIA SYNC ADAPTER (RULE 95.A)
# ==============================================================================

async def safe_edit_channel_message(
    bot: Bot,
    chat_id: Union[int, str],
    message_id: int,
    new_text: str,
    reply_markup: Optional[InlineKeyboardMarkup] = None,
    is_media: Optional[bool] = None,
    parse_mode: str = ParseMode.HTML,
) -> Tuple[bool, str]:
    """
    Updates both text-only and media-caption Telegram channel messages cleanly,
    locking or replacing old inline buttons without failing silently.
    """
    try:
        if is_media is True:
            await bot.edit_message_caption(
                chat_id=chat_id,
                message_id=message_id,
                caption=truncate_text(new_text, MAX_TELEGRAM_CAPTION_LEN),
                parse_mode=parse_mode,
                reply_markup=reply_markup,
            )
            return True, ""
        if is_media is False:
            await bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=truncate_text(new_text, MAX_TELEGRAM_MESSAGE_LEN),
                parse_mode=parse_mode,
                reply_markup=reply_markup,
            )
            return True, ""

        try:
            await bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=truncate_text(new_text, MAX_TELEGRAM_MESSAGE_LEN),
                parse_mode=parse_mode,
                reply_markup=reply_markup,
            )
            return True, ""
        except BadRequest as exc:
            err_l = str(exc).lower()
            if "no text in the message" in err_l or "message has no text" in err_l:
                await bot.edit_message_caption(
                    chat_id=chat_id,
                    message_id=message_id,
                    caption=truncate_text(new_text, MAX_TELEGRAM_CAPTION_LEN),
                    parse_mode=parse_mode,
                    reply_markup=reply_markup,
                )
                return True, ""
            if "message is not modified" in err_l:
                return True, ""
            return False, str(exc)
    except BadRequest as exc:
        if "message is not modified" in str(exc).lower():
            return True, ""
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


async def safe_send_message_to_chat(
    bot: Bot,
    chat_id: Union[int, str],
    text: str,
    reply_markup: Optional[Union[InlineKeyboardMarkup, ReplyKeyboardMarkup, ReplyKeyboardRemove]] = None,
    parse_mode: str = ParseMode.HTML,
    disable_notification: bool = False,
) -> Tuple[Optional[Message], str]:
    try:
        msg = await bot.send_message(
            chat_id=chat_id,
            text=truncate_text(text, MAX_TELEGRAM_MESSAGE_LEN),
            parse_mode=parse_mode,
            reply_markup=reply_markup,
            disable_web_page_preview=True,
            disable_notification=disable_notification,
        )
        return msg, ""
    except RetryAfter as exc:
        await asyncio.sleep(min(float(exc.retry_after) + 0.5, 15.0))
        try:
            msg = await bot.send_message(
                chat_id=chat_id,
                text=truncate_text(text, MAX_TELEGRAM_MESSAGE_LEN),
                parse_mode=parse_mode,
                reply_markup=reply_markup,
                disable_web_page_preview=True,
                disable_notification=disable_notification,
            )
            return msg, ""
        except Exception as inner_exc:
            return None, str(inner_exc)
    except Exception as exc:
        return None, str(exc)


# ==============================================================================
# DYNAMIC BOT NAME & TOTP RFC-6238 / COOKIE HELPERS (NO HARDCODED BOT NAME)
# ==============================================================================

class BotIdentityHolder:
    """Caches Telegram bot identity from get_me() without hardcoding any bot name."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.bot_id: Optional[int] = None
        self.username: str = ""
        self.first_name: str = ""

    def set_identity(self, bot_id: Optional[int], username: Optional[str], first_name: Optional[str]) -> None:
        with self._lock:
            self.bot_id = bot_id
            self.username = str(username or "").strip().lstrip("@")
            self.first_name = str(first_name or "").strip()

    def get_live_name(self, lang: str = "bn") -> str:
        with self._lock:
            if self.first_name:
                return self.first_name
            if self.username:
                return f"@{self.username}"
        return "বট" if lang == "bn" else "Bot"

    def get_username(self) -> str:
        with self._lock:
            return self.username


BOT_IDENTITY = BotIdentityHolder()


def resolve_bot_name(settings_getter: Optional[Callable[[str, str], str]] = None, lang: str = "bn") -> str:
    if settings_getter is not None:
        key = "bot_name_bn" if lang == "bn" else "bot_name_en"
        configured = str(settings_getter(key, "AUTO") or "AUTO").strip()
        if configured and configured.upper() != "AUTO":
            return configured
        other_key = "bot_name_en" if lang == "bn" else "bot_name_bn"
        other_val = str(settings_getter(other_key, "AUTO") or "AUTO").strip()
        if other_val and other_val.upper() != "AUTO":
            return other_val
    return BOT_IDENTITY.get_live_name(lang=lang)


def compute_rfc6238_totp(secret_raw: str, at_time: Optional[int] = None) -> Tuple[bool, str, int, str, str]:
    """
    Validates a 16 or 32-char Base32 key and generates a 6-digit RFC-6238 UTC TOTP code.
    Returns: (is_valid, code_6digit, remaining_seconds, normalized_secret, error_message)
    """
    normalized = re.sub(r"[\s\-]+", "", str(secret_raw or "").strip().upper())
    if len(normalized) not in (16, 32):
        return (
            False,
            "",
            0,
            normalized,
            "Invalid key length: must be exactly 16 or 32 Base32 characters.",
        )
    if not re.fullmatch(r"[A-Z2-7]+", normalized):
        return (
            False,
            "",
            0,
            normalized,
            "Invalid Base32 characters: only A-Z and 2-7 are allowed.",
        )
    try:
        key_bytes = base64.b32decode(normalized, casefold=True)
    except Exception as exc:
        return False, "", 0, normalized, f"Base32 decode failed: {exc}"

    ts = int(time.time()) if at_time is None else int(at_time)
    step = 30
    counter = ts // step
    remaining = step - (ts % step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key_bytes, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    otp_int = binary % 1_000_000
    code = f"{otp_int:06d}"
    return True, code, remaining, normalized, ""


def parse_and_canonicalize_cookie(
    raw_cookie: str,
    required_keys_csv: str = "none",
) -> Tuple[bool, Dict[str, str], str, str, str]:
    text = str(raw_cookie or "").strip()
    text = re.sub(r"^cookie\s*:\s*", "", text, flags=re.IGNORECASE).strip()
    if len(text) < 8:
        return False, {}, "", "", "Cookie text is too short (minimum 8 characters required)."

    pairs: Dict[str, str] = {}

    if text.startswith("[") or text.startswith("{"):
        try:
            loaded = json.loads(text)
            if isinstance(loaded, dict) and isinstance(loaded.get("cookies"), list):
                loaded = loaded["cookies"]
            if isinstance(loaded, list):
                for item in loaded:
                    if isinstance(item, dict) and "name" in item and "value" in item:
                        k = str(item["name"]).strip()
                        v = str(item["value"]).strip()
                        if k:
                            pairs[k] = v
            elif isinstance(loaded, dict):
                if "name" in loaded and "value" in loaded:
                    k = str(loaded["name"]).strip()
                    v = str(loaded["value"]).strip()
                    if k:
                        pairs[k] = v
                else:
                    for k, v in loaded.items():
                        ks = str(k).strip()
                        if ks and not isinstance(v, (dict, list)):
                            pairs[ks] = str(v).strip()
        except Exception:
            pairs = {}

    if not pairs and "\t" in text:
        for line in text.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith("#"):
                continue
            parts = line_s.split("\t")
            if len(parts) >= 7:
                k = parts[5].strip()
                v = parts[6].strip()
                if k:
                    pairs[k] = v

    if not pairs:
        normalized_lines = text.replace("\r\n", "\n").replace("\n", ";")
        for chunk in normalized_lines.split(";"):
            part = chunk.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k and not re.search(r"\s", k):
                pairs[k] = v

    non_empty_count = sum(1 for v in pairs.values() if str(v).strip())
    if len(pairs) < 1 or non_empty_count < 1:
        return (
            False,
            {},
            "",
            "",
            "Invalid cookie format: provide valid key=value, JSON, or Netscape cookie.",
        )

    req_raw = str(required_keys_csv or "none").strip()
    if req_raw and req_raw.lower() not in {"none", "any", "*"}:
        groups = [g.strip() for g in req_raw.split("|") if g.strip()]
        matched_any_group = False
        first_missing: List[str] = []
        for grp in groups:
            req_keys = [rk.strip() for rk in grp.split(",") if rk.strip()]
            missing = [rk for rk in req_keys if rk not in pairs or not str(pairs[rk]).strip()]
            if not missing:
                matched_any_group = True
                break
            if not first_missing:
                first_missing = missing
        if not matched_any_group and first_missing:
            return (
                False,
                pairs,
                "",
                "",
                f"Missing required cookie key(s): {', '.join(first_missing)}",
            )

    canonical_items = sorted(pairs.items(), key=lambda kv: kv[0])
    canonical_str = "; ".join(f"{k}={v}" for k, v in canonical_items)
    cookie_hash = sha256_text(canonical_str)
    return True, pairs, canonical_str, cookie_hash, ""

# ==============================================================================
# DATABASE MANAGER: SQLITE WAL, SAFE ATOMIC SAVEPOINT & NON-DESTRUCTIVE MIGRATION
# ==============================================================================

class DatabaseManager:
    """
    Thread-safe SQLite manager with WAL mode, nested SAVEPOINT support inside atomic(),
    pre-upgrade automatic .db backups, and zero executescript() inside transactions.
    """

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.RLock()

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA temp_store=MEMORY")
        return conn

    def get_conn(self) -> sqlite3.Connection:
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._create_connection()
            self._local.conn = conn
        return conn

    def close_thread_conn(self) -> None:
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    @contextmanager
    def atomic(self, immediate: bool = True):
        """
        Safe transaction context manager supporting nested SAVEPOINTs.
        Never uses executescript() inside transactions.
        """
        with self._write_lock:
            conn = self.get_conn()
            if not conn.in_transaction:
                begin_sql = "BEGIN IMMEDIATE" if immediate else "BEGIN"
                conn.execute(begin_sql)
                try:
                    yield conn
                    if conn.in_transaction:
                        conn.execute("COMMIT")
                except Exception:
                    if conn.in_transaction:
                        try:
                            conn.execute("ROLLBACK")
                        except Exception:
                            pass
                    raise
            else:
                depth = getattr(self._local, "sp_depth", 0) + 1
                self._local.sp_depth = depth
                sp_name = f"sp_{depth}_{int(time.time() * 1000) % 100000}"
                conn.execute(f"SAVEPOINT {sp_name}")
                try:
                    yield conn
                    conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                except Exception:
                    try:
                        conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                        conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                    except Exception:
                        pass
                    raise
                finally:
                    self._local.sp_depth = max(0, depth - 1)

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
        conn = self.get_conn()
        cur = conn.execute(sql, params)
        return cur.fetchone()

    def query_all(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        conn = self.get_conn()
        cur = conn.execute(sql, params)
        return cur.fetchall()

    def execute_write(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self.atomic(immediate=True) as conn:
            cur = conn.execute(sql, params)
            return int(cur.lastrowid or 0)

    @staticmethod
    def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _get_table_columns(conn: sqlite3.Connection, table_name: str) -> Set[str]:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(r["name"]) for r in rows}

    def _ensure_columns(
        self,
        conn: sqlite3.Connection,
        table_name: str,
        columns: Sequence[Tuple[str, str]],
    ) -> None:
        existing = self._get_table_columns(conn, table_name)
        for col_name, col_def in columns:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}")

    def create_raw_db_backup(self, label: str = "pre_upgrade") -> Optional[Path]:
        if not self.db_path.exists() or self.db_path.stat().st_size == 0:
            return None
        DATA_DIRS["backups"].mkdir(parents=True, exist_ok=True)
        stamp = now_dhaka().strftime("%Y%m%d_%H%M%S")
        backup_file = DATA_DIRS["backups"] / f"{sanitize_filename(label)}_{stamp}.db"
        src = sqlite3.connect(str(self.db_path), timeout=30.0)
        dst = sqlite3.connect(str(backup_file), timeout=30.0)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        return backup_file

    def initialize_and_migrate(self) -> Dict[str, Any]:
        """
        Creates all platform tables and performs safe, non-destructive column migrations.
        """
        with self._write_lock:
            conn = self.get_conn()
            prev_version = 0
            backup_path_str = ""

            if self._table_exists(conn, "schema_meta"):
                row = conn.execute(
                    "SELECT value FROM schema_meta WHERE key='db_schema_version'"
                ).fetchone()
                if row is not None:
                    try:
                        prev_version = int(row["value"])
                    except Exception:
                        prev_version = 0

            if prev_version > 0 and prev_version < DB_SCHEMA_VERSION:
                bkp = self.create_raw_db_backup(label=f"pre_v{DB_SCHEMA_VERSION}_upgrade")
                backup_path_str = str(bkp) if bkp else ""

            ddl_statements: List[str] = [
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS migration_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_version INTEGER NOT NULL,
                    to_version INTEGER NOT NULL,
                    notes TEXT NOT NULL DEFAULT '',
                    backup_path TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS runtime_states (
                    user_id INTEGER PRIMARY KEY,
                    flow TEXT NOT NULL DEFAULT '',
                    step TEXT NOT NULL DEFAULT '',
                    data_json TEXT NOT NULL DEFAULT '{}',
                    temp_message_ids_json TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL DEFAULT '',
                    full_name TEXT NOT NULL DEFAULT '',
                    language TEXT NOT NULL DEFAULT 'bn',
                    status TEXT NOT NULL DEFAULT 'active',
                    block_reason TEXT NOT NULL DEFAULT '',
                    warning_count INTEGER NOT NULL DEFAULT 0,
                    vip_tier TEXT NOT NULL DEFAULT 'Bronze',
                    referrer_id INTEGER,
                    earned_balance REAL NOT NULL DEFAULT 0.0,
                    deposit_balance REAL NOT NULL DEFAULT 0.0,
                    held_balance REAL NOT NULL DEFAULT 0.0,
                    total_withdrawn REAL NOT NULL DEFAULT 0.0,
                    total_earnings REAL NOT NULL DEFAULT 0.0,
                    points_balance REAL NOT NULL DEFAULT 0.0,
                    task_field_access_json TEXT NOT NULL DEFAULT '{}',
                    last_active_at TEXT NOT NULL DEFAULT '',
                    spam_score INTEGER NOT NULL DEFAULT 0,
                    registered_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS user_warnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    admin_id INTEGER NOT NULL,
                    reason_bn TEXT NOT NULL DEFAULT '',
                    reason_en TEXT NOT NULL DEFAULT '',
                    strike_delta INTEGER NOT NULL DEFAULT 1,
                    is_broadcast INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS channels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    purpose TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    title TEXT NOT NULL DEFAULT '',
                    join_link TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    last_test_at TEXT NOT NULL DEFAULT '',
                    last_test_ok INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS support_contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    username_or_link TEXT NOT NULL,
                    description_bn TEXT NOT NULL DEFAULT '',
                    description_en TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS bot_texts (
                    text_key TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    label_bn TEXT NOT NULL DEFAULT '',
                    label_en TEXT NOT NULL DEFAULT '',
                    text_bn TEXT NOT NULL,
                    text_en TEXT NOT NULL,
                    default_bn TEXT NOT NULL,
                    default_en TEXT NOT NULL,
                    placeholders_json TEXT NOT NULL DEFAULT '[]',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    updated_by INTEGER NOT NULL DEFAULT 0
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS rule_controls (
                    rule_key TEXT PRIMARY KEY,
                    sector_no INTEGER NOT NULL DEFAULT 1,
                    rule_code TEXT NOT NULL DEFAULT '',
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    desc_bn TEXT NOT NULL DEFAULT '',
                    desc_en TEXT NOT NULL DEFAULT '',
                    usage_guide_bn TEXT NOT NULL DEFAULT '',
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_locked INTEGER NOT NULL DEFAULT 0,
                    config_json TEXT NOT NULL DEFAULT '{}',
                    default_config_json TEXT NOT NULL DEFAULT '{}',
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS dynamic_buttons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    button_key TEXT UNIQUE NOT NULL,
                    menu_scope TEXT NOT NULL DEFAULT 'user_main',
                    label_bn TEXT NOT NULL,
                    label_en TEXT NOT NULL,
                    emoji TEXT NOT NULL DEFAULT '',
                    action_type TEXT NOT NULL DEFAULT 'builtin',
                    action_target TEXT NOT NULL DEFAULT '',
                    description_bn TEXT NOT NULL DEFAULT '',
                    description_en TEXT NOT NULL DEFAULT '',
                    instruction_bn TEXT NOT NULL DEFAULT '',
                    instruction_en TEXT NOT NULL DEFAULT '',
                    button_style TEXT NOT NULL DEFAULT 'default',
                    placement TEXT NOT NULL DEFAULT 'both',
                    row_group INTEGER NOT NULL DEFAULT 1,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    col_span INTEGER NOT NULL DEFAULT 1,
                    is_builtin INTEGER NOT NULL DEFAULT 0,
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    value_type TEXT NOT NULL DEFAULT 'str',
                    category TEXT NOT NULL DEFAULT 'general',
                    description_bn TEXT NOT NULL DEFAULT '',
                    description_en TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    updated_by INTEGER NOT NULL DEFAULT 0
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS settings_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    setting_key TEXT NOT NULL,
                    old_value TEXT NOT NULL DEFAULT '',
                    new_value TEXT NOT NULL DEFAULT '',
                    admin_id INTEGER NOT NULL DEFAULT 0,
                    reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS assistant_permissions (
                    admin_id INTEGER PRIMARY KEY,
                    full_name TEXT NOT NULL DEFAULT '',
                    username TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    permissions_json TEXT NOT NULL DEFAULT '{}',
                    added_by INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_id INTEGER NOT NULL,
                    actor_role TEXT NOT NULL DEFAULT 'user',
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL DEFAULT '',
                    target_id TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    desc_bn TEXT NOT NULL DEFAULT '',
                    desc_en TEXT NOT NULL DEFAULT '',
                    instruction_bn TEXT NOT NULL DEFAULT '',
                    instruction_en TEXT NOT NULL DEFAULT '',
                    task_type TEXT NOT NULL DEFAULT 'standard',
                    reward_amount REAL NOT NULL DEFAULT 0.0,
                    daily_limit INTEGER NOT NULL DEFAULT 0,
                    user_limit INTEGER NOT NULL DEFAULT 0,
                    cooldown_sec INTEGER NOT NULL DEFAULT 0,
                    start_at TEXT NOT NULL DEFAULT '',
                    end_at TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    source_enabled INTEGER NOT NULL DEFAULT 0,
                    field_combo_mode TEXT NOT NULL DEFAULT 'user_pass',
                    custom_fields_json TEXT NOT NULL DEFAULT '[]',
                    allowed_vip_tiers_json TEXT NOT NULL DEFAULT '[]',
                    password_mode TEXT NOT NULL DEFAULT 'file_only',
                    static_password TEXT NOT NULL DEFAULT '',
                    password_pattern TEXT NOT NULL DEFAULT 'Work@{4DIGIT}{2ALPHA}',
                    allocation_timeout_sec INTEGER NOT NULL DEFAULT 900,
                    require_totp INTEGER NOT NULL DEFAULT 0,
                    totp_dup_block INTEGER NOT NULL DEFAULT 1,
                    require_cookie INTEGER NOT NULL DEFAULT 0,
                    cookie_dup_block INTEGER NOT NULL DEFAULT 1,
                    cookie_required_keys TEXT NOT NULL DEFAULT 'none',
                    auto_approve_enabled INTEGER NOT NULL DEFAULT 0,
                    auto_approve_sec INTEGER NOT NULL DEFAULT 60,
                    auto_reject_enabled INTEGER NOT NULL DEFAULT 0,
                    auto_reject_sec INTEGER NOT NULL DEFAULT 300,
                    auto_reject_reason TEXT NOT NULL DEFAULT 'Auto rejected after timeout',
                    auto_delete_messages INTEGER NOT NULL DEFAULT 0,
                    auto_pause_on_empty INTEGER NOT NULL DEFAULT 1,
                    auto_resume_on_stock INTEGER NOT NULL DEFAULT 1,
                    low_stock_threshold INTEGER NOT NULL DEFAULT 5,
                    test_code_enabled INTEGER NOT NULL DEFAULT 0,
                    test_code_length INTEGER NOT NULL DEFAULT 16,
                    created_by INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS task_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL,
                    phase TEXT NOT NULL DEFAULT 'pre_code',
                    step_order INTEGER NOT NULL DEFAULT 1,
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    instruction_bn TEXT NOT NULL DEFAULT '',
                    instruction_en TEXT NOT NULL DEFAULT '',
                    input_type TEXT NOT NULL DEFAULT 'text',
                    options_json TEXT NOT NULL DEFAULT '[]',
                    min_len INTEGER NOT NULL DEFAULT 0,
                    max_len INTEGER NOT NULL DEFAULT 2000,
                    regex_pattern TEXT NOT NULL DEFAULT '',
                    is_required INTEGER NOT NULL DEFAULT 1,
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    allow_skip INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS task_source_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL,
                    batch_id TEXT NOT NULL DEFAULT '',
                    row_index INTEGER NOT NULL DEFAULT 1,
                    columns_json TEXT NOT NULL DEFAULT '{}',
                    raw_line TEXT NOT NULL DEFAULT '',
                    record_hash TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'available',
                    allocated_to INTEGER,
                    allocated_at TEXT NOT NULL DEFAULT '',
                    expires_at TEXT NOT NULL DEFAULT '',
                    submission_id INTEGER,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS task_allocations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL,
                    source_record_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    allocated_fields_json TEXT NOT NULL DEFAULT '{}',
                    assigned_password TEXT NOT NULL DEFAULT '',
                    internal_test_code TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    allocated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    released_at TEXT NOT NULL DEFAULT '',
                    submission_id INTEGER
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS task_submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sub_uid TEXT UNIQUE NOT NULL,
                    task_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    user_full_name TEXT NOT NULL DEFAULT '',
                    user_username TEXT NOT NULL DEFAULT '',
                    allocation_id INTEGER,
                    source_record_id INTEGER,
                    source_snapshot_json TEXT NOT NULL DEFAULT '{}',
                    step_answers_json TEXT NOT NULL DEFAULT '[]',
                    totp_secret TEXT NOT NULL DEFAULT '',
                    totp_secret_hash TEXT NOT NULL DEFAULT '',
                    totp_6digit_code TEXT NOT NULL DEFAULT '',
                    cookie_raw TEXT NOT NULL DEFAULT '',
                    cookie_canonical TEXT NOT NULL DEFAULT '',
                    cookie_hash TEXT NOT NULL DEFAULT '',
                    proof_hash TEXT NOT NULL DEFAULT '',
                    reward_snapshot REAL NOT NULL DEFAULT 0.0,
                    referral_rate_snapshot REAL NOT NULL DEFAULT 0.0,
                    status TEXT NOT NULL DEFAULT 'pending',
                    auto_review_mode TEXT NOT NULL DEFAULT 'manual',
                    auto_action_at TEXT NOT NULL DEFAULT '',
                    review_channel_id TEXT NOT NULL DEFAULT '',
                    review_message_id INTEGER NOT NULL DEFAULT 0,
                    reject_reason TEXT NOT NULL DEFAULT '',
                    reviewed_by INTEGER NOT NULL DEFAULT 0,
                    reviewed_at TEXT NOT NULL DEFAULT '',
                    is_suspicious INTEGER NOT NULL DEFAULT 0,
                    suspicious_note TEXT NOT NULL DEFAULT '',
                    is_exported INTEGER NOT NULL DEFAULT 0,
                    exported_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS task_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workflow_uid TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    chat_id INTEGER NOT NULL,
                    message_id INTEGER NOT NULL,
                    task_id INTEGER NOT NULL DEFAULT 0,
                    is_bot_msg INTEGER NOT NULL DEFAULT 1,
                    is_deleted INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS totp_used_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    secret_normalized TEXT NOT NULL,
                    secret_hash TEXT NOT NULL,
                    task_id INTEGER NOT NULL DEFAULT 0,
                    user_id INTEGER NOT NULL DEFAULT 0,
                    submission_uid TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS cookie_submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cookie_hash TEXT NOT NULL,
                    cookie_canonical TEXT NOT NULL,
                    task_id INTEGER NOT NULL DEFAULT 0,
                    user_id INTEGER NOT NULL DEFAULT 0,
                    submission_uid TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS internal_test_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL DEFAULT 0,
                    code_value TEXT NOT NULL,
                    is_single_use INTEGER NOT NULL DEFAULT 1,
                    is_used INTEGER NOT NULL DEFAULT 0,
                    used_by INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    used_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS fs_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    desc_bn TEXT NOT NULL DEFAULT '',
                    desc_en TEXT NOT NULL DEFAULT '',
                    instruction_bn TEXT NOT NULL DEFAULT '',
                    instruction_en TEXT NOT NULL DEFAULT '',
                    reward_per_record REAL NOT NULL DEFAULT 0.0,
                    allowed_formats_json TEXT NOT NULL DEFAULT '["txt","csv","xls","xlsx","text"]',
                    submission_mode TEXT NOT NULL DEFAULT 'line_by_line',
                    delimiter TEXT NOT NULL DEFAULT 'auto',
                    min_records INTEGER NOT NULL DEFAULT 1,
                    max_records INTEGER NOT NULL DEFAULT 1000,
                    min_columns INTEGER NOT NULL DEFAULT 1,
                    pattern_type TEXT NOT NULL DEFAULT 'any',
                    custom_regex TEXT NOT NULL DEFAULT '',
                    duplicate_scope TEXT NOT NULL DEFAULT 'global',
                    smart_skip_invalid INTEGER NOT NULL DEFAULT 1,
                    daily_limit INTEGER NOT NULL DEFAULT 0,
                    cooldown_sec INTEGER NOT NULL DEFAULT 0,
                    commission_enabled INTEGER NOT NULL DEFAULT 1,
                    commission_type TEXT NOT NULL DEFAULT 'percent',
                    commission_value REAL NOT NULL DEFAULT 5.0,
                    status TEXT NOT NULL DEFAULT 'active',
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS fs_source_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fs_task_id INTEGER NOT NULL,
                    file_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    record_count INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    uploaded_by INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS fs_submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sub_uid TEXT UNIQUE NOT NULL,
                    fs_task_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    user_full_name TEXT NOT NULL DEFAULT '',
                    user_username TEXT NOT NULL DEFAULT '',
                    file_name TEXT NOT NULL DEFAULT '',
                    file_path TEXT NOT NULL DEFAULT '',
                    file_hash TEXT NOT NULL DEFAULT '',
                    total_records INTEGER NOT NULL DEFAULT 0,
                    approved_count INTEGER NOT NULL DEFAULT 0,
                    rejected_count INTEGER NOT NULL DEFAULT 0,
                    pending_count INTEGER NOT NULL DEFAULT 0,
                    skipped_count INTEGER NOT NULL DEFAULT 0,
                    reward_per_record_snapshot REAL NOT NULL DEFAULT 0.0,
                    total_reward_credited REAL NOT NULL DEFAULT 0.0,
                    status TEXT NOT NULL DEFAULT 'pending',
                    review_channel_id TEXT NOT NULL DEFAULT '',
                    review_message_id INTEGER NOT NULL DEFAULT 0,
                    delivery_status TEXT NOT NULL DEFAULT 'pending',
                    delivery_error TEXT NOT NULL DEFAULT '',
                    locked_by_admin INTEGER NOT NULL DEFAULT 0,
                    locked_at TEXT NOT NULL DEFAULT '',
                    current_version INTEGER NOT NULL DEFAULT 0,
                    is_exported INTEGER NOT NULL DEFAULT 0,
                    exported_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    finalized_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS fs_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fs_submission_id INTEGER NOT NULL,
                    fs_task_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    line_no INTEGER NOT NULL,
                    stable_uid TEXT UNIQUE NOT NULL,
                    raw_line TEXT NOT NULL DEFAULT '',
                    columns_json TEXT NOT NULL DEFAULT '[]',
                    record_hash TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    reject_reason TEXT NOT NULL DEFAULT '',
                    reviewed_by INTEGER NOT NULL DEFAULT 0,
                    reviewed_at TEXT NOT NULL DEFAULT '',
                    is_exported INTEGER NOT NULL DEFAULT 0
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS report_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    submission_type TEXT NOT NULL,
                    submission_id INTEGER NOT NULL,
                    version_no INTEGER NOT NULL DEFAULT 1,
                    report_kind TEXT NOT NULL DEFAULT 'FINAL',
                    summary_json TEXT NOT NULL DEFAULT '{}',
                    message_text TEXT NOT NULL DEFAULT '',
                    sent_to_user INTEGER NOT NULL DEFAULT 0,
                    created_by INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS reject_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL DEFAULT 'all',
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    reason_bn TEXT NOT NULL,
                    reason_en TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS store_categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name_bn TEXT NOT NULL,
                    name_en TEXT NOT NULL,
                    emoji TEXT NOT NULL DEFAULT '🛍️',
                    desc_bn TEXT NOT NULL DEFAULT '',
                    desc_en TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS store_products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category_id INTEGER NOT NULL DEFAULT 0,
                    name_bn TEXT NOT NULL,
                    name_en TEXT NOT NULL,
                    desc_bn TEXT NOT NULL DEFAULT '',
                    desc_en TEXT NOT NULL DEFAULT '',
                    instruction_bn TEXT NOT NULL DEFAULT '',
                    instruction_en TEXT NOT NULL DEFAULT '',
                    price REAL NOT NULL DEFAULT 0.0,
                    min_qty INTEGER NOT NULL DEFAULT 1,
                    max_qty INTEGER NOT NULL DEFAULT 100,
                    daily_limit INTEGER NOT NULL DEFAULT 0,
                    lifetime_limit INTEGER NOT NULL DEFAULT 0,
                    cooldown_sec INTEGER NOT NULL DEFAULT 0,
                    wallet_mode TEXT NOT NULL DEFAULT 'any',
                    delivery_mode TEXT NOT NULL DEFAULT 'instant',
                    min_approved_tasks INTEGER NOT NULL DEFAULT 0,
                    min_deposit_total REAL NOT NULL DEFAULT 0.0,
                    min_vip_tier TEXT NOT NULL DEFAULT 'Bronze',
                    warranty_hours INTEGER NOT NULL DEFAULT 0,
                    low_stock_threshold INTEGER NOT NULL DEFAULT 5,
                    auto_pause_on_empty INTEGER NOT NULL DEFAULT 1,
                    auto_resume_on_stock INTEGER NOT NULL DEFAULT 1,
                    payout_post_enabled INTEGER NOT NULL DEFAULT 1,
                    payout_mask_buyer INTEGER NOT NULL DEFAULT 1,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS store_product_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    step_order INTEGER NOT NULL DEFAULT 1,
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    instruction_bn TEXT NOT NULL DEFAULT '',
                    instruction_en TEXT NOT NULL DEFAULT '',
                    input_type TEXT NOT NULL DEFAULT 'text',
                    options_json TEXT NOT NULL DEFAULT '[]',
                    is_required INTEGER NOT NULL DEFAULT 1,
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS product_stock_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    item_line TEXT NOT NULL,
                    item_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'available',
                    order_id INTEGER,
                    buyer_id INTEGER,
                    sold_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS store_price_tiers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    min_qty INTEGER NOT NULL,
                    unit_price REAL NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS store_coupons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT UNIQUE NOT NULL,
                    discount_type TEXT NOT NULL DEFAULT 'percent',
                    discount_value REAL NOT NULL DEFAULT 0.0,
                    max_uses INTEGER NOT NULL DEFAULT 0,
                    used_count INTEGER NOT NULL DEFAULT 0,
                    per_user_limit INTEGER NOT NULL DEFAULT 1,
                    min_order_amount REAL NOT NULL DEFAULT 0.0,
                    product_id INTEGER NOT NULL DEFAULT 0,
                    expires_at TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS store_orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    order_uid TEXT UNIQUE NOT NULL,
                    product_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    qty INTEGER NOT NULL DEFAULT 1,
                    unit_price_snapshot REAL NOT NULL DEFAULT 0.0,
                    discount_amount REAL NOT NULL DEFAULT 0.0,
                    total_paid REAL NOT NULL DEFAULT 0.0,
                    wallet_bucket_used TEXT NOT NULL DEFAULT 'deposit',
                    coupon_code TEXT NOT NULL DEFAULT '',
                    step_answers_json TEXT NOT NULL DEFAULT '[]',
                    delivered_lines_json TEXT NOT NULL DEFAULT '[]',
                    delivery_file_path TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'completed',
                    warranty_expires_at TEXT NOT NULL DEFAULT '',
                    review_channel_id TEXT NOT NULL DEFAULT '',
                    review_message_id INTEGER NOT NULL DEFAULT 0,
                    payout_channel_id TEXT NOT NULL DEFAULT '',
                    payout_message_id INTEGER NOT NULL DEFAULT 0,
                    reviewed_by INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS store_warranty_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    warranty_uid TEXT UNIQUE NOT NULL,
                    order_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    proof_file_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    resolution_note TEXT NOT NULL DEFAULT '',
                    replacement_lines_json TEXT NOT NULL DEFAULT '[]',
                    refund_amount REAL NOT NULL DEFAULT 0.0,
                    admin_id INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS store_stock_notify (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    notified INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    notified_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS otp_countries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name_bn TEXT NOT NULL,
                    name_en TEXT NOT NULL,
                    flag_emoji TEXT NOT NULL DEFAULT '🏳️',
                    country_code TEXT NOT NULL DEFAULT '+1',
                    numbers_per_click INTEGER NOT NULL DEFAULT 1,
                    fee_amount REAL NOT NULL DEFAULT 0.0,
                    wait_timeout_sec INTEGER NOT NULL DEFAULT 300,
                    service_filter TEXT NOT NULL DEFAULT 'Any',
                    multi_otp_enabled INTEGER NOT NULL DEFAULT 0,
                    max_swaps_per_session INTEGER NOT NULL DEFAULT 2,
                    recycle_after_hours INTEGER NOT NULL DEFAULT 0,
                    burn_after_use INTEGER NOT NULL DEFAULT 1,
                    auto_pause_on_empty INTEGER NOT NULL DEFAULT 1,
                    auto_resume_on_stock INTEGER NOT NULL DEFAULT 1,
                    low_stock_threshold INTEGER NOT NULL DEFAULT 5,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS otp_numbers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    country_id INTEGER NOT NULL,
                    phone_number TEXT NOT NULL,
                    phone_normalized TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'available',
                    assigned_to INTEGER,
                    session_id INTEGER,
                    assigned_at TEXT NOT NULL DEFAULT '',
                    burned_at TEXT NOT NULL DEFAULT '',
                    recycle_available_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS otp_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    otp_uid TEXT UNIQUE NOT NULL,
                    country_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    phone_ids_json TEXT NOT NULL DEFAULT '[]',
                    phone_numbers_json TEXT NOT NULL DEFAULT '[]',
                    fee_paid_snapshot REAL NOT NULL DEFAULT 0.0,
                    wallet_bucket TEXT NOT NULL DEFAULT 'deposit',
                    service_name TEXT NOT NULL DEFAULT 'Any',
                    status TEXT NOT NULL DEFAULT 'waiting',
                    swap_count INTEGER NOT NULL DEFAULT 0,
                    otp_received_count INTEGER NOT NULL DEFAULT 0,
                    last_otp_code TEXT NOT NULL DEFAULT '',
                    expires_at TEXT NOT NULL,
                    review_channel_id TEXT NOT NULL DEFAULT '',
                    review_message_id INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    closed_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS otp_sms_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL DEFAULT 0,
                    country_id INTEGER NOT NULL DEFAULT 0,
                    user_id INTEGER NOT NULL DEFAULT 0,
                    phone_number TEXT NOT NULL,
                    bridge_source TEXT NOT NULL DEFAULT 'manual',
                    raw_sms TEXT NOT NULL,
                    extracted_code TEXT NOT NULL DEFAULT '',
                    sms_hash TEXT NOT NULL DEFAULT '',
                    pushed_to_user INTEGER NOT NULL DEFAULT 0,
                    posted_to_channel INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS deposit_methods (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name_bn TEXT NOT NULL,
                    name_en TEXT NOT NULL,
                    method_type TEXT NOT NULL DEFAULT 'mobile_banking',
                    account_number TEXT NOT NULL DEFAULT '',
                    account_label TEXT NOT NULL DEFAULT '',
                    network_info TEXT NOT NULL DEFAULT '',
                    account_holder_type TEXT NOT NULL DEFAULT 'Personal',
                    min_amount REAL NOT NULL DEFAULT 10.0,
                    max_amount REAL NOT NULL DEFAULT 50000.0,
                    bonus_percent REAL NOT NULL DEFAULT 0.0,
                    charge_percent REAL NOT NULL DEFAULT 0.0,
                    require_amount INTEGER NOT NULL DEFAULT 1,
                    require_sender INTEGER NOT NULL DEFAULT 1,
                    require_txid INTEGER NOT NULL DEFAULT 1,
                    require_screenshot INTEGER NOT NULL DEFAULT 1,
                    custom_fields_json TEXT NOT NULL DEFAULT '[]',
                    instruction_bn TEXT NOT NULL DEFAULT '',
                    instruction_en TEXT NOT NULL DEFAULT '',
                    auto_approve_enabled INTEGER NOT NULL DEFAULT 0,
                    auto_approve_sec INTEGER NOT NULL DEFAULT 60,
                    auto_reject_enabled INTEGER NOT NULL DEFAULT 0,
                    auto_reject_sec INTEGER NOT NULL DEFAULT 300,
                    proof_auto_reject_enabled INTEGER NOT NULL DEFAULT 1,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS deposits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    deposit_uid TEXT UNIQUE NOT NULL,
                    method_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    amount REAL NOT NULL DEFAULT 0.0,
                    bonus_amount REAL NOT NULL DEFAULT 0.0,
                    charge_amount REAL NOT NULL DEFAULT 0.0,
                    net_credit REAL NOT NULL DEFAULT 0.0,
                    sender_number TEXT NOT NULL DEFAULT '',
                    txid_user TEXT NOT NULL DEFAULT '',
                    txid_ocr TEXT NOT NULL DEFAULT '',
                    ocr_raw_text TEXT NOT NULL DEFAULT '',
                    ocr_status TEXT NOT NULL DEFAULT 'not_run',
                    screenshot_file_id TEXT NOT NULL DEFAULT '',
                    screenshot_unique_id TEXT NOT NULL DEFAULT '',
                    screenshot_sha256 TEXT NOT NULL DEFAULT '',
                    custom_answers_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'pending',
                    auto_review_mode TEXT NOT NULL DEFAULT 'manual',
                    auto_action_at TEXT NOT NULL DEFAULT '',
                    reject_reason TEXT NOT NULL DEFAULT '',
                    channel_id TEXT NOT NULL DEFAULT '',
                    channel_message_id INTEGER NOT NULL DEFAULT 0,
                    is_media_msg INTEGER NOT NULL DEFAULT 0,
                    reviewed_by INTEGER NOT NULL DEFAULT 0,
                    reviewed_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS withdraw_methods (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name_bn TEXT NOT NULL,
                    name_en TEXT NOT NULL,
                    method_type TEXT NOT NULL DEFAULT 'bd_mobile',
                    fee_type TEXT NOT NULL DEFAULT 'fixed',
                    fee_value REAL NOT NULL DEFAULT 0.0,
                    min_amount REAL NOT NULL DEFAULT 20.0,
                    max_amount REAL NOT NULL DEFAULT 25000.0,
                    wallet_regex TEXT NOT NULL DEFAULT '',
                    custom_conditions_json TEXT NOT NULL DEFAULT '{}',
                    instruction_bn TEXT NOT NULL DEFAULT '',
                    instruction_en TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS withdrawals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    withdraw_uid TEXT UNIQUE NOT NULL,
                    method_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    account_or_wallet TEXT NOT NULL,
                    gross_amount REAL NOT NULL DEFAULT 0.0,
                    fee_amount REAL NOT NULL DEFAULT 0.0,
                    net_amount REAL NOT NULL DEFAULT 0.0,
                    custom_answers_json TEXT NOT NULL DEFAULT '[]',
                    conditions_snapshot_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'requested',
                    reject_reason TEXT NOT NULL DEFAULT '',
                    channel_id TEXT NOT NULL DEFAULT '',
                    channel_message_id INTEGER NOT NULL DEFAULT 0,
                    payout_channel_id TEXT NOT NULL DEFAULT '',
                    payout_message_id INTEGER NOT NULL DEFAULT 0,
                    reviewed_by INTEGER NOT NULL DEFAULT 0,
                    reviewed_at TEXT NOT NULL DEFAULT '',
                    paid_by INTEGER NOT NULL DEFAULT 0,
                    paid_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS ledger_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tx_uid TEXT UNIQUE NOT NULL,
                    idempotency_key TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    tx_type TEXT NOT NULL,
                    amount REAL NOT NULL,
                    direction TEXT NOT NULL,
                    prev_balance REAL NOT NULL,
                    new_balance REAL NOT NULL,
                    wallet_bucket TEXT NOT NULL DEFAULT 'earned',
                    source TEXT NOT NULL DEFAULT '',
                    ref_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'completed',
                    admin_id INTEGER NOT NULL DEFAULT 0,
                    reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS bonuses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    desc_bn TEXT NOT NULL DEFAULT '',
                    desc_en TEXT NOT NULL DEFAULT '',
                    reward_amount REAL NOT NULL DEFAULT 0.0,
                    wallet_bucket TEXT NOT NULL DEFAULT 'earned',
                    bonus_type TEXT NOT NULL DEFAULT 'campaign',
                    min_tasks_required INTEGER NOT NULL DEFAULT 0,
                    max_claims INTEGER NOT NULL DEFAULT 0,
                    claimed_count INTEGER NOT NULL DEFAULT 0,
                    cooldown_sec INTEGER NOT NULL DEFAULT 0,
                    start_at TEXT NOT NULL DEFAULT '',
                    end_at TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS bonus_claims (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bonus_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    amount_credited REAL NOT NULL,
                    claim_uid TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS daily_checkins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    checkin_date_dhaka TEXT NOT NULL,
                    streak_day INTEGER NOT NULL DEFAULT 1,
                    base_amount REAL NOT NULL DEFAULT 0.0,
                    streak_bonus REAL NOT NULL DEFAULT 0.0,
                    vip_multiplier REAL NOT NULL DEFAULT 1.0,
                    total_credited REAL NOT NULL DEFAULT 0.0,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, checkin_date_dhaka)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS leaderboard_cycles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    board_type TEXT NOT NULL,
                    cycle_no INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'active',
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL DEFAULT '',
                    prize_tiers_json TEXT NOT NULL DEFAULT '{}',
                    top_n INTEGER NOT NULL DEFAULT 10,
                    published_channel_id TEXT NOT NULL DEFAULT '',
                    published_message_id INTEGER NOT NULL DEFAULT 0
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS leaderboard_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cycle_id INTEGER NOT NULL,
                    board_type TEXT NOT NULL,
                    cycle_no INTEGER NOT NULL,
                    rank_pos INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    work_count INTEGER NOT NULL DEFAULT 0,
                    manual_adjust INTEGER NOT NULL DEFAULT 0,
                    total_score INTEGER NOT NULL DEFAULT 0,
                    prize_amount REAL NOT NULL DEFAULT 0.0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS leaderboard_adjustments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cycle_id INTEGER NOT NULL,
                    board_type TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    delta_score INTEGER NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    admin_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS support_tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_uid TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    subject TEXT NOT NULL DEFAULT 'Support',
                    message_text TEXT NOT NULL,
                    photo_file_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    admin_id INTEGER NOT NULL DEFAULT 0,
                    admin_reply TEXT NOT NULL DEFAULT '',
                    replied_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    closed_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS appeals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    appeal_uid TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    item_type TEXT NOT NULL,
                    item_id INTEGER NOT NULL,
                    item_uid TEXT NOT NULL,
                    reason_text TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    admin_id INTEGER NOT NULL DEFAULT 0,
                    admin_note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT NOT NULL DEFAULT '',
                    UNIQUE(user_id, item_type, item_id)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS message_studio_events (
                    event_key TEXT PRIMARY KEY,
                    category TEXT NOT NULL DEFAULT 'general',
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    delivery_mode TEXT NOT NULL DEFAULT 'rotate',
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    silent_mode INTEGER NOT NULL DEFAULT 0,
                    mask_privacy INTEGER NOT NULL DEFAULT 1,
                    is_custom INTEGER NOT NULL DEFAULT 0,
                    placeholders_json TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS message_studio_variants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_key TEXT NOT NULL,
                    variant_no INTEGER NOT NULL,
                    title_bn TEXT NOT NULL,
                    title_en TEXT NOT NULL,
                    body_bn TEXT NOT NULL,
                    body_en TEXT NOT NULL,
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    is_builtin INTEGER NOT NULL DEFAULT 1,
                    is_archived INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    UNIQUE(event_key, variant_no)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS notification_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    text_html TEXT NOT NULL,
                    parse_mode TEXT NOT NULL DEFAULT 'HTML',
                    status TEXT NOT NULL DEFAULT 'pending',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    max_retries INTEGER NOT NULL DEFAULT 3,
                    next_retry_at TEXT NOT NULL,
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    sent_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS broadcast_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    broadcast_uid TEXT UNIQUE NOT NULL,
                    admin_id INTEGER NOT NULL,
                    audience_filter TEXT NOT NULL DEFAULT 'all',
                    language_filter TEXT NOT NULL DEFAULT 'all',
                    media_type TEXT NOT NULL DEFAULT 'text',
                    content_text TEXT NOT NULL DEFAULT '',
                    media_file_id TEXT NOT NULL DEFAULT '',
                    target_count INTEGER NOT NULL DEFAULT 0,
                    sent_count INTEGER NOT NULL DEFAULT 0,
                    failed_count INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL DEFAULT ''
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS export_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    export_uid TEXT UNIQUE NOT NULL,
                    export_type TEXT NOT NULL,
                    ref_id TEXT NOT NULL DEFAULT '',
                    file_format TEXT NOT NULL DEFAULT 'xlsx',
                    file_path TEXT NOT NULL,
                    row_count INTEGER NOT NULL DEFAULT 0,
                    admin_id INTEGER NOT NULL DEFAULT 0,
                    delivery_ok INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS backup_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_uid TEXT UNIQUE NOT NULL,
                    backup_type TEXT NOT NULL DEFAULT 'manual',
                    file_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    sent_to_telegram INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'completed',
                    admin_id INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS reconciliation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_uid TEXT UNIQUE NOT NULL,
                    total_users INTEGER NOT NULL DEFAULT 0,
                    mismatches_found INTEGER NOT NULL DEFAULT 0,
                    total_earned_liability REAL NOT NULL DEFAULT 0.0,
                    total_deposit_liability REAL NOT NULL DEFAULT 0.0,
                    total_held_liability REAL NOT NULL DEFAULT 0.0,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    admin_id INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS scheduled_jobs_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_name TEXT NOT NULL,
                    run_date_dhaka TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'completed',
                    details TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """,
            ]

            for stmt in ddl_statements:
                conn.execute(stmt)

            # Non-destructive column upgrades for existing databases
            self._ensure_columns(
                conn,
                "tasks",
                [
                    ("totp_dup_block", "INTEGER NOT NULL DEFAULT 1"),
                    ("require_cookie", "INTEGER NOT NULL DEFAULT 0"),
                    ("cookie_dup_block", "INTEGER NOT NULL DEFAULT 1"),
                    ("cookie_required_keys", "TEXT NOT NULL DEFAULT 'none'"),
                ],
            )
            self._ensure_columns(
                conn,
                "task_submissions",
                [
                    ("user_full_name", "TEXT NOT NULL DEFAULT ''"),
                    ("user_username", "TEXT NOT NULL DEFAULT ''"),
                    ("totp_secret_hash", "TEXT NOT NULL DEFAULT ''"),
                    ("totp_6digit_code", "TEXT NOT NULL DEFAULT ''"),
                    ("cookie_raw", "TEXT NOT NULL DEFAULT ''"),
                    ("cookie_canonical", "TEXT NOT NULL DEFAULT ''"),
                    ("cookie_hash", "TEXT NOT NULL DEFAULT ''"),
                ],
            )
            self._ensure_columns(
                conn,
                "dynamic_buttons",
                [
                    ("button_style", "TEXT NOT NULL DEFAULT 'default'"),
                    ("placement", "TEXT NOT NULL DEFAULT 'both'"),
                ],
            )
            existing_user_cols = self._get_table_columns(conn, "users")
            self._ensure_columns(
                conn,
                "users",
                [("lang_selected", "INTEGER NOT NULL DEFAULT 0")],
            )
            if "lang_selected" not in existing_user_cols:
                conn.execute("UPDATE users SET lang_selected=1")

            existing_asst_cols = self._get_table_columns(conn, "assistant_permissions")
            self._ensure_columns(
                conn,
                "assistant_permissions",
                [
                    ("approval_status", "TEXT NOT NULL DEFAULT 'pending'"),
                    ("approved_by", "INTEGER NOT NULL DEFAULT 0"),
                    ("approved_at", "TEXT NOT NULL DEFAULT ''"),
                    ("rejection_note", "TEXT NOT NULL DEFAULT ''"),
                ],
            )
            if "approval_status" not in existing_asst_cols:
                conn.execute("UPDATE assistant_permissions SET approval_status='approved' WHERE is_active=1")

            existing_ch_cols = self._get_table_columns(conn, "channels")
            self._ensure_columns(
                conn,
                "channels",
                [
                    ("privacy_mode", "TEXT NOT NULL DEFAULT 'public'"),
                    ("join_required", "INTEGER NOT NULL DEFAULT 0"),
                ],
            )
            if "join_required" not in existing_ch_cols:
                conn.execute("UPDATE channels SET join_required=1, privacy_mode='public' WHERE purpose='force_join'")
                conn.execute("UPDATE channels SET join_required=0, privacy_mode='admin_only' WHERE purpose IN ('task_fs_review','finance_review','otp_relay','auto_backup')")

            has_bk_ch = conn.execute(
                "SELECT id FROM channels WHERE purpose='auto_backup' AND chat_id=?",
                (str(DEFAULT_AUTO_BACKUP_CHANNEL),),
            ).fetchone()
            if has_bk_ch is None:
                conn.execute(
                    """
                    INSERT INTO channels (purpose, chat_id, title, join_link, is_active, is_hidden, sort_order, privacy_mode, join_required, created_at)
                    VALUES ('auto_backup', ?, 'Private Auto-Backup Channel', '', 1, 0, 1, 'admin_only', 0, ?)
                    """,
                    (str(DEFAULT_AUTO_BACKUP_CHANNEL), now_utc_iso()),
                )

            index_statements: List[str] = [
                "CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)",
                "CREATE INDEX IF NOT EXISTS idx_users_referrer ON users(referrer_id)",
                "CREATE INDEX IF NOT EXISTS idx_task_src_status ON task_source_records(task_id, status)",
                "CREATE INDEX IF NOT EXISTS idx_task_sub_user ON task_submissions(task_id, user_id, status)",
                "CREATE INDEX IF NOT EXISTS idx_task_sub_auto ON task_submissions(status, auto_action_at)",
                "CREATE INDEX IF NOT EXISTS idx_totp_hash ON totp_used_keys(secret_hash, task_id)",
                "CREATE INDEX IF NOT EXISTS idx_cookie_hash ON cookie_submissions(cookie_hash, task_id)",
                "CREATE INDEX IF NOT EXISTS idx_fs_rec_sub ON fs_records(fs_submission_id, status)",
                "CREATE INDEX IF NOT EXISTS idx_fs_rec_hash ON fs_records(record_hash, fs_task_id)",
                "CREATE INDEX IF NOT EXISTS idx_store_stock_avail ON product_stock_items(product_id, status)",
                "CREATE INDEX IF NOT EXISTS idx_otp_num_avail ON otp_numbers(country_id, status)",
                "CREATE INDEX IF NOT EXISTS idx_otp_sess_wait ON otp_sessions(status, expires_at)",
                "CREATE INDEX IF NOT EXISTS idx_dep_txid ON deposits(txid_user, status)",
                "CREATE INDEX IF NOT EXISTS idx_dep_hash ON deposits(screenshot_sha256)",
                "CREATE INDEX IF NOT EXISTS idx_dep_auto ON deposits(status, auto_action_at)",
                "CREATE INDEX IF NOT EXISTS idx_wd_user ON withdrawals(user_id, status)",
                "CREATE INDEX IF NOT EXISTS idx_ledger_user ON ledger_transactions(user_id, created_at)",
                "CREATE INDEX IF NOT EXISTS idx_notif_pending ON notification_queue(status, next_retry_at)",
                "CREATE INDEX IF NOT EXISTS idx_ms_variants ON message_studio_variants(event_key, is_enabled, is_archived)",
            ]
            for idx_stmt in index_statements:
                conn.execute(idx_stmt)

            now_s = now_utc_iso()
            with self.atomic(immediate=True) as tx_conn:
                tx_conn.execute(
                    """
                    INSERT INTO schema_meta (key, value, updated_at)
                    VALUES ('bot_engine_version', ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                    """,
                    (BOT_ENGINE_VERSION, now_s),
                )
                tx_conn.execute(
                    """
                    INSERT INTO schema_meta (key, value, updated_at)
                    VALUES ('db_schema_version', ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                    """,
                    (str(DB_SCHEMA_VERSION), now_s),
                )
                if prev_version != DB_SCHEMA_VERSION:
                    tx_conn.execute(
                        """
                        INSERT INTO migration_history (from_version, to_version, notes, backup_path, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            prev_version,
                            DB_SCHEMA_VERSION,
                            "Initial schema or non-destructive upgrade completed",
                            backup_path_str,
                            now_s,
                        ),
                    )

            return {
                "previous_version": prev_version,
                "current_version": DB_SCHEMA_VERSION,
                "backup_path": backup_path_str,
                "db_path": str(self.db_path),
            }

    def get_table_counts(self) -> Dict[str, int]:
        conn = self.get_conn()
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        counts: Dict[str, int] = {}
        for t in tables:
            tname = str(t["name"])
            row = conn.execute(f"SELECT COUNT(*) AS c FROM {tname}").fetchone()
            counts[tname] = int(row["c"]) if row else 0
        return counts


# ==============================================================================
# RUNTIME STATE DATABASE (ISOLATED FROM PERMANENT FINANCIAL & USER DATA)
# ==============================================================================

class RuntimeDB:
    """
    Stores ephemeral multi-step wizard flows, batch selections, and temporary message IDs.
    Safe to clear via Admin Runtime-Only Reset without affecting balances or history.
    """

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def get_state(self, user_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM runtime_states WHERE user_id=?", (user_id,))
        if not row:
            return None
        expires_dt = parse_iso_dt(row["expires_at"])
        if expires_dt and now_utc() > expires_dt:
            self.clear_state(user_id)
            return None
        return {
            "user_id": int(row["user_id"]),
            "flow": str(row["flow"]),
            "step": str(row["step"]),
            "data": safe_json_loads(row["data_json"], {}),
            "temp_message_ids": safe_json_loads(row["temp_message_ids_json"], []),
            "updated_at": str(row["updated_at"]),
            "expires_at": str(row["expires_at"]),
        }

    def set_state(
        self,
        user_id: int,
        flow: str,
        step: str,
        data: Optional[Dict[str, Any]] = None,
        temp_message_ids: Optional[List[int]] = None,
        ttl_seconds: int = 3600,
    ) -> None:
        now_dt = now_utc()
        exp_dt = now_dt + timedelta(seconds=max(60, int(ttl_seconds)))
        existing = self.get_state(user_id) if temp_message_ids is None else None
        msg_ids = (
            temp_message_ids
            if temp_message_ids is not None
            else (existing.get("temp_message_ids", []) if existing else [])
        )
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO runtime_states (user_id, flow, step, data_json, temp_message_ids_json, updated_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    flow=excluded.flow,
                    step=excluded.step,
                    data_json=excluded.data_json,
                    temp_message_ids_json=excluded.temp_message_ids_json,
                    updated_at=excluded.updated_at,
                    expires_at=excluded.expires_at
                """,
                (
                    user_id,
                    flow,
                    step,
                    safe_json_dumps(data if data is not None else {}),
                    safe_json_dumps(msg_ids),
                    now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    exp_dt.strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

    def update_data(self, user_id: int, patch: Dict[str, Any], new_step: Optional[str] = None) -> None:
        st = self.get_state(user_id)
        if not st:
            return
        merged = dict(st["data"])
        merged.update(patch)
        self.set_state(
            user_id=user_id,
            flow=st["flow"],
            step=new_step if new_step is not None else st["step"],
            data=merged,
            temp_message_ids=st["temp_message_ids"],
        )

    def add_temp_message(self, user_id: int, message_id: int) -> None:
        st = self.get_state(user_id)
        if not st:
            return
        ids = list(st["temp_message_ids"])
        if message_id not in ids:
            ids.append(int(message_id))
        self.set_state(
            user_id=user_id,
            flow=st["flow"],
            step=st["step"],
            data=st["data"],
            temp_message_ids=ids,
        )

    def clear_state(self, user_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute("DELETE FROM runtime_states WHERE user_id=?", (user_id,))

    def cleanup_expired(self) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute("DELETE FROM runtime_states WHERE expires_at < ?", (now_s,))
            return int(cur.rowcount or 0)

    def clear_all_runtime(self) -> int:
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute("DELETE FROM runtime_states")
            return int(cur.rowcount or 0)
# ==============================================================================
# CONFIG MANAGER & GLOBAL BILINGUAL TEXT / RULES MANAGER (RULE 6, 35, 56, 90.A)
# ==============================================================================

TEXT_CATEGORIES: Tuple[Tuple[str, str, str], ...] = (
    ("start", "১. ওয়েলকাম ও স্টার্ট", "1. Welcome & Start"),
    ("force_join", "২. ফোর্স জয়েন", "2. Force Join"),
    ("main_menu", "৩. মেইন মেনু ও বাটন", "3. Main Menu & Buttons"),
    ("profile_balance", "৪. প্রোফাইল ও ব্যালেন্স", "4. Profile & Balance"),
    ("rules", "৫. ইউজার নিয়মাবলী", "5. User Rules"),
    ("task_prompts", "৬. টাস্ক ও ১৬/৩২ কী/কুকি", "6. Task, 16/32 Key & Cookie"),
    ("file_submit", "৭. ফাইল সাবমিট", "7. File Submit"),
    ("product_store", "৮. প্রোডাক্ট স্টোর", "8. Product Store"),
    ("deposit", "৯. ডিপোজিট ও OCR", "9. Deposit & OCR"),
    ("withdraw", "১০. উইথড্র ও ওয়ালেট", "10. Withdraw & Wallet"),
    ("otp_receiver", "১১. OTP রিসিভার", "11. OTP Receiver"),
    ("growth_lb", "১২. রেফারেল, বোনাস, চেক-ইন, লিডারবোর্ড", "12. Growth & Leaderboard"),
    ("tickets_appeals", "১৩. টিকেট, আপিল ও ওয়ার্নিং", "13. Tickets, Appeals & Warnings"),
    ("notifications", "১৪. নোটিফিকেশন", "14. Notifications"),
    ("channel_formats", "১৫. চ্যানেল পোস্ট ফরম্যাট", "15. Channel Post Formats"),
    ("reject_reasons", "১৬. রিজেক্ট কারণ", "16. Reject Reasons"),
    ("locks_abuse", "১৭. লক ও অ্যান্টি-অ্যাবিউজ", "17. Locks & Anti-Abuse"),
    ("system_errors", "১৮. সিস্টেম এরর ও নির্দেশনা", "18. System Errors & Prompts"),
)


class ConfigManager:
    """
    Manages typed persistent settings with change history audit, conflict validation,
    and dynamic bot name resolution (no hardcoded bot name).
    """

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self._lock = threading.RLock()
        self._cache: Dict[str, str] = {}

    def reload_cache(self) -> None:
        rows = self.db.query_all("SELECT key, value FROM settings")
        with self._lock:
            self._cache = {str(r["key"]): str(r["value"]) for r in rows}

    def get_str(self, key: str, default: str = "") -> str:
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        row = self.db.query_one("SELECT value FROM settings WHERE key=?", (key,))
        if row is not None:
            val = str(row["value"])
            with self._lock:
                self._cache[key] = val
            return val
        return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        raw = self.get_str(key, "1" if default else "0").strip().lower()
        return raw in {"1", "true", "yes", "on"}

    def get_int(self, key: str, default: int = 0) -> int:
        raw = self.get_str(key, str(default)).strip()
        try:
            return int(float(raw))
        except Exception:
            return default

    def get_float(self, key: str, default: float = 0.0) -> float:
        raw = self.get_str(key, str(default)).strip()
        try:
            return float(raw)
        except Exception:
            return default

    def set_setting(
        self,
        key: str,
        value: Any,
        admin_id: int = 0,
        reason: str = "admin_update",
        value_type: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Tuple[bool, str]:
        if isinstance(value, bool):
            val_str = "1" if value else "0"
            inferred_type = "bool"
        elif isinstance(value, int):
            val_str = str(value)
            inferred_type = "int"
        elif isinstance(value, float):
            val_str = str(value)
            inferred_type = "float"
        else:
            val_str = str(value)
            inferred_type = "str"

        # Conflict validation
        if key in {"ocr_cloud_api_key", "otp_webhook_secret", "otp_provider_api_key", "admin_panel_password"}:
            SECRET_FILTER.register_secret(val_str)

        old_row = self.db.query_one("SELECT value, value_type, category FROM settings WHERE key=?", (key,))
        old_val = str(old_row["value"]) if old_row else ""
        final_type = value_type or (str(old_row["value_type"]) if old_row else inferred_type)
        final_cat = category or (str(old_row["category"]) if old_row else "general")
        now_s = now_utc_iso()

        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value, value_type, category, updated_at, updated_by)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    value_type=excluded.value_type,
                    updated_at=excluded.updated_at,
                    updated_by=excluded.updated_by
                """,
                (key, val_str, final_type, final_cat, now_s, admin_id),
            )
            if old_val != val_str:
                conn.execute(
                    """
                    INSERT INTO settings_history (setting_key, old_value, new_value, admin_id, reason, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (key, old_val, val_str, admin_id, reason, now_s),
                )
        with self._lock:
            self._cache[key] = val_str
        return True, "Updated"

    def toggle_bool(self, key: str, admin_id: int = 0, reason: str = "toggle") -> bool:
        new_val = not self.get_bool(key, False)
        self.set_setting(key, new_val, admin_id=admin_id, reason=reason)
        return new_val

    def get_bot_name(self, lang: str = "bn") -> str:
        return resolve_bot_name(self.get_str, lang=lang)

    def get_theme(self) -> Dict[str, str]:
        return {
            "name": self.get_str("theme_name", "Royal Modern"),
            "icon": self.get_str("theme_header_icon", "💎"),
            "divider": self.get_str("theme_divider", "━━━━━━━━━━━━━━━━━━━━"),
        }

    def list_settings_by_category(self, category: str) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM settings WHERE category=? ORDER BY key",
            (category,),
        )

    def get_recent_history(self, limit: int = 30) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM settings_history ORDER BY id DESC LIMIT ?",
            (limit,),
        )


class TextManager:
    """
    Manages all bilingual (BN/EN) texts & user rules stored in bot_texts (RULE 6, 40-Rules, 90.A).
    Supports category browsing, search, independent BN/EN edits, HTML validation, and reset.
    """

    def __init__(self, db: DatabaseManager, config: ConfigManager) -> None:
        self.db = db
        self.config = config

    def get_raw_row(self, text_key: str) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM bot_texts WHERE text_key=?", (text_key,))

    def get_text(self, text_key: str, lang: str = "bn", **kwargs: Any) -> str:
        row = self.get_raw_row(text_key)
        theme = self.config.get_theme()
        bot_name = self.config.get_bot_name(lang=lang)
        fmt_vars: Dict[str, Any] = {
            "bot_name": escape_html(bot_name),
            "divider": escape_html(theme["divider"]),
            "header_icon": escape_html(theme["icon"]),
        }
        for k, v in kwargs.items():
            if k in {"raw_html", "buttons_preview"}:
                fmt_vars[k] = v
            else:
                fmt_vars[k] = escape_html(v)

        if row is None:
            return f"[{text_key}]"
        if int(row["is_active"]) == 0 or int(row["is_hidden"]) == 1:
            return ""
        template = str(row["text_bn"] if lang == "bn" else row["text_en"])
        if not template.strip():
            template = str(row["text_en"] if lang == "bn" else row["text_bn"])
        try:
            template = template.replace('[{"name":...}]', '[{{"name":...}}]')
            rendered = template.format_map(_SafeFormatDict(fmt_vars))
        except Exception:
            rendered = template

        per_key_mode = self.config.get_str(f"msg_size_txt_{text_key}", "global")
        size_mode = self.config.get_str("message_size_mode", "current") if per_key_mode == "global" else per_key_mode

        if size_mode == "short":
            if text_key == "welcome_header":
                return f"{fmt_vars['header_icon']} স্বাগতম <b>{escape_html(kwargs.get('name',''))}</b>! (<code>{escape_html(kwargs.get('user_id',''))}</code>)" if lang == "bn" else f"{fmt_vars['header_icon']} Welcome <b>{escape_html(kwargs.get('name',''))}</b>!"
            if text_key == "main_menu_header":
                return f"{fmt_vars['header_icon']} <b>{fmt_vars['bot_name']}</b> | 💰 <code>{escape_html(kwargs.get('balance',''))}</code>"
            if text_key == "profile_template":
                return f"👤 <b>{escape_html(kwargs.get('name',''))}</b> (<code>{escape_html(kwargs.get('user_id',''))}</code>) | 🏅 {escape_html(kwargs.get('vip_tier',''))} | ✅ {escape_html(kwargs.get('tasks_ok','0'))} Tasks"
            if text_key == "balance_template":
                return f"💰 মোট: <code>{escape_html(kwargs.get('available',''))}</code> (Earned: <code>{escape_html(kwargs.get('earned',''))}</code> | Dep: <code>{escape_html(kwargs.get('deposit',''))}</code>)"
            rendered = apply_message_size_style(rendered, "short", divider=theme["divider"], preserve_full_lines=(text_key == "force_join_required"))
        elif size_mode == "medium":
            rendered = apply_message_size_style(rendered, "medium", divider=theme["divider"])
        return rendered

    def list_categories(self) -> List[Tuple[str, str, str, int]]:
        rows = self.db.query_all("SELECT category, COUNT(*) AS c FROM bot_texts GROUP BY category")
        count_map = {str(r["category"]): int(r["c"]) for r in rows}
        return [(cat, bn, en, count_map.get(cat, 0)) for cat, bn, en in TEXT_CATEGORIES]

    def list_by_category(self, category: str) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM bot_texts WHERE category=? ORDER BY text_key",
            (category,),
        )

    def search_texts(self, query_text: str, limit: int = 30) -> List[sqlite3.Row]:
        q = f"%{query_text.strip()}%"
        return self.db.query_all(
            """
            SELECT * FROM bot_texts
            WHERE text_key LIKE ? OR label_bn LIKE ? OR label_en LIKE ? OR text_bn LIKE ? OR text_en LIKE ?
            ORDER BY category, text_key LIMIT ?
            """,
            (q, q, q, q, q, limit),
        )

    @staticmethod
    def validate_html_and_placeholders(text: str) -> Tuple[bool, str]:
        open_tags = re.findall(r"<(b|i|u|s|code|pre|blockquote)>", text)
        close_tags = re.findall(r"</(b|i|u|s|code|pre|blockquote)>", text)
        if len(open_tags) != len(close_tags):
            return False, "HTML tag mismatch: opened and closed tag counts do not match."
        try:
            text.format_map(_SafeFormatDict({"bot_name": "X", "divider": "---", "header_icon": "*"}))
        except Exception as exc:
            return False, f"Invalid placeholder syntax: {exc}"
        return True, ""

    def update_text(
        self,
        text_key: str,
        lang_code: str,
        new_text: str,
        admin_id: int,
    ) -> Tuple[bool, str]:
        ok, err = self.validate_html_and_placeholders(new_text)
        if not ok:
            return False, err
        row = self.get_raw_row(text_key)
        if row is None:
            return False, "Text key not found."
        col = "text_bn" if lang_code == "bn" else "text_en"
        old_val = str(row[col])
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                f"UPDATE bot_texts SET {col}=?, updated_at=?, updated_by=? WHERE text_key=?",
                (new_text, now_s, admin_id, text_key),
            )
            conn.execute(
                """
                INSERT INTO settings_history (setting_key, old_value, new_value, admin_id, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (f"bot_texts.{text_key}.{lang_code}", old_val[:500], new_text[:500], admin_id, "text_edit", now_s),
            )
        return True, "Text updated successfully."

    def toggle_text_flag(self, text_key: str, field: str, admin_id: int) -> Tuple[bool, int]:
        if field not in ("is_active", "is_hidden"):
            return False, 0
        row = self.get_raw_row(text_key)
        if row is None:
            return False, 0
        new_val = 0 if int(row[field]) == 1 else 1
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                f"UPDATE bot_texts SET {field}=?, updated_at=?, updated_by=? WHERE text_key=?",
                (new_val, now_utc_iso(), admin_id, text_key),
            )
        return True, new_val

    def reset_text_to_default(self, text_key: str, admin_id: int) -> bool:
        row = self.get_raw_row(text_key)
        if row is None:
            return False
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                UPDATE bot_texts
                SET text_bn=default_bn, text_en=default_en, is_active=1, is_hidden=0, updated_at=?, updated_by=?
                WHERE text_key=?
                """,
                (now_utc_iso(), admin_id, text_key),
            )
        return True


class _SafeFormatDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


# ==============================================================================
# SECTOR & RULE CONTROLLER (SECTORS 1-17, RULE 1-96+, TOTP DUP & COOKIE VERIFY)
# ==============================================================================

SECTORS_CATALOG: Tuple[Tuple[int, str, str], ...] = (
    (1, "সেক্টর ১: মূল প্রযুক্তি, SQLite ও টোকেন", "Sector 1: Core Tech, SQLite & Token"),
    (2, "সেক্টর ২: চ্যানেল, সাপোর্ট ও ফোর্স জয়েন", "Sector 2: Channels, Support & Force Join"),
    (3, "সেক্টর ৩: ইউজার, প্রোফাইল, ব্যালেন্স ও ওয়ার্নিং", "Sector 3: Users, Profile, Balance & Warnings"),
    (4, "সেক্টর ৪: বাংলা/English ভাষা ও টেক্সট ম্যানেজার", "Sector 4: BN/EN Language & Text Manager"),
    (5, "সেক্টর ৫: ডুয়াল কিবোর্ড, বাটন কালার ও থিম", "Sector 5: Dual Keyboard, Colors & Theme"),
    (6, "সেক্টর ৬: টাস্ক, TOTP কী ও কুকি যাচাই", "Sector 6: Tasks, 16/32 Key & Cookie Verify"),
    (7, "সেক্টর ৭: লিমিট, ডুপ্লিকেট ও Auto-Review", "Sector 7: Limits, Duplicates & Auto-Review"),
    (8, "সেক্টর ৮: ফাইল সাবমিট ও ব্যাচ রিভিউ", "Sector 8: File Submit & Batch Review"),
    (9, "সেক্টর ৯: ডিজিটাল প্রোডাক্ট স্টোর", "Sector 9: Digital Product Store"),
    (10, "সেক্টর ১০: মাল্টি-কান্ট্রি OTP রিসিভার", "Sector 10: Multi-Country OTP Receiver"),
    (11, "সেক্টর ১১: ডিপোজিট OCR ও স্মার্ট উইথড্র", "Sector 11: Deposit OCR & Smart Withdraw"),
    (12, "সেক্টর ১২: রেফারেল, বোনাস, চেক-ইন, লিডারবোর্ড", "Sector 12: Referral, Bonus, Check-in & LB"),
    (13, "সেক্টর ১৩: টিকেট, আপিল, ব্রডকাস্ট ও কিউ", "Sector 13: Tickets, Appeals & Broadcast"),
    (14, "সেক্টর ১৪: রিপোর্ট, অ্যান্টি-অ্যাবিউজ ও লক", "Sector 14: Reports, Anti-Abuse & Locks"),
    (15, "সেক্টর ১৫: এডমিন প্যানেল, পারমিশন ও ব্যাকআপ", "Sector 15: Admin Panel, Permissions & Backup"),
    (16, "সেক্টর ১৬: আর্কিটেকচার ও সেলফ-টেস্ট", "Sector 16: Architecture & Self-Test"),
    (17, "সেক্টর ১৭: সেন্ট্রাল মেসেজ স্টুডিও (RULE 96)", "Sector 17: Central Message Studio"),
)


class RuleController:
    """
    Provides bilingual (BN/EN) admin control over every Sector, Rule, and sub-rule:
    ON/OFF, Hide/Unhide, Edit BN/EN descriptions, Edit rule config, and Reset.
    """

    def __init__(self, db: DatabaseManager, config: ConfigManager) -> None:
        self.db = db
        self.config = config

    def list_sectors(self) -> List[Tuple[int, str, str, int, int]]:
        rows = self.db.query_all(
            "SELECT sector_no, COUNT(*) AS total, SUM(is_enabled) AS active_cnt FROM rule_controls GROUP BY sector_no"
        )
        stats = {int(r["sector_no"]): (int(r["total"]), int(r["active_cnt"] or 0)) for r in rows}
        return [
            (s_no, bn, en, stats.get(s_no, (0, 0))[0], stats.get(s_no, (0, 0))[1])
            for s_no, bn, en in SECTORS_CATALOG
        ]

    def list_rules_by_sector(self, sector_no: int) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM rule_controls WHERE sector_no=? ORDER BY sort_order, rule_key",
            (sector_no,),
        )

    def get_rule(self, rule_key: str) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM rule_controls WHERE rule_key=?", (rule_key,))

    def is_rule_enabled(self, rule_key: str, default: bool = True) -> bool:
        row = self.get_rule(rule_key)
        if row is None:
            return default
        return int(row["is_enabled"]) == 1

    def toggle_rule(self, rule_key: str, field: str, admin_id: int) -> Tuple[bool, str, int]:
        if field not in ("is_enabled", "is_hidden"):
            return False, "Invalid field.", 0
        row = self.get_rule(rule_key)
        if row is None:
            return False, "Rule not found.", 0
        if int(row["is_locked"]) == 1 and field == "is_enabled":
            return False, "Core safety rule cannot be disabled.", int(row[field])
        new_val = 0 if int(row[field]) == 1 else 1
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                f"UPDATE rule_controls SET {field}=?, updated_at=? WHERE rule_key=?",
                (new_val, now_s, rule_key),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', ?, 'rule_control', ?, ?, ?)
                """,
                (admin_id, f"toggle_{field}", rule_key, safe_json_dumps({"value": new_val}), now_s),
            )
        return True, "Updated", new_val

    def update_rule_texts(
        self,
        rule_key: str,
        lang: str,
        title: Optional[str],
        desc: Optional[str],
        admin_id: int,
    ) -> Tuple[bool, str]:
        row = self.get_rule(rule_key)
        if row is None:
            return False, "Rule not found."
        t_col = "title_bn" if lang == "bn" else "title_en"
        d_col = "desc_bn" if lang == "bn" else "desc_en"
        new_title = title.strip() if title is not None and title.strip() else str(row[t_col])
        new_desc = desc.strip() if desc is not None else str(row[d_col])
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                f"UPDATE rule_controls SET {t_col}=?, {d_col}=?, updated_at=? WHERE rule_key=?",
                (new_title, new_desc, now_utc_iso(), rule_key),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', 'edit_rule_text', 'rule_control', ?, ?, ?)
                """,
                (admin_id, rule_key, safe_json_dumps({"lang": lang}), now_utc_iso()),
            )
        return True, "Rule text updated."

    def update_rule_config(self, rule_key: str, new_cfg: Dict[str, Any], admin_id: int) -> Tuple[bool, str]:
        row = self.get_rule(rule_key)
        if row is None:
            return False, "Rule not found."
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE rule_controls SET config_json=?, updated_at=? WHERE rule_key=?",
                (safe_json_dumps(new_cfg), now_utc_iso(), rule_key),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', 'edit_rule_config', 'rule_control', ?, ?, ?)
                """,
                (admin_id, rule_key, safe_json_dumps(new_cfg), now_utc_iso()),
            )
        return True, "Rule configuration updated."

    def reset_rule(self, rule_key: str, admin_id: int) -> bool:
        row = self.get_rule(rule_key)
        if row is None:
            return False
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                UPDATE rule_controls
                SET is_enabled=1, is_hidden=0, config_json=default_config_json, updated_at=?
                WHERE rule_key=?
                """,
                (now_utc_iso(), rule_key),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', 'reset_rule', 'rule_control', ?, '{}', ?)
                """,
                (admin_id, rule_key, now_utc_iso()),
            )
        return True


# ==============================================================================
# DEFAULT SEEDER (IDEMPOTENT INITIAL DATA FOR ALL 17 SECTORS + TOTP & COOKIE)
# ==============================================================================

class DefaultSeeder:
    """
    Seeds default settings, channels, support contacts, buttons (U-01..U-17),
    18-category bilingual texts, rule_controls, deposit/withdraw methods,
    reject templates, and initial leaderboard cycles without overwriting existing data.
    """

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def seed_all(self) -> None:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            self._seed_settings(conn, now_s)
            self._seed_channels_and_support(conn, now_s)
            self._seed_dynamic_buttons(conn, now_s)
            self._seed_bot_texts(conn, now_s)
            self._seed_rule_controls(conn, now_s)
            self._seed_payment_methods(conn, now_s)
            self._seed_reject_templates(conn, now_s)
            self._seed_leaderboard_cycles(conn, now_s)

    def _seed_settings(self, conn: sqlite3.Connection, now_s: str) -> None:
        defaults: List[Tuple[str, str, str, str, str, str]] = [
            ("bot_name_bn", "AUTO", "str", "general", "বাংলা বট নাম (AUTO দিলে Telegram নাম নেবে)", "Bot Name BN (AUTO uses Telegram name)"),
            ("bot_name_en", "AUTO", "str", "general", "ইংরেজি বট নাম (AUTO দিলে Telegram নাম নেবে)", "Bot Name EN (AUTO uses Telegram name)"),
            ("default_language", "bn", "str", "language", "ডিফল্ট ভাষা (bn/en)", "Default language"),
            ("language_switcher_enabled", "1", "bool", "language", "ভাষা পরিবর্তনের বাটন চালু", "Language switcher enabled"),
            ("theme_name", "Royal Modern", "str", "theme", "থিমের নাম", "Theme name"),
            ("theme_header_icon", "💎", "str", "theme", "হেডার আইকন", "Header icon"),
            ("theme_divider", "━━━━━━━━━━━━━━━━━━━━", "str", "theme", "ডিভাইডার লাইন", "Divider line"),
            ("reply_keyboard_enabled", "1", "bool", "keyboard", "নিচের Reply Keyboard চালু", "Reply keyboard enabled"),
            ("reply_keyboard_hidden", "0", "bool", "keyboard", "Reply Keyboard লুকানো", "Reply keyboard hidden"),
            ("inline_keyboard_enabled", "1", "bool", "keyboard", "মেসেজের Inline Keyboard চালু", "Inline keyboard enabled"),
            ("inline_keyboard_hidden", "0", "bool", "keyboard", "Inline Keyboard লুকানো", "Inline keyboard hidden"),
            ("reply_placeholder_bn", "মেনু থেকে একটি অপশন বেছে নিন...", "str", "keyboard", "Reply কিবোর্ড প্লেসহোল্ডার (BN)", "Reply placeholder BN"),
            ("reply_placeholder_en", "Choose an option from menu...", "str", "keyboard", "Reply কিবোর্ড প্লেসহোল্ডার (EN)", "Reply placeholder EN"),
            ("menu_columns", "2", "int", "keyboard", "মেনু কলাম সংখ্যা (১ বা ২)", "Menu columns"),
            ("button_colors_enabled", "1", "bool", "colors", "API 9.4 বাটন কালার সিস্টেম চালু", "Button color system enabled"),
            ("color_action_primary", "primary", "str", "colors", "প্রাইমারি অ্যাকশন রঙ", "Primary action style"),
            ("color_action_confirm", "success", "str", "colors", "কনফার্ম অ্যাকশন রঙ", "Confirm action style"),
            ("color_action_cancel", "danger", "str", "colors", "বাতিল/রিজেক্ট রঙ", "Cancel action style"),
            ("color_action_copy", "success", "str", "colors", "কপি বাটন রঙ", "Copy action style"),
            ("force_join_enabled", "1", "bool", "force_join", "ফোর্স জয়েন চালু/বন্ধ", "Force join master toggle"),
            ("force_join_hidden", "0", "bool", "force_join", "ফোর্স জয়েন লুকানো", "Force join hidden"),
            ("force_join_strict", "1", "bool", "force_join", "সব চ্যানেলে বাধ্যতামূলক জয়েন", "Strict multi-channel lock"),
            ("force_join_check_freq", "always", "str", "force_join", "জয়েন চেক ফ্রিকোয়েন্সি", "Join check frequency"),
            # New TOTP Dup + Cookie Verification Global Settings (Section 09)
            ("global_totp_enabled", "1", "bool", "task_totp", "১৬/৩২ কী থেকে ৬-ডিজিট TOTP সিস্টেম", "Global 16/32 TOTP system"),
            ("global_totp_dup_block", "1", "bool", "task_totp", "একই ১৬/৩২ কী ডুপ্লিকেট ব্লক", "Global TOTP duplicate block"),
            ("global_cookie_step_enabled", "1", "bool", "task_cookie", "পুরো বটে কুকি নেওয়ার ধাপ চালু/বন্ধ", "Global cookie step ON/OFF"),
            ("global_cookie_dup_block", "1", "bool", "task_cookie", "একই কুকি একাধিকবার জমা দেওয়া ব্লক", "Global cookie duplicate block"),
            ("global_cookie_required_keys", "none", "str", "task_cookie", "কুকিতে বাধ্যতামূলক কী (যেমন c_user,xs বা none)", "Required cookie keys or none"),
            ("internal_test_code_enabled", "1", "bool", "task_totp", "অভ্যন্তরীণ টেস্ট কোড চালু", "Internal test code enabled"),
            ("internal_test_code_len", "16", "int", "task_totp", "টেস্ট কোড দৈর্ঘ্য (16/32)", "Internal test code length"),
            ("internal_test_code_single_use", "1", "bool", "task_totp", "টেস্ট কোড সিঙ্গেল-ইউজ", "Internal test code single-use"),
            # Task & Auto-Review & Limits
            ("global_task_daily_limit", "0", "int", "limits", "গ্লোবাল দৈনিক টাস্ক লিমিট (0=Unlimited)", "Global daily task limit"),
            ("global_task_cooldown_sec", "0", "int", "limits", "গ্লোবাল টাস্ক কুলডাউন (সেকেন্ড)", "Global task cooldown sec"),
            ("excel_export_cooldown_hours", "24", "int", "limits", "এক্সেল এক্সপোর্ট কুলডাউন (ঘণ্টা)", "Excel export cooldown hours"),
            ("duplicate_check_scope", "global", "str", "limits", "ডুপ্লিকেট স্কোপ (global/task/user)", "Duplicate check scope"),
            ("duplicate_hash_check", "1", "bool", "limits", "SHA-256 হ্যাশ ডুপ্লিকেট চেক", "SHA-256 hash check"),
            ("task_auto_approve_global", "0", "bool", "auto_review", "টাস্ক গ্লোবাল Auto-Approve", "Global task auto-approve"),
            ("task_auto_approve_sec", "60", "int", "auto_review", "টাস্ক Auto-Approve সময় (সেকেন্ড)", "Task auto-approve seconds"),
            ("task_auto_reject_global", "0", "bool", "auto_review", "টাস্ক গ্লোবাল Auto-Reject", "Global task auto-reject"),
            ("task_auto_reject_sec", "300", "int", "auto_review", "টাস্ক Auto-Reject সময় (সেকেন্ড)", "Task auto-reject seconds"),
            ("task_auto_delete_default", "0", "bool", "tasks", "নতুন টাস্কে Auto-Delete ডিফল্ট", "Default auto-delete messages"),
            ("task_allocation_timeout_sec", "900", "int", "tasks", "সোর্স রেকর্ড বরাদ্দ মেয়াদ (সেকেন্ড)", "Allocation timeout seconds"),
            # Deposit, OCR & Auto-Review
            ("deposit_auto_approve_global", "0", "bool", "auto_review", "ডিপোজিট গ্লোবাল Auto-Approve", "Global deposit auto-approve"),
            ("deposit_auto_approve_sec", "60", "int", "auto_review", "ডিপোজিট Auto-Approve সময় (সেকেন্ড)", "Deposit auto-approve seconds"),
            ("deposit_auto_reject_global", "0", "bool", "auto_review", "ডিপোজিট গ্লোবাল Auto-Reject", "Global deposit auto-reject"),
            ("deposit_auto_reject_sec", "300", "int", "auto_review", "ডিপোজিট Auto-Reject সময় (সেকেন্ড)", "Deposit auto-reject seconds"),
            ("deposit_proof_auto_reject", "1", "bool", "auto_review", "প্রুফ/TxID অমিল বা অনুপস্থিত Auto-Reject", "Deposit proof auto-reject"),
            ("deposit_max_auto_cap", "5000", "float", "auto_review", "অটো-অ্যাপ্রুভ সর্বোচ্চ অ্যামাউন্ট ক্যাপ", "Max auto-approve deposit cap"),
            ("ocr_enabled", "1", "bool", "deposit", "ডিপোজিট স্ক্রিনশট OCR TxID ম্যাচিং চালু", "Deposit screenshot OCR enabled"),
            ("ocr_cloud_api_url", "", "str", "deposit", "Cloud OCR HTTP API Endpoint", "Cloud OCR API URL"),
            ("ocr_cloud_api_key", "", "str", "deposit", "Cloud OCR API Key", "Cloud OCR API Key"),
            ("ocr_txid_regex", r"\b[A-Z0-9]{8,20}\b", "str", "deposit", "OCR TxID এক্সট্র্যাকশন Regex", "OCR TxID Regex"),
            ("ocr_strict_mismatch_reject", "1", "bool", "deposit", "OCR TxID না মিললে সাথে সাথে অটো-রিজেক্ট", "Strict reject on OCR mismatch"),
            ("ocr_unreadable_policy", "flag_manual", "str", "deposit", "OCR অস্পষ্ট হলে নীতি (flag_manual/strict_reject)", "Unreadable OCR fallback"),
            ("ocr_amount_match", "0", "bool", "deposit", "OCR দিয়ে অ্যামাউন্ট ম্যাচিং বাধ্যতামূলক", "OCR amount matching"),
            # Anti-Abuse 77.1 - 77.8 & System Locks
            ("anti_dup_txid_hash", "1", "bool", "security", "৭৭.১ ডুপ্লিকেট TxID ও হ্যাশ ব্লক", "Block duplicate TxID/hash"),
            ("anti_multi_wallet_block", "1", "bool", "security", "৭৭.২ এক ওয়ালেটে মাল্টি-অ্যাকাউন্ট ব্লক", "Block shared wallet multi-account"),
            ("anti_wash_enabled", "1", "bool", "security", "৭৭.৩ Deposit বনাম Earned পৃথকীকরণ", "Anti-wash earned vs deposit"),
            ("anti_spam_rate_limit", "1", "bool", "security", "৭৭.৪ স্প্যাম রেট-লিমিট", "Anti-spam rate limit"),
            ("anti_spam_max_per_min", "25", "int", "security", "প্রতি মিনিটে সর্বোচ্চ অ্যাকশন", "Max actions per minute"),
            ("big_withdraw_threshold", "5000", "float", "security", "৭৭.৫ বড় উইথড্র অটো-হোল্ড সীমা", "Big withdraw threshold"),
            ("low_stock_alert_enabled", "1", "bool", "security", "৭৭.৬ লো-স্টক অ্যালার্ট চালু", "Low stock alert enabled"),
            ("low_stock_threshold", "5", "int", "security", "লো-স্টক থ্রেশহোল্ড", "Low stock threshold"),
            ("warning_auto_block_enabled", "1", "bool", "security", "৭৭.৭ ওয়ার্নিং স্ট্রাইক অটো-ব্লক", "Warning strike auto-block"),
            ("warning_auto_block_strikes", "3", "int", "security", "কতটি স্ট্রাইকে ব্লক হবে", "Strikes before auto-block"),
            ("emergency_panic_freeze", "0", "bool", "security", "৭৭.৮ ইমার্জেন্সি প্যানিক ফ্রিজ", "Emergency panic freeze"),
            ("admin_panel_password_enabled", "0", "bool", "security", "এডমিন প্যানেল পাসওয়ার্ড লক চালু/বন্ধ", "Admin panel password lock ON/OFF"),
            ("admin_panel_password", "", "str", "security", "এডমিন প্যানেল প্রবেশ পাসওয়ার্ড", "Admin panel entry password"),
            ("admin_panel_password_main", "0", "bool", "security", "মূল এডমিনের জন্যও পাসওয়ার্ড চাওয়া", "Require password for Main Admin too"),
            ("maintenance_mode", "0", "bool", "locks", "মেইনটেন্যান্স মোড", "Maintenance mode"),
            ("lock_task", "0", "bool", "locks", "টাস্ক লক", "Task module lock"),
            ("lock_fs", "0", "bool", "locks", "ফাইল সাবমিট লক", "File submit lock"),
            ("lock_store", "0", "bool", "locks", "স্টোর লক", "Store lock"),
            ("lock_otp", "0", "bool", "locks", "OTP লক", "OTP lock"),
            ("lock_deposit", "0", "bool", "locks", "ডিপোজিট লক", "Deposit lock"),
            ("lock_withdraw", "0", "bool", "locks", "উইথড্র লক", "Withdraw lock"),
            ("lock_registration", "0", "bool", "locks", "নতুন রেজিস্ট্রেশন লক", "Registration lock"),
            ("lock_reward", "0", "bool", "locks", "রিওয়ার্ড/বোনাস লক", "Reward lock"),
            ("lock_full_system", "0", "bool", "locks", "সম্পূর্ণ সিস্টেম লক", "Full system lock"),
            # Growth, FS, Store, OTP, Backup & Scheduler
            ("referral_enabled", "1", "bool", "growth", "রেফারেল সিস্টেম চালু", "Referral system enabled"),
            ("referral_commission_type", "percent", "str", "growth", "রেফারেল কমিশন ধরন (percent/fixed)", "Referral commission type"),
            ("referral_commission_value", "10.0", "float", "growth", "রেফারেল কমিশন মান", "Referral commission value"),
            ("fs_commission_enabled", "1", "bool", "growth", "স্বাধীন FS কমিশন চালু", "FS commission enabled"),
            ("fs_commission_type", "percent", "str", "growth", "FS কমিশন ধরন", "FS commission type"),
            ("fs_commission_value", "5.0", "float", "growth", "FS কমিশন মান", "FS commission value"),
            ("daily_checkin_enabled", "1", "bool", "growth", "ডেইলি চেক-ইন চালু", "Daily check-in enabled"),
            ("daily_checkin_amount", "2.0", "float", "growth", "দৈনিক চেক-ইন বোনাস", "Daily check-in amount"),
            ("daily_checkin_streak7_bonus", "10.0", "float", "growth", "৭ দিন স্ট্রিক বোনাস", "7-day streak bonus"),
            ("daily_checkin_streak30_bonus", "50.0", "float", "growth", "৩০ দিন স্ট্রিক বোনাস", "30-day streak bonus"),
            ("task_lb_enabled", "1", "bool", "growth", "টাস্ক লিডারবোর্ড চালু", "Task leaderboard enabled"),
            ("fs_lb_enabled", "1", "bool", "growth", "ফাইল সাবমিট লিডারবোর্ড চালু", "FS leaderboard enabled"),
            ("lb_top_n", "10", "int", "growth", "লিডারবোর্ড প্রদর্শন সংখ্যা (Top N)", "Leaderboard Top N"),
            ("lb_mask_privacy", "1", "bool", "growth", "লিডারবোর্ডে নামের প্রাইভেসি মাস্কিং", "Leaderboard privacy masking"),
            ("points_exchange_enabled", "0", "bool", "extensions", "পয়েন্টস থেকে টাকা এক্সচেঞ্জ চালু", "Points exchange enabled"),
            ("points_per_currency", "100", "float", "extensions", "প্রতি ১ টাকায় কত পয়েন্ট", "Points per 1 currency unit"),
            ("happy_hour_enabled", "0", "bool", "extensions", "হ্যাপি-আওয়ার বোনাস মাল্টিপ্লায়ার", "Happy hour enabled"),
            ("happy_hour_multiplier", "1.5", "float", "extensions", "হ্যাপি-আওয়ার গুণিতক", "Happy hour multiplier"),
            ("otp_system_enabled", "1", "bool", "otp", "OTP রিসিভার সিস্টেম চালু", "OTP receiver enabled"),
            ("otp_relay_bridge_enabled", "1", "bool", "otp", "১. প্রাইভেট রিলে চ্যানেল ব্রিজ", "Relay channel bridge"),
            ("otp_webhook_bridge_enabled", "0", "bool", "otp", "২. HTTP Webhook ব্রিজ", "HTTP webhook bridge"),
            ("otp_webhook_port", "8089", "int", "otp", "Webhook লোকাল পোর্ট", "Webhook port"),
            ("otp_webhook_secret", "", "str", "otp", "Webhook সিক্রেট কী", "Webhook secret key"),
            ("otp_provider_api_enabled", "0", "bool", "otp", "৩. প্রোভাইডার API পোলিং ব্রিজ", "Provider API polling"),
            ("otp_provider_api_url", "", "str", "otp", "প্রোভাইডার API URL", "Provider API URL"),
            ("otp_provider_api_key", "", "str", "otp", "প্রোভাইডার API Key", "Provider API key"),
            ("otp_regex", r"(?<!\d)(\d{3}-\d{3}|\d{4,8})(?!\d)", "str", "otp", "OTP কোড এক্সট্র্যাক্ট Regex", "OTP extraction regex"),
            ("otp_max_active_per_user", "3", "int", "otp", "প্রতি ইউজার সর্বোচ্চ সক্রিয় নাম্বার", "Max active OTP numbers per user"),
            ("otp_cancel_cooldown_sec", "30", "int", "otp", "ক্যানসেল কুলডাউন (সেকেন্ড)", "OTP cancel cooldown"),
            ("otp_channel_mask_privacy", "1", "bool", "otp", "OTP চ্যানেলে নাম্বার প্রাইভেসি মাস্কিং", "Mask number in OTP channel"),
            ("max_upload_size_mb", "15", "int", "security", "সর্বোচ্চ ফাইল আপলোড সাইজ (MB)", "Max upload file size MB"),
            ("auto_backup_enabled", "1", "bool", "backup", "Telegram অটো-ব্যাকআপ চালু", "Telegram auto-backup enabled"),
            ("auto_backup_interval_hours", "24", "int", "backup", "কত ঘণ্টা পরপর অটো-ব্যাকআপ", "Auto-backup interval hours"),
            ("auto_backup_target", "channel", "str", "backup", "ব্যাকআপ টার্গেট (main_admin/channel/both)", "Auto-backup target"),
            ("auto_backup_send_individual_files", "1", "bool", "backup", "ব্যাকআপ চ্যানেলে সব ডাউনলোডযোগ্য ফাইল আলাদাভাবে পাঠানো", "Send all downloadable XLSX exports to backup channel"),
            ("last_auto_backup_ts", "0", "str", "backup", "সর্বশেষ অটো-ব্যাকআপ টাইমস্ট্যাম্প", "Last auto-backup epoch timestamp"),
            ("first_join_lang_prompt_enabled", "1", "bool", "language", "প্রথম জয়েনে ভাষা নির্বাচনের মেসেজ চালু", "Ask language on first join"),
            ("message_size_mode", "current", "str", "studio", "মেসেজ সাইজ মোড (current/medium/short)", "Message size mode (current/medium/short)"),
            ("daily_summary_enabled", "1", "bool", "scheduler", "রাত ১২টায় ডেইলি সামারি রিপোর্ট", "Midnight daily summary report"),
            ("payout_mask_user", "1", "bool", "channels", "পেআউট/অর্ডার চ্যানেলে ইউজার প্রাইভেসি মাস্ক", "Mask user in payout channel"),
        ]
        for k, v, vt, cat, dbn, den in defaults:
            conn.execute(
                """
                INSERT OR IGNORE INTO settings (key, value, value_type, category, description_bn, description_en, updated_at, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (k, v, vt, cat, dbn, den, now_s),
            )

    def _seed_channels_and_support(self, conn: sqlite3.Connection, now_s: str) -> None:
        row_cnt = conn.execute("SELECT COUNT(*) AS c FROM channels").fetchone()
        if int(row_cnt["c"]) == 0:
            channels_seed = [
                ("force_join", DEFAULT_FORCE_JOIN_CHANNEL, "Official Channel", f"https://t.me/{DEFAULT_FORCE_JOIN_CHANNEL.lstrip('@')}", 1),
                ("task_fs_review", str(DEFAULT_TASK_FS_REVIEW_CHANNEL), "Task & File Submit Review", "", 1),
                ("finance_review", str(DEFAULT_FINANCE_REVIEW_CHANNEL), "Deposit & Withdraw Review", "", 1),
                ("payout_order", str(DEFAULT_PAYOUT_ORDER_CHANNEL), "Payout & Order Channel", "", 1),
                ("leaderboard", str(DEFAULT_LEADERBOARD_CHANNEL), "Public Leaderboard", "", 1),
            ]
            for purpose, chat_id, title, link, order in channels_seed:
                is_fj = (purpose == "force_join")
                priv_mode = "public" if is_fj else "admin_only"
                join_req = 1 if is_fj else 0
                conn.execute(
                    """
                    INSERT INTO channels (purpose, chat_id, title, join_link, is_active, is_hidden, sort_order, privacy_mode, join_required, created_at)
                    VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?)
                    """,
                    (purpose, chat_id, title, link, order, priv_mode, join_req, now_s),
                )

        sup_cnt = conn.execute("SELECT COUNT(*) AS c FROM support_contacts").fetchone()
        if int(sup_cnt["c"]) == 0:
            conn.execute(
                """
                INSERT INTO support_contacts (name, username_or_link, description_bn, description_en, is_active, is_hidden, sort_order, created_at)
                VALUES (?, ?, ?, ?, 1, 0, 1, ?)
                """,
                (
                    "Official Support",
                    DEFAULT_SUPPORT_USERNAME,
                    "যেকোনো সমস্যায় সরাসরি সাপোর্টে যোগাযোগ করুন",
                    "Contact official support for assistance",
                    now_s,
                ),
            )

    def _seed_dynamic_buttons(self, conn: sqlite3.Connection, now_s: str) -> None:
        # Built-in User Menu Buttons U-01 to U-15 (U-16 custom, U-17 navigation)
        builtins: List[Tuple[str, str, str, str, str, str, str, int, int]] = [
            ("u_tasks", "কাজ করুন", "Tasks", "📋", "builtin", "tasks", "primary", 1, 1),
            ("u_file_submit", "ফাইল সাবমিট", "File Submit", "📁", "builtin", "file_submit", "primary", 1, 2),
            ("u_store", "প্রোডাক্ট স্টোর", "Product Store", "🛒", "builtin", "store", "primary", 2, 3),
            ("u_otp", "নাম্বার OTP", "OTP Receive", "📲", "builtin", "otp", "primary", 2, 4),
            ("u_deposit", "টাকা অ্যাড", "Add Money", "💳", "builtin", "deposit", "primary", 3, 5),
            ("u_withdraw", "টাকা উত্তোলন", "Withdraw", "💸", "builtin", "withdraw", "success", 3, 6),
            ("u_profile", "প্রোফাইল", "Profile", "👤", "builtin", "profile", "default", 4, 7),
            ("u_balance", "ব্যালেন্স", "Balance", "💰", "builtin", "balance", "default", 4, 8),
            ("u_orders", "আমার অর্ডার ও কাজ", "My Orders & Activity", "📦", "builtin", "orders", "default", 5, 9),
            ("u_referral", "রেফারেল", "Referral", "👥", "builtin", "referral", "primary", 5, 10),
            ("u_task_lb", "টাস্ক লিডারবোর্ড", "Task Leaderboard", "🏆", "builtin", "task_lb", "default", 6, 11),
            ("u_fs_lb", "FS লিডারবোর্ড", "FS Leaderboard", "📊", "builtin", "fs_lb", "default", 6, 12),
            ("u_bonus", "ক্যাম্পেইন বোনাস", "Bonus", "🎁", "builtin", "bonus", "success", 7, 13),
            ("u_checkin", "ডেইলি চেক-ইন", "Daily Check-in", "📅", "builtin", "checkin", "success", 7, 14),
            ("u_support", "সাপোর্ট ও টিকেট", "Support & Tickets", "🎫", "builtin", "support", "default", 8, 15),
            ("u_rules", "নিয়মাবলী", "Rules", "📜", "builtin", "rules", "default", 8, 16),
            ("u_language", "ভাষা / Language", "Language / ভাষা", "🌐", "builtin", "language", "default", 9, 17),
        ]
        for bkey, lbn, len_, emoji, atype, atarget, style, row_g, order in builtins:
            conn.execute(
                """
                INSERT OR IGNORE INTO dynamic_buttons
                (button_key, menu_scope, label_bn, label_en, emoji, action_type, action_target,
                 button_style, placement, row_group, sort_order, col_span, is_builtin, is_enabled, is_hidden, is_archived, created_at, updated_at)
                VALUES (?, 'user_main', ?, ?, ?, ?, ?, ?, 'both', ?, ?, 1, 1, 1, 0, 0, ?, ?)
                """,
                (bkey, lbn, len_, emoji, atype, atarget, style, row_g, order, now_s, now_s),
            )

    def _seed_bot_texts(self, conn: sqlite3.Connection, now_s: str) -> None:
        texts: List[Tuple[str, str, str, str, str, str, str]] = [
            (
                "welcome_header",
                "start",
                "স্বাগতম শিরোনাম",
                "Welcome Header",
                "{header_icon} <b>স্বাগতম {name}!</b>\n{divider}\n<b>{bot_name}</b>-এ আপনার অ্যাকাউন্ট প্রস্তুত (আইডি: <code>{user_id}</code>)।",
                "{header_icon} <b>Welcome {name}!</b>\n{divider}\nYour account on <b>{bot_name}</b> is ready (ID: <code>{user_id}</code>).",
                '["name","user_id","bot_name","divider","header_icon"]',
            ),
            (
                "choose_language_prompt",
                "start",
                "প্রথম জয়েন ও ভাষা নির্বাচনের বার্তা",
                "First Join & Choose Language Prompt",
                "🌐 <b>স্বাগতম {bot_name}-এ!</b>\nঅনুগ্রহ করে আপনার পছন্দের ভাষা নির্বাচন করুন (বাংলা / English):",
                "🌐 <b>Welcome to {bot_name}!</b>\nPlease select your preferred language (বাংলা / English):",
                '["bot_name"]',
            ),
            (
                "force_join_required",
                "force_join",
                "ফোর্স জয়েন বাধ্যতামূলক বার্তা",
                "Force Join Required Message",
                "🔐 <b>অ্যাক্সেস লকড!</b>\n{divider}\n<b>{bot_name}</b> ব্যবহার করতে হলে নিচের সবগুলো সক্রিয় চ্যানেলে জয়েন থাকতে হবে:\n\n{channels_status}\n\nজয়েন করার পর <b>✅ Verify Joined</b> চাপুন।",
                "🔐 <b>Access Locked!</b>\n{divider}\nTo use <b>{bot_name}</b>, you must join all active channels below:\n\n{channels_status}\n\nTap <b>✅ Verify Joined</b> after joining.",
                '["bot_name","divider","channels_status"]',
            ),
            (
                "main_menu_header",
                "main_menu",
                "মেইন মেনু শিরোনাম",
                "Main Menu Header",
                "{header_icon} <b>{bot_name} — মেইন মেনু</b>\n{divider}\n👤 <b>{name}</b> | 💰 ব্যালেন্স: <code>{balance}</code>",
                "{header_icon} <b>{bot_name} — Main Menu</b>\n{divider}\n👤 <b>{name}</b> | 💰 Balance: <code>{balance}</code>",
                '["bot_name","divider","header_icon","name","balance"]',
            ),
            (
                "profile_template",
                "profile_balance",
                "প্রোফাইল কার্ড",
                "Profile Card",
                "👤 <b>আমার প্রোফাইল</b>\n{divider}\n🆔 আইডি: <code>{user_id}</code>\n📛 নাম: <b>{name}</b>\n🔗 ইউজারনেম: {username}\n📅 রেজিস্ট্রেশন: {reg_date}\n🏅 VIP লেভেল: <b>{vip_tier}</b> | ⚠️ স্ট্রাইক: {warnings}/{max_strikes}\n🚦 স্ট্যাটাস: <b>{status}</b>\n\n📊 <b>পরিসংখ্যান:</b>\n• টাস্ক Approved: {tasks_ok}\n• FS Approved রেকর্ড: {fs_ok}\n• স্টোর অর্ডার: {orders_ok}\n• ডিপোজিট: {deposits_ok}\n• রেফারেল: {refs_count}",
                "👤 <b>My Profile</b>\n{divider}\n🆔 ID: <code>{user_id}</code>\n📛 Name: <b>{name}</b>\n🔗 Username: {username}\n📅 Registered: {reg_date}\n🏅 VIP Tier: <b>{vip_tier}</b> | ⚠️ Strikes: {warnings}/{max_strikes}\n🚦 Status: <b>{status}</b>\n\n📊 <b>Statistics:</b>\n• Approved Tasks: {tasks_ok}\n• Approved FS Records: {fs_ok}\n• Store Orders: {orders_ok}\n• Deposits: {deposits_ok}\n• Referrals: {refs_count}",
                '["divider","user_id","name","username","reg_date","vip_tier","warnings","max_strikes","status"]',
            ),
            (
                "balance_template",
                "profile_balance",
                "ব্যালেন্স ও লেজার কার্ড",
                "Balance & Ledger Card",
                "💰 <b>ব্যালেন্স ও ওয়ালেট বিবরণ</b>\n{divider}\n✅ মোট উপলব্ধ: <code>{available}</code>\n💵 অর্জিত (Withdraw-যোগ্য): <code>{earned}</code>\n💳 ডিপোজিট (Store/OTP): <code>{deposit}</code>\n🔒 হোল্ড (Pending Withdraw): <code>{held}</code>\n💸 মোট উত্তোলন: <code>{withdrawn}</code>\n📈 সর্বমোট আয়: <code>{total_earnings}</code>",
                "💰 <b>Balance & Wallet Breakdown</b>\n{divider}\n✅ Total Available: <code>{available}</code>\n💵 Earned (Withdrawable): <code>{earned}</code>\n💳 Deposit (Store/OTP): <code>{deposit}</code>\n🔒 Held (Pending Withdraw): <code>{held}</code>\n💸 Total Withdrawn: <code>{withdrawn}</code>\n📈 Total Earnings: <code>{total_earnings}</code>",
                '["divider","available","earned","deposit","held","withdrawn","total_earnings"]',
            ),
            (
                "rules_content",
                "rules",
                "প্ল্যাটফর্মের নিয়মাবলী",
                "Platform Rules",
                "📜 <b>প্ল্যাটফর্মের নতুন নিয়মাবলী</b>\n{divider}\n১. প্রতিটি কাজের নির্দেশনা ভালোভাবে পড়ে সঠিক প্রমাণ জমা দিন।\n২. <b>১৬ বা ৩২ অক্ষরের কী (2FA Key):</b> প্রতিটি কাজে অবশ্যই নতুন ও বৈধ ১৬/৩২ অক্ষরের কী দিতে হবে। একই কী একাধিকবার দিলে সিস্টেম সাথে সাথেই বাতিল (Reject) করবে।\n৩. <b>অ্যাকাউন্ট কুকি (Cookie):</b> কুকি চাওয়া হলে সঠিক ফরম্যাটের (JSON বা key=value;) বৈধ কুকি দিন। ভুয়া, অসম্পূর্ণ বা পূর্বে ব্যবহৃত কুকি দিলে অটো-রিজেক্ট হবে।\n৪. <b>ডিপোজিট ও উইথড্র:</b> ডিপোজিটে স্ক্রিনশটের সাথে TxID মিলতে হবে এবং উইথড্রয়ালের জন্য সঠিক পার্সোনাল ওয়ালেট নম্বর আবশ্যক।\n৫. ডুপ্লিকেট বা ভুয়া তথ্য দেওয়ার চেষ্টা করলে ওয়ার্নিং স্ট্রাইক ও অ্যাকাউন্ট স্থায়ীভাবে ব্লক হতে পারে।",
                "📜 <b>Updated Platform Rules</b>\n{divider}\n1. Read every task instruction carefully and submit genuine proof.\n2. <b>16/32-Char 2FA Key:</b> Always enter a fresh, valid 16 or 32-character Base32 key. Submitting the same key more than once is automatically rejected.\n3. <b>Account Cookies:</b> When requested, provide a valid formatted cookie (JSON or key=value;). Fake, incomplete, or duplicate cookies are instantly rejected.\n4. <b>Deposits & Withdrawals:</b> Deposit TxID must match the payment screenshot, and withdrawals require a valid personal wallet.\n5. Submitting fake or duplicate data may result in warning strikes or permanent account suspension.",
                '["divider"]',
            ),
            (
                "task_totp_prompt",
                "task_prompts",
                "১৬/৩২ কী চাওয়ার প্রম্পট",
                "16/32 Key Prompt",
                "🔑 <b>১৬ বা ৩২ অক্ষরের কী (Base32 Key) দিন:</b>\nউদাহরণ: <code>JBSWY3DPEHPK3PXP</code>\nবট এখান থেকে স্বয়ংক্রিয়ভাবে ৬-ডিজিট TOTP কোড তৈরি করবে এবং ডুপ্লিকেট কী ব্লক করবে।",
                "🔑 <b>Enter your 16 or 32-character Base32 Key:</b>\nExample: <code>JBSWY3DPEHPK3PXP</code>\nA 6-digit TOTP code will be generated and duplicate keys will be blocked.",
                "[]",
            ),
            (
                "task_totp_duplicate_err",
                "task_prompts",
                "ডুপ্লিকেট ১৬/৩২ কী এরর",
                "Duplicate 16/32 Key Error",
                "❌ <b>বাতিল (Rejected):</b> এই ১৬/৩২ অক্ষরের কী আগে থেকেই বটে ব্যবহৃত হয়েছে! অনুগ্রহ করে নতুন ও বৈধ কী দিন।",
                "❌ <b>Rejected:</b> This 16/32-char key has already been used! Please enter a fresh, valid key.",
                "[]",
            ),
            (
                "task_cookie_prompt",
                "task_prompts",
                "অ্যাকাউন্ট কুকি চাওয়ার প্রম্পট",
                "Account Cookie Prompt",
                "🍪 <b>অ্যাকাউন্ট কুকি (Cookie) জমা দিন:</b>\nসমর্থিত ফরম্যাট:\n• <code>key1=val1; key2=val2</code>\n• ব্রাউজার এক্সটেনশন JSON কুকি <code>[{{\"name\":...}}]</code>\n• Netscape ট্যাব-সেপারেটেড কুকি\nবাধ্যতামূলক কী: <code>{required_keys}</code>",
                "🍪 <b>Submit Account Cookie:</b>\nSupported formats:\n• <code>key1=val1; key2=val2</code>\n• Browser extension JSON <code>[{{\"name\":...}}]</code>\n• Netscape tab-separated cookie\nRequired keys: <code>{required_keys}</code>",
                '["required_keys"]',
            ),
            (
                "task_cookie_duplicate_err",
                "task_prompts",
                "ডুপ্লিকেট বা অবৈধ কুকি এরর",
                "Duplicate or Invalid Cookie Error",
                "❌ <b>কুকি রিজেক্ট হয়েছে:</b> {reason}\nঅনুগ্রহ করে সঠিক ফরম্যাটে সম্পূর্ণ নতুন কুকি দিন।",
                "❌ <b>Cookie Rejected:</b> {reason}\nPlease submit a fresh, valid cookie.",
                '["reason"]',
            ),
            (
                "fs_intro_prompt",
                "file_submit",
                "ফাইল সাবমিট নির্দেশনা",
                "File Submit Prompt",
                "📁 <b>ফাইল সাবমিট:</b>\nএকটি কাজ বেছে নিয়ে .txt, .csv, .xls, .xlsx ফাইল আপলোড করুন অথবা সরাসরি টেক্সট পেস্ট করুন।",
                "📁 <b>File Submit:</b>\nSelect an FS task and upload a .txt, .csv, .xls, .xlsx file or paste lines directly.",
                "[]",
            ),
            (
                "store_intro_prompt",
                "product_store",
                "প্রোডাক্ট স্টোর পরিচিতি",
                "Product Store Intro",
                "🛒 <b>ডিজিটাল প্রোডাক্ট স্টোর</b>\n{divider}\nনিচে ক্যাটাগরি ও পণ্যের লাইভ স্টক দেখানো হলো:",
                "🛒 <b>Digital Product Store</b>\n{divider}\nBrowse categories and live available stock below:",
                '["divider"]',
            ),
            (
                "deposit_ocr_mismatch_reject",
                "deposit",
                "OCR TxID অমিল অটো-রিজেক্ট",
                "OCR TxID Mismatch Auto-Reject",
                "❌ <b>ডিপোজিট অটো-রিজেক্ট (TxID অমিল):</b>\nআপনার দেওয়া TxID: <code>{txid_user}</code>\nস্ক্রিনশট থেকে পাওয়া TxID: <code>{txid_ocr}</code>\nতথ্য না মেলায় অনুরোধটি সাথে সাথেই বাতিল করা হয়েছে।",
                "❌ <b>Deposit Auto-Rejected (TxID Mismatch):</b>\nYour TxID: <code>{txid_user}</code>\nExtracted from Screenshot: <code>{txid_ocr}</code>\nRequest was automatically rejected due to mismatch.",
                '["txid_user","txid_ocr"]',
            ),
            (
                "withdraw_intro_prompt",
                "withdraw",
                "উইথড্রয়াল নির্দেশনা",
                "Withdraw Intro",
                "💸 <b>টাকা উত্তোলন (Withdraw)</b>\n{divider}\nউত্তোলনযোগ্য অর্জিত ব্যালেন্স: <code>{earned}</code>\nএকটি পেমেন্ট মেথড বেছে নিন:",
                "💸 <b>Withdraw Funds</b>\n{divider}\nWithdrawable Earned Balance: <code>{earned}</code>\nSelect a payment method:",
                '["divider","earned"]',
            ),
            (
                "otp_intro_prompt",
                "otp_receiver",
                "OTP রিসিভার পরিচিতি",
                "OTP Receiver Intro",
                "📲 <b>মাল্টি-কান্ট্রি OTP রিসিভার</b>\n{divider}\nদেশ ও লাইভ নাম্বার স্টক দেখে একটি দেশ নির্বাচন করুন:",
                "📲 <b>Multi-Country OTP Receiver</b>\n{divider}\nSelect a country with live available numbers:",
                '["divider"]',
            ),
            (
                "referral_dashboard_header",
                "growth_lb",
                "রেফারেল ড্যাশবোর্ড",
                "Referral Dashboard",
                "👥 <b>রেফারেল প্রোগ্রাম</b>\n{divider}\n🔗 আপনার লিংক:\n<code>{ref_link}</code>\n\n👥 মোট রেফারেল: <b>{total_refs} জন</b>\n💹 কমিশন রেট: <b>{rate_text}</b>\n💰 রেফারেল থেকে আয়: <code>{ref_earnings}</code>",
                "👥 <b>Referral Program</b>\n{divider}\n🔗 Your Link:\n<code>{ref_link}</code>\n\n👥 Total Referrals: <b>{total_refs}</b>\n💹 Commission Rate: <b>{rate_text}</b>\n💰 Referral Earnings: <code>{ref_earnings}</code>",
                '["divider","ref_link","total_refs","rate_text","ref_earnings"]',
            ),
            (
                "ticket_intro_prompt",
                "tickets_appeals",
                "সাপোর্ট ও টিকেট বার্তা",
                "Support & Ticket Prompt",
                "🎫 <b>সাপোর্ট ও হেল্প ডেস্ক</b>\n{divider}\nঅফিশিয়াল সাপোর্ট:\n{contacts}\nঅথবা নিচের বাটনে চাপ দিয়ে ইন-বট সাপোর্ট টিকেট খুলুন।",
                "🎫 <b>Support & Help Desk</b>\n{divider}\nOfficial Support:\n{contacts}\nOr tap below to open an in-bot support ticket.",
                '["divider","contacts"]',
            ),
            (
                "generic_notification_prefix",
                "notifications",
                "নোটিফিকেশন প্রিফিক্স",
                "Notification Prefix",
                "🔔 <b>{bot_name} নোটিফিকেশন</b>\n{divider}",
                "🔔 <b>{bot_name} Notification</b>\n{divider}",
                '["bot_name","divider"]',
            ),
            (
                "channel_review_footer",
                "channel_formats",
                "চ্যানেল পোস্ট ফুটার",
                "Channel Post Footer",
                "{divider}\n🕒 সময় (ঢাকা): {dhaka_time}",
                "{divider}\n🕒 Time (Dhaka): {dhaka_time}",
                '["divider","dhaka_time"]',
            ),
            (
                "default_reject_reason",
                "reject_reasons",
                "ডিফল্ট রিজেক্ট কারণ",
                "Default Reject Reason",
                "নির্দেশনা অনুযায়ী সঠিক প্রমাণ পাওয়া যায়নি।",
                "Submitted proof did not match instructions.",
                "[]",
            ),
            (
                "system_locked_msg",
                "locks_abuse",
                "সিস্টেম লক বার্তা",
                "System Locked Message",
                "🔒 <b>সাময়িকভাবে বন্ধ আছে:</b> {feature_name} বর্তমানে এডমিন কর্তৃক লক বা মেইনটেন্যান্সে রয়েছে।",
                "🔒 <b>Temporarily Unavailable:</b> {feature_name} is currently locked or under maintenance.",
                '["feature_name"]',
            ),
            (
                "invalid_input_error",
                "system_errors",
                "ভুল ইনপুট এরর",
                "Invalid Input Error",
                "⚠️ অবৈধ ইনপুট: {detail}। অনুগ্রহ করে সঠিকভাবে আবার চেষ্টা করুন।",
                "⚠️ Invalid input: {detail}. Please try again.",
                '["detail"]',
            ),
        ]
        for key, cat, lbn, len_, tbn, ten, ph in texts:
            conn.execute(
                """
                INSERT OR IGNORE INTO bot_texts
                (text_key, category, label_bn, label_en, text_bn, text_en, default_bn, default_en, placeholders_json, is_active, is_hidden, updated_at, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, 0)
                """,
                (key, cat, lbn, len_, tbn, ten, tbn, ten, ph, now_s),
            )

    def _seed_rule_controls(self, conn: sqlite3.Connection, now_s: str) -> None:
        rules: List[Tuple[str, int, str, str, str, str, str, str, int, int]] = [
            ("RULE_1_CORE", 1, "RULE 1,3,56", "কোর সিস্টেম ও টোকেন সুরক্ষা", "Core System & Token Security", "Python/PTB, Asia/Dhaka ও নিরাপদ টোকেন লোডার।", "Python/PTB, Asia/Dhaka and secure token loader.", "বটের টোকেন পরিবেশ চলক BOT_TOKEN থেকে নিরাপদভাবে লোড হয় এবং লগে মাস্ক থাকে।", 1, 1),
            ("RULE_63_64_SQLITE", 1, "RULE 63-64", "SQLite WAL, SAVEPOINT ও মাইগ্রেশন", "SQLite WAL, SAVEPOINT & Migration", "নন-ডেসট্রাক্টিভ মাইগ্রেশন ও ডাবল-ট্যাপ প্রতিরোধ।", "Non-destructive migration and atomic transactions.", "ডাটাবেজের পুরোনো ডেটা অক্ষত রেখে নতুন কলাম আপডেট হয়; এটি নিরাপত্তার জন্য সর্বদা সক্রিয় থাকে।", 1, 2),
            ("RULE_2_CHANNELS", 2, "RULE 2,95.A", "চ্যানেল, সাপোর্ট ও বাটন সিঙ্ক", "Channels, Support & Button Sync", "রিভিউ, পেআউট, লিডারবোর্ড চ্যানেল ও মিডিয়া ক্যাপশন সিঙ্ক।", "Review, payout, leaderboard channels and caption sync.", "Admin -> Channels & Support থেকে যেকোনো চ্যানেল বা সাপোর্ট আইডি যুক্ত/পরিবর্তন ও Test Post করুন।", 0, 3),
            ("RULE_5_FORCE_JOIN", 2, "RULE 5", "কঠোর মাল্টি-চ্যানেল ফোর্স জয়েন", "Strict Multi-Channel Force Join", "সব সক্রিয় চ্যানেলে জয়েন ছাড়া বট লক থাকবে।", "Locks bot until user joins all active channels.", "Admin -> Force Join থেকে মাস্টার সুইচ ON/OFF ও একাধিক চ্যানেল যুক্ত করুন।", 0, 4),
            ("RULE_4_8_54_73_USER", 3, "RULE 4,8,54,73", "প্রোফাইল, লেজার, ওয়ার্নিং ও এক্সপোর্ট", "Profile, Ledger, Warnings & Export", "অ্যাটমিক লেজার ব্যালেন্স, ওয়ার্নিং স্ট্রাইক ও অল-ইউজার এক্সপোর্ট।", "Atomic ledger balances, warning strikes & all-user export.", "Admin -> Users, Finance & Warnings থেকে যেকোনো ইউজারকে সার্চ, Credit/Deduct, Warning ও Export করুন।", 0, 5),
            ("RULE_6_90A_TEXT", 4, "RULE 6,90.A", "দ্বিভাষিক BN/EN টেক্সট ও রুলস ম্যানেজার", "Bilingual BN/EN Text & Rules Manager", "১৮ ক্যাটাগরির প্রতিটি লাইন এডমিন প্যানেল থেকে পরিবর্তনযোগ্য।", "Every bot text line in 18 categories editable in BN & EN.", "Admin -> Text, Language & Rules থেকে যেকোনো লেখা সার্চ করে BN/EN এডিট ও Reset করুন।", 0, 6),
            ("RULE_88_89_KEYBOARD", 5, "RULE 7,76,88,89", "ডুয়াল কিবোর্ড, বাটন কালার ও ডাইনামিক বাটন", "Dual Keyboard, Button Colors & Custom Builder", "Reply ও Inline আলাদা ON/OFF/Hide ও ৪টি API 9.4 কালার।", "Independent Reply/Inline toggles and 4 official API colors.", "Admin -> Keyboard, Buttons & Colors থেকে Reply/Inline আলাদাভাবে চালু/বন্ধ এবং প্রতিটি বাটনের রঙ বদলান।", 0, 7),
            ("RULE_9_10_91_TASK", 6, "RULE 9-11,83,91", "৫-স্তর টাস্ক, ৬-ধাপ উইজার্ড ও সোর্স কার্ড", "5-Layer Task, Wizard & Source Card", "বাটন-ক্লিক কম্বো/পাসওয়ার্ড উইজার্ড, ফুল নেম/ইউজারনেম সোর্স কার্ড ও অটো-রিলিজ।", "Button-click combo/password wizard, source card and timeout auto-release.", "Admin -> Task Manager থেকে ৬-ধাপের উইজার্ডে টাস্ক বানিয়ে সোর্স ফাইল দিন ও Test as User দিয়ে যাচাই করুন।", 0, 8),
            ("RULE_12_TOTP_DUP", 6, "RULE 12+NEW", "১৬/৩২ কী TOTP ও ডুপ্লিকেট ব্লক", "16/32 Key TOTP & Duplicate Block", "১৬/৩২ অক্ষর থেকে ৬-ডিজিট TOTP কোড ও একই কী ডুপ্লিকেট ব্লক।", "6-digit TOTP generator from 16/32 key with duplicate key blocking.", "Admin -> Task Manager-এর ওপরে 'TOTP Dup Blk: ON/OFF' এবং টাস্কের ভেতরে Toggle TOTP / TOTP Dup সেট করুন।", 0, 9),
            ("NEW_COOKIE_VERIFY", 6, "NEW COOKIE", "কুকি যাচাই, ডুপ্লিকেট ব্লক ও Required Keys", "Cookie Verification, Dup Block & Keys", "JSON/key=value/Netscape কুকি পার্সিং, Required Keys (c_user,xs/none) ও রি-অর্ডার প্রুফ ডুপ্লিকেট ব্লক।", "Parses JSON/key=value/Netscape cookies, validates required keys, and blocks reordered duplicates.", "Admin -> Task Manager থেকে 'Cookie Step: ON/OFF', 'Cookie Dup Blk' এবং 'Cookie Keys' (যেমন c_user,xs বা none) সেট করুন।", 0, 10),
            ("RULE_15_16_78_AUTO", 7, "RULE 15,16,78", "লিমিট, ডুপ্লিকেট ও সেকেন্ড/মিনিট Auto-Review", "Limits, Duplicate & Sec/Min Auto-Review", "সেকেন্ড ও মিনিট টাইমারে Task ও Deposit Auto-Approve/Auto-Reject।", "Flexible second/minute timers for task & deposit auto-review.", "Admin -> Auto-Review & Scheduler থেকে গ্লোবাল বা পার-আইটেম টাইমার (যেমন 30s, 2m) সেট করুন।", 0, 11),
            ("RULE_18_26_92_FS", 8, "RULE 18-26,92", "স্বাধীন ফাইল সাবমিট ও ১/৩/৫/৭/১০/১৫/২০ ব্যাচ", "Independent File Submit & Batch Review", "Zero-Column-Mixing পার্সার, ১ ও ৩–২০ ব্যাচ রিভিউ ও FS কমিশন।", "Zero-column-mixing parser, 1 & 3-20 batch review and FS commission.", "Admin -> File Submit Manager থেকে FS টাস্ক তৈরি ও রিভিউ কিউতে ব্যাচ বাটন ব্যবহার করুন।", 0, 12),
            ("RULE_74_93_STORE", 9, "RULE 74,84,93", "ডিজিটাল স্টোর, ২০+ স্টেপ ও পেআউট পোস্ট", "Product Store, 20+ Steps & Payout Post", "লাইন-বাই-লাইন স্টক, কুপন, টিয়ার, ওয়ারেন্টি ও অর্ডার চ্যানেল পোস্ট।", "Line stock delivery, coupons, bulk tiers, warranty and payout post.", "Admin -> Product Store Manager থেকে ক্যাটাগরি, পণ্য ও স্টক ফাইল আপলোড করুন।", 0, 13),
            ("RULE_81_82_OTP", 10, "RULE 81,82,84", "মাল্টি-কান্ট্রি OTP, লাইভ স্টক ও ৪ ব্রিজ", "Multi-Country OTP, Live Stock & 4 Bridges", "১/২/৩/N নাম্বার বরাদ্দ, ৪টি SMS ব্রিজ, Smart Regex ও অটো-রিফান্ড।", "1/2/3/N allocation, 4 SMS bridges, smart regex and auto-refund.", "Admin -> OTP Receiver Manager থেকে দেশ, নাম্বার ফাইল ও ৪টি ব্রিজের যেকোনোটি চালু করুন।", 0, 14),
            ("RULE_75_OCR_DEPOSIT", 11, "RULE 75+OCR", "ডুয়াল ডিপোজিট ও স্ক্রিনশট OCR TxID ম্যাচ", "Dual Deposit & OCR TxID Strict Match", "হাইব্রিড OCR দিয়ে স্ক্রিনশট থেকে TxID পড়ে ম্যাচিং; অমিল হলে সাথে সাথে অটো-রিজেক্ট।", "Hybrid OCR extracts TxID from screenshot and auto-rejects mismatch.", "Admin -> Deposit Manager থেকে OCR API/Regex/Fallback নীতি ও মেথড নিয়ন্ত্রণ করুন।", 0, 15),
            ("RULE_29_30_70_WD", 11, "RULE 29,30,70", "স্মার্ট উইথড্র, ওয়ালেট চেক ও Mark Paid", "Smart Withdraw, Wallet Check & Mark Paid", "BD ১১-ডিজিট/Crypto ভ্যালিডেশন, ডামি ব্লক, কাস্টম শর্ত ও Hold/Paid।", "BD 11-digit/Crypto validation, dummy block, custom conditions & Hold/Paid.", "Admin -> Withdrawal Manager থেকে মেথড, ফি, শর্ত ও ওয়ালেট Regex সেট করুন।", 0, 16),
            ("RULE_27_31_94_GROWTH", 12, "RULE 27-31,94", "রেফারেল, বোনাস, চেক-ইন ও ম্যানুয়াল LB স্কোর", "Referral, Bonus, Check-in & Manual LB Score", "স্বাধীন টাস্ক ও FS Approved-only লিডারবোর্ড, অটো-অ্যাওয়ার্ড ও Manual +N/-N।", "Independent Task & FS Approved leaderboards, auto-award reset & manual score adjust.", "Admin -> Growth & Rewards থেকে পুরস্কার টিয়ার, ম্যানুয়াল স্কোর (+N/-N) ও রিসেট চালান।", 0, 17),
            ("RULE_37_79_95B_MSG", 13, "RULE 37,79,95B", "টিকেট, আপিল, ব্রডকাস্ট ও রাত ১২টার সামারি", "Tickets, Appeals, Broadcast & Midnight Summary", "ইন-বট স্ক্রিনশট টিকেট, ১-বার আপিল, ব্রডকাস্ট কিউ ও ডেইলি সামারি।", "In-bot screenshot tickets, 1-time appeals, broadcast queue & daily summary.", "Admin -> Tickets, Appeals & Broadcast থেকে রিপ্লাই, ব্রডকাস্ট ও ফেইলড কিউ নিয়ন্ত্রণ করুন।", 0, 18),
            ("RULE_77_SECURITY", 14, "RULE 77.1-77.8", "অ্যান্টি-অ্যাবিউজ, ৯ লক ও প্যানিক ফ্রিজ", "Anti-Abuse, 9 Locks & Panic Freeze", "ডুপ্লিকেট TxID, মাল্টি-ওয়ালেট ব্লক, Anti-Wash, স্প্যাম লিমিট ও Panic Freeze।", "Dup TxID, multi-wallet block, anti-wash, rate-limit and panic freeze.", "Admin -> Security, Locks & Panic Freeze থেকে প্রতিটি লক বা ইমার্জেন্সি ফ্রিজ নিয়ন্ত্রণ করুন।", 0, 19),
            ("RULE_32_34_41_ADMIN", 15, "RULE 32-34,41", "২০-সেকশন প্যানেল, পারমিশন ও অটো-ব্যাকআপ", "20-Section Panel, Permissions & Auto-Backup", "Assistant Admin-এর ২০ পারমিশন গ্রুপ, Reconciliation, Runtime Reset ও .zip ব্যাকআপ।", "Assistant granular permissions, reconciliation, runtime reset & Telegram auto-backup.", "Admin -> Permissions, Ledger, Audit & Backup থেকে ব্যাকআপ, রিস্টোর ও অডিট করুন।", 0, 20),
            ("RULE_44_61_ARCH", 16, "RULE 44-62", "মডুলার ম্যানেজার ও সেলফ-টেস্ট", "Modular Managers & Self-Test", "সকল ম্যানেজার হেলথ, DB চেক ও অসংক্ষিপ্ত টেস্ট ভেরিফিকেশন।", "All managers health check, DB integrity and self-test suite.", "Admin -> System Status & Diagnostics থেকে One-Click Self-Test রান করুন।", 1, 21),
            ("RULE_96_STUDIO", 17, "RULE 96", "সেন্ট্রাল মেসেজ স্টুডিও (২৫×৩০×২)", "Central Message Studio (25x30x2)", "২৫টি ইভেন্টে ৩০+ ভ্যারিয়েন্ট, Fixed/Rotate/Random ও প্রাইভেসি মাস্কিং।", "25 events x 30+ variants in BN & EN with Fixed/Rotate/Random delivery.", "Admin -> Central Message Studio থেকে প্রতিটি ইভেন্ট ও প্রতিটি ভ্যারিয়েন্ট ON/OFF বা এডিট করুন।", 0, 22),
        ]
        for rk, sec, rcode, tbn, ten, dbn, den, guide, locked, order in rules:
            conn.execute(
                """
                INSERT OR IGNORE INTO rule_controls
                (rule_key, sector_no, rule_code, title_bn, title_en, desc_bn, desc_en, usage_guide_bn,
                 is_enabled, is_hidden, is_locked, config_json, default_config_json, sort_order, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, '{}', '{}', ?, ?)
                """,
                (rk, sec, rcode, tbn, ten, dbn, den, guide, locked, order, now_s),
            )

    def _seed_payment_methods(self, conn: sqlite3.Connection, now_s: str) -> None:
        dep_cnt = conn.execute("SELECT COUNT(*) AS c FROM deposit_methods").fetchone()
        if int(dep_cnt["c"]) == 0:
            dep_seed = [
                ("বিকাশ (bKash)", "bKash", "mobile_banking", "01700000000", "bKash Personal", "", "Personal", 20.0, 25000.0, 0.0, 0.0, "টাকা পাঠিয়ে Sender নম্বর, সঠিক TxID এবং পেমেন্ট স্ক্রিনশট দিন।", "Send money and submit Sender number, exact TxID, and payment screenshot.", 1),
                ("নগদ (Nagad)", "Nagad", "mobile_banking", "01800000000", "Nagad Personal", "", "Personal", 20.0, 25000.0, 0.0, 0.0, "নগদ সেন্ড মানি করে TxID ও স্ক্রিনশট দিন।", "Send money via Nagad and submit TxID and screenshot.", 2),
                ("রকেট (Rocket)", "Rocket", "mobile_banking", "01900000000", "Rocket Personal", "", "Personal", 20.0, 25000.0, 0.0, 0.0, "রকেট সেন্ড মানি করে TxID ও স্ক্রিনশট দিন।", "Send money via Rocket and submit TxID and screenshot.", 3),
                ("বাইনান্স পে (Binance Pay)", "Binance Pay", "crypto", "PAY-ID-SET-IN-ADMIN", "Binance Pay ID", "TRC20 / PayID", "Merchant", 100.0, 100000.0, 0.0, 0.0, "Binance Pay ID-তে পাঠিয়ে Order/TxID ও স্ক্রিনশট দিন।", "Transfer via Binance Pay and provide Order/TxID and screenshot.", 4),
            ]
            for nbn, nen, mtype, acc, albl, net, htype, mina, maxa, bon, chg, ibn, ien, order in dep_seed:
                conn.execute(
                    """
                    INSERT INTO deposit_methods
                    (name_bn, name_en, method_type, account_number, account_label, network_info, account_holder_type,
                     min_amount, max_amount, bonus_percent, charge_percent, instruction_bn, instruction_en, sort_order, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (nbn, nen, mtype, acc, albl, net, htype, mina, maxa, bon, chg, ibn, ien, order, now_s),
                )

        wd_cnt = conn.execute("SELECT COUNT(*) AS c FROM withdraw_methods").fetchone()
        if int(wd_cnt["c"]) == 0:
            wd_seed = [
                ("বিকাশ (bKash)", "bKash", "bd_mobile", "fixed", 0.0, 50.0, 25000.0, r"^01[3-9]\d{8}$", "আপনার ১১ ডিজিটের পার্সোনাল বিকাশ নম্বর দিন।", "Enter your 11-digit personal bKash number.", 1),
                ("নগদ (Nagad)", "Nagad", "bd_mobile", "fixed", 0.0, 50.0, 25000.0, r"^01[3-9]\d{8}$", "আপনার ১১ ডিজিটের পার্সোনাল নগদ নম্বর দিন।", "Enter your 11-digit personal Nagad number.", 2),
                ("বাইনান্স (Binance Pay / TRC20)", "Binance / TRC20", "crypto", "percent", 2.0, 200.0, 100000.0, r"^(T[A-Za-z1-9]{33}|0x[a-fA-F0-9]{40}|\d{6,15})$", "বৈধ Binance Pay ID অথবা TRC20/BEP20 ওয়ালেট অ্যাড্রেস দিন।", "Enter valid Binance Pay ID or TRC20/BEP20 wallet address.", 3),
            ]
            for nbn, nen, mtype, ftype, fval, mina, maxa, regex, ibn, ien, order in wd_seed:
                conn.execute(
                    """
                    INSERT INTO withdraw_methods
                    (name_bn, name_en, method_type, fee_type, fee_value, min_amount, max_amount, wallet_regex,
                     custom_conditions_json, instruction_bn, instruction_en, sort_order, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?)
                    """,
                    (nbn, nen, mtype, ftype, fval, mina, maxa, regex, ibn, ien, order, now_s),
                )

    def _seed_reject_templates(self, conn: sqlite3.Connection, now_s: str) -> None:
        cnt = conn.execute("SELECT COUNT(*) AS c FROM reject_templates").fetchone()
        if int(cnt["c"]) == 0:
            templates = [
                ("all", "ভুল বা ভুয়া প্রমাণ", "Fake or Invalid Proof", "প্রদত্ত প্রমাণ/স্ক্রিনশট নির্দেশনার সাথে মেলেনি।", "Submitted proof did not match instructions.", 1),
                ("all", "ডুপ্লিকেট তথ্য", "Duplicate Submission", "একই তথ্য বা কী পূর্বেই জমা দেওয়া হয়েছে।", "Duplicate data or key already submitted.", 2),
                ("fs", "অবৈধ ফরম্যাট/কলাম", "Invalid Format/Columns", "ফাইলের কলাম বা প্যাটার্ন নিয়ম অনুযায়ী নয়।", "File columns or pattern did not match rules.", 3),
                ("deposit", "TxID অমিল/পাওয়া যায়নি", "TxID Not Found/Mismatch", "প্রদত্ত TxID পেমেন্ট লগের সাথে মেলেনি।", "Provided TxID could not be verified.", 4),
            ]
            for scope, tbn, ten, rbn, ren, order in templates:
                conn.execute(
                    """
                    INSERT INTO reject_templates (scope, title_bn, title_en, reason_bn, reason_en, is_active, is_hidden, sort_order, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)
                    """,
                    (scope, tbn, ten, rbn, ren, order, now_s),
                )

    def _seed_leaderboard_cycles(self, conn: sqlite3.Connection, now_s: str) -> None:
        for board_type in ("task", "fs"):
            row = conn.execute(
                "SELECT id FROM leaderboard_cycles WHERE board_type=? AND status='active'",
                (board_type,),
            ).fetchone()
            if row is None:
                default_tiers = safe_json_dumps({"1": 100.0, "2": 60.0, "3": 40.0, "4": 20.0, "5": 10.0})
                conn.execute(
                    """
                    INSERT INTO leaderboard_cycles (board_type, cycle_no, status, started_at, prize_tiers_json, top_n)
                    VALUES (?, 1, 'active', ?, ?, 10)
                    """,
                    (board_type, now_s, default_tiers),
                )
# ==============================================================================
# CENTRAL MESSAGE DESIGN & SMART NOTIFICATION STUDIO (RULE 96 | SECTOR 17)
# ==============================================================================

STUDIO_STYLE_PREFIXES: Tuple[Tuple[str, str, str, str], ...] = (
    ("💎", "প্রিমিয়াম আপডেট", "Premium Update", "উজ্জ্বল সূচনা"),
    ("🌸", "শুভ বার্তা", "Warm Notice", "আন্তরিক শুভেচ্ছা"),
    ("🚀", "দ্রুতগতি", "Fast Track", "হাই-স্পিড প্রগ্রেস"),
    ("🌟", "তারকা অর্জন", "Star Highlight", "চমৎকার পারফরম্যান্স"),
    ("⚡", "তাৎক্ষণিক", "Instant Alert", "রিয়েল-টাইম আপডেট"),
    ("🏆", "চ্যাম্পিয়ন", "Champion Mode", "সেরা ফলাফল"),
    ("💼", "প্রফেশনাল", "Professional Desk", "নির্ভরযোগ্য সেবা"),
    ("🎊", "উৎসব বার্তা", "Celebration", "আনন্দময় মুহূর্ত"),
    ("🔵", "রয়্যাল কার্ড", "Royal Card", "স্ট্যান্ডার্ড প্রো"),
    ("🟢", "সফল সিগন্যাল", "Green Signal", "সবুজ সংকেত"),
    ("🟡", "সোনালি সুযোগ", "Golden Touch", "গোল্ডেন নোটিশ"),
    ("🛡️", "সুরক্ষিত সিস্টেম", "Shielded Notice", "নিরাপদ প্রক্রিয়া"),
    ("🎯", "নির্ভুল লক্ষ্য", "Target Hit", "সঠিক পদক্ষেপ"),
    ("🔥", "হাই অ্যাকশন", "High Energy", "দারুণ গতি"),
    ("🌐", "গ্লোবাল সিস্টেম", "Global Hub", "স্মার্ট সংযোগ"),
    ("🎁", "বিশেষ উপহার", "Special Reward", "বোনাস ফোকাস"),
    ("💳", "ডিজিটাল ওয়ালেট", "Wallet Update", "অ্যাকাউন্ট লগ"),
    ("🧩", "স্মার্ট ধাপ", "Smart Step", "সহজ সমাধান"),
    ("👑", "ভিআইপি স্ট্যাটাস", "VIP Experience", "এলিট সেবা"),
    ("✨", "শুভ সংকেত", "Sparkle Note", "পরিচ্ছন্ন তথ্য"),
    ("📌", "গুরুত্বপূর্ণ পিন", "Pinned Note", "জরুরি তথ্য"),
    ("🧾", "অফিশিয়াল স্লিপ", "Official Slip", "রেকর্ড রসিদ"),
    ("🔔", "স্মার্ট অ্যালার্ট", "Smart Alert", "সক্রিয় বিজ্ঞপ্তি"),
    ("🟣", "আধুনিক কার্ড", "Modern Card", "ডাইনামিক লুক"),
    ("💠", "ডায়মন্ড লগ", "Diamond Log", "নিশ্চিত তথ্য"),
    ("🌈", "রঙিন বার্তা", "Vibrant Notice", "আকর্ষণীয় আপডেট"),
    ("📣", "সিস্টেম ঘোষণা", "System Dispatch", "সরাসরি বার্তা"),
    ("🧭", "দিকনির্দেশনা", "Guided Info", "সঠিক পথ"),
    ("🏅", "অর্জন ব্যাজ", "Achievement", "সফল রেকর্ড"),
    ("🕊️", "শান্তি ও আস্থা", "Trusted Note", "স্বচ্ছতা ও ভরসা"),
)

# 25 Core Events: (event_key, category, title_bn, title_en, body_bn_tpl, body_en_tpl, placeholders_json)
STUDIO_CORE_EVENTS: Tuple[Tuple[str, str, str, str, str, str, str], ...] = (
    (
        "start_welcome",
        "start",
        "ওয়েলকাম মেসেজ",
        "Welcome Message",
        "স্বাগতম <b>{name}</b>! <b>{bot_name}</b>-এ আপনার অ্যাকাউন্ট (<code>{user_id}</code>) সক্রিয় হয়েছে। ব্যালেন্স: <code>{balance}</code>।",
        "Welcome <b>{name}</b>! Your account on <b>{bot_name}</b> (<code>{user_id}</code>) is active. Balance: <code>{balance}</code>.",
        '["name","bot_name","user_id","balance"]',
    ),
    (
        "task_submitted_confirm",
        "tasks",
        "টাস্ক সাবমিট কনফার্ম",
        "Task Submitted",
        "টাস্ক <b>{task_title}</b> (<code>{sub_uid}</code>) জমা হয়েছে! সম্ভাব্য রিওয়ার্ড: <code>{reward}</code> (রিভিউ অপেক্ষমাণ)।",
        "Task <b>{task_title}</b> (<code>{sub_uid}</code>) submitted! Reward: <code>{reward}</code> (Pending Review).",
        '["task_title","sub_uid","reward","name","time"]',
    ),
    (
        "task_approved_msg",
        "tasks",
        "টাস্ক Approve মেসেজ",
        "Task Approved",
        "অভিনন্দন {name}! টাস্ক <code>{sub_uid}</code> Approved হয়েছে। যুক্ত: <code>+{reward}</code> | নতুন ব্যালেন্স: <code>{new_balance}</code>।",
        "Congrats {name}! Task <code>{sub_uid}</code> Approved. Credited: <code>+{reward}</code> | Balance: <code>{new_balance}</code>.",
        '["name","sub_uid","task_title","reward","new_balance","time"]',
    ),
    (
        "task_rejected_msg",
        "tasks",
        "টাস্ক Reject মেসেজ",
        "Task Rejected",
        "দুঃখিত {name}, টাস্ক <code>{sub_uid}</code> Rejected হয়েছে। কারণ: <i>{reject_reason}</i>। সঠিক হলে Appeal করুন।",
        "Sorry {name}, task <code>{sub_uid}</code> Rejected. Reason: <i>{reject_reason}</i>. You may appeal once if valid.",
        '["name","sub_uid","task_title","reject_reason","time"]',
    ),
    (
        "fs_submitted_complete",
        "file_submit",
        "ফাইল সাবমিট কমপ্লিট",
        "FS Submitted",
        "ফাইল সাবমিট <b>{fs_title}</b> (<code>{sub_uid}</code>) সফল! বৈধ রেকর্ড: <b>{total_records}টি</b> (প্রতি রেকর্ড: <code>{unit_reward}</code>)।",
        "File Submit <b>{fs_title}</b> (<code>{sub_uid}</code>) received! Valid records: <b>{total_records}</b> (Unit: <code>{unit_reward}</code>).",
        '["fs_title","sub_uid","total_records","unit_reward","name","time"]',
    ),
    (
        "fs_approved_final_msg",
        "file_submit",
        "ফাইল সাবমিট Approve (FINAL)",
        "FS Approved Final",
        "FS রিপোর্ট (<code>{sub_uid}</code>) v{version}: ✅ {approved}/{total} Approved | ❌ {rejected} | আয়: <code>+{earned_reward}</code> | ব্যালেন্স: <code>{new_balance}</code>।",
        "FS Report (<code>{sub_uid}</code>) v{version}: ✅ {approved}/{total} Approved | ❌ {rejected} | Earned: <code>+{earned_reward}</code> | Balance: <code>{new_balance}</code>.",
        '["sub_uid","approved","rejected","total","earned_reward","new_balance","version"]',
    ),
    (
        "fs_rejected_final_msg",
        "file_submit",
        "ফাইল সাবমিট Reject (FINAL)",
        "FS Rejected Final",
        "FS রিপোর্ট (<code>{sub_uid}</code>) বাতিল হয়েছে ({rejected}/{total}টি)। বিবরণ: {rejected_lines_summary}।",
        "FS Report (<code>{sub_uid}</code>) rejected ({rejected}/{total}). Details: {rejected_lines_summary}.",
        '["sub_uid","rejected","total","rejected_lines_summary","time"]',
    ),
    (
        "withdraw_request_submitted",
        "withdraw",
        "উইথড্র রিকোয়েস্ট জমা",
        "Withdraw Requested",
        "উইথড্র রিকোয়েস্ট <code>{withdraw_uid}</code> জমা হয়েছে! {method} (<code>{account}</code>) | Gross: <code>{gross}</code> | Fee: {fee} | নেট প্রাপ্য: <code>{net_amount}</code>।",
        "Withdrawal <code>{withdraw_uid}</code> submitted! {method} (<code>{account}</code>) | Gross: <code>{gross}</code> | Fee: {fee} | Net: <code>{net_amount}</code>.",
        '["withdraw_uid","method","account","gross","fee","net_amount","time"]',
    ),
    (
        "withdraw_paid_success",
        "withdraw",
        "উইথড্র সাকসেসফুল (Paid)",
        "Withdraw Paid",
        "পেমেন্ট সম্পন্ন! <code>{withdraw_uid}</code> | {method} (<code>{account}</code>)-এ <code>{net_amount}</code> সফলভাবে পাঠানো হয়েছে।",
        "Payment Completed! <code>{withdraw_uid}</code> | <code>{net_amount}</code> sent to {method} (<code>{account}</code>).",
        '["withdraw_uid","method","account","net_amount","name","time"]',
    ),
    (
        "store_order_success_delivery",
        "store",
        "স্টোর অর্ডার ও ডেলিভারি",
        "Store Order Delivered",
        "অর্ডার <code>{order_uid}</code> সফল! পণ্য: <b>{product_name}</b> x{qty} | পরিশোধ: <code>{total_paid}</code> | ওয়ারেন্টি: {warranty_hours}h।",
        "Order <code>{order_uid}</code> delivered! Product: <b>{product_name}</b> x{qty} | Paid: <code>{total_paid}</code> | Warranty: {warranty_hours}h.",
        '["order_uid","product_name","qty","total_paid","discount","warranty_hours","time"]',
    ),
    (
        "otp_code_received_push",
        "otp",
        "OTP কোড রিসিভ পুশ",
        "OTP Code Received",
        "{country_flag} <code>{phone_number}</code>-এ নতুন OTP এসেছে!\n👉 কোড: <code>{otp_code}</code>\n📩 SMS: {sms_text}",
        "{country_flag} New OTP received for <code>{phone_number}</code>!\n👉 Code: <code>{otp_code}</code>\n📩 SMS: {sms_text}",
        '["country_flag","country_name","phone_number","otp_code","otp_uid","sms_text","time"]',
    ),
    (
        "deposit_request_submitted",
        "deposit",
        "ডিপোজিট রিকোয়েস্ট জমা",
        "Deposit Requested",
        "ডিপোজিট <code>{deposit_uid}</code> ({method}) জমা হয়েছে! পরিমাণ: <code>{amount}</code> | TxID: <code>{txid}</code> | নিট ক্রেডিট: <code>{net_credit}</code>।",
        "Deposit <code>{deposit_uid}</code> ({method}) submitted! Amount: <code>{amount}</code> | TxID: <code>{txid}</code> | Net: <code>{net_credit}</code>.",
        '["deposit_uid","method","amount","bonus","net_credit","sender","txid","time"]',
    ),
    (
        "deposit_approved_success",
        "deposit",
        "ডিপোজিট সাকসেসফুল",
        "Deposit Approved",
        "টাকা অ্যাড সফল! <code>{deposit_uid}</code> Approved | যুক্ত: <code>+{net_credit}</code> | নতুন ডিপোজিট ব্যালেন্স: <code>{new_deposit_balance}</code>।",
        "Deposit Approved! <code>{deposit_uid}</code> | Credited: <code>+{net_credit}</code> | Deposit Balance: <code>{new_deposit_balance}</code>.",
        '["deposit_uid","method","net_credit","new_deposit_balance","name","time"]',
    ),
    (
        "referral_new_join_alert",
        "referral",
        "নতুন রেফারেল জয়েন অ্যালার্ট",
        "New Referral Joined",
        "আপনার রেফারেল লিংকে নতুন সদস্য <b>{ref_name}</b> ({ref_id_masked}) জয়েন করেছেন! মোট টিম: <b>{total_refs} জন</b> (রেট: {rate})।",
        "New member <b>{ref_name}</b> ({ref_id_masked}) joined via your referral link! Total team: <b>{total_refs}</b> (Rate: {rate}).",
        '["name","ref_name","ref_id_masked","total_refs","rate","time"]',
    ),
    (
        "referral_commission_msg",
        "referral",
        "রেফারেল কমিশন মেসেজ",
        "Referral Commission",
        "প্যাসিভ আয়! {ref_name}-এর {source_label} থেকে কমিশন <code>+{amount}</code> যুক্ত হয়েছে। নতুন ব্যালেন্স: <code>{new_balance}</code>।",
        "Passive income! Earned <code>+{amount}</code> commission from {ref_name}'s {source_label}. New balance: <code>{new_balance}</code>.",
        '["name","ref_name","source_label","amount","new_balance","rate","tx_uid","time"]',
    ),
    (
        "force_join_required",
        "force_join",
        "ফোর্স জয়েন বাধ্যতামূলক",
        "Force Join Notice",
        "<b>{bot_name}</b> ব্যবহারের আগে সবগুলো সক্রিয় চ্যানেলে জয়েন করুন:\n{channels_status}",
        "Join all active channels below before using <b>{bot_name}</b>:\n{channels_status}",
        '["bot_name","channels_status"]',
    ),
    (
        "task_credentials_issued",
        "tasks",
        "সোর্স ডেটা কার্ড বরাদ্দ",
        "Source Credentials Issued",
        "কাজ <b>{task_title}</b>-এর জন্য আপনার নির্ধারিত রেকর্ড বরাদ্দ হয়েছে (মেয়াদ: {timeout_text})। নিচের কপি বাটন ব্যবহার করুন।",
        "Source record allocated for <b>{task_title}</b> (Expires in {timeout_text}). Use copy buttons below.",
        '["task_title","timeout_text","alloc_id"]',
    ),
    (
        "deposit_rejected_msg",
        "deposit",
        "ডিপোজিট Reject মেসেজ",
        "Deposit Rejected",
        "ডিপোজিট <code>{deposit_uid}</code> বাতিল হয়েছে। কারণ: <i>{reject_reason}</i>।",
        "Deposit <code>{deposit_uid}</code> rejected. Reason: <i>{reject_reason}</i>.",
        '["deposit_uid","reject_reason","time"]',
    ),
    (
        "withdraw_rejected_refund",
        "withdraw",
        "উইথড্র Reject ও রিফান্ড",
        "Withdraw Rejected & Refunded",
        "উইথড্র <code>{withdraw_uid}</code> বাতিল হওয়ায় <code>{gross}</code> আপনার অর্জিত ব্যালেন্সে ফেরত দেওয়া হয়েছে। কারণ: {reject_reason}।",
        "Withdrawal <code>{withdraw_uid}</code> rejected; <code>{gross}</code> refunded to Earned balance. Reason: {reject_reason}.",
        '["withdraw_uid","gross","reject_reason","time"]',
    ),
    (
        "otp_number_allocated",
        "otp",
        "OTP নাম্বার বরাদ্দ",
        "OTP Number Allocated",
        "{country_flag} <b>{country_name}</b> থেকে আপনার নাম্বার বরাদ্দ হয়েছে (<code>{otp_uid}</code>) | অপেক্ষার সময়: {wait_text}।",
        "{country_flag} Number(s) allocated from <b>{country_name}</b> (<code>{otp_uid}</code>) | Wait timer: {wait_text}.",
        '["country_flag","country_name","otp_uid","wait_text"]',
    ),
    (
        "otp_timeout_refund",
        "otp",
        "OTP টাইমআউট ও অটো-রিফান্ড",
        "OTP Timeout Auto-Refund",
        "সেশন <code>{otp_uid}</code>-এর সময় শেষ হয়েছে। প্রদত্ত ফি <code>{refund_amount}</code> আপনার ব্যালেন্সে ফেরত দেওয়া হয়েছে।",
        "OTP session <code>{otp_uid}</code> timed out. Fee <code>{refund_amount}</code> has been auto-refunded.",
        '["otp_uid","refund_amount"]',
    ),
    (
        "daily_checkin_bonus",
        "growth",
        "ডেইলি চেক-ইন বোনাস",
        "Daily Check-in Bonus",
        "ডেইলি চেক-ইন সফল (দিন #{streak_day})! প্রাপ্তি: <code>+{total_credited}</code> | নতুন ব্যালেন্স: <code>{new_balance}</code>।",
        "Daily Check-in claimed (Day #{streak_day})! Credited: <code>+{total_credited}</code> | Balance: <code>{new_balance}</code>.",
        '["streak_day","total_credited","new_balance"]',
    ),
    (
        "leaderboard_prize_won",
        "growth",
        "লিডারবোর্ড পুরস্কার",
        "Leaderboard Prize Won",
        "অভিনন্দন! {board_label} সাইকেল #{cycle_no}-এ আপনার অবস্থান <b>#{rank_pos}</b>। পুরস্কার <code>+{prize}</code> ক্রেডিট হয়েছে!",
        "Congratulations! You ranked <b>#{rank_pos}</b> in {board_label} Cycle #{cycle_no}. Prize <code>+{prize}</code> credited!",
        '["board_label","cycle_no","rank_pos","prize"]',
    ),
    (
        "user_warning_strike",
        "security",
        "ওয়ার্নিং স্ট্রাইক নোটিশ",
        "Warning Strike Notice",
        "সতর্কবার্তা! আপনার অ্যাকাউন্টে ওয়ার্নিং যুক্ত হয়েছে ({strikes}/{max_strikes})। কারণ: {reason}।",
        "Warning Notice! A strike was added to your account ({strikes}/{max_strikes}). Reason: {reason}.",
        '["strikes","max_strikes","reason"]',
    ),
    (
        "support_ticket_appeal",
        "support",
        "টিকেট ও আপিল আপডেট",
        "Ticket & Appeal Update",
        "আপনার রেফারেন্স <code>{ref_uid}</code>-এর স্ট্যাটাস এখন <b>{status}</b>। নোট: {note}",
        "Your reference <code>{ref_uid}</code> is now <b>{status}</b>. Note: {note}",
        '["ref_uid","status","note"]',
    ),
)
STUDIO_COMPACT_TEMPLATES: Dict[str, Dict[str, Tuple[str, str]]] = {
    "start_welcome": {
        "medium": ("💎 <b>স্বাগতম {name}!</b>\n<b>{bot_name}</b> (<code>{user_id}</code>) | ব্যালেন্স: <code>{balance}</code>", "💎 <b>Welcome {name}!</b>\n<b>{bot_name}</b> (<code>{user_id}</code>) | Balance: <code>{balance}</code>"),
        "short": ("💎 স্বাগতম {name}! ব্যালেন্স: <code>{balance}</code>", "💎 Welcome {name}! Balance: <code>{balance}</code>"),
    },
    "task_submitted_confirm": {
        "medium": ("📋 <b>টাস্ক জমা হয়েছে</b>\n<b>{task_title}</b> (<code>{sub_uid}</code>) | রিওয়ার্ড: <code>{reward}</code>", "📋 <b>Task Submitted</b>\n<b>{task_title}</b> (<code>{sub_uid}</code>) | Reward: <code>{reward}</code>"),
        "short": ("⏳ টাস্ক জমা: <code>{sub_uid}</code> ({reward})", "⏳ Submitted: <code>{sub_uid}</code> ({reward})"),
    },
    "task_approved_msg": {
        "medium": ("✅ <b>টাস্ক Approved</b>\nID: <code>{sub_uid}</code> | যুক্ত: <code>+{reward}</code> | ব্যালেন্স: <code>{new_balance}</code>", "✅ <b>Task Approved</b>\nID: <code>{sub_uid}</code> | Credited: <code>+{reward}</code> | Balance: <code>{new_balance}</code>"),
        "short": ("✅ Approved <code>{sub_uid}</code> (+{reward}) | <code>{new_balance}</code>", "✅ Approved <code>{sub_uid}</code> (+{reward}) | <code>{new_balance}</code>"),
    },
    "task_rejected_msg": {
        "medium": ("❌ <b>টাস্ক Rejected</b>\nID: <code>{sub_uid}</code> | কারণ: <i>{reject_reason}</i>", "❌ <b>Task Rejected</b>\nID: <code>{sub_uid}</code> | Reason: <i>{reject_reason}</i>"),
        "short": ("❌ Rejected <code>{sub_uid}</code>: {reject_reason}", "❌ Rejected <code>{sub_uid}</code>: {reject_reason}"),
    },
    "fs_submitted_complete": {
        "medium": ("📁 <b>ফাইল সাবমিট সফল</b>\n<b>{fs_title}</b> (<code>{sub_uid}</code>) | রেকর্ড: <b>{total_records}টি</b>", "📁 <b>File Submitted</b>\n<b>{fs_title}</b> (<code>{sub_uid}</code>) | Records: <b>{total_records}</b>"),
        "short": ("📁 FS জমা: <code>{sub_uid}</code> ({total_records}টি)", "📁 FS Submitted: <code>{sub_uid}</code> ({total_records})"),
    },
    "fs_approved_final_msg": {
        "medium": ("📊 <b>FS রিপোর্ট</b> (<code>{sub_uid}</code>)\n✅ {approved}/{total} | ❌ {rejected} | আয়: <code>+{earned_reward}</code> | ব্যালেন্স: <code>{new_balance}</code>", "📊 <b>FS Report</b> (<code>{sub_uid}</code>)\n✅ {approved}/{total} | ❌ {rejected} | Earned: <code>+{earned_reward}</code> | Balance: <code>{new_balance}</code>"),
        "short": ("✅ FS {sub_uid}: {approved}/{total} (+{earned_reward})", "✅ FS {sub_uid}: {approved}/{total} (+{earned_reward})"),
    },
    "fs_rejected_final_msg": {
        "medium": ("❌ <b>FS বাতিল</b> (<code>{sub_uid}</code>)\nবাতিল: {rejected}/{total} | {rejected_lines_summary}", "❌ <b>FS Rejected</b> (<code>{sub_uid}</code>)\nRejected: {rejected}/{total} | {rejected_lines_summary}"),
        "short": ("❌ FS বাতিল {sub_uid} ({rejected}/{total})", "❌ FS Rejected {sub_uid} ({rejected}/{total})"),
    },
    "withdraw_request_submitted": {
        "medium": ("💸 <b>উইথড্র জমা</b>\nID: <code>{withdraw_uid}</code> | {method} (<code>{account}</code>) | নেট: <code>{net_amount}</code>", "💸 <b>Withdraw Submitted</b>\nID: <code>{withdraw_uid}</code> | {method} (<code>{account}</code>) | Net: <code>{net_amount}</code>"),
        "short": ("⏳ Withdraw <code>{withdraw_uid}</code>: <code>{net_amount}</code>", "⏳ Withdraw <code>{withdraw_uid}</code>: <code>{net_amount}</code>"),
    },
    "withdraw_paid_success": {
        "medium": ("💸 <b>পেমেন্ট সম্পন্ন</b>\n<code>{withdraw_uid}</code> | {method} (<code>{account}</code>) — <code>{net_amount}</code>", "💸 <b>Payment Sent</b>\n<code>{withdraw_uid}</code> | {method} (<code>{account}</code>) — <code>{net_amount}</code>"),
        "short": ("✅ Paid <code>{withdraw_uid}</code> ({net_amount})", "✅ Paid <code>{withdraw_uid}</code> ({net_amount})"),
    },
    "store_order_success_delivery": {
        "medium": ("🛒 <b>অর্ডার সফল</b>\n<code>{order_uid}</code> | <b>{product_name}</b> x{qty} | মোট: <code>{total_paid}</code>", "🛒 <b>Order Completed</b>\n<code>{order_uid}</code> | <b>{product_name}</b> x{qty} | Paid: <code>{total_paid}</code>"),
        "short": ("🛒 অর্ডার {order_uid}: {product_name} x{qty} ({total_paid})", "🛒 Order {order_uid}: {product_name} x{qty} ({total_paid})"),
    },
    "otp_code_received_push": {
        "medium": ("{country_flag} <code>{phone_number}</code>\n🔑 OTP: <code>{otp_code}</code>\n📩 {sms_text}", "{country_flag} <code>{phone_number}</code>\n🔑 OTP: <code>{otp_code}</code>\n📩 {sms_text}"),
        "short": ("🔑 OTP: <code>{otp_code}</code> (<code>{phone_number}</code>)", "🔑 OTP: <code>{otp_code}</code> (<code>{phone_number}</code>)"),
    },
    "deposit_request_submitted": {
        "medium": ("💳 <b>ডিপোজিট জমা</b>\nID: <code>{deposit_uid}</code> | {method} | <code>{amount}</code> | TxID: <code>{txid}</code>", "💳 <b>Deposit Submitted</b>\nID: <code>{deposit_uid}</code> | {method} | <code>{amount}</code> | TxID: <code>{txid}</code>"),
        "short": ("⏳ ডিপোজিট <code>{deposit_uid}</code>: <code>{amount}</code>", "⏳ Deposit <code>{deposit_uid}</code>: <code>{amount}</code>"),
    },
    "deposit_approved_success": {
        "medium": ("✅ <b>ডিপোজিট সফল</b>\n<code>{deposit_uid}</code> | যুক্ত: <code>+{net_credit}</code> | ব্যালেন্স: <code>{new_deposit_balance}</code>", "✅ <b>Deposit Approved</b>\n<code>{deposit_uid}</code> | Credited: <code>+{net_credit}</code> | Balance: <code>{new_deposit_balance}</code>"),
        "short": ("✅ ডিপোজিট +{net_credit} (<code>{new_deposit_balance}</code>)", "✅ Deposit +{net_credit} (<code>{new_deposit_balance}</code>)"),
    },
    "referral_new_join_alert": {
        "medium": ("👥 <b>নতুন রেফারেল:</b> {ref_name} | মোট টিম: <b>{total_refs} জন</b>", "👥 <b>New Referral:</b> {ref_name} | Team: <b>{total_refs}</b>"),
        "short": ("👥 নতুন রেফারেল: {ref_name} ({total_refs})", "👥 New Ref: {ref_name} ({total_refs})"),
    },
    "referral_commission_msg": {
        "medium": ("💹 <b>রেফারেল কমিশন:</b> <code>+{amount}</code> ({ref_name}) | ব্যালেন্স: <code>{new_balance}</code>", "💹 <b>Referral Commission:</b> <code>+{amount}</code> ({ref_name}) | Balance: <code>{new_balance}</code>"),
        "short": ("💹 কমিশন +{amount} (<code>{new_balance}</code>)", "💹 Comm +{amount} (<code>{new_balance}</code>)"),
    },
    "task_credentials_issued": {
        "medium": ("🔐 <b>{task_title}</b> — তথ্য বরাদ্দ (মেয়াদ: {timeout_text})", "🔐 <b>{task_title}</b> — Source allocated ({timeout_text})"),
        "short": ("🔐 বরাদ্দ: {task_title} ({timeout_text})", "🔐 Allocated: {task_title} ({timeout_text})"),
    },
    "deposit_rejected_msg": {
        "medium": ("❌ <b>ডিপোজিট বাতিল</b> (<code>{deposit_uid}</code>)\nকারণ: <i>{reject_reason}</i>", "❌ <b>Deposit Rejected</b> (<code>{deposit_uid}</code>)\nReason: <i>{reject_reason}</i>"),
        "short": ("❌ ডিপোজিট বাতিল {deposit_uid}: {reject_reason}", "❌ Deposit Rejected {deposit_uid}: {reject_reason}"),
    },
    "withdraw_rejected_refund": {
        "medium": ("❌ <b>উইথড্র বাতিল ও রিফান্ড</b>\n<code>{withdraw_uid}</code> | ফেরত: <code>{gross}</code> | কারণ: {reject_reason}", "❌ <b>Withdraw Rejected & Refunded</b>\n<code>{withdraw_uid}</code> | Refund: <code>{gross}</code> | Reason: {reject_reason}"),
        "short": ("❌ উইথড্র রিফান্ড {withdraw_uid} (+{gross})", "❌ Withdraw Refunded {withdraw_uid} (+{gross})"),
    },
    "otp_number_allocated": {
        "medium": ("{country_flag} <b>{country_name}</b> (<code>{otp_uid}</code>) | সময়: {wait_text}", "{country_flag} <b>{country_name}</b> (<code>{otp_uid}</code>) | Wait: {wait_text}"),
        "short": ("{country_flag} {otp_uid} ({wait_text})", "{country_flag} {otp_uid} ({wait_text})"),
    },
    "otp_timeout_refund": {
        "medium": ("⏳ <b>OTP টাইমআউট</b> (<code>{otp_uid}</code>) | রিফান্ড: <code>{refund_amount}</code>", "⏳ <b>OTP Timeout</b> (<code>{otp_uid}</code>) | Refund: <code>{refund_amount}</code>"),
        "short": ("⏳ OTP মেয়াদ শেষ {otp_uid} (+{refund_amount})", "⏳ OTP Timeout {otp_uid} (+{refund_amount})"),
    },
    "daily_checkin_bonus": {
        "medium": ("📅 <b>চেক-ইন সফল</b> (দিন #{streak_day}) | <code>+{total_credited}</code> | ব্যালেন্স: <code>{new_balance}</code>", "📅 <b>Check-in Claimed</b> (Day #{streak_day}) | <code>+{total_credited}</code> | Balance: <code>{new_balance}</code>"),
        "short": ("📅 চেক-ইন #{streak_day}: +{total_credited}", "📅 Check-in #{streak_day}: +{total_credited}"),
    },
    "leaderboard_prize_won": {
        "medium": ("🏆 <b>লিডারবোর্ড পুরস্কার</b> (#{rank_pos}) | যুক্ত: <code>+{prize}</code>", "🏆 <b>Leaderboard Prize</b> (#{rank_pos}) | <code>+{prize}</code>"),
        "short": ("🏆 LB #{rank_pos}: +{prize}", "🏆 LB #{rank_pos}: +{prize}"),
    },
    "user_warning_strike": {
        "medium": ("⚠️ <b>ওয়ার্নিং</b> ({strikes}/{max_strikes}) | কারণ: {reason}", "⚠️ <b>Warning</b> ({strikes}/{max_strikes}) | Reason: {reason}"),
        "short": ("⚠️ স্ট্রাইক {strikes}/{max_strikes}: {reason}", "⚠️ Strike {strikes}/{max_strikes}: {reason}"),
    },
    "support_ticket_appeal": {
        "medium": ("🎫 <b>{ref_uid}</b> — স্ট্যাটাস: <b>{status}</b> | {note}", "🎫 <b>{ref_uid}</b> — Status: <b>{status}</b> | {note}"),
        "short": ("🎫 {ref_uid}: {status}", "🎫 {ref_uid}: {status}"),
    },
}
class MessageStudioManager:
    """
    RULE 96 Central Message Studio:
    Seeds 25 events x 30 variants x 2 languages = 1,500 HTML card designs,
    supports Fixed / Sequential Rotate / Smart Random modes, custom variants (31+),
    custom events, silent mode, privacy masking, and live previews.
    """

    def __init__(self, db: DatabaseManager, config: ConfigManager) -> None:
        self.db = db
        self.config = config
        self._rotate_lock = threading.Lock()

    def seed_all_variants(self) -> int:
        cnt_row = self.db.query_one("SELECT COUNT(*) AS c FROM message_studio_variants")
        if cnt_row and int(cnt_row["c"]) >= 750:
            return int(cnt_row["c"])

        now_s = now_utc_iso()
        inserted = 0
        with self.db.atomic(immediate=True) as conn:
            for ev_key, cat, ev_tbn, ev_ten, body_bn_tpl, body_en_tpl, ph_json in STUDIO_CORE_EVENTS:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO message_studio_events
                    (event_key, category, title_bn, title_en, delivery_mode, is_enabled, is_hidden,
                     silent_mode, mask_privacy, is_custom, placeholders_json, updated_at)
                    VALUES (?, ?, ?, ?, 'rotate', 1, 0, 0, 1, 0, ?, ?)
                    """,
                    (ev_key, cat, ev_tbn, ev_ten, ph_json, now_s),
                )
                for idx, (emoji, badge_bn, badge_en, tone_bn) in enumerate(STUDIO_STYLE_PREFIXES, start=1):
                    v_title_bn = f"{emoji} {ev_tbn} — {badge_bn} (#{idx})"
                    v_title_en = f"{emoji} {ev_ten} — {badge_en} (#{idx})"
                    v_body_bn = f"{emoji} <b>{tone_bn}:</b> {body_bn_tpl}"
                    v_body_en = f"{emoji} <b>{badge_en}:</b> {body_en_tpl}"
                    cur = conn.execute(
                        """
                        INSERT OR IGNORE INTO message_studio_variants
                        (event_key, variant_no, title_bn, title_en, body_bn, body_en,
                         is_enabled, is_hidden, is_builtin, is_archived, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, 1, 0, 1, 0, ?)
                        """,
                        (ev_key, idx, v_title_bn, v_title_en, v_body_bn, v_body_en, now_s),
                    )
                    inserted += int(cur.rowcount or 0)
        return inserted

    def list_events(self) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM message_studio_events ORDER BY is_custom ASC, category ASC, event_key ASC"
        )

    def get_event(self, event_key: str) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM message_studio_events WHERE event_key=?", (event_key,))

    def list_variants(self, event_key: str, include_archived: bool = False) -> List[sqlite3.Row]:
        if include_archived:
            return self.db.query_all(
                "SELECT * FROM message_studio_variants WHERE event_key=? ORDER BY variant_no ASC",
                (event_key,),
            )
        return self.db.query_all(
            "SELECT * FROM message_studio_variants WHERE event_key=? AND is_archived=0 ORDER BY variant_no ASC",
            (event_key,),
        )

    def get_variant(self, variant_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM message_studio_variants WHERE id=?", (variant_id,))

    def set_event_delivery_mode(self, event_key: str, mode: str, admin_id: int, fixed_no: Optional[int] = None) -> bool:
        if mode not in ("fixed", "rotate", "random"):
            return False
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE message_studio_events SET delivery_mode=?, updated_at=? WHERE event_key=?",
                (mode, now_utc_iso(), event_key),
            )
        if fixed_no is not None:
            self.config.set_setting(f"studio_fixed_{event_key}", int(fixed_no), admin_id=admin_id, reason="studio_fixed_no")
        return True

    def toggle_event_flag(self, event_key: str, field: str, admin_id: int) -> Tuple[bool, int]:
        if field not in ("is_enabled", "is_hidden", "silent_mode", "mask_privacy"):
            return False, 0
        row = self.get_event(event_key)
        if row is None:
            return False, 0
        new_val = 0 if int(row[field]) == 1 else 1
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                f"UPDATE message_studio_events SET {field}=?, updated_at=? WHERE event_key=?",
                (new_val, now_utc_iso(), event_key),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', ?, 'studio_event', ?, ?, ?)
                """,
                (admin_id, f"toggle_{field}", event_key, safe_json_dumps({"val": new_val}), now_utc_iso()),
            )
        return True, new_val

    def toggle_variant_flag(self, variant_id: int, field: str, admin_id: int) -> Tuple[bool, int]:
        if field not in ("is_enabled", "is_hidden", "is_archived"):
            return False, 0
        row = self.get_variant(variant_id)
        if row is None:
            return False, 0
        new_val = 0 if int(row[field]) == 1 else 1
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                f"UPDATE message_studio_variants SET {field}=?, updated_at=? WHERE id=?",
                (new_val, now_utc_iso(), variant_id),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', ?, 'studio_variant', ?, ?, ?)
                """,
                (admin_id, f"variant_{field}", str(variant_id), safe_json_dumps({"val": new_val}), now_utc_iso()),
            )
        return True, new_val

    def edit_variant(
        self,
        variant_id: int,
        lang: str,
        new_title: Optional[str],
        new_body: Optional[str],
        admin_id: int,
    ) -> Tuple[bool, str]:
        row = self.get_variant(variant_id)
        if row is None:
            return False, "Variant not found."
        if new_body is not None:
            ok, err = TextManager.validate_html_and_placeholders(new_body)
            if not ok:
                return False, err
        t_col = "title_bn" if lang == "bn" else "title_en"
        b_col = "body_bn" if lang == "bn" else "body_en"
        title_val = new_title.strip() if new_title is not None and new_title.strip() else str(row[t_col])
        body_val = new_body.strip() if new_body is not None and new_body.strip() else str(row[b_col])
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                f"UPDATE message_studio_variants SET {t_col}=?, {b_col}=?, updated_at=? WHERE id=?",
                (title_val, body_val, now_utc_iso(), variant_id),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', 'edit_variant', 'studio_variant', ?, ?, ?)
                """,
                (admin_id, str(variant_id), safe_json_dumps({"lang": lang}), now_utc_iso()),
            )
        return True, "Variant updated."

    def add_custom_variant(
        self,
        event_key: str,
        title_bn: str,
        title_en: str,
        body_bn: str,
        body_en: str,
        admin_id: int,
    ) -> Tuple[bool, str, int]:
        if self.get_event(event_key) is None:
            return False, "Event not found.", 0
        for txt in (body_bn, body_en):
            ok, err = TextManager.validate_html_and_placeholders(txt)
            if not ok:
                return False, err, 0
        max_row = self.db.query_one(
            "SELECT COALESCE(MAX(variant_no), 30) AS m FROM message_studio_variants WHERE event_key=?",
            (event_key,),
        )
        next_no = max(31, int(max_row["m"]) + 1) if max_row else 31
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO message_studio_variants
                (event_key, variant_no, title_bn, title_en, body_bn, body_en,
                 is_enabled, is_hidden, is_builtin, is_archived, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, 0, 0, 0, ?)
                """,
                (event_key, next_no, title_bn, title_en, body_bn, body_en, now_s),
            )
            new_id = int(cur.lastrowid or 0)
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', 'add_variant', 'studio_event', ?, ?, ?)
                """,
                (admin_id, event_key, safe_json_dumps({"variant_no": next_no}), now_s),
            )
        return True, f"Added variant #{next_no}", new_id

    def add_custom_event(
        self,
        event_key: str,
        title_bn: str,
        title_en: str,
        body_bn: str,
        body_en: str,
        admin_id: int,
    ) -> Tuple[bool, str]:
        cleaned_key = re.sub(r"[^a-z0-9_]+", "_", event_key.strip().lower()).strip("_")
        if not cleaned_key or self.get_event(cleaned_key) is not None:
            return False, "Event key is empty or already exists."
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO message_studio_events
                (event_key, category, title_bn, title_en, delivery_mode, is_enabled, is_hidden,
                 silent_mode, mask_privacy, is_custom, placeholders_json, updated_at)
                VALUES (?, 'custom', ?, ?, 'fixed', 1, 0, 0, 1, 1, '[]', ?)
                """,
                (cleaned_key, title_bn, title_en, now_s),
            )
            conn.execute(
                """
                INSERT INTO message_studio_variants
                (event_key, variant_no, title_bn, title_en, body_bn, body_en,
                 is_enabled, is_hidden, is_builtin, is_archived, updated_at)
                VALUES (?, 1, ?, ?, ?, ?, 1, 0, 0, 0, ?)
                """,
                (cleaned_key, title_bn, title_en, body_bn, body_en, now_s),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, 'admin', 'add_custom_event', 'studio_event', ?, '{}', ?)
                """,
                (admin_id, cleaned_key, now_s),
            )
        return True, f"Custom event '{cleaned_key}' created."

    def _pick_variant(self, event_row: sqlite3.Row) -> Optional[sqlite3.Row]:
        event_key = str(event_row["event_key"])
        active_variants = self.db.query_all(
            """
            SELECT * FROM message_studio_variants
            WHERE event_key=? AND is_enabled=1 AND is_hidden=0 AND is_archived=0
            ORDER BY variant_no ASC
            """,
            (event_key,),
        )
        if not active_variants:
            return None
        mode = str(event_row["delivery_mode"] or "rotate")
        if mode == "fixed":
            fixed_no = self.config.get_int(f"studio_fixed_{event_key}", 1)
            for v in active_variants:
                if int(v["variant_no"]) == fixed_no:
                    return v
            return active_variants[0]
        if mode == "random":
            return secrets.choice(active_variants)
        # Sequential rotate
        with self._rotate_lock:
            cursor_key = f"studio_cursor_{event_key}"
            idx = self.config.get_int(cursor_key, 0)
            chosen = active_variants[idx % len(active_variants)]
            next_idx = (idx + 1) % len(active_variants)
            self.config.set_setting(cursor_key, next_idx, admin_id=0, reason="auto_rotate", category="studio")
            return chosen

    def render_event_message(
        self,
        event_key: str,
        lang: str = "bn",
        variant_id: Optional[int] = None,
        **kwargs: Any,
    ) -> Tuple[str, bool, bool]:
        """
        Renders an HTML card:
        ━━ Title ━━
        <blockquote>Body</blockquote>
        Returns: (html_text, silent_mode, is_enabled)
        """
        ev_row = self.get_event(event_key)
        if ev_row is None:
            return "", False, False
        if int(ev_row["is_enabled"]) == 0 or int(ev_row["is_hidden"]) == 1:
            return "", bool(ev_row["silent_mode"]), False

        var_row = self.get_variant(variant_id) if variant_id is not None else self._pick_variant(ev_row)
        if var_row is None:
            return "", bool(ev_row["silent_mode"]), False

        theme = self.config.get_theme()
        bot_name = self.config.get_bot_name(lang=lang)
        mask_privacy = int(ev_row["mask_privacy"]) == 1

        safe_vars: Dict[str, Any] = {
            "bot_name": escape_html(bot_name),
            "divider": escape_html(theme["divider"]),
            "header_icon": escape_html(theme["icon"]),
            "time": escape_html(now_dhaka().strftime("%I:%M %p")),
        }
        for k, v in kwargs.items():
            val_str = str(v if v is not None else "")
            if mask_privacy and k == "ref_id_masked" and val_str.isdigit():
                val_str = mask_phone_or_account(val_str)
            safe_vars[k] = escape_html(val_str)

        raw_title = str(var_row["title_bn"] if lang == "bn" else var_row["title_en"])
        raw_body = str(var_row["body_bn"] if lang == "bn" else var_row["body_en"])
        try:
            rendered_title = raw_title.format_map(_SafeFormatDict(safe_vars))
        except Exception:
            rendered_title = raw_title
        try:
            rendered_body = raw_body.format_map(_SafeFormatDict(safe_vars))
        except Exception:
            rendered_body = raw_body

        per_ev_mode = self.config.get_str(f"msg_size_ev_{event_key}", "global")
        size_mode = self.config.get_str("message_size_mode", "current") if per_ev_mode == "global" else per_ev_mode

        if variant_id is None and size_mode in ("medium", "short"):
            compact_pair = STUDIO_COMPACT_TEMPLATES.get(event_key, {}).get(size_mode)
            if compact_pair:
                c_tpl = compact_pair[0] if lang == "bn" else compact_pair[1]
                try:
                    compact_out = c_tpl.format_map(_SafeFormatDict(safe_vars))
                except Exception:
                    compact_out = c_tpl
                return truncate_text(compact_out), bool(ev_row["silent_mode"]), True
            return truncate_text(apply_message_size_style(f"<b>{rendered_title}</b>\n{rendered_body}", size_mode, divider=theme["divider"])), bool(ev_row["silent_mode"]), True

        card_html = f"━━ <b>{rendered_title}</b> ━━\n<blockquote>{rendered_body}</blockquote>"
        return truncate_text(card_html), bool(ev_row["silent_mode"]), True
# ==============================================================================
# VALIDATION MANAGER & AUDIT MANAGER (RULE 10.5, 33, 42, 59)
# ==============================================================================

class ValidationManager:
    """Validates uploads, regexes, wallets, dynamic inputs, and security constraints."""

    def __init__(self, config: ConfigManager) -> None:
        self.config = config

    def validate_upload_file(self, file_name: str, file_size_bytes: int) -> Tuple[bool, str]:
        ext = Path(str(file_name or "")).suffix.lower()
        if ext in FORBIDDEN_EXECUTABLE_EXTENSIONS:
            return False, f"Executable or script files ({ext}) are strictly forbidden."
        max_mb = max(1, self.config.get_int("max_upload_size_mb", 15))
        if file_size_bytes > max_mb * 1024 * 1024:
            return False, f"File exceeds maximum allowed size of {max_mb} MB."
        return True, ""

    @staticmethod
    def validate_wallet_address(method_type: str, value: str, custom_regex: str = "") -> Tuple[bool, str, str]:
        raw = str(value or "").strip()
        if not raw:
            return False, "", "Wallet or account number cannot be empty."
        if method_type == "bd_mobile":
            ok, norm, err = normalize_bd_phone(raw)
            if not ok:
                return False, norm, err
            if custom_regex:
                try:
                    if not re.fullmatch(custom_regex, norm):
                        return False, norm, "Mobile number does not match method pattern."
                except re.error:
                    pass
            return True, norm, ""
        if method_type == "crypto":
            if custom_regex:
                try:
                    if not re.fullmatch(custom_regex, raw):
                        return False, raw, "Invalid crypto wallet / Pay ID format."
                except re.error:
                    pass
            else:
                is_trc20 = bool(re.fullmatch(r"T[A-Za-z1-9]{33}", raw))
                is_evm = bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", raw))
                is_payid = bool(re.fullmatch(r"\d{6,15}", raw))
                if not (is_trc20 or is_evm or is_payid):
                    return False, raw, "Must be valid TRC20 (T+34), BEP20/ERC20 (0x+42), or Binance Pay ID."
            return True, raw, ""
        if custom_regex:
            try:
                if not re.fullmatch(custom_regex, raw):
                    return False, raw, "Account format did not match required regex."
            except re.error:
                pass
        if len(raw) < 4:
            return False, raw, "Account value is too short."
        return True, raw, ""

    @staticmethod
    def validate_step_input(
        input_type: str,
        value: str,
        min_len: int = 0,
        max_len: int = 2000,
        regex_pattern: str = "",
        options: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        val = str(value or "").strip()
        if min_len > 0 and len(val) < min_len:
            return False, f"Minimum length is {min_len} characters."
        if max_len > 0 and len(val) > max_len:
            return False, f"Maximum length is {max_len} characters."
        if input_type == "number":
            if parse_positive_float(val) is None:
                return False, "Please enter a valid non-negative number."
        elif input_type == "email":
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", val):
                return False, "Please enter a valid email address."
        elif input_type == "url":
            if not re.match(r"^https?://[^\s]+$", val, re.IGNORECASE):
                return False, "Please enter a valid http:// or https:// URL."
        elif input_type == "select" and options:
            if val not in options:
                return False, f"Must choose one of: {', '.join(options)}"
        if regex_pattern:
            try:
                if not re.fullmatch(regex_pattern, val):
                    return False, "Input did not match the required pattern."
            except re.error:
                pass
        return True, ""


class AuditManager:
    """Centralized immutable audit trail for admin & security events."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def log(
        self,
        actor_id: int,
        actor_role: str,
        action: str,
        target_type: str = "",
        target_id: Any = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, details_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(actor_id),
                    actor_role,
                    action,
                    target_type,
                    str(target_id),
                    safe_json_dumps(details or {}),
                    now_utc_iso(),
                ),
            )

    def list_recent(self, limit: int = 30, offset: int = 0) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )


# ==============================================================================
# PERMISSION MANAGER (RULE 34: MAIN ADMIN + 20 GRANULAR ASSISTANT PERMISSIONS)
# ==============================================================================

PERMISSION_GROUPS: Tuple[Tuple[str, str, str], ...] = (
    ("dashboard", "A-01 ড্যাশবোর্ড দেখা", "A-01 View Dashboard"),
    ("diagnostics", "A-02 সিস্টেম ও ডায়াগনস্টিকস", "A-02 System Diagnostics"),
    ("channels", "A-03 চ্যানেল ও সাপোর্ট", "A-03 Channels & Support"),
    ("force_join", "A-04 ফোর্স জয়েন নিয়ন্ত্রণ", "A-04 Force Join Control"),
    ("texts", "A-05 টেক্সট, ভাষা ও রুলস", "A-05 Texts, Language & Rules"),
    ("buttons_colors", "A-06 কিবোর্ড, বাটন ও কালার", "A-06 Keyboard, Buttons & Colors"),
    ("message_studio", "A-07 মেসেজ স্টুডিও", "A-07 Central Message Studio"),
    ("rules_controller", "A-08 সেক্টর ও রুল কন্ট্রোলার", "A-08 Sector & Rule Controller"),
    ("tasks", "A-09 টাস্ক ও TOTP/কুকি ম্যানেজার", "A-09 Task, TOTP & Cookie Manager"),
    ("auto_review", "A-10 অটো-রিভিউ ও শিডিউলার", "A-10 Auto-Review & Scheduler"),
    ("file_submit", "A-11 ফাইল সাবমিট ও ব্যাচ রিভিউ", "A-11 File Submit & Batch Review"),
    ("product_store", "A-12 প্রোডাক্ট স্টোর ও স্টক", "A-12 Product Store & Stock"),
    ("otp_system", "A-13 OTP রিসিভার ও ব্রিজ", "A-13 OTP Receiver & Bridges"),
    ("deposits", "A-14 ডিপোজিট ও OCR রিভিউ", "A-14 Deposit & OCR Review"),
    ("withdrawals", "A-15 উইথড্রয়াল ও Mark Paid", "A-15 Withdrawal & Mark Paid"),
    ("growth_lb", "A-16 রেফারেল, বোনাস, লিডারবোর্ড", "A-16 Growth & Leaderboard"),
    ("users_finance", "A-17 ইউজার, ব্যালেন্স ও ওয়ার্নিং", "A-17 Users, Finance & Warnings"),
    ("tickets_broadcast", "A-18 টিকেট, আপিল ও ব্রডকাস্ট", "A-18 Tickets, Appeals & Broadcast"),
    ("security_locks", "A-19 সিকিউরিটি, লক ও রুলস", "A-19 Security & Locks"),
    ("backup_ledger", "A-20 লেজার, অডিট ও ব্যাকআপ", "A-20 Ledger, Audit & Backup"),
)


class PermissionManager:
    """
    Main Admin (8882139752) owns full system. Assistant Admins require Main Admin approval,
    optional Admin Panel Password verification, and cannot alter Main Admin or password rules.
    """

    def __init__(self, db: DatabaseManager, audit: AuditManager) -> None:
        self.db = db
        self.audit = audit
        self._lock = threading.Lock()
        self._unlocked_until: Dict[int, float] = {}

    @staticmethod
    def is_main_admin(user_id: int) -> bool:
        return int(user_id) == DEFAULT_MAIN_ADMIN_ID

    def is_any_admin(self, user_id: int) -> bool:
        if self.is_main_admin(user_id):
            return True
        row = self.db.query_one(
            "SELECT is_active, approval_status FROM assistant_permissions WHERE admin_id=?",
            (int(user_id),),
        )
        return bool(row and int(row["is_active"]) == 1 and str(row["approval_status"] or "approved") == "approved")

    def get_access_block_reason(self, user_id: int) -> str:
        if self.is_main_admin(user_id):
            return ""
        row = self.get_assistant(user_id)
        if row is None:
            return "⛔ Access Denied: Admins only."
        st = str(row["approval_status"] or "pending")
        if st == "pending":
            return "⏳ আপনার এডমিন অনুমোদন এখনো মূল এডমিনের অপেক্ষায় রয়েছে।"
        if st == "rejected":
            return "⛔ আপনার এডমিন অনুরোধ মূল এডমিন কর্তৃক রিজেক্ট করা হয়েছে।"
        if int(row["is_active"]) != 1:
            return "⛔ আপনার এডমিন অ্যাক্সেস নিষ্ক্রিয় করা হয়েছে।"
        return ""

    def get_assistant(self, admin_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM assistant_permissions WHERE admin_id=?", (int(admin_id),))

    def list_assistants(self) -> List[sqlite3.Row]:
        return self.db.query_all("SELECT * FROM assistant_permissions ORDER BY created_at DESC")

    def has_permission(self, user_id: int, perm_key: str) -> bool:
        if self.is_main_admin(user_id):
            return True
        if perm_key in {"manage_admins", "panic_freeze_unlock", "big_withdraw_override"}:
            return False
        row = self.get_assistant(user_id)
        if not row or int(row["is_active"]) != 1 or str(row["approval_status"] or "approved") != "approved":
            return False
        perms = safe_json_loads(row["permissions_json"], {})
        return bool(perms.get(perm_key, False))

    def is_password_required_for(self, user_id: int, config: ConfigManager) -> bool:
        if not config.get_bool("admin_panel_password_enabled", False):
            return False
        if not config.get_str("admin_panel_password", "").strip():
            return False
        if self.is_main_admin(user_id) and not config.get_bool("admin_panel_password_main", False):
            return False
        return True

    def is_admin_session_unlocked(self, user_id: int) -> bool:
        with self._lock:
            return self._unlocked_until.get(int(user_id), 0.0) > time.time()

    def unlock_admin_session(self, user_id: int, ttl_sec: int = 3600) -> None:
        with self._lock:
            self._unlocked_until[int(user_id)] = time.time() + max(60, int(ttl_sec))

    def lock_admin_session(self, user_id: int) -> None:
        with self._lock:
            self._unlocked_until.pop(int(user_id), None)

    def revoke_all_admin_sessions(self) -> None:
        with self._lock:
            self._unlocked_until.clear()

    def add_or_update_assistant(
        self,
        actor_id: int,
        target_admin_id: int,
        full_name: str = "",
        username: str = "",
        initial_perms: Optional[Dict[str, bool]] = None,
    ) -> Tuple[bool, str]:
        if not self.is_main_admin(actor_id):
            return False, "Only Main Admin can manage Assistant Admins."
        if int(target_admin_id) == DEFAULT_MAIN_ADMIN_ID:
            return False, "Cannot modify Main Admin permissions."
        now_s = now_utc_iso()
        existing = self.get_assistant(target_admin_id)
        if existing is None:
            default_perms = {k: (k == "dashboard") for k, _, _ in PERMISSION_GROUPS}
            if initial_perms:
                default_perms.update(initial_perms)
            with self.db.atomic(immediate=True) as conn:
                conn.execute(
                    """
                    INSERT INTO assistant_permissions
                    (admin_id, full_name, username, is_active, approval_status, permissions_json, added_by, created_at, updated_at)
                    VALUES (?, ?, ?, 0, 'pending', ?, ?, ?, ?)
                    """,
                    (
                        int(target_admin_id),
                        full_name,
                        username,
                        safe_json_dumps(default_perms),
                        actor_id,
                        now_s,
                        now_s,
                    ),
                )
            self.audit.log(actor_id, "main_admin", "request_assistant_approval", "assistant_admin", target_admin_id)
            return True, "Assistant Admin queued for approval."
        perms = safe_json_loads(existing["permissions_json"], {})
        if initial_perms:
            perms.update(initial_perms)
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                UPDATE assistant_permissions
                SET full_name=COALESCE(NULLIF(?, ''), full_name),
                    username=COALESCE(NULLIF(?, ''), username),
                    permissions_json=?, approval_status='pending', is_active=0, updated_at=?
                WHERE admin_id=?
                """,
                (full_name, username, safe_json_dumps(perms), now_s, int(target_admin_id)),
            )
        self.lock_admin_session(target_admin_id)
        self.audit.log(actor_id, "main_admin", "upsert_assistant", "assistant_admin", target_admin_id)
        return True, "Assistant Admin updated (Pending Approval)."

    def approve_assistant(self, actor_id: int, target_admin_id: int) -> Tuple[bool, str]:
        if not self.is_main_admin(actor_id):
            return False, "শুধুমাত্র মূল এডমিন অনুমোদন দিতে পারবেন।"
        row = self.get_assistant(target_admin_id)
        if not row:
            return False, "Admin record not found."
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                UPDATE assistant_permissions
                SET approval_status='approved', is_active=1, approved_by=?, approved_at=?, updated_at=?
                WHERE admin_id=?
                """,
                (int(actor_id), now_s, now_s, int(target_admin_id)),
            )
        self.audit.log(actor_id, "main_admin", "approve_assistant", "assistant_admin", target_admin_id)
        return True, "Assistant Admin Approved!"

    def reject_assistant(self, actor_id: int, target_admin_id: int, note: str = "") -> Tuple[bool, str]:
        if not self.is_main_admin(actor_id):
            return False, "শুধুমাত্র মূল এডমিন রিজেক্ট করতে পারবেন।"
        row = self.get_assistant(target_admin_id)
        if not row:
            return False, "Admin record not found."
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                UPDATE assistant_permissions
                SET approval_status='rejected', is_active=0, rejection_note=?, updated_at=?
                WHERE admin_id=?
                """,
                (note.strip(), now_s, int(target_admin_id)),
            )
        self.lock_admin_session(target_admin_id)
        self.audit.log(actor_id, "main_admin", "reject_assistant", "assistant_admin", target_admin_id)
        return True, "Assistant Admin Rejected!"

    def toggle_assistant_active(self, actor_id: int, target_admin_id: int) -> Tuple[bool, int]:
        if not self.is_main_admin(actor_id) or int(target_admin_id) == DEFAULT_MAIN_ADMIN_ID:
            return False, 0
        row = self.get_assistant(target_admin_id)
        if not row:
            return False, 0
        new_val = 0 if int(row["is_active"]) == 1 else 1
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE assistant_permissions SET is_active=?, updated_at=? WHERE admin_id=?",
                (new_val, now_utc_iso(), int(target_admin_id)),
            )
        if new_val == 0:
            self.lock_admin_session(target_admin_id)
        self.audit.log(actor_id, "main_admin", "toggle_assistant_active", "assistant_admin", target_admin_id, {"active": new_val})
        return True, new_val

    def toggle_assistant_perm(self, actor_id: int, target_admin_id: int, perm_key: str) -> Tuple[bool, bool]:
        if not self.is_main_admin(actor_id) or int(target_admin_id) == DEFAULT_MAIN_ADMIN_ID:
            return False, False
        row = self.get_assistant(target_admin_id)
        if not row:
            return False, False
        perms = safe_json_loads(row["permissions_json"], {})
        new_val = not bool(perms.get(perm_key, False))
        perms[perm_key] = new_val
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE assistant_permissions SET permissions_json=?, updated_at=? WHERE admin_id=?",
                (safe_json_dumps(perms), now_utc_iso(), int(target_admin_id)),
            )
        self.audit.log(actor_id, "main_admin", "toggle_perm", "assistant_admin", target_admin_id, {perm_key: new_val})
        return True, new_val

    def remove_assistant(self, actor_id: int, target_admin_id: int) -> Tuple[bool, str]:
        if not self.is_main_admin(actor_id):
            return False, "Main Admin only."
        if int(target_admin_id) == DEFAULT_MAIN_ADMIN_ID:
            return False, "Cannot remove Main Admin."
        with self.db.atomic(immediate=True) as conn:
            conn.execute("DELETE FROM assistant_permissions WHERE admin_id=?", (int(target_admin_id),))
        self.lock_admin_session(target_admin_id)
        self.audit.log(actor_id, "main_admin", "remove_assistant", "assistant_admin", target_admin_id)
        return True, "Assistant Admin removed."


# ==============================================================================
# DUAL KEYBOARD, DYNAMIC BUTTONS & BUTTON COLOR MANAGER (RULE 7, 76, 88, 89)
# ==============================================================================

class DualKeyboardManager:
    """
    Manages built-in & custom dynamic buttons, No-Duplicate menu registry,
    independent Reply & Inline keyboard ON/OFF/Hide, and API 9.4 button colors.
    """

    def __init__(self, db: DatabaseManager, config: ConfigManager, audit: AuditManager) -> None:
        self.db = db
        self.config = config
        self.audit = audit

    def colors_enabled(self) -> bool:
        return self.config.get_bool("button_colors_enabled", True)

    def resolve_action_style(self, action_kind: str, custom_style: Optional[str] = None) -> str:
        if custom_style and custom_style != "default" and custom_style in OFFICIAL_BUTTON_STYLES:
            return custom_style
        kind = action_kind.lower()
        if kind in {"confirm", "approve", "paid", "copy", "checkin", "bonus", "withdraw"}:
            return self.config.get_str("color_action_confirm", "success")
        if kind in {"cancel", "reject", "delete", "block", "panic", "swap"}:
            return self.config.get_str("color_action_cancel", "danger")
        if kind in {"primary", "task", "store", "otp", "deposit", "verify", "admin", "home", "referral"}:
            return self.config.get_str("color_action_primary", "primary")
        return "default"

    def ibtn(
        self,
        text: str,
        callback_data: Optional[str] = None,
        url: Optional[str] = None,
        action_kind: str = "default",
        custom_style: Optional[str] = None,
    ) -> InlineKeyboardButton:
        style = self.resolve_action_style(action_kind, custom_style)
        return BUTTON_ADAPTER.make_inline_button(
            text=text,
            callback_data=callback_data,
            url=url,
            style=style,
            colors_enabled=self.colors_enabled(),
        )

    def rbtn(
        self,
        text: str,
        action_kind: str = "default",
        custom_style: Optional[str] = None,
    ) -> KeyboardButton:
        style = self.resolve_action_style(action_kind, custom_style)
        return BUTTON_ADAPTER.make_reply_button(
            text=text,
            style=style,
            colors_enabled=self.colors_enabled(),
        )

    def list_menu_buttons(self, include_hidden: bool = False, include_disabled: bool = False) -> List[sqlite3.Row]:
        clauses = ["menu_scope='user_main'", "is_archived=0"]
        if not include_hidden:
            clauses.append("is_hidden=0")
        if not include_disabled:
            clauses.append("is_enabled=1")
        where_sql = " AND ".join(clauses)
        return self.db.query_all(
            f"SELECT * FROM dynamic_buttons WHERE {where_sql} ORDER BY row_group ASC, sort_order ASC, id ASC"
        )

    def get_button_by_key(self, button_key: str) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM dynamic_buttons WHERE button_key=?", (button_key,))

    def get_button_by_id(self, btn_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM dynamic_buttons WHERE id=?", (btn_id,))

    def _get_filtered_active_buttons(self, placement_filter: str) -> List[sqlite3.Row]:
        """
        Enforces No-Duplicate Menu Registry & smart Leaderboard/Bonus slot visibility.
        """
        rows = self.list_menu_buttons(include_hidden=False, include_disabled=False)
        task_lb_on = self.config.get_bool("task_lb_enabled", True)
        fs_lb_on = self.config.get_bool("fs_lb_enabled", True)
        seen_keys: Set[str] = set()
        seen_labels: Set[str] = set()
        result: List[sqlite3.Row] = []

        for r in rows:
            bkey = str(r["button_key"])
            if bkey in seen_keys:
                continue
            pl = str(r["placement"] or "both")
            if pl != "both" and pl != placement_filter:
                continue
            if bkey == "u_task_lb" and not task_lb_on:
                continue
            if bkey == "u_fs_lb" and not fs_lb_on:
                continue
            if bkey == "u_otp" and not self.config.get_bool("otp_system_enabled", True):
                continue
            if bkey == "u_checkin" and not self.config.get_bool("daily_checkin_enabled", True):
                continue
            if bkey == "u_referral" and not self.config.get_bool("referral_enabled", True):
                continue
            if bkey == "u_language" and not self.config.get_bool("language_switcher_enabled", True):
                continue

            lbl = f"{r['emoji']} {r['label_bn']}".strip().lower()
            if lbl in seen_labels:
                continue
            seen_keys.add(bkey)
            seen_labels.add(lbl)
            result.append(r)
        return result

    @staticmethod
    def format_button_label(row: sqlite3.Row, lang: str = "bn") -> str:
        emoji = str(row["emoji"] or "").strip()
        label = str(row["label_bn"] if lang == "bn" else row["label_en"]).strip()
        return f"{emoji} {label}".strip() if emoji else label

    def build_user_reply_keyboard(
        self,
        lang: str = "bn",
        is_admin: bool = False,
    ) -> Union[ReplyKeyboardMarkup, ReplyKeyboardRemove]:
        reply_on = self.config.get_bool("reply_keyboard_enabled", True)
        reply_hidden = self.config.get_bool("reply_keyboard_hidden", False)
        if not reply_on or reply_hidden:
            return ReplyKeyboardRemove()

        buttons = self._get_filtered_active_buttons("reply")
        cols = max(1, min(3, self.config.get_int("menu_columns", 2)))
        grid: List[List[KeyboardButton]] = []
        current_row: List[KeyboardButton] = []

        for r in buttons:
            text = self.format_button_label(r, lang=lang)
            style = str(r["button_style"] or "default")
            btn = self.rbtn(text, action_kind=str(r["action_target"]), custom_style=style)
            if int(r["col_span"]) >= 2:
                if current_row:
                    grid.append(current_row)
                    current_row = []
                grid.append([btn])
            else:
                current_row.append(btn)
                if len(current_row) >= cols:
                    grid.append(current_row)
                    current_row = []
        if current_row:
            grid.append(current_row)

        if is_admin:
            adm_lbl = "⚙️ এডমিন প্যানেল" if lang == "bn" else "⚙️ Admin Panel"
            grid.append([self.rbtn(adm_lbl, action_kind="admin", custom_style="primary")])

        placeholder = self.config.get_str(
            "reply_placeholder_bn" if lang == "bn" else "reply_placeholder_en",
            "একটি বাটন নির্বাচন করুন..." if lang == "bn" else "Choose an option...",
        )
        return ReplyKeyboardMarkup(
            grid,
            resize_keyboard=True,
            is_persistent=True,
            input_field_placeholder=placeholder[:64],
        )

    def build_user_inline_menu(
        self,
        lang: str = "bn",
        is_admin: bool = False,
    ) -> Optional[InlineKeyboardMarkup]:
        inline_on = self.config.get_bool("inline_keyboard_enabled", True)
        inline_hidden = self.config.get_bool("inline_keyboard_hidden", False)
        if not inline_on or inline_hidden:
            return None

        buttons = self._get_filtered_active_buttons("inline")
        cols = max(1, min(3, self.config.get_int("menu_columns", 2)))
        grid: List[List[InlineKeyboardButton]] = []
        current_row: List[InlineKeyboardButton] = []

        for r in buttons:
            text = self.format_button_label(r, lang=lang)
            style = str(r["button_style"] or "default")
            atype = str(r["action_type"])
            atarget = str(r["action_target"])
            bkey = str(r["button_key"])
            if atype == "url" and atarget.startswith(("http://", "https://", "tg://")):
                btn = self.ibtn(text, url=atarget, action_kind="primary", custom_style=style)
            else:
                cb = f"um:{bkey}" if atype == "builtin" else f"ucb:{r['id']}"
                btn = self.ibtn(text, callback_data=cb, action_kind=atarget, custom_style=style)

            if int(r["col_span"]) >= 2:
                if current_row:
                    grid.append(current_row)
                    current_row = []
                grid.append([btn])
            else:
                current_row.append(btn)
                if len(current_row) >= cols:
                    grid.append(current_row)
                    current_row = []
        if current_row:
            grid.append(current_row)

        if is_admin:
            adm_lbl = "⚙️ এডমিন প্যানেল" if lang == "bn" else "⚙️ Admin Panel"
            grid.append([self.ibtn(adm_lbl, callback_data="adm:home", action_kind="admin", custom_style="primary")])

        return InlineKeyboardMarkup(grid) if grid else None

    def match_reply_button(self, text: str) -> Optional[sqlite3.Row]:
        cleaned = str(text or "").strip()
        if not cleaned:
            return None
        for r in self.list_menu_buttons(include_hidden=False, include_disabled=False):
            if cleaned == self.format_button_label(r, "bn") or cleaned == self.format_button_label(r, "en"):
                return r
            if cleaned == str(r["label_bn"]).strip() or cleaned == str(r["label_en"]).strip():
                return r
        return None

    def create_custom_button(
        self,
        label_bn: str,
        label_en: str,
        emoji: str,
        action_type: str,
        action_target: str,
        button_style: str = "primary",
        placement: str = "both",
        admin_id: int = 0,
    ) -> Tuple[bool, str, int]:
        style = BUTTON_ADAPTER.validate_style(button_style)
        if placement not in ("both", "reply", "inline"):
            placement = "both"
        existing = self.list_menu_buttons(include_hidden=True, include_disabled=True)
        for ex in existing:
            if str(ex["label_bn"]).strip().lower() == label_bn.strip().lower():
                return False, "A button with this Bengali label already exists (No-Duplicate rule).", 0
        bkey = f"cust_{secrets.token_hex(4)}"
        max_order = max((int(x["sort_order"]) for x in existing), default=20)
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO dynamic_buttons
                (button_key, menu_scope, label_bn, label_en, emoji, action_type, action_target,
                 button_style, placement, row_group, sort_order, col_span, is_builtin, is_enabled, is_hidden, is_archived, created_at, updated_at)
                VALUES (?, 'user_main', ?, ?, ?, ?, ?, ?, ?, 10, ?, 1, 0, 1, 0, 0, ?, ?)
                """,
                (bkey, label_bn.strip(), label_en.strip(), emoji.strip(), action_type, action_target.strip(), style, placement, max_order + 1, now_s, now_s),
            )
            btn_id = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_custom_button", "dynamic_button", btn_id, {"key": bkey})
        return True, "Custom button created.", btn_id

    def set_button_style(self, btn_id: int, style: str, admin_id: int) -> Tuple[bool, str]:
        valid = BUTTON_ADAPTER.validate_style(style)
        if style.lower() not in OFFICIAL_BUTTON_STYLES:
            return False, "Only default, primary, success, danger are supported by Telegram API."
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE dynamic_buttons SET button_style=?, updated_at=? WHERE id=?",
                (valid, now_utc_iso(), btn_id),
            )
        self.audit.log(admin_id, "admin", "set_button_style", "dynamic_button", btn_id, {"style": valid})
        return True, f"Style updated to {valid}."

    def reset_all_button_colors(self, admin_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute("UPDATE dynamic_buttons SET button_style='default', updated_at=?", (now_utc_iso(),))
        self.config.set_setting("button_colors_enabled", True, admin_id=admin_id, reason="reset_colors")
        self.audit.log(admin_id, "admin", "reset_all_button_colors", "dynamic_buttons", "all")

    def toggle_keyboard_switch(self, setting_key: str, admin_id: int) -> Tuple[bool, str, bool]:
        if setting_key not in {
            "reply_keyboard_enabled",
            "reply_keyboard_hidden",
            "inline_keyboard_enabled",
            "inline_keyboard_hidden",
        }:
            return False, "Invalid keyboard setting.", False
        current = self.config.get_bool(setting_key, False)
        proposed = not current

        # Anti-Lockout Safety Guard: prevent turning off both keyboards at the same time
        reply_eff = (
            (proposed if setting_key == "reply_keyboard_enabled" else self.config.get_bool("reply_keyboard_enabled", True))
            and not (proposed if setting_key == "reply_keyboard_hidden" else self.config.get_bool("reply_keyboard_hidden", False))
        )
        inline_eff = (
            (proposed if setting_key == "inline_keyboard_enabled" else self.config.get_bool("inline_keyboard_enabled", True))
            and not (proposed if setting_key == "inline_keyboard_hidden" else self.config.get_bool("inline_keyboard_hidden", False))
        )
        if not reply_eff and not inline_eff:
            return False, "Anti-Lockout Guard: Reply এবং Inline উভয় কিবোর্ড একসাথে বন্ধ বা লুকানো যাবে না!", current

        self.config.set_setting(setting_key, proposed, admin_id=admin_id, reason="keyboard_toggle")
        return True, "Keyboard setting updated.", proposed

    def nav_row(self, lang: str = "bn", back_cb: Optional[str] = None, include_home: bool = True) -> List[InlineKeyboardButton]:
        row: List[InlineKeyboardButton] = []
        if back_cb:
            lbl = "⬅️ পেছনে" if lang == "bn" else "⬅️ Back"
            row.append(self.ibtn(lbl, callback_data=back_cb, action_kind="default"))
        if include_home:
            lbl_h = "🏠 মেইন মেনু" if lang == "bn" else "🏠 Home"
            row.append(self.ibtn(lbl_h, callback_data="um:home", action_kind="primary"))
        return row

    def cancel_row(self, lang: str = "bn", cancel_cb: str = "flow:cancel") -> List[InlineKeyboardButton]:
        lbl = "❌ বাতিল" if lang == "bn" else "❌ Cancel"
        return [self.ibtn(lbl, callback_data=cancel_cb, action_kind="cancel")]


# ==============================================================================
# STRICT MULTI-CHANNEL FORCE JOIN MANAGER (RULE 5)
# ==============================================================================

class ForceJoinManager:
    """
    Enforces Strict Multi-Channel Force Join across all bot features.
    Never marks a channel as joined when Telegram API returns an error.
    """

    def __init__(self, db: DatabaseManager, config: ConfigManager, kb: DualKeyboardManager) -> None:
        self.db = db
        self.config = config
        self.kb = kb

    def list_force_join_channels(self, active_only: bool = True) -> List[sqlite3.Row]:
        if active_only:
            return self.db.query_all(
                "SELECT * FROM channels WHERE is_active=1 AND is_hidden=0 AND privacy_mode='public' AND join_required=1 ORDER BY sort_order, id"
            )
        return self.db.query_all(
            "SELECT * FROM channels WHERE purpose='force_join' OR join_required=1 ORDER BY sort_order, id"
        )

    async def verify_user_membership(self, bot: Bot, user_id: int) -> Tuple[bool, List[Dict[str, Any]], List[str]]:
        if not self.config.get_bool("force_join_enabled", True):
            return True, [], []
        channels = self.list_force_join_channels(active_only=True)
        if not channels:
            return True, [], []

        statuses: List[Dict[str, Any]] = []
        api_errors: List[str] = []
        all_joined = True

        for ch in channels:
            ch_id_db = int(ch["id"])
            chat_ref = str(ch["chat_id"]).strip()
            title = str(ch["title"] or chat_ref)
            join_link = str(ch["join_link"] or "")
            if not join_link and chat_ref.startswith("@"):
                join_link = f"https://t.me/{chat_ref.lstrip('@')}"

            joined = False
            err_msg = ""
            try:
                member = await bot.get_chat_member(chat_id=chat_ref, user_id=user_id)
                st = member.status
                if st in (ChatMember.MEMBER, ChatMember.ADMINISTRATOR, ChatMember.OWNER):
                    joined = True
                elif st == ChatMember.RESTRICTED and getattr(member, "is_member", False):
                    joined = True
                else:
                    joined = False
                with self.db.atomic(immediate=True) as conn:
                    conn.execute(
                        "UPDATE channels SET last_test_at=?, last_test_ok=1, last_error='' WHERE id=?",
                        (now_utc_iso(), ch_id_db),
                    )
            except Exception as exc:
                joined = False
                err_msg = str(exc)
                api_errors.append(f"{chat_ref}: {err_msg}")
                with self.db.atomic(immediate=True) as conn:
                    conn.execute(
                        "UPDATE channels SET last_test_at=?, last_test_ok=0, last_error=? WHERE id=?",
                        (now_utc_iso(), err_msg[:300], ch_id_db),
                    )

            if not joined:
                all_joined = False
            statuses.append(
                {
                    "id": ch_id_db,
                    "chat_id": chat_ref,
                    "title": title,
                    "join_link": join_link,
                    "joined": joined,
                    "error": err_msg,
                }
            )
        return all_joined, statuses, api_errors

    def build_force_join_markup(self, statuses: List[Dict[str, Any]], lang: str = "bn") -> InlineKeyboardMarkup:
        rows: List[List[InlineKeyboardButton]] = []
        for idx, item in enumerate(statuses, start=1):
            mark = "✅" if item["joined"] else "❌"
            btn_text = f"{mark} {item['title']}"
            if item["join_link"]:
                rows.append([
                    self.kb.ibtn(
                        btn_text,
                        url=item["join_link"],
                        action_kind="confirm" if item["joined"] else "primary",
                    )
                ])
        verify_lbl = "✅ Verify Joined / যাচাই করুন" if lang == "bn" else "✅ Verify Joined"
        rows.append([self.kb.ibtn(verify_lbl, callback_data="fj:verify", action_kind="verify")])
        return InlineKeyboardMarkup(rows)

    @staticmethod
    def format_status_lines(statuses: List[Dict[str, Any]], lang: str = "bn") -> str:
        lines: List[str] = []
        for idx, item in enumerate(statuses, start=1):
            mark = "✅" if item["joined"] else "❌"
            state_txt = ("জয়েন আছে" if item["joined"] else "জয়েন নেই") if lang == "bn" else ("Joined" if item["joined"] else "Not Joined")
            lines.append(f"{idx}. {mark} <b>{escape_html(item['title'])}</b> — {state_txt}")
        return "\n".join(lines)
# ==============================================================================
# LEDGER MANAGER & RECONCILIATION ENGINE (RULE 17, 54, 77.3)
# ==============================================================================

class LedgerManager:
    """
    Immutable, idempotent, BEGIN IMMEDIATE atomic financial ledger supporting
    separate Earned, Deposit, and Held wallet buckets plus full reconciliation.
    """

    def __init__(self, db: DatabaseManager, config: ConfigManager, audit: AuditManager) -> None:
        self.db = db
        self.config = config
        self.audit = audit

    def apply_transaction(
        self,
        user_id: int,
        tx_type: str,
        amount: float,
        direction: str,
        wallet_bucket: str = "earned",
        idempotency_key: Optional[str] = None,
        source: str = "system",
        ref_id: str = "",
        admin_id: int = 0,
        reason: str = "",
        allow_negative: bool = False,
    ) -> Tuple[bool, str, str, float]:
        """
        Atomically updates user wallet bucket and inserts ledger_transactions record.
        Returns: (ok, message, tx_uid, new_bucket_balance)
        """
        amt = round(float(amount), 4)
        if amt < 0:
            return False, "Amount cannot be negative.", "", 0.0
        if direction not in ("credit", "debit"):
            return False, "Invalid transaction direction.", "", 0.0
        if wallet_bucket not in ("earned", "deposit", "held"):
            return False, "Invalid wallet bucket.", "", 0.0

        idem = idempotency_key or f"{tx_type}:{user_id}:{ref_id}:{secrets.token_hex(8)}"
        col_map = {
            "earned": "earned_balance",
            "deposit": "deposit_balance",
            "held": "held_balance",
        }
        bal_col = col_map[wallet_bucket]
        now_s = now_utc_iso()

        with self.db.atomic(immediate=True) as conn:
            existing = conn.execute(
                "SELECT tx_uid, new_balance FROM ledger_transactions WHERE idempotency_key=?",
                (idem,),
            ).fetchone()
            if existing is not None:
                return True, "Already processed (idempotent).", str(existing["tx_uid"]), float(existing["new_balance"])

            u_row = conn.execute(
                f"SELECT earned_balance, deposit_balance, held_balance, total_earnings, total_withdrawn FROM users WHERE user_id=?",
                (int(user_id),),
            ).fetchone()
            if u_row is None:
                return False, "User account not found.", "", 0.0

            prev_bal = float(u_row[bal_col])
            if direction == "credit":
                new_bal = round(prev_bal + amt, 4)
            else:
                new_bal = round(prev_bal - amt, 4)
                if new_bal < -1e-6 and not allow_negative:
                    return False, "Insufficient balance in selected wallet.", "", prev_bal
                if abs(new_bal) < 1e-6:
                    new_bal = 0.0

            tx_uid = generate_uid("TX", 8)
            conn.execute(
                f"UPDATE users SET {bal_col}=?, updated_at=? WHERE user_id=?",
                (new_bal, now_s, int(user_id)),
            )

            # Update lifetime totals cleanly
            if direction == "credit" and wallet_bucket == "earned" and tx_type in {
                "task_reward",
                "file_submit_reward",
                "referral_commission",
                "file_submit_commission",
                "bonus",
                "daily_checkin_bonus",
                "leaderboard_prize",
                "points_exchange",
            }:
                conn.execute(
                    "UPDATE users SET total_earnings = ROUND(total_earnings + ?, 4) WHERE user_id=?",
                    (amt, int(user_id)),
                )
            elif tx_type == "withdrawal_paid" and direction == "debit":
                conn.execute(
                    "UPDATE users SET total_withdrawn = ROUND(total_withdrawn + ?, 4) WHERE user_id=?",
                    (amt, int(user_id)),
                )

            conn.execute(
                """
                INSERT INTO ledger_transactions
                (tx_uid, idempotency_key, user_id, tx_type, amount, direction, prev_balance, new_balance,
                 wallet_bucket, source, ref_id, status, admin_id, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?)
                """,
                (
                    tx_uid,
                    idem,
                    int(user_id),
                    tx_type,
                    amt,
                    direction,
                    prev_bal,
                    new_bal,
                    wallet_bucket,
                    source,
                    str(ref_id),
                    int(admin_id),
                    reason,
                    now_s,
                ),
            )
            return True, "Transaction completed.", tx_uid, new_bal

    def hold_for_withdrawal(
        self,
        user_id: int,
        gross_amount: float,
        withdraw_uid: str,
    ) -> Tuple[bool, str]:
        amt = round(float(gross_amount), 4)
        with self.db.atomic(immediate=True) as conn:
            ok1, msg1, _, _ = self.apply_transaction(
                user_id=user_id,
                tx_type="withdrawal_hold",
                amount=amt,
                direction="debit",
                wallet_bucket="earned",
                idempotency_key=f"wd_hold_ern:{withdraw_uid}",
                source="withdrawal",
                ref_id=withdraw_uid,
                reason=f"Hold for withdrawal {withdraw_uid}",
            )
            if not ok1:
                raise ValueError(msg1)
            ok2, msg2, _, _ = self.apply_transaction(
                user_id=user_id,
                tx_type="withdrawal_hold",
                amount=amt,
                direction="credit",
                wallet_bucket="held",
                idempotency_key=f"wd_hold_hld:{withdraw_uid}",
                source="withdrawal",
                ref_id=withdraw_uid,
                reason=f"Reserved in held for {withdraw_uid}",
            )
            if not ok2:
                raise ValueError(msg2)
        return True, "Held successfully."

    def release_withdrawal_hold(
        self,
        user_id: int,
        gross_amount: float,
        withdraw_uid: str,
        admin_id: int = 0,
        reason: str = "Withdrawal rejected",
    ) -> Tuple[bool, str]:
        amt = round(float(gross_amount), 4)
        with self.db.atomic(immediate=True) as conn:
            ok1, msg1, _, _ = self.apply_transaction(
                user_id=user_id,
                tx_type="withdrawal_release",
                amount=amt,
                direction="debit",
                wallet_bucket="held",
                idempotency_key=f"wd_rel_hld:{withdraw_uid}",
                source="withdrawal",
                ref_id=withdraw_uid,
                admin_id=admin_id,
                reason=reason,
            )
            if not ok1:
                return False, msg1
            ok2, msg2, _, _ = self.apply_transaction(
                user_id=user_id,
                tx_type="withdrawal_release",
                amount=amt,
                direction="credit",
                wallet_bucket="earned",
                idempotency_key=f"wd_rel_ern:{withdraw_uid}",
                source="withdrawal",
                ref_id=withdraw_uid,
                admin_id=admin_id,
                reason=reason,
            )
            if not ok2:
                raise ValueError(msg2)
        return True, "Released back to earned balance."

    def finalize_withdrawal_paid(
        self,
        user_id: int,
        gross_amount: float,
        withdraw_uid: str,
        admin_id: int = 0,
    ) -> Tuple[bool, str]:
        amt = round(float(gross_amount), 4)
        ok, msg, _, _ = self.apply_transaction(
            user_id=user_id,
            tx_type="withdrawal_paid",
            amount=amt,
            direction="debit",
            wallet_bucket="held",
            idempotency_key=f"wd_paid:{withdraw_uid}",
            source="withdrawal",
            ref_id=withdraw_uid,
            admin_id=admin_id,
            reason=f"Paid withdrawal {withdraw_uid}",
        )
        return ok, msg

    def spend_for_service(
        self,
        user_id: int,
        amount: float,
        wallet_mode: str,
        tx_type: str,
        ref_id: str,
        reason: str = "",
    ) -> Tuple[bool, str, str]:
        """
        Spends funds respecting Anti-Wash (deposit_only vs any wallet).
        Returns: (ok, message, bucket_used_label)
        """
        amt = round(float(amount), 4)
        if amt <= 0:
            return True, "Free service.", "free"

        anti_wash = self.config.get_bool("anti_wash_enabled", True)
        with self.db.atomic(immediate=True) as conn:
            u = conn.execute(
                "SELECT earned_balance, deposit_balance FROM users WHERE user_id=?",
                (int(user_id),),
            ).fetchone()
            if u is None:
                return False, "User not found.", ""
            dep_bal = float(u["deposit_balance"])
            ern_bal = float(u["earned_balance"])

            if anti_wash and wallet_mode == "deposit_only":
                if dep_bal + 1e-6 < amt:
                    return False, "Insufficient Deposit Balance (this item requires Deposit Wallet).", ""
                ok, msg, _, _ = self.apply_transaction(
                    user_id=user_id,
                    tx_type=tx_type,
                    amount=amt,
                    direction="debit",
                    wallet_bucket="deposit",
                    idempotency_key=f"{tx_type}:dep:{ref_id}",
                    source=tx_type,
                    ref_id=ref_id,
                    reason=reason,
                )
                return ok, msg, "deposit"

            total_avail = dep_bal + ern_bal
            if total_avail + 1e-6 < amt:
                return False, "Insufficient total available balance.", ""

            from_dep = round(min(dep_bal, amt), 4)
            from_ern = round(amt - from_dep, 4)
            used_parts: List[str] = []
            if from_dep > 0:
                ok_d, msg_d, _, _ = self.apply_transaction(
                    user_id=user_id,
                    tx_type=tx_type,
                    amount=from_dep,
                    direction="debit",
                    wallet_bucket="deposit",
                    idempotency_key=f"{tx_type}:dep:{ref_id}",
                    source=tx_type,
                    ref_id=ref_id,
                    reason=reason,
                )
                if not ok_d:
                    raise ValueError(msg_d)
                used_parts.append("deposit")
            if from_ern > 0:
                ok_e, msg_e, _, _ = self.apply_transaction(
                    user_id=user_id,
                    tx_type=tx_type,
                    amount=from_ern,
                    direction="debit",
                    wallet_bucket="earned",
                    idempotency_key=f"{tx_type}:ern:{ref_id}",
                    source=tx_type,
                    ref_id=ref_id,
                    reason=reason,
                )
                if not ok_e:
                    raise ValueError(msg_e)
                used_parts.append("earned")
            return True, "Charged successfully.", "+".join(used_parts)

    def get_user_transactions(self, user_id: int, limit: int = 10, offset: int = 0) -> Tuple[List[sqlite3.Row], int]:
        rows = self.db.query_all(
            "SELECT * FROM ledger_transactions WHERE user_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
            (int(user_id), limit, offset),
        )
        cnt_row = self.db.query_one("SELECT COUNT(*) AS c FROM ledger_transactions WHERE user_id=?", (int(user_id),))
        return rows, (int(cnt_row["c"]) if cnt_row else 0)

    def find_transaction(self, tx_uid: str) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM ledger_transactions WHERE tx_uid=?", (tx_uid.strip(),))

    def reverse_transaction(self, tx_uid: str, admin_id: int, reason: str) -> Tuple[bool, str]:
        row = self.find_transaction(tx_uid)
        if row is None:
            return False, "Transaction ID not found."
        rev_dir = "debit" if str(row["direction"]) == "credit" else "credit"
        ok, msg, new_uid, _ = self.apply_transaction(
            user_id=int(row["user_id"]),
            tx_type="reversal",
            amount=float(row["amount"]),
            direction=rev_dir,
            wallet_bucket=str(row["wallet_bucket"]),
            idempotency_key=f"rev:{tx_uid}",
            source="admin_reversal",
            ref_id=tx_uid,
            admin_id=admin_id,
            reason=f"Reversal of {tx_uid}: {reason}",
        )
        if ok:
            self.audit.log(admin_id, "admin", "reverse_transaction", "ledger", tx_uid, {"new_tx": new_uid, "reason": reason})
        return ok, f"{msg} ({new_uid})" if ok else msg

    def run_reconciliation(self, admin_id: int = 0) -> Dict[str, Any]:
        """
        Verifies every user's stored balances against summed ledger_transactions
        and calculates platform-wide payable liabilities.
        """
        users = self.db.query_all("SELECT user_id, earned_balance, deposit_balance, held_balance FROM users")
        ledger_rows = self.db.query_all(
            """
            SELECT user_id, wallet_bucket,
                   SUM(CASE WHEN direction='credit' THEN amount ELSE -amount END) AS net_amt
            FROM ledger_transactions
            WHERE status='completed'
            GROUP BY user_id, wallet_bucket
            """
        )
        net_map: Dict[Tuple[int, str], float] = {
            (int(r["user_id"]), str(r["wallet_bucket"])): round(float(r["net_amt"] or 0.0), 4)
            for r in ledger_rows
        }
        mismatches: List[Dict[str, Any]] = []
        tot_earned = 0.0
        tot_deposit = 0.0
        tot_held = 0.0

        for u in users:
            uid = int(u["user_id"])
            eb = round(float(u["earned_balance"]), 4)
            dbal = round(float(u["deposit_balance"]), 4)
            hb = round(float(u["held_balance"]), 4)
            tot_earned += eb
            tot_deposit += dbal
            tot_held += hb

            l_eb = net_map.get((uid, "earned"), 0.0)
            l_db = net_map.get((uid, "deposit"), 0.0)
            l_hb = net_map.get((uid, "held"), 0.0)
            if abs(eb - l_eb) > 0.01 or abs(dbal - l_db) > 0.01 or abs(hb - l_hb) > 0.01:
                mismatches.append(
                    {
                        "user_id": uid,
                        "stored": [eb, dbal, hb],
                        "ledger": [l_eb, l_db, l_hb],
                    }
                )

        run_uid = generate_uid("REC", 6)
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO reconciliation_logs
                (run_uid, total_users, mismatches_found, total_earned_liability, total_deposit_liability,
                 total_held_liability, details_json, admin_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_uid,
                    len(users),
                    len(mismatches),
                    round(tot_earned, 4),
                    round(tot_deposit, 4),
                    round(tot_held, 4),
                    safe_json_dumps({"mismatches": mismatches[:50]}),
                    admin_id,
                    now_s,
                ),
            )
        return {
            "run_uid": run_uid,
            "total_users": len(users),
            "mismatches_found": len(mismatches),
            "total_earned_liability": round(tot_earned, 2),
            "total_deposit_liability": round(tot_deposit, 2),
            "total_held_liability": round(tot_held, 2),
            "mismatches": mismatches,
        }


# ==============================================================================
# USER MANAGER & REWARD MANAGER (RULE 4, 8, 17, 73, 77.7)
# ==============================================================================

class UserManager:
    """Handles unique user registration, profile stats, warnings, blocking, and search."""

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        ledger: LedgerManager,
        audit: AuditManager,
    ) -> None:
        self.db = db
        self.config = config
        self.ledger = ledger
        self.audit = audit

    def get_user(self, user_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM users WHERE user_id=?", (int(user_id),))

    def ensure_user_registered(
        self,
        user_id: int,
        full_name: str,
        username: str = "",
        referrer_id: Optional[int] = None,
    ) -> Tuple[sqlite3.Row, bool]:
        """
        Registers user on first /start without creating duplicates.
        Returns: (user_row, is_newly_created)
        """
        existing = self.get_user(user_id)
        now_s = now_utc_iso()
        clean_un = str(username or "").strip().lstrip("@")
        clean_fn = str(full_name or "").strip() or f"User {user_id}"

        if existing is not None:
            with self.db.atomic(immediate=True) as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET full_name=?, username=?, last_active_at=?, updated_at=?
                    WHERE user_id=?
                    """,
                    (clean_fn, clean_un, now_s, now_s, int(user_id)),
                )
            refreshed = self.get_user(user_id)
            assert refreshed is not None
            return refreshed, False

        valid_ref: Optional[int] = None
        if referrer_id is not None and int(referrer_id) != int(user_id):
            ref_row = self.get_user(int(referrer_id))
            if ref_row is not None and str(ref_row["status"]) != "blocked":
                valid_ref = int(referrer_id)

        default_lang = self.config.get_str("default_language", "bn")
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO users
                (user_id, username, full_name, language, status, referrer_id, last_active_at, registered_at, updated_at)
                VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
                """,
                (int(user_id), clean_un, clean_fn, default_lang, valid_ref, now_s, now_s, now_s),
            )
        created = self.get_user(user_id)
        assert created is not None
        return created, True

    def set_language(self, user_id: int, lang: str) -> None:
        clean_lang = "en" if lang == "en" else "bn"
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE users SET language=?, lang_selected=1, updated_at=? WHERE user_id=?",
                (clean_lang, now_utc_iso(), int(user_id)),
            )

    def get_lang(self, user_id: int) -> str:
        row = self.get_user(user_id)
        if row is not None and str(row["language"]) in ("bn", "en"):
            return str(row["language"])
        return self.config.get_str("default_language", "bn")

    def get_profile_stats(self, user_id: int) -> Dict[str, Any]:
        uid = int(user_id)
        t_ok = self.db.query_one("SELECT COUNT(*) AS c FROM task_submissions WHERE user_id=? AND status='approved'", (uid,))
        fs_ok = self.db.query_one("SELECT COUNT(*) AS c FROM fs_records WHERE user_id=? AND status='approved'", (uid,))
        ord_ok = self.db.query_one("SELECT COUNT(*) AS c FROM store_orders WHERE user_id=? AND status='completed'", (uid,))
        dep_ok = self.db.query_one("SELECT COUNT(*) AS c, COALESCE(SUM(net_credit),0) AS s FROM deposits WHERE user_id=? AND status='approved'", (uid,))
        refs = self.db.query_one("SELECT COUNT(*) AS c FROM users WHERE referrer_id=?", (uid,))
        bon = self.db.query_one("SELECT COUNT(*) AS c FROM bonus_claims WHERE user_id=?", (uid,))
        otps = self.db.query_one("SELECT COUNT(*) AS c FROM otp_sessions WHERE user_id=?", (uid,))
        return {
            "tasks_ok": int(t_ok["c"]) if t_ok else 0,
            "fs_ok": int(fs_ok["c"]) if fs_ok else 0,
            "orders_ok": int(ord_ok["c"]) if ord_ok else 0,
            "deposits_ok": int(dep_ok["c"]) if dep_ok else 0,
            "deposits_sum": float(dep_ok["s"]) if dep_ok else 0.0,
            "refs_count": int(refs["c"]) if refs else 0,
            "bonus_count": int(bon["c"]) if bon else 0,
            "otp_count": int(otps["c"]) if otps else 0,
        }

    def set_block_status(self, user_id: int, block: bool, reason: str, admin_id: int) -> Tuple[bool, str]:
        row = self.get_user(user_id)
        if row is None:
            return False, "User not found."
        if int(user_id) == DEFAULT_MAIN_ADMIN_ID:
            return False, "Cannot block Main Admin."
        new_status = "blocked" if block else "active"
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE users SET status=?, block_reason=?, updated_at=? WHERE user_id=?",
                (new_status, reason if block else "", now_utc_iso(), int(user_id)),
            )
        self.audit.log(admin_id, "admin", "block_user" if block else "unblock_user", "user", user_id, {"reason": reason})
        return True, f"User status updated to {new_status}."

    def issue_warning(
        self,
        user_id: int,
        admin_id: int,
        reason_bn: str,
        reason_en: str = "",
        strike_delta: int = 1,
        is_broadcast: bool = False,
    ) -> Tuple[bool, int, bool]:
        """
        Issues warning strike and auto-blocks if RULE 77.7 strike limit is reached.
        Returns: (ok, new_warning_count, auto_blocked)
        """
        u = self.get_user(user_id)
        if u is None:
            return False, 0, False
        max_strikes = max(1, self.config.get_int("warning_auto_block_strikes", 3))
        auto_block_on = self.config.get_bool("warning_auto_block_enabled", True)
        new_count = max(0, int(u["warning_count"]) + int(strike_delta))
        auto_blocked = False
        now_s = now_utc_iso()

        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO user_warnings (user_id, admin_id, reason_bn, reason_en, strike_delta, is_broadcast, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (int(user_id), int(admin_id), reason_bn, reason_en or reason_bn, strike_delta, 1 if is_broadcast else 0, now_s),
            )
            conn.execute(
                "UPDATE users SET warning_count=?, updated_at=? WHERE user_id=?",
                (new_count, now_s, int(user_id)),
            )
            if auto_block_on and new_count >= max_strikes and int(user_id) != DEFAULT_MAIN_ADMIN_ID:
                conn.execute(
                    "UPDATE users SET status='blocked', block_reason=?, updated_at=? WHERE user_id=?",
                    (f"Auto-blocked after {new_count} warning strikes: {reason_bn}", now_s, int(user_id)),
                )
                auto_blocked = True

        self.audit.log(admin_id, "admin", "issue_warning", "user", user_id, {"strikes": new_count, "auto_blocked": auto_blocked})
        return True, new_count, auto_blocked

    def search_users(self, query_str: str, limit: int = 20) -> List[sqlite3.Row]:
        q = query_str.strip().lstrip("@")
        if not q:
            return self.db.query_all("SELECT * FROM users ORDER BY registered_at DESC LIMIT ?", (limit,))
        if q.isdigit():
            exact = self.db.query_all("SELECT * FROM users WHERE user_id=?", (int(q),))
            if exact:
                return exact
        # Check Submission / Order / Deposit / Withdraw UIDs
        for sql in (
            "SELECT user_id FROM task_submissions WHERE sub_uid=?",
            "SELECT user_id FROM fs_submissions WHERE sub_uid=?",
            "SELECT user_id FROM store_orders WHERE order_uid=?",
            "SELECT user_id FROM deposits WHERE deposit_uid=? OR txid_user=?",
            "SELECT user_id FROM withdrawals WHERE withdraw_uid=?",
        ):
            params = (q, q) if "txid_user" in sql else (q,)
            hit = self.db.query_one(sql, params)
            if hit:
                return self.db.query_all("SELECT * FROM users WHERE user_id=?", (int(hit["user_id"]),))

        like_q = f"%{q}%"
        return self.db.query_all(
            "SELECT * FROM users WHERE username LIKE ? OR full_name LIKE ? OR CAST(user_id AS TEXT) LIKE ? LIMIT ?",
            (like_q, like_q, like_q, limit),
        )

    def set_vip_tier(self, user_id: int, tier: str, admin_id: int) -> bool:
        if tier not in ("Bronze", "Silver", "Gold", "VIP"):
            return False
        with self.db.atomic(immediate=True) as conn:
            conn.execute("UPDATE users SET vip_tier=?, updated_at=? WHERE user_id=?", (tier, now_utc_iso(), int(user_id)))
        self.audit.log(admin_id, "admin", "set_vip_tier", "user", user_id, {"tier": tier})
        return True

    def set_task_field_access(self, user_id: int, access_cfg: Dict[str, Any], admin_id: int) -> bool:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE users SET task_field_access_json=?, updated_at=? WHERE user_id=?",
                (safe_json_dumps(access_cfg), now_utc_iso(), int(user_id)),
            )
        self.audit.log(admin_id, "admin", "set_field_access", "user", user_id, access_cfg)
        return True

    def list_all_for_export(self) -> List[Dict[str, Any]]:
        rows = self.db.query_all("SELECT * FROM users ORDER BY registered_at ASC")
        result: List[Dict[str, Any]] = []
        for u in rows:
            uid = int(u["user_id"])
            st = self.get_profile_stats(uid)
            result.append(
                {
                    "User_ID": uid,
                    "Username": f"@{u['username']}" if u["username"] else "",
                    "Full_Name": u["full_name"],
                    "Language": u["language"],
                    "Status": u["status"],
                    "VIP_Tier": u["vip_tier"],
                    "Warning_Count": int(u["warning_count"]),
                    "Earned_Balance": round(float(u["earned_balance"]), 2),
                    "Deposit_Balance": round(float(u["deposit_balance"]), 2),
                    "Held_Balance": round(float(u["held_balance"]), 2),
                    "Total_Withdrawn": round(float(u["total_withdrawn"]), 2),
                    "Total_Earnings": round(float(u["total_earnings"]), 2),
                    "Approved_Tasks": st["tasks_ok"],
                    "Approved_FS_Records": st["fs_ok"],
                    "Store_Orders": st["orders_ok"],
                    "Deposits_Approved": st["deposits_ok"],
                    "OTP_Sessions": st["otp_count"],
                    "Referrals": st["refs_count"],
                    "Registered_At": format_dhaka_dt(u["registered_at"]),
                }
            )
        return result


class RewardManager:
    """Computes effective rewards (Happy-Hour / VIP) and executes atomic credits."""

    def __init__(self, config: ConfigManager, ledger: LedgerManager) -> None:
        self.config = config
        self.ledger = ledger

    def compute_effective_reward(self, base_reward: float) -> float:
        amt = float(base_reward)
        if self.config.get_bool("happy_hour_enabled", False):
            mult = max(1.0, self.config.get_float("happy_hour_multiplier", 1.0))
            amt = amt * mult
        return round(amt, 4)

    def credit_reward(
        self,
        user_id: int,
        tx_type: str,
        amount: float,
        idempotency_key: str,
        ref_id: str,
        reason: str = "",
        wallet_bucket: str = "earned",
    ) -> Tuple[bool, str, str, float]:
        return self.ledger.apply_transaction(
            user_id=user_id,
            tx_type=tx_type,
            amount=amount,
            direction="credit",
            wallet_bucket=wallet_bucket,
            idempotency_key=idempotency_key,
            source="reward_engine",
            ref_id=ref_id,
            reason=reason,
        )


# ==============================================================================
# SECURITY MANAGER (RULE 33, 40, 77.1-77.8, 95.C — ANTI-ABUSE & LOCKS)
# ==============================================================================

class SecurityManager:
    """
    Enforces RULE 77.1-77.8 anti-abuse checks, velocity rate-limiting,
    9 independent module locks, maintenance mode, and Main-Admin-Only Panic Freeze.
    """

    def __init__(self, db: DatabaseManager, config: ConfigManager, audit: AuditManager) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self._rate_lock = threading.Lock()
        self._action_timestamps: Dict[int, List[float]] = {}

    def is_panic_frozen(self) -> bool:
        return self.config.get_bool("emergency_panic_freeze", False)

    def toggle_panic_freeze(self, admin_id: int, enable: bool) -> Tuple[bool, str]:
        if int(admin_id) != DEFAULT_MAIN_ADMIN_ID:
            return False, "Only Main Admin can activate or unlock Emergency Panic Freeze."
        self.config.set_setting("emergency_panic_freeze", enable, admin_id=admin_id, reason="panic_freeze")
        self.audit.log(admin_id, "main_admin", "panic_freeze_on" if enable else "panic_freeze_off", "system", "panic")
        return True, "Emergency Panic Freeze ENABLED." if enable else "Emergency Panic Freeze UNLOCKED."

    def check_module_access(self, user_id: int, module_key: str, is_admin: bool = False) -> Tuple[bool, str]:
        if not is_admin:
            if self.config.get_bool("maintenance_mode", False):
                return False, "Bot is currently in Maintenance Mode."
            if self.config.get_bool("lock_full_system", False):
                return False, "System is temporarily locked by Admin."
            u = self.db.query_one("SELECT status, block_reason FROM users WHERE user_id=?", (int(user_id),))
            if u and str(u["status"]) == "blocked":
                reason = str(u["block_reason"] or "Violating platform rules")
                return False, f"Your account is blocked: {reason}"

        if self.is_panic_frozen() and module_key in {"deposit", "withdraw", "auto_approve"}:
            return False, "Emergency Panic Freeze is active. Financial actions are temporarily paused."

        lock_map = {
            "task": "lock_task",
            "fs": "lock_fs",
            "store": "lock_store",
            "otp": "lock_otp",
            "deposit": "lock_deposit",
            "withdraw": "lock_withdraw",
            "registration": "lock_registration",
            "reward": "lock_reward",
        }
        lock_key = lock_map.get(module_key)
        if lock_key and self.config.get_bool(lock_key, False):
            return False, f"The '{module_key}' module is currently locked by Admin."
        return True, ""

    def check_rate_limit(self, user_id: int) -> Tuple[bool, int]:
        if not self.config.get_bool("anti_spam_rate_limit", True):
            return True, 0
        if int(user_id) == DEFAULT_MAIN_ADMIN_ID:
            return True, 0
        max_per_min = max(5, self.config.get_int("anti_spam_max_per_min", 25))
        now_ts = time.time()
        cutoff = now_ts - 60.0
        with self._rate_lock:
            stamps = [t for t in self._action_timestamps.get(user_id, []) if t >= cutoff]
            if len(stamps) >= max_per_min:
                wait_sec = max(1, int(60.0 - (now_ts - stamps[0])))
                self._action_timestamps[user_id] = stamps
                return False, wait_sec
            stamps.append(now_ts)
            self._action_timestamps[user_id] = stamps
        return True, 0

    def is_duplicate_deposit_proof(self, txid_user: str, screenshot_uid: str, screenshot_sha256: str) -> Tuple[bool, str]:
        if not self.config.get_bool("anti_dup_txid_hash", True):
            return False, ""
        tx_clean = str(txid_user or "").strip().upper()
        if tx_clean:
            hit_tx = self.db.query_one(
                "SELECT deposit_uid FROM deposits WHERE UPPER(txid_user)=? AND status IN ('pending','approved')",
                (tx_clean,),
            )
            if hit_tx:
                return True, f"Duplicate TxID already used in {hit_tx['deposit_uid']}."
        if screenshot_uid:
            hit_uid = self.db.query_one(
                "SELECT deposit_uid FROM deposits WHERE screenshot_unique_id=? AND status IN ('pending','approved')",
                (screenshot_uid,),
            )
            if hit_uid:
                return True, f"Duplicate payment screenshot file already used in {hit_uid['deposit_uid']}."
        if screenshot_sha256:
            hit_hash = self.db.query_one(
                "SELECT deposit_uid FROM deposits WHERE screenshot_sha256=? AND status IN ('pending','approved')",
                (screenshot_sha256,),
            )
            if hit_hash:
                return True, f"Duplicate screenshot image hash detected in {hit_hash['deposit_uid']}."
        return False, ""

    def check_shared_wallet_multi_account(self, user_id: int, account_or_wallet: str) -> Tuple[bool, str]:
        if not self.config.get_bool("anti_multi_wallet_block", True):
            return True, ""
        norm = str(account_or_wallet or "").strip().lower()
        if not norm:
            return True, ""
        other = self.db.query_one(
            """
            SELECT user_id, withdraw_uid FROM withdrawals
            WHERE LOWER(account_or_wallet)=? AND user_id != ? AND status != 'rejected'
            LIMIT 1
            """,
            (norm, int(user_id)),
        )
        if other is not None:
            return False, f"This wallet/number is already linked to another user account ({other['withdraw_uid']})."
        return True, ""

    def is_big_withdraw(self, gross_amount: float) -> bool:
        threshold = max(0.0, self.config.get_float("big_withdraw_threshold", 5000.0))
        return threshold > 0 and float(gross_amount) >= threshold

# ==============================================================================
# TASK MANAGER — PART A (CRUD, WIZARD, STEPS, SOURCE MAPPER & ATOMIC ALLOCATION)
# ==============================================================================

HEADER_ALIAS_MAP: Dict[str, str] = {
    "username": "username",
    "user_name": "username",
    "user": "username",
    "uid": "username",
    "login": "username",
    "email": "email",
    "mail": "email",
    "password": "password",
    "pass": "password",
    "pwd": "password",
    "full_name": "full_name",
    "fullname": "full_name",
    "name": "full_name",
    "first_last": "full_name",
    "phone": "phone",
    "mobile": "phone",
    "number": "phone",
    "recovery": "recovery",
    "recovery_email": "recovery",
}

VIP_TIER_RANK: Dict[str, int] = {
    "Bronze": 1,
    "Silver": 2,
    "Gold": 3,
    "VIP": 4,
}


def canonicalize_header_name(raw_header: str) -> str:
    cleaned = re.sub(r"[\s\-]+", "_", str(raw_header or "").strip().lower()).strip("_")
    return HEADER_ALIAS_MAP.get(cleaned, cleaned or "col")


def generate_pattern_password(pattern: str) -> str:
    tpl = str(pattern or "Work@{4DIGIT}{2ALPHA}")

    def _repl(m: re.Match[str]) -> str:
        token = m.group(1).upper()
        num_m = re.match(r"(\d+)(DIGIT|ALPHA|ALNUM)", token)
        if num_m:
            cnt = max(1, min(32, int(num_m.group(1))))
            kind = num_m.group(2)
        else:
            kind_m = re.match(r"(DIGIT|ALPHA|ALNUM)(\d+)", token)
            if not kind_m:
                return m.group(0)
            kind = kind_m.group(1)
            cnt = max(1, min(32, int(kind_m.group(2))))

        if kind == "DIGIT":
            chars = "0123456789"
        elif kind == "ALPHA":
            chars = "ABCDEFGHJKLMNPQRSTUVWXYZ"
        else:
            chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return "".join(secrets.choice(chars) for _ in range(cnt))

    return re.sub(r"\{([A-Za-z0-9]+)\}", _repl, tpl)


def parse_tabular_file_bytes(
    file_bytes: bytes,
    file_name: str,
    delimiter: str = "auto",
) -> Tuple[bool, List[str], List[List[str]], str]:
    """
    Zero-Column-Mixing parser for .xlsx, .xls, .csv, and .txt files.
    Preserves native cell boundaries and pads empty cells with "" so columns never shift left.
    Returns: (ok, headers, data_rows, error_msg)
    """
    ext = Path(str(file_name or "")).suffix.lower()
    raw_rows: List[List[str]] = []

    try:
        if ext == ".xlsx":
            wb = load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
            ws = wb.active
            for row in ws.iter_rows(values_only=True):
                cells = [("" if c is None else str(c).strip()) for c in row]
                if any(cells):
                    raw_rows.append(cells)
            wb.close()
        elif ext == ".xls":
            book = xlrd.open_workbook(file_contents=file_bytes)
            sheet = book.sheet_by_index(0)
            for rx in range(sheet.nrows):
                cells = [str(sheet.cell_value(rx, cx)).strip() for cx in range(sheet.ncols)]
                if any(cells):
                    raw_rows.append(cells)
        elif ext == ".csv":
            text = file_bytes.decode("utf-8-sig", errors="replace")
            reader = csv.reader(io.StringIO(text))
            for row in reader:
                cells = [str(c).strip() for c in row]
                if any(cells):
                    raw_rows.append(cells)
        else:
            # .txt or pasted text
            text = file_bytes.decode("utf-8-sig", errors="replace")
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if not lines:
                return False, [], [], "Uploaded file contains no non-empty lines."
            chosen_delim = delimiter
            if chosen_delim == "auto":
                sample = lines[0]
                for cand in ("|", "\t", ";", ",", ":"):
                    if cand in sample:
                        chosen_delim = cand
                        break
                else:
                    chosen_delim = ""
            for ln in lines:
                if chosen_delim:
                    cells = [c.strip() for c in ln.split(chosen_delim)]
                else:
                    cells = [ln]
                if any(cells):
                    raw_rows.append(cells)
    except Exception as exc:
        return False, [], [], f"Failed to parse {ext or 'text'} file: {exc}"

    if not raw_rows:
        return False, [], [], "No records found inside file."

    max_cols = max(len(r) for r in raw_rows)
    padded_rows: List[List[str]] = []
    for r in raw_rows:
        padded_rows.append(r + [""] * (max_cols - len(r)))

    # Detect whether first row looks like a header row
    first = padded_rows[0]
    first_canon = [canonicalize_header_name(c) for c in first]
    has_header = any(
        fc in set(HEADER_ALIAS_MAP.values()) or fc in {"col1", "column1", "id", "email", "username", "password", "full_name"}
        for fc in first_canon
    ) and len(padded_rows) > 1

    if has_header:
        headers = [c if c else f"Column_{i + 1}" for i, c in enumerate(first)]
        data_rows = padded_rows[1:]
    else:
        headers = [f"Column_{i + 1}" for i in range(max_cols)]
        data_rows = padded_rows

    if not data_rows:
        return False, headers, [], "Header found, but 0 data rows present."
    return True, headers, data_rows, ""


class TaskManager:
    """
    Universal 5-Layer Task Engine (Part A):
    - Task CRUD, 6-Step Wizard, Clone & Archive
    - Pre-Code & Post-Code Dynamic Steps + Task Button & Rule Settings
    - Source File Upload with Case-Insensitive Auto-Mapper & Zero-Column-Mixing
    - Button-Click Combo & 4-Mode Custom Password Wizard (RULE 91)
    - Atomic Single Allocation (BEGIN IMMEDIATE), Timeout Auto-Release & Auto-Pause/Resume
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        security: SecurityManager,
        ledger: LedgerManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.security = security
        self.ledger = ledger

    def list_tasks(self, active_only: bool = False, include_archived: bool = False) -> List[sqlite3.Row]:
        clauses: List[str] = []
        if not include_archived:
            clauses.append("is_archived=0")
        if active_only:
            clauses.append("status='active'")
            clauses.append("is_hidden=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM tasks {where_sql} ORDER BY id DESC")

    def get_task(self, task_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM tasks WHERE id=?", (int(task_id),))

    def create_task(
        self,
        title_bn: str,
        title_en: str,
        reward_amount: float,
        desc_bn: str = "",
        desc_en: str = "",
        instruction_bn: str = "",
        instruction_en: str = "",
        source_enabled: bool = False,
        field_combo_mode: str = "user_pass",
        password_mode: str = "file_only",
        static_password: str = "",
        password_pattern: str = "Work@{4DIGIT}{2ALPHA}",
        require_totp: bool = False,
        totp_dup_block: bool = True,
        require_cookie: bool = False,
        cookie_dup_block: bool = True,
        cookie_required_keys: str = "none",
        auto_approve_enabled: bool = False,
        auto_approve_sec: int = 60,
        auto_delete_messages: bool = False,
        admin_id: int = 0,
    ) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO tasks (
                    title_bn, title_en, desc_bn, desc_en, instruction_bn, instruction_en,
                    reward_amount, status, source_enabled, field_combo_mode,
                    password_mode, static_password, password_pattern,
                    require_totp, totp_dup_block, require_cookie, cookie_dup_block, cookie_required_keys,
                    auto_approve_enabled, auto_approve_sec, auto_delete_messages,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    title_bn.strip(),
                    (title_en or title_bn).strip(),
                    desc_bn.strip(),
                    (desc_en or desc_bn).strip(),
                    instruction_bn.strip(),
                    (instruction_en or instruction_bn).strip(),
                    round(float(reward_amount), 4),
                    1 if source_enabled else 0,
                    field_combo_mode,
                    password_mode,
                    static_password,
                    password_pattern,
                    1 if require_totp else 0,
                    1 if totp_dup_block else 0,
                    1 if require_cookie else 0,
                    1 if cookie_dup_block else 0,
                    cookie_required_keys or "none",
                    1 if auto_approve_enabled else 0,
                    max(5, int(auto_approve_sec)),
                    1 if auto_delete_messages else 0,
                    int(admin_id),
                    now_s,
                    now_s,
                ),
            )
            task_id = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_task", "task", task_id, {"title": title_bn})
        return task_id

    def update_task_fields(self, task_id: int, updates: Dict[str, Any], admin_id: int) -> Tuple[bool, str]:
        allowed_cols = {
            "title_bn", "title_en", "desc_bn", "desc_en", "instruction_bn", "instruction_en",
            "reward_amount", "daily_limit", "user_limit", "cooldown_sec", "start_at", "end_at",
            "status", "is_hidden", "is_archived", "source_enabled", "field_combo_mode",
            "custom_fields_json", "allowed_vip_tiers_json", "password_mode", "static_password",
            "password_pattern", "allocation_timeout_sec", "require_totp", "totp_dup_block",
            "require_cookie", "cookie_dup_block", "cookie_required_keys", "auto_approve_enabled",
            "auto_approve_sec", "auto_reject_enabled", "auto_reject_sec", "auto_reject_reason",
            "auto_delete_messages", "auto_pause_on_empty", "auto_resume_on_stock",
            "low_stock_threshold", "test_code_enabled", "test_code_length",
        }
        filtered = {k: v for k, v in updates.items() if k in allowed_cols}
        if not filtered:
            return False, "No valid task fields provided."
        filtered["updated_at"] = now_utc_iso()
        set_sql = ", ".join(f"{k}=?" for k in filtered.keys())
        params = list(filtered.values()) + [int(task_id)]
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE tasks SET {set_sql} WHERE id=?", params)
        self.audit.log(admin_id, "admin", "update_task", "task", task_id, filtered)
        return True, "Task updated."

    def toggle_task_bool(self, task_id: int, field: str, admin_id: int) -> Tuple[bool, int]:
        if field not in {
            "is_hidden", "source_enabled", "require_totp", "totp_dup_block",
            "require_cookie", "cookie_dup_block", "auto_approve_enabled",
            "auto_reject_enabled", "auto_delete_messages", "auto_pause_on_empty",
            "auto_resume_on_stock", "test_code_enabled",
        }:
            return False, 0
        row = self.get_task(task_id)
        if row is None:
            return False, 0
        new_val = 0 if int(row[field]) == 1 else 1
        self.update_task_fields(task_id, {field: new_val}, admin_id=admin_id)
        return True, new_val

    def clone_task(self, task_id: int, admin_id: int) -> Tuple[bool, str, int]:
        src = self.get_task(task_id)
        if src is None:
            return False, "Source task not found.", 0
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO tasks (
                    title_bn, title_en, desc_bn, desc_en, instruction_bn, instruction_en,
                    task_type, reward_amount, daily_limit, user_limit, cooldown_sec,
                    status, is_hidden, is_archived, source_enabled, field_combo_mode,
                    custom_fields_json, allowed_vip_tiers_json, password_mode, static_password,
                    password_pattern, allocation_timeout_sec, require_totp, totp_dup_block,
                    require_cookie, cookie_dup_block, cookie_required_keys,
                    auto_approve_enabled, auto_approve_sec, auto_reject_enabled, auto_reject_sec,
                    auto_reject_reason, auto_delete_messages, auto_pause_on_empty, auto_resume_on_stock,
                    low_stock_threshold, test_code_enabled, test_code_length, created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{src['title_bn']} (কপি)",
                    f"{src['title_en']} (Copy)",
                    src["desc_bn"],
                    src["desc_en"],
                    src["instruction_bn"],
                    src["instruction_en"],
                    src["task_type"],
                    src["reward_amount"],
                    src["daily_limit"],
                    src["user_limit"],
                    src["cooldown_sec"],
                    src["source_enabled"],
                    src["field_combo_mode"],
                    src["custom_fields_json"],
                    src["allowed_vip_tiers_json"],
                    src["password_mode"],
                    src["static_password"],
                    src["password_pattern"],
                    src["allocation_timeout_sec"],
                    src["require_totp"],
                    src["totp_dup_block"],
                    src["require_cookie"],
                    src["cookie_dup_block"],
                    src["cookie_required_keys"],
                    src["auto_approve_enabled"],
                    src["auto_approve_sec"],
                    src["auto_reject_enabled"],
                    src["auto_reject_sec"],
                    src["auto_reject_reason"],
                    src["auto_delete_messages"],
                    src["auto_pause_on_empty"],
                    src["auto_resume_on_stock"],
                    src["low_stock_threshold"],
                    src["test_code_enabled"],
                    src["test_code_length"],
                    int(admin_id),
                    now_s,
                    now_s,
                ),
            )
            new_id = int(cur.lastrowid or 0)
            steps = conn.execute(
                "SELECT * FROM task_steps WHERE task_id=? ORDER BY phase, step_order",
                (int(task_id),),
            ).fetchall()
            for st in steps:
                conn.execute(
                    """
                    INSERT INTO task_steps
                    (task_id, phase, step_order, title_bn, title_en, instruction_bn, instruction_en,
                     input_type, options_json, min_len, max_len, regex_pattern, is_required, is_enabled, is_hidden, allow_skip, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_id,
                        st["phase"],
                        st["step_order"],
                        st["title_bn"],
                        st["title_en"],
                        st["instruction_bn"],
                        st["instruction_en"],
                        st["input_type"],
                        st["options_json"],
                        st["min_len"],
                        st["max_len"],
                        st["regex_pattern"],
                        st["is_required"],
                        st["is_enabled"],
                        st["is_hidden"],
                        st["allow_skip"],
                        now_s,
                    ),
                )
        self.audit.log(admin_id, "admin", "clone_task", "task", task_id, {"new_task_id": new_id})
        return True, f"Cloned as Task #{new_id} (Draft).", new_id

    # --- Dynamic Steps & Task Button/Rule Settings (RULE 9.4, 66) ---

    def add_task_step(
        self,
        task_id: int,
        phase: str,
        title_bn: str,
        title_en: str = "",
        instruction_bn: str = "",
        instruction_en: str = "",
        input_type: str = "text",
        options: Optional[List[str]] = None,
        min_len: int = 0,
        max_len: int = 2000,
        regex_pattern: str = "",
        is_required: bool = True,
        allow_skip: bool = False,
    ) -> int:
        clean_phase = "post_code" if phase == "post_code" else "pre_code"
        max_row = self.db.query_one(
            "SELECT COALESCE(MAX(step_order), 0) AS m FROM task_steps WHERE task_id=? AND phase=?",
            (int(task_id), clean_phase),
        )
        next_ord = (int(max_row["m"]) if max_row else 0) + 1
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO task_steps
                (task_id, phase, step_order, title_bn, title_en, instruction_bn, instruction_en,
                 input_type, options_json, min_len, max_len, regex_pattern, is_required, is_enabled, is_hidden, allow_skip, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
                """,
                (
                    int(task_id),
                    clean_phase,
                    next_ord,
                    title_bn.strip(),
                    (title_en or title_bn).strip(),
                    instruction_bn.strip(),
                    (instruction_en or instruction_bn).strip(),
                    input_type,
                    safe_json_dumps(options or []),
                    int(min_len),
                    int(max_len),
                    regex_pattern.strip(),
                    1 if is_required else 0,
                    1 if allow_skip else 0,
                    now_utc_iso(),
                ),
            )
            return int(cur.lastrowid or 0)

    def list_task_steps(
        self,
        task_id: int,
        phase: Optional[str] = None,
        active_only: bool = False,
    ) -> List[sqlite3.Row]:
        clauses = ["task_id=?"]
        params: List[Any] = [int(task_id)]
        if phase is not None:
            clauses.append("phase=?")
            params.append(phase)
        if active_only:
            clauses.append("is_enabled=1 AND is_hidden=0")
        where_sql = " AND ".join(clauses)
        return self.db.query_all(
            f"SELECT * FROM task_steps WHERE {where_sql} ORDER BY phase ASC, step_order ASC, id ASC",
            params,
        )

    def toggle_step_flag(self, step_id: int, field: str) -> Tuple[bool, int]:
        if field not in ("is_enabled", "is_hidden", "is_required", "allow_skip"):
            return False, 0
        row = self.db.query_one("SELECT * FROM task_steps WHERE id=?", (int(step_id),))
        if row is None:
            return False, 0
        new_val = 0 if int(row[field]) == 1 else 1
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE task_steps SET {field}=? WHERE id=?", (new_val, int(step_id)))
        return True, new_val

    def reorder_step(self, step_id: int, direction: str) -> bool:
        row = self.db.query_one("SELECT * FROM task_steps WHERE id=?", (int(step_id),))
        if row is None:
            return False
        siblings = self.list_task_steps(int(row["task_id"]), phase=str(row["phase"]), active_only=False)
        ids = [int(s["id"]) for s in siblings]
        if int(step_id) not in ids:
            return False
        idx = ids.index(int(step_id))
        swap_idx = idx - 1 if direction == "up" else idx + 1
        if swap_idx < 0 or swap_idx >= len(ids):
            return False
        ids[idx], ids[swap_idx] = ids[swap_idx], ids[idx]
        with self.db.atomic(immediate=True) as conn:
            for new_ord, sid in enumerate(ids, start=1):
                conn.execute("UPDATE task_steps SET step_order=? WHERE id=?", (new_ord, sid))
        return True

    def delete_step(self, step_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute("DELETE FROM task_steps WHERE id=?", (int(step_id),))

    # --- Source Stock, Case-Insensitive Mapper & Atomic Allocation ---

    def get_source_counts(self, task_id: int) -> Dict[str, int]:
        rows = self.db.query_all(
            "SELECT status, COUNT(*) AS c FROM task_source_records WHERE task_id=? GROUP BY status",
            (int(task_id),),
        )
        counts = {"available": 0, "allocated": 0, "submitted": 0}
        for r in rows:
            counts[str(r["status"])] = int(r["c"])
        counts["total"] = sum(counts.values())
        return counts

    def upload_source_file(
        self,
        task_id: int,
        file_bytes: bytes,
        file_name: str,
        admin_id: int,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        task = self.get_task(task_id)
        if task is None:
            return False, "Task not found.", {}

        ok, headers, data_rows, err = parse_tabular_file_bytes(file_bytes, file_name)
        if not ok:
            return False, err, {}

        # Save raw source file archive
        DATA_DIRS["source_files"].mkdir(parents=True, exist_ok=True)
        batch_id = generate_uid("SRC", 6)
        save_path = DATA_DIRS["source_files"] / f"task_{task_id}_{batch_id}_{sanitize_filename(file_name)}"
        save_path.write_bytes(file_bytes)

        canon_headers = [canonicalize_header_name(h) for h in headers]
        added = 0
        duplicates = 0
        sample_preview: List[Dict[str, str]] = []
        now_s = now_utc_iso()

        with self.db.atomic(immediate=True) as conn:
            existing_hashes = {
                str(r["record_hash"])
                for r in conn.execute(
                    "SELECT record_hash FROM task_source_records WHERE task_id=?",
                    (int(task_id),),
                ).fetchall()
            }
            for r_idx, row_cells in enumerate(data_rows, start=1):
                col_dict: Dict[str, str] = {}
                for c_idx, orig_h in enumerate(headers):
                    val = row_cells[c_idx] if c_idx < len(row_cells) else ""
                    col_dict[orig_h] = val
                raw_line = " | ".join(row_cells)
                rec_hash = sha256_text(raw_line.lower())
                if rec_hash in existing_hashes:
                    duplicates += 1
                    continue
                existing_hashes.add(rec_hash)
                conn.execute(
                    """
                    INSERT INTO task_source_records
                    (task_id, batch_id, row_index, columns_json, raw_line, record_hash, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'available', ?)
                    """,
                    (int(task_id), batch_id, r_idx, safe_json_dumps(col_dict), raw_line, rec_hash, now_s),
                )
                added += 1
                if len(sample_preview) < 3:
                    sample_preview.append(col_dict)

            # Auto-Resume if task was auto_paused on empty stock (RULE 84)
            auto_resumed = False
            if added > 0 and str(task["status"]) == "auto_paused" and int(task["auto_resume_on_stock"]) == 1:
                conn.execute(
                    "UPDATE tasks SET status='active', source_enabled=1, updated_at=? WHERE id=?",
                    (now_s, int(task_id)),
                )
                auto_resumed = True
            elif added > 0 and int(task["source_enabled"]) == 0:
                conn.execute(
                    "UPDATE tasks SET source_enabled=1, updated_at=? WHERE id=?",
                    (now_s, int(task_id)),
                )

        self.audit.log(
            admin_id,
            "admin",
            "upload_task_source",
            "task",
            task_id,
            {"added": added, "duplicates": duplicates, "headers": headers},
        )
        return True, f"Uploaded {added} records ({duplicates} duplicates skipped).", {
            "batch_id": batch_id,
            "headers": headers,
            "mapped_headers": canon_headers,
            "added": added,
            "duplicates": duplicates,
            "auto_resumed": auto_resumed,
            "sample": sample_preview,
        }

    @staticmethod
    def map_record_canonical(col_dict: Dict[str, Any]) -> Dict[str, str]:
        """Case-insensitively maps raw source columns to canonical aliases while retaining originals."""
        mapped: Dict[str, str] = {}
        for k, v in col_dict.items():
            val_s = str(v if v is not None else "").strip()
            canon = canonicalize_header_name(k)
            if canon not in mapped or not mapped[canon]:
                mapped[canon] = val_s
        return mapped

    def _compute_assigned_password(self, task: sqlite3.Row, mapped_cols: Dict[str, str]) -> str:
        pmode = str(task["password_mode"] or "file_only")
        file_pw = mapped_cols.get("password", "")
        if pmode == "static":
            return str(task["static_password"] or file_pw)
        if pmode == "pattern":
            return generate_pattern_password(str(task["password_pattern"] or "Work@{4DIGIT}{2ALPHA}"))
        if pmode == "hybrid":
            custom = str(task["static_password"] or "").strip()
            if not custom:
                custom = generate_pattern_password(str(task["password_pattern"] or "Work@{4DIGIT}{2ALPHA}"))
            return custom
        return file_pw

    def _select_fields_for_combo(
        self,
        task: sqlite3.Row,
        user_row: sqlite3.Row,
        raw_cols: Dict[str, Any],
        assigned_password: str,
    ) -> Dict[str, str]:
        mapped = self.map_record_canonical(raw_cols)
        combo = str(task["field_combo_mode"] or "user_pass")

        # Per-user field access override (RULE 10.3 / 83.2)
        user_access = safe_json_loads(user_row["task_field_access_json"], {})
        if str(task["id"]) in user_access:
            combo = str(user_access[str(task["id"])])
        elif "default" in user_access:
            combo = str(user_access["default"])

        out: Dict[str, str] = {}
        if combo == "only_pass":
            out["Password"] = assigned_password or mapped.get("password", "")
        elif combo == "user_pass":
            if mapped.get("username") or mapped.get("email"):
                out["Username"] = mapped.get("username") or mapped.get("email", "")
            out["Password"] = assigned_password or mapped.get("password", "")
        elif combo == "user_pass_full":
            if mapped.get("full_name"):
                out["Full Name"] = mapped["full_name"]
            if mapped.get("username") or mapped.get("email"):
                out["Username"] = mapped.get("username") or mapped.get("email", "")
            out["Password"] = assigned_password or mapped.get("password", "")
        elif combo == "full_pass":
            if mapped.get("full_name"):
                out["Full Name"] = mapped["full_name"]
            out["Password"] = assigned_password or mapped.get("password", "")
        else:
            # Custom combination or all columns
            custom_list = safe_json_loads(task["custom_fields_json"], [])
            if custom_list:
                for wanted in custom_list:
                    w_canon = canonicalize_header_name(wanted)
                    if w_canon == "password":
                        out[wanted] = assigned_password or mapped.get("password", "")
                    elif wanted in raw_cols:
                        out[wanted] = str(raw_cols[wanted])
                    elif w_canon in mapped:
                        out[wanted] = mapped[w_canon]
            else:
                for k, v in raw_cols.items():
                    if canonicalize_header_name(k) == "password" and assigned_password:
                        out[k] = assigned_password
                    else:
                        out[k] = str(v)
                if assigned_password and not any(canonicalize_header_name(k) == "password" for k in out):
                    out["Password"] = assigned_password
        return out

    def check_user_eligibility_and_limits(self, task: sqlite3.Row, user_row: sqlite3.Row, allow_auto_paused: bool = False) -> Tuple[bool, str]:
        task_id = int(task["id"])
        user_id = int(user_row["user_id"])

        t_status = str(task["status"])
        if t_status != "active" and not (allow_auto_paused and t_status == "auto_paused"):
            return False, f"Task is currently {t_status}."
        now_dt = now_utc()
        st_dt = parse_iso_dt(task["start_at"])
        en_dt = parse_iso_dt(task["end_at"])
        if st_dt and now_dt < st_dt:
            return False, "This task has not started yet."
        if en_dt and now_dt > en_dt:
            return False, "This task has expired."

        allowed_vips = safe_json_loads(task["allowed_vip_tiers_json"], [])
        if allowed_vips and str(user_row["vip_tier"]) not in allowed_vips:
            return False, f"Restricted to tiers: {', '.join(allowed_vips)}."

        # Per-user total limit
        u_limit = int(task["user_limit"] or 0)
        if u_limit > 0:
            cnt = self.db.query_one(
                "SELECT COUNT(*) AS c FROM task_submissions WHERE task_id=? AND user_id=? AND status != 'rejected'",
                (task_id, user_id),
            )
            if cnt and int(cnt["c"]) >= u_limit:
                return False, f"Task limit reached ({u_limit} per user)."

        # Daily limit (Task & Global — strictest wins, Asia/Dhaka midnight reset)
        dhaka_start_utc = (
            now_dhaka().replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        )
        t_daily = int(task["daily_limit"] or 0)
        g_daily = self.config.get_int("global_task_daily_limit", 0)
        if t_daily > 0:
            cnt_td = self.db.query_one(
                "SELECT COUNT(*) AS c FROM task_submissions WHERE task_id=? AND user_id=? AND created_at>=? AND status != 'rejected'",
                (task_id, user_id, dhaka_start_utc),
            )
            if cnt_td and int(cnt_td["c"]) >= t_daily:
                return False, f"Daily limit reached for this task ({t_daily}/day)."
        if g_daily > 0:
            cnt_gd = self.db.query_one(
                "SELECT COUNT(*) AS c FROM task_submissions WHERE user_id=? AND created_at>=? AND status != 'rejected'",
                (user_id, dhaka_start_utc),
            )
            if cnt_gd and int(cnt_gd["c"]) >= g_daily:
                return False, f"Global daily task limit reached ({g_daily}/day)."

        # Cooldown (strictest of task vs global)
        cd_sec = max(int(task["cooldown_sec"] or 0), self.config.get_int("global_task_cooldown_sec", 0))
        if cd_sec > 0:
            last_sub = self.db.query_one(
                "SELECT created_at FROM task_submissions WHERE task_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
                (task_id, user_id),
            )
            if last_sub:
                last_dt = parse_iso_dt(last_sub["created_at"])
                if last_dt:
                    elapsed = (now_dt - last_dt).total_seconds()
                    if elapsed < cd_sec:
                        rem = int(cd_sec - elapsed)
                        return False, f"Cooldown active: please wait {rem}s before starting again."

        return True, ""

    def allocate_source_for_user(
        self,
        task_id: int,
        user_row: sqlite3.Row,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Atomically allocates 1 unique source record (BEGIN IMMEDIATE) for user,
        reusing any unexpired active allocation if present.
        Returns: (ok, error_msg, allocation_payload)
        """
        task = self.get_task(task_id)
        if task is None:
            return False, "Task not found.", None

        user_id = int(user_row["user_id"])
        has_active_alloc = bool(self.db.query_one(
            "SELECT id FROM task_allocations WHERE task_id=? AND user_id=? AND status='active' AND expires_at > ? LIMIT 1",
            (int(task_id), user_id, now_utc_iso()),
        ))
        ok_elig, err_elig = self.check_user_eligibility_and_limits(task, user_row, allow_auto_paused=has_active_alloc)
        if not ok_elig:
            return False, err_elig, None

        if int(task["source_enabled"]) == 0:
            test_code = ""
            if int(task["test_code_enabled"]) == 1 and self.config.get_bool("internal_test_code_enabled", True):
                test_code = generate_internal_test_code(int(task["test_code_length"] or 16))
            return True, "", {
                "allocation_id": 0,
                "source_record_id": 0,
                "fields": {},
                "assigned_password": "",
                "internal_test_code": test_code,
                "expires_at": "",
                "low_stock_alert": False,
            }

        now_dt = now_utc()
        now_s = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        timeout_sec = max(60, int(task["allocation_timeout_sec"] or self.config.get_int("task_allocation_timeout_sec", 900)))
        exp_s = (now_dt + timedelta(seconds=timeout_sec)).strftime("%Y-%m-%d %H:%M:%S")

        with self.db.atomic(immediate=True) as conn:
            # 1. Reuse existing active unexpired allocation
            existing_alloc = conn.execute(
                """
                SELECT * FROM task_allocations
                WHERE task_id=? AND user_id=? AND status='active' AND expires_at > ?
                ORDER BY id DESC LIMIT 1
                """,
                (int(task_id), user_id, now_s),
            ).fetchone()
            if existing_alloc is not None:
                return True, "", {
                    "allocation_id": int(existing_alloc["id"]),
                    "source_record_id": int(existing_alloc["source_record_id"]),
                    "fields": safe_json_loads(existing_alloc["allocated_fields_json"], {}),
                    "assigned_password": str(existing_alloc["assigned_password"]),
                    "internal_test_code": str(existing_alloc["internal_test_code"]),
                    "expires_at": str(existing_alloc["expires_at"]),
                    "low_stock_alert": False,
                }

            # 2. Pick 1 available source record atomically
            rec = conn.execute(
                "SELECT * FROM task_source_records WHERE task_id=? AND status='available' ORDER BY id ASC LIMIT 1",
                (int(task_id),),
            ).fetchone()
            if rec is None:
                if int(task["auto_pause_on_empty"]) == 1:
                    conn.execute("UPDATE tasks SET status='auto_paused', updated_at=? WHERE id=?", (now_s, int(task_id)))
                return False, "Out of Stock: No source records available right now.", None

            rec_id = int(rec["id"])
            upd = conn.execute(
                """
                UPDATE task_source_records
                SET status='allocated', allocated_to=?, allocated_at=?, expires_at=?
                WHERE id=? AND status='available'
                """,
                (user_id, now_s, exp_s, rec_id),
            )
            if int(upd.rowcount or 0) != 1:
                return False, "Concurrent allocation conflict, please retry.", None

            raw_cols = safe_json_loads(rec["columns_json"], {})
            mapped_cols = self.map_record_canonical(raw_cols)
            assigned_pw = self._compute_assigned_password(task, mapped_cols)
            display_fields = self._select_fields_for_combo(task, user_row, raw_cols, assigned_pw)

            test_code = ""
            if int(task["test_code_enabled"]) == 1 and self.config.get_bool("internal_test_code_enabled", True):
                test_code = generate_internal_test_code(int(task["test_code_length"] or 16))
                conn.execute(
                    "INSERT INTO internal_test_codes (task_id, code_value, is_single_use, is_used, used_by, created_at) VALUES (?, ?, 1, 0, ?, ?)",
                    (int(task_id), test_code, user_id, now_s),
                )

            cur_a = conn.execute(
                """
                INSERT INTO task_allocations
                (task_id, source_record_id, user_id, allocated_fields_json, assigned_password, internal_test_code, status, allocated_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
                """,
                (int(task_id), rec_id, user_id, safe_json_dumps(display_fields), assigned_pw, test_code, now_s, exp_s),
            )
            alloc_id = int(cur_a.lastrowid or 0)

            rem_row = conn.execute(
                "SELECT COUNT(*) AS c FROM task_source_records WHERE task_id=? AND status='available'",
                (int(task_id),),
            ).fetchone()
            rem_cnt = int(rem_row["c"]) if rem_row else 0
            low_thresh = int(task["low_stock_threshold"] or self.config.get_int("low_stock_threshold", 5))
            low_alert = self.config.get_bool("low_stock_alert_enabled", True) and rem_cnt <= low_thresh
            if rem_cnt == 0 and int(task["auto_pause_on_empty"]) == 1:
                conn.execute("UPDATE tasks SET status='auto_paused', updated_at=? WHERE id=?", (now_s, int(task_id)))

            return True, "", {
                "allocation_id": alloc_id,
                "source_record_id": rec_id,
                "fields": display_fields,
                "assigned_password": assigned_pw,
                "internal_test_code": test_code,
                "expires_at": exp_s,
                "remaining_stock": rem_cnt,
                "low_stock_alert": low_alert,
            }

    def release_expired_allocations(self) -> int:
        now_s = now_utc_iso()
        released = 0
        with self.db.atomic(immediate=True) as conn:
            expired_rows = conn.execute(
                "SELECT id, task_id, source_record_id FROM task_allocations WHERE status='active' AND expires_at < ?",
                (now_s,),
            ).fetchall()
            affected_tasks: Set[int] = set()
            for r in expired_rows:
                conn.execute(
                    "UPDATE task_allocations SET status='released', released_at=? WHERE id=?",
                    (now_s, int(r["id"])),
                )
                conn.execute(
                    """
                    UPDATE task_source_records
                    SET status='available', allocated_to=NULL, allocated_at='', expires_at=''
                    WHERE id=? AND status='allocated'
                    """,
                    (int(r["source_record_id"]),),
                )
                affected_tasks.add(int(r["task_id"]))
                released += 1
            for tid in affected_tasks:
                t = conn.execute("SELECT status, auto_resume_on_stock FROM tasks WHERE id=?", (tid,)).fetchone()
                if t and str(t["status"]) == "auto_paused" and int(t["auto_resume_on_stock"]) == 1:
                    conn.execute("UPDATE tasks SET status='active', updated_at=? WHERE id=?", (now_s, tid))
        return released

    def test_as_user_preview(self, task_id: int, admin_row: sqlite3.Row, lang: str = "bn") -> str:
        task = self.get_task(task_id)
        if task is None:
            return "Task not found."
        pre_steps = self.list_task_steps(task_id, "pre_code", active_only=True)
        post_steps = self.list_task_steps(task_id, "post_code", active_only=True)
        counts = self.get_source_counts(task_id)

        sample_rec = self.db.query_one(
            "SELECT * FROM task_source_records WHERE task_id=? ORDER BY id ASC LIMIT 1",
            (int(task_id),),
        )
        sample_fields: Dict[str, str] = {}
        if sample_rec:
            raw_cols = safe_json_loads(sample_rec["columns_json"], {})
            assigned_pw = self._compute_assigned_password(task, self.map_record_canonical(raw_cols))
            sample_fields = self._select_fields_for_combo(task, admin_row, raw_cols, assigned_pw)

        title = task["title_bn"] if lang == "bn" else task["title_en"]
        lines = [
            f"👁️ <b>Test as User Preview: {escape_html(title)}</b>",
            f"💰 Reward: <code>{format_money(task['reward_amount'])}</code> | 📦 Stock: {counts['available']}/{counts['total']}",
            f"1️⃣ Layer 1 (Source): {'ON' if task['source_enabled'] else 'OFF'} | Combo: <code>{task['field_combo_mode']}</code> | PW Mode: <code>{task['password_mode']}</code>",
        ]
        if sample_fields:
            lines.append("📋 <b>Sample Source Data Card:</b>")
            for k, v in sample_fields.items():
                lines.append(f"  • {escape_html(k)}: <code>{escape_html(v)}</code>")
        lines.append(f"2️⃣ Layer 2 (Pre-Code Steps): {len(pre_steps)} active step(s)")
        lines.append(
            f"3️⃣ Layer 3 (16/32 TOTP + Cookie): TOTP={'ON' if task['require_totp'] else 'OFF'} (DupBlk={'ON' if task['totp_dup_block'] else 'OFF'}) | "
            f"Cookie={'ON' if task['require_cookie'] else 'OFF'} (DupBlk={'ON' if task['cookie_dup_block'] else 'OFF'}, Keys={task['cookie_required_keys']})"
        )
        lines.append(f"4️⃣ Layer 4 (Post-Code Steps): {len(post_steps)} active step(s)")
        lines.append(
            f"5️⃣ Layer 5 (Auto-Delete & Auto-Approve): AutoDel={'ON' if task['auto_delete_messages'] else 'OFF'} | "
            f"AutoApp={'ON (' + str(task['auto_approve_sec']) + 's)' if task['auto_approve_enabled'] else 'OFF'}"
        )
        return "\n".join(lines)
# ==============================================================================
# TASK SUBMISSION ENGINE — TOTP DUP, COOKIE VERIFY, AUTO-DELETE & MASTER EXPORT
# ==============================================================================

class TaskSubmissionEngine:
    """
    Handles Task Layer 2-5 execution:
    - 16/32 Base32 TOTP + Duplicate Block (totp_used_keys)
    - Cookie Parsing (JSON / key=value / Netscape) + Required Keys + Canonical Reorder-Proof Duplicate Block
    - Atomic Task Submission, Auto-Delete Cleanup (task_messages), Approve/Reject & Master Export
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        security: SecurityManager,
        ledger: LedgerManager,
        reward: RewardManager,
        task_mgr: TaskManager,
        studio: MessageStudioManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.security = security
        self.ledger = ledger
        self.reward = reward
        self.task_mgr = task_mgr
        self.studio = studio

    def is_totp_required(self, task: sqlite3.Row) -> bool:
        return self.config.get_bool("global_totp_enabled", True) and int(task["require_totp"]) == 1

    def is_totp_dup_blocked(self, task: sqlite3.Row) -> bool:
        return self.config.get_bool("global_totp_dup_block", True) and int(task["totp_dup_block"]) == 1

    def is_cookie_required(self, task: sqlite3.Row) -> bool:
        return self.config.get_bool("global_cookie_step_enabled", True) and int(task["require_cookie"]) == 1

    def is_cookie_dup_blocked(self, task: sqlite3.Row) -> bool:
        return self.config.get_bool("global_cookie_dup_block", True) and int(task["cookie_dup_block"]) == 1

    def get_effective_cookie_keys(self, task: sqlite3.Row) -> str:
      task_keys = str(task["cookie_required_keys"] or "").strip()
      if task_keys.lower() in {"any", "*"}:
          return "none"
      if task_keys and task_keys.lower() != "none":
          return task_keys
      return self.config.get_str("global_cookie_required_keys", "none")

    def validate_totp_submission(
        self,
        task: sqlite3.Row,
        raw_secret: str,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        ok, code_6, remaining, norm_secret, err = compute_rfc6238_totp(raw_secret)
        if not ok:
            return False, err, {}

        sec_hash = sha256_text(norm_secret)
        if self.is_totp_dup_blocked(task):
            hit = self.db.query_one(
                "SELECT submission_uid FROM totp_used_keys WHERE secret_hash=? LIMIT 1",
                (sec_hash,),
            )
            if hit is not None:
                return (
                    False,
                    f"Duplicate 16/32 Key: already used in submission {hit['submission_uid']}.",
                    {},
                )
        return True, "", {
            "totp_secret": norm_secret,
            "totp_secret_hash": sec_hash,
            "totp_6digit_code": code_6,
            "remaining_sec": remaining,
        }

    def validate_cookie_submission(
        self,
        task: sqlite3.Row,
        raw_cookie: str,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        req_keys = self.get_effective_cookie_keys(task)
        ok, pairs, canonical_str, ck_hash, err = parse_and_canonicalize_cookie(raw_cookie, req_keys)
        if not ok:
            return False, err, {}

        if self.is_cookie_dup_blocked(task):
            hit = self.db.query_one(
                "SELECT submission_uid FROM cookie_submissions WHERE cookie_hash=? LIMIT 1",
                (ck_hash,),
            )
            if hit is not None:
                return (
                    False,
                    f"Duplicate Cookie: this exact cookie was already submitted ({hit['submission_uid']}).",
                    {},
                )
        return True, "", {
            "cookie_raw": raw_cookie,
            "cookie_canonical": canonical_str,
            "cookie_hash": ck_hash,
            "cookie_pairs_count": len(pairs),
        }

    def track_workflow_message(
        self,
        workflow_uid: str,
        user_id: int,
        chat_id: int,
        message_id: int,
        task_id: int,
        is_bot_msg: bool = True,
    ) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO task_messages (workflow_uid, user_id, chat_id, message_id, task_id, is_bot_msg, is_deleted, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (workflow_uid, int(user_id), int(chat_id), int(message_id), int(task_id), 1 if is_bot_msg else 0, now_utc_iso()),
            )

    async def cleanup_workflow_messages(self, bot: Bot, workflow_uid: str) -> Tuple[int, int]:
        rows = self.db.query_all(
            "SELECT id, chat_id, message_id FROM task_messages WHERE workflow_uid=? AND is_deleted=0",
            (workflow_uid,),
        )
        deleted = 0
        failed = 0
        for r in rows:
            try:
                await bot.delete_message(chat_id=int(r["chat_id"]), message_id=int(r["message_id"]))
                with self.db.atomic(immediate=True) as conn:
                    conn.execute("UPDATE task_messages SET is_deleted=1 WHERE id=?", (int(r["id"]),))
                deleted += 1
            except Exception as exc:
                failed += 1
                LOGGER.warning("Auto-delete skipped for msg %s in chat %s: %s", r["message_id"], r["chat_id"], exc)
        return deleted, failed

    def _compute_auto_review_schedule(self, task: sqlite3.Row) -> Tuple[str, str]:
        """Returns (auto_review_mode, auto_action_at_utc_iso)."""
        if self.security.is_panic_frozen():
            return "manual", ""

        task_app_on = int(task["auto_approve_enabled"]) == 1
        glob_app_on = self.config.get_bool("task_auto_approve_global", False)
        if task_app_on or glob_app_on:
            delay = int(task["auto_approve_sec"] or 0) if task_app_on else self.config.get_int("task_auto_approve_sec", 60)
            delay = max(5, delay)
            act_at = (now_utc() + timedelta(seconds=delay)).strftime("%Y-%m-%d %H:%M:%S")
            return "auto_approve", act_at

        task_rej_on = int(task["auto_reject_enabled"]) == 1
        glob_rej_on = self.config.get_bool("task_auto_reject_global", False)
        if task_rej_on or glob_rej_on:
            delay = int(task["auto_reject_sec"] or 0) if task_rej_on else self.config.get_int("task_auto_reject_sec", 300)
            delay = max(5, delay)
            act_at = (now_utc() + timedelta(seconds=delay)).strftime("%Y-%m-%d %H:%M:%S")
            return "auto_reject", act_at

        return "manual", ""

    def submit_task(
        self,
        task_id: int,
        user_row: sqlite3.Row,
        allocation_id: int,
        source_record_id: int,
        source_snapshot: Dict[str, Any],
        step_answers: List[Dict[str, Any]],
        totp_data: Optional[Dict[str, Any]] = None,
        cookie_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Atomically submits a task with TOTP/Cookie duplicate enforcement,
        RULE 16 proof-hash suspicious detection, reward/referral snapshots,
        and auto-review scheduling.
        """
        task = self.task_mgr.get_task(task_id)
        if task is None:
            return False, "Task not found.", None
        user_id = int(user_row["user_id"])
        ok_elig, err_elig = self.task_mgr.check_user_eligibility_and_limits(task, user_row, allow_auto_paused=(int(allocation_id) > 0))
        if not ok_elig:
            return False, err_elig, None

        totp_secret = str((totp_data or {}).get("totp_secret", ""))
        totp_hash = str((totp_data or {}).get("totp_secret_hash", ""))
        totp_code = str((totp_data or {}).get("totp_6digit_code", ""))

        ck_raw = str((cookie_data or {}).get("cookie_raw", ""))
        ck_canon = str((cookie_data or {}).get("cookie_canonical", ""))
        ck_hash = str((cookie_data or {}).get("cookie_hash", ""))

        proof_payload = safe_json_dumps({"steps": step_answers, "totp": totp_hash, "cookie": ck_hash})
        proof_hash = sha256_text(proof_payload)
        sub_uid = generate_uid("TSK", 7)
        now_s = now_utc_iso()

        eff_reward = self.reward.compute_effective_reward(float(task["reward_amount"]))
        ref_rate = (
            self.config.get_float("referral_commission_value", 10.0)
            if self.config.get_bool("referral_enabled", True)
            else 0.0
        )

        with self.db.atomic(immediate=True) as conn:
            # Atomic re-check of TOTP & Cookie duplicates against race conditions
            if totp_hash and self.is_totp_dup_blocked(task):
                hit_t = conn.execute(
                    "SELECT submission_uid FROM totp_used_keys WHERE secret_hash=? LIMIT 1",
                    (totp_hash,),
                ).fetchone()
                if hit_t:
                    return False, f"Duplicate 16/32 Key detected ({hit_t['submission_uid']}).", None

            if ck_hash and self.is_cookie_dup_blocked(task):
                hit_c = conn.execute(
                    "SELECT submission_uid FROM cookie_submissions WHERE cookie_hash=? LIMIT 1",
                    (ck_hash,),
                ).fetchone()
                if hit_c:
                    return False, f"Duplicate Cookie detected ({hit_c['submission_uid']}).", None

            # RULE 16 Proof Hash Duplicate / Suspicious Detection
            is_suspicious = 0
            suspicious_note = ""
            dup_scope = self.config.get_str("duplicate_check_scope", "global")
            if self.config.get_bool("duplicate_hash_check", True) and step_answers:
                if dup_scope == "user":
                    dup_hit = conn.execute(
                        "SELECT sub_uid FROM task_submissions WHERE proof_hash=? AND user_id=? AND status != 'rejected' LIMIT 1",
                        (proof_hash, user_id),
                    ).fetchone()
                elif dup_scope == "task":
                    dup_hit = conn.execute(
                        "SELECT sub_uid FROM task_submissions WHERE proof_hash=? AND task_id=? AND status != 'rejected' LIMIT 1",
                        (proof_hash, int(task_id)),
                    ).fetchone()
                else:
                    dup_hit = conn.execute(
                        "SELECT sub_uid FROM task_submissions WHERE proof_hash=? AND status != 'rejected' LIMIT 1",
                        (proof_hash,),
                    ).fetchone()
                if dup_hit is not None:
                    is_suspicious = 1
                    suspicious_note = f"Duplicate proof hash matches {dup_hit['sub_uid']}"

            auto_mode, auto_action_at = self._compute_auto_review_schedule(task)
            if is_suspicious == 1 and auto_mode == "auto_approve":
                # RULE 16: Suspicious records must NEVER auto-approve
                auto_mode = "manual"
                auto_action_at = ""

            user_full_name = str(user_row["full_name"] or "")
            user_username = str(user_row["username"] or "")

            cur = conn.execute(
                """
                INSERT INTO task_submissions (
                    sub_uid, task_id, user_id, user_full_name, user_username,
                    allocation_id, source_record_id, source_snapshot_json, step_answers_json,
                    totp_secret, totp_secret_hash, totp_6digit_code,
                    cookie_raw, cookie_canonical, cookie_hash, proof_hash,
                    reward_snapshot, referral_rate_snapshot, status, auto_review_mode, auto_action_at,
                    is_suspicious, suspicious_note, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
                """,
                (
                    sub_uid,
                    int(task_id),
                    user_id,
                    user_full_name,
                    user_username,
                    int(allocation_id) if allocation_id else None,
                    int(source_record_id) if source_record_id else None,
                    safe_json_dumps(source_snapshot),
                    safe_json_dumps(step_answers),
                    totp_secret,
                    totp_hash,
                    totp_code,
                    ck_raw,
                    ck_canon,
                    ck_hash,
                    proof_hash,
                    eff_reward,
                    ref_rate,
                    auto_mode,
                    auto_action_at,
                    is_suspicious,
                    suspicious_note,
                    now_s,
                ),
            )
            sub_id = int(cur.lastrowid or 0)

            if totp_hash:
                conn.execute(
                    """
                    INSERT INTO totp_used_keys (secret_normalized, secret_hash, task_id, user_id, submission_uid, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (totp_secret, totp_hash, int(task_id), user_id, sub_uid, now_s),
                )
            if ck_hash:
                conn.execute(
                    """
                    INSERT INTO cookie_submissions (cookie_hash, cookie_canonical, task_id, user_id, submission_uid, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (ck_hash, ck_canon, int(task_id), user_id, sub_uid, now_s),
                )

            if allocation_id:
                conn.execute(
                    "UPDATE task_allocations SET status='submitted', submission_id=? WHERE id=?",
                    (sub_id, int(allocation_id)),
                )
            if source_record_id:
                conn.execute(
                    "UPDATE task_source_records SET status='submitted', submission_id=? WHERE id=?",
                    (sub_id, int(source_record_id)),
                )

        return True, "Task submitted.", {
            "id": sub_id,
            "sub_uid": sub_uid,
            "task_id": int(task_id),
            "task_title_bn": str(task["title_bn"]),
            "task_title_en": str(task["title_en"]),
            "reward": eff_reward,
            "is_suspicious": bool(is_suspicious),
            "suspicious_note": suspicious_note,
            "auto_mode": auto_mode,
            "auto_action_at": auto_action_at,
        }

    def set_review_channel_ref(self, sub_id: int, channel_id: str, message_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE task_submissions SET review_channel_id=?, review_message_id=? WHERE id=?",
                (str(channel_id), int(message_id), int(sub_id)),
            )

    def get_submission(self, sub_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM task_submissions WHERE id=?", (int(sub_id),))

    def get_submission_by_uid(self, sub_uid: str) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM task_submissions WHERE sub_uid=?", (sub_uid.strip(),))

    def approve_submission(
        self,
        sub_id: int,
        admin_id: int,
        is_auto: bool = False,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            sub = conn.execute("SELECT * FROM task_submissions WHERE id=?", (int(sub_id),)).fetchone()
            if sub is None:
                return False, "Submission not found.", {}
            if str(sub["status"]) != "pending":
                return False, f"Already finalized ({sub['status']}).", {"already_status": str(sub["status"])}

            upd = conn.execute(
                """
                UPDATE task_submissions
                SET status='approved', reviewed_by=?, reviewed_at=?, auto_action_at=''
                WHERE id=? AND status='pending'
                """,
                (int(admin_id), now_s, int(sub_id)),
            )
            if int(upd.rowcount or 0) != 1:
                return False, "Concurrent review conflict.", {}

            user_id = int(sub["user_id"])
            sub_uid = str(sub["sub_uid"])
            reward_amt = float(sub["reward_snapshot"])

            ok_r, msg_r, _, new_bal = self.reward.credit_reward(
                user_id=user_id,
                tx_type="task_reward",
                amount=reward_amt,
                idempotency_key=f"task_app:{sub_uid}",
                ref_id=sub_uid,
                reason=f"Task submission {sub_uid} approved",
                wallet_bucket="earned",
            )
            if not ok_r:
                raise ValueError(msg_r)

            # Referral Commission (RULE 27)
            ref_info: Dict[str, Any] = {}
            if self.config.get_bool("referral_enabled", True) and reward_amt > 0:
                u_row = conn.execute(
                    "SELECT referrer_id, full_name FROM users WHERE user_id=?",
                    (user_id,),
                ).fetchone()
                if u_row and u_row["referrer_id"]:
                    ref_uid = int(u_row["referrer_id"])
                    ref_user = conn.execute("SELECT status, language FROM users WHERE user_id=?", (ref_uid,)).fetchone()
                    if ref_user and str(ref_user["status"]) != "blocked":
                        ctype = self.config.get_str("referral_commission_type", "percent")
                        cval = float(sub["referral_rate_snapshot"] or self.config.get_float("referral_commission_value", 10.0))
                        comm_amt = round(reward_amt * (cval / 100.0), 4) if ctype == "percent" else round(cval, 4)
                        if comm_amt > 0:
                            ok_c, _, comm_tx, ref_new_bal = self.ledger.apply_transaction(
                                user_id=ref_uid,
                                tx_type="referral_commission",
                                amount=comm_amt,
                                direction="credit",
                                wallet_bucket="earned",
                                idempotency_key=f"ref_comm:task:{sub_uid}",
                                source="referral_task",
                                ref_id=sub_uid,
                                reason=f"Referral commission from {sub_uid}",
                            )
                            if ok_c:
                                ref_info = {
                                    "referrer_id": ref_uid,
                                    "ref_lang": str(ref_user["language"]),
                                    "ref_name": str(u_row["full_name"]),
                                    "comm_amount": comm_amt,
                                    "ref_new_balance": ref_new_bal,
                                    "tx_uid": comm_tx,
                                }

        self.audit.log(admin_id, "auto" if is_auto else "admin", "approve_task", "task_submission", sub_id)
        return True, "Approved", {
            "sub": dict(sub),
            "new_balance": new_bal,
            "referral": ref_info,
        }

    def reject_submission(
        self,
        sub_id: int,
        admin_id: int,
        reason: str,
        is_auto: bool = False,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        clean_reason = str(reason or "").strip() or "Rejected by review"
        with self.db.atomic(immediate=True) as conn:
            sub = conn.execute("SELECT * FROM task_submissions WHERE id=?", (int(sub_id),)).fetchone()
            if sub is None:
                return False, "Submission not found.", {}
            if str(sub["status"]) != "pending":
                return False, f"Already finalized ({sub['status']}).", {"already_status": str(sub["status"])}
            upd = conn.execute(
                """
                UPDATE task_submissions
                SET status='rejected', reject_reason=?, reviewed_by=?, reviewed_at=?, auto_action_at=''
                WHERE id=? AND status='pending'
                """,
                (clean_reason, int(admin_id), now_s, int(sub_id)),
            )
            if int(upd.rowcount or 0) != 1:
                return False, "Concurrent review conflict.", {}

        self.audit.log(admin_id, "auto" if is_auto else "admin", "reject_task", "task_submission", sub_id, {"reason": clean_reason})
        return True, "Rejected", {"sub": dict(sub), "reason": clean_reason}

    def export_task_master_file(
        self,
        task_id: int,
        file_format: str = "xlsx",
        incremental_only: bool = False,
        admin_id: int = 0,
        bypass_cooldown: bool = False,
    ) -> Tuple[bool, str, Optional[Path], List[int]]:
        """
        Zero-Column-Mixing Task Master Export (RULE 13, 85 + TOTP_Secret, TOTP_6Digit_Code, Cookie_Data).
        Caller marks submissions as exported ONLY after Telegram document send succeeds!
        Returns: (ok, message, file_path, exported_submission_ids)
        """
        task = self.task_mgr.get_task(task_id)
        if task is None:
            return False, "Task not found.", None, []

        cd_hours = self.config.get_int("excel_export_cooldown_hours", 24)
        if cd_hours > 0 and not bypass_cooldown:
            last_exp = self.db.query_one(
                """
                SELECT created_at FROM export_history
                WHERE export_type='task_master' AND ref_id=? AND delivery_ok=1
                ORDER BY id DESC LIMIT 1
                """,
                (str(task_id),),
            )
            if last_exp:
                last_dt = parse_iso_dt(last_exp["created_at"])
                if last_dt and (now_utc() - last_dt).total_seconds() < cd_hours * 3600:
                    rem_h = round((cd_hours * 3600 - (now_utc() - last_dt).total_seconds()) / 3600, 1)
                    return False, f"Export Cooldown active: {rem_h}h remaining.", None, []

        where_inc = "AND ts.is_exported=0" if incremental_only else ""
        subs = self.db.query_all(
            f"""
            SELECT ts.*, tsr.columns_json AS raw_src_cols, ta.assigned_password, ta.internal_test_code
            FROM task_submissions ts
            LEFT JOIN task_source_records tsr ON tsr.id = ts.source_record_id
            LEFT JOIN task_allocations ta ON ta.id = ts.allocation_id
            WHERE ts.task_id=? {where_inc}
            ORDER BY ts.id ASC
            """,
            (int(task_id),),
        )
        if not subs:
            return False, "No submissions found to export.", None, []

        # Collect union of all Admin Source columns and all Step titles cleanly
        src_col_names: List[str] = []
        src_col_seen: Set[str] = set()
        step_col_names: List[str] = []
        step_col_seen: Set[str] = set()

        parsed_rows: List[Dict[str, Any]] = []
        for s in subs:
            raw_src = safe_json_loads(s["raw_src_cols"], {})
            if not raw_src:
                raw_src = safe_json_loads(s["source_snapshot_json"], {})
            for k in raw_src.keys():
                col_key = f"Admin_Src_{k}"
                if col_key not in src_col_seen:
                    src_col_seen.add(col_key)
                    src_col_names.append(col_key)

            steps_ans = safe_json_loads(s["step_answers_json"], [])
            step_map: Dict[str, str] = {}
            for idx, item in enumerate(steps_ans, start=1):
                st_lbl = str(item.get("label") or f"Step_{idx}")
                col_s = f"Step_{idx}_{st_lbl}"
                if col_s not in step_col_seen:
                    step_col_seen.add(col_s)
                    step_col_names.append(col_s)
                step_map[col_s] = str(item.get("value", ""))
            parsed_rows.append({"row": s, "src": raw_src, "steps": step_map})

        has_uid_col = any(
            sc[len("Admin_Src_") :].strip().lower() in {"uid", "account_uid", "fb_uid"}
            for sc in src_col_names
        )
        extra_uid_col = ["UID"] if (str(task["field_combo_mode"]) == "full_pass" and not has_uid_col) else []

        headers = (
            ["Submission_UID", "Status", "User_ID", "User_Full_Name", "User_Username"]
            + src_col_names
            + extra_uid_col
            + ["Custom_Password", "Internal_Test_Code", "TOTP_Secret", "TOTP_6Digit_Code", "Cookie_Data"]
            + step_col_names
            + ["Reward", "Suspicious", "Created_At_Dhaka"]
        )

        export_rows: List[List[str]] = []
        raw_export_rows: List[List[Any]] = []
        exported_ids: List[int] = []
        for item in parsed_rows:
            s = item["row"]
            src = item["src"]
            st_map = item["steps"]
            exported_ids.append(int(s["id"]))
            uname = f"@{s['user_username']}" if s["user_username"] else ""
            row_vals: List[Any] = [
                s["sub_uid"],
                s["status"],
                int(s["user_id"]),
                s["user_full_name"],
                uname,
            ]
            for sc in src_col_names:
                orig_key = sc[len("Admin_Src_") :]
                row_vals.append(src.get(orig_key, ""))
            if extra_uid_col:
                row_vals.append("")
            row_vals.extend(
                [
                    s["assigned_password"] or "",
                    s["internal_test_code"] or "",
                    s["totp_secret"] or "",
                    s["totp_6digit_code"] or "",
                    s["cookie_raw"] or s["cookie_canonical"] or "",
                ]
            )
            for stc in step_col_names:
                row_vals.append(st_map.get(stc, ""))
            row_vals.extend(
                [
                    s["reward_snapshot"],
                    "YES" if int(s["is_suspicious"]) == 1 else "NO",
                    format_dhaka_dt(s["created_at"]),
                ]
            )
            raw_export_rows.append(list(row_vals))
            export_rows.append([sanitize_excel_cell(v) for v in row_vals])

        DATA_DIRS["exports"].mkdir(parents=True, exist_ok=True)
        stamp = now_dhaka().strftime("%Y%m%d_%H%M%S")
        mode_tag = "NEW" if incremental_only else "ALL"
        safe_title = sanitize_filename(str(task["title_en"]), f"task_{task_id}")[:24]
        ext = file_format.lower() if file_format.lower() in ("xlsx", "csv", "txt") else "xlsx"
        out_path = DATA_DIRS["exports"] / f"Task_{task_id}_{safe_title}_{mode_tag}_{stamp}.{ext}"

        if ext == "xlsx":
            wb = Workbook()
            ws = wb.active
            ws.title = "Task_Master"
            ws.append(headers)
            for r in export_rows:
                ws.append(r)
            for col_idx, col_cells in enumerate(ws.columns, start=1):
                max_w = max((len(str(c.value or "")) for c in col_cells), default=10)
                ws.column_dimensions[get_column_letter(col_idx)].width = min(48, max(12, max_w + 3))
            wb.save(out_path)
            wb.close()
        elif ext == "csv":
            with open(out_path, "w", newline="", encoding="utf-8-sig") as fp:
                writer = csv.writer(fp)
                writer.writerow(headers)
                writer.writerows(export_rows)
        else:
            # Separate-line structured .txt export (RULE 13.2 / 85.2)
            with open(out_path, "w", encoding="utf-8") as fp:
                for idx, row_vals in enumerate(export_rows, start=1):
                    fp.write(f"=== RECORD #{idx} ===\n")
                    for h, val in zip(headers, row_vals):
                        if str(val).strip():
                            fp.write(f"{h}: {val}\n")
                    fp.write("\n")

        return True, f"Prepared {len(exported_ids)} record(s).", out_path, exported_ids

    def mark_submissions_exported(self, task_id: int, sub_ids: List[int], file_path: Path, fmt: str, admin_id: int) -> None:
        now_s = now_utc_iso()
        exp_uid = generate_uid("EXP", 6)
        with self.db.atomic(immediate=True) as conn:
            for sid in sub_ids:
                conn.execute(
                    "UPDATE task_submissions SET is_exported=1, exported_at=? WHERE id=?",
                    (now_s, int(sid)),
                )
            conn.execute(
                """
                INSERT INTO export_history (export_uid, export_type, ref_id, file_format, file_path, row_count, admin_id, delivery_ok, created_at)
                VALUES (?, 'task_master', ?, ?, ?, ?, ?, 1, ?)
                """,
                (exp_uid, str(task_id), fmt, str(file_path), len(sub_ids), int(admin_id), now_s),
            )
# ==============================================================================
# EXCEL MANAGER (ZERO-COLUMN-MIXING & FORMULA-INJECTION SAFE EXPORTS)
# ==============================================================================

class ExcelManager:
    """Handles safe .xlsx/.csv exports across Users, File Submit, OTP, Bonuses & Reports."""

    def __init__(self, db: DatabaseManager, config: ConfigManager) -> None:
        self.db = db
        self.config = config

    def export_rows(
        self,
        headers: List[str],
        rows: List[List[Any]],
        export_type: str,
        ref_id: str = "",
        file_format: str = "xlsx",
        sheet_title: str = "Report",
        admin_id: int = 0,
    ) -> Tuple[Path, str]:
        DATA_DIRS["exports"].mkdir(parents=True, exist_ok=True)
        stamp = now_dhaka().strftime("%Y%m%d_%H%M%S")
        ext = file_format.lower() if file_format.lower() in ("xlsx", "csv") else "xlsx"
        safe_type = sanitize_filename(export_type, "export")
        out_path = DATA_DIRS["exports"] / f"{safe_type}_{stamp}.{ext}"

        safe_rows = [[sanitize_excel_cell(cell) for cell in r] for r in rows]

        if ext == "xlsx":
            wb = Workbook()
            ws = wb.active
            ws.title = sheet_title[:31]
            ws.append(headers)
            for r in safe_rows:
                ws.append(r)
            for col_idx, col_cells in enumerate(ws.columns, start=1):
                max_w = max((len(str(c.value or "")) for c in col_cells), default=10)
                ws.column_dimensions[get_column_letter(col_idx)].width = min(48, max(12, max_w + 3))
            wb.save(out_path)
            wb.close()
        else:
            with open(out_path, "w", newline="", encoding="utf-8-sig") as fp:
                writer = csv.writer(fp)
                writer.writerow(headers)
                writer.writerows(safe_rows)

        exp_uid = generate_uid("EXP", 6)
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO export_history (export_uid, export_type, ref_id, file_format, file_path, row_count, admin_id, delivery_ok, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (exp_uid, export_type, str(ref_id), ext, str(out_path), len(safe_rows), int(admin_id), now_utc_iso()),
            )
        return out_path, exp_uid

    def export_fs_master(
        self,
        fs_task_id: Optional[int] = None,
        incremental_only: bool = False,
        file_format: str = "xlsx",
        admin_id: int = 0,
    ) -> Tuple[bool, str, Optional[Path], List[int]]:
        clauses: List[str] = []
        params: List[Any] = []
        if fs_task_id is not None:
            clauses.append("r.fs_task_id=?")
            params.append(int(fs_task_id))
        if incremental_only:
            clauses.append("r.is_exported=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        rows = self.db.query_all(
            f"""
            SELECT r.*, s.sub_uid, s.user_full_name, s.user_username, s.reward_per_record_snapshot, s.created_at AS sub_created_at
            FROM fs_records r
            JOIN fs_submissions s ON s.id = r.fs_submission_id
            {where_sql}
            ORDER BY r.id ASC
            """,
            params,
        )
        if not rows:
            return False, "No File Submit records available to export.", None, []

        parsed_cols: List[List[str]] = []
        max_cols = 1
        rec_ids: List[int] = []
        for r in rows:
            cols = safe_json_loads(r["columns_json"], [])
            if not isinstance(cols, list) or not cols:
                cols = [str(r["raw_line"])]
            max_cols = max(max_cols, len(cols))
            parsed_cols.append([str(c) for c in cols])
            rec_ids.append(int(r["id"]))

        col_headers = [f"Submitted_Col_{i + 1}" for i in range(max_cols)]
        headers = (
            ["FS_Sub_UID", "Record_UID", "Line_No", "Status", "Reject_Reason", "User_ID", "User_Full_Name", "User_Username"]
            + col_headers
            + ["Unit_Reward", "Reviewed_At_Dhaka", "Submitted_At_Dhaka"]
        )

        out_rows: List[List[Any]] = []
        for r, cols in zip(rows, parsed_cols):
            padded = cols + [""] * (max_cols - len(cols))
            uname = f"@{r['user_username']}" if r["user_username"] else ""
            out_rows.append(
                [
                    r["sub_uid"],
                    r["stable_uid"],
                    int(r["line_no"]),
                    r["status"],
                    r["reject_reason"],
                    int(r["user_id"]),
                    r["user_full_name"],
                    uname,
                ]
                + padded
                + [
                    r["reward_per_record_snapshot"],
                    format_dhaka_dt(r["reviewed_at"]),
                    format_dhaka_dt(r["sub_created_at"]),
                ]
            )

        out_path, _ = self.export_rows(
            headers=headers,
            rows=out_rows,
            export_type=f"FS_Master_{fs_task_id or 'all'}",
            ref_id=str(fs_task_id or "all"),
            file_format=file_format,
            sheet_title="FS_Master",
            admin_id=admin_id,
        )
        return True, f"Exported {len(rec_ids)} FS records.", out_path, rec_ids

    def mark_fs_records_exported(self, rec_ids: List[int]) -> None:
        if not rec_ids:
            return
        with self.db.atomic(immediate=True) as conn:
            for rid in rec_ids:
                conn.execute("UPDATE fs_records SET is_exported=1 WHERE id=?", (int(rid),))


# ==============================================================================
# FILE SUBMIT MANAGER (INDEPENDENT FS, RULE 92, BATCH 1/3/5/7/10/15/20 & VERSIONS)
# ==============================================================================

class FileSubmitManager:
    """
    Completely independent File Submit engine supporting:
    - Multiple FS tasks & source file archive
    - Multi-column Zero-Column-Mixing parser & RULE 92 validation/smart-skip
    - Review queue with 1 & batch 3/5/7/10/15/20 + Select All + Concurrent Lock
    - Record-level Reject Templates, Correction Workflow, report_versions & FS Commission
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        ledger: LedgerManager,
        reward: RewardManager,
        excel: ExcelManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.ledger = ledger
        self.reward = reward
        self.excel = excel

    def list_fs_tasks(self, active_only: bool = False, include_archived: bool = False) -> List[sqlite3.Row]:
        clauses: List[str] = []
        if not include_archived:
            clauses.append("is_archived=0")
        if active_only:
            clauses.append("status='active'")
            clauses.append("is_hidden=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM fs_tasks {where_sql} ORDER BY id DESC")

    def get_fs_task(self, fs_task_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM fs_tasks WHERE id=?", (int(fs_task_id),))

    def create_fs_task(
        self,
        title_bn: str,
        title_en: str,
        reward_per_record: float,
        desc_bn: str = "",
        desc_en: str = "",
        instruction_bn: str = "",
        instruction_en: str = "",
        min_columns: int = 1,
        pattern_type: str = "any",
        duplicate_scope: str = "global",
        smart_skip_invalid: bool = True,
        admin_id: int = 0,
    ) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO fs_tasks (
                    title_bn, title_en, desc_bn, desc_en, instruction_bn, instruction_en,
                    reward_per_record, min_columns, pattern_type, duplicate_scope, smart_skip_invalid,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    title_bn.strip(),
                    (title_en or title_bn).strip(),
                    desc_bn.strip(),
                    (desc_en or desc_bn).strip(),
                    instruction_bn.strip(),
                    (instruction_en or instruction_bn).strip(),
                    round(float(reward_per_record), 4),
                    max(1, int(min_columns)),
                    pattern_type,
                    duplicate_scope,
                    1 if smart_skip_invalid else 0,
                    now_s,
                    now_s,
                ),
            )
            fs_id = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_fs_task", "fs_task", fs_id, {"title": title_bn})
        return fs_id

    def update_fs_task(self, fs_task_id: int, updates: Dict[str, Any], admin_id: int) -> Tuple[bool, str]:
        allowed = {
            "title_bn", "title_en", "desc_bn", "desc_en", "instruction_bn", "instruction_en",
            "reward_per_record", "allowed_formats_json", "submission_mode", "delimiter",
            "min_records", "max_records", "min_columns", "pattern_type", "custom_regex",
            "duplicate_scope", "smart_skip_invalid", "daily_limit", "cooldown_sec",
            "commission_enabled", "commission_type", "commission_value", "status",
            "is_hidden", "is_archived",
        }
        clean = {k: v for k, v in updates.items() if k in allowed}
        if not clean:
            return False, "No valid fields."
        clean["updated_at"] = now_utc_iso()
        set_sql = ", ".join(f"{k}=?" for k in clean.keys())
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE fs_tasks SET {set_sql} WHERE id=?", list(clean.values()) + [int(fs_task_id)])
        self.audit.log(admin_id, "admin", "update_fs_task", "fs_task", fs_task_id, clean)
        return True, "FS Task updated."

    def upload_fs_source_file(
        self,
        fs_task_id: int,
        file_bytes: bytes,
        file_name: str,
        admin_id: int,
    ) -> Tuple[bool, str, int]:
        ok, _, data_rows, err = parse_tabular_file_bytes(file_bytes, file_name)
        if not ok:
            return False, err, 0
        DATA_DIRS["source_files"].mkdir(parents=True, exist_ok=True)
        stamp = now_dhaka().strftime("%Y%m%d_%H%M%S")
        save_path = DATA_DIRS["source_files"] / f"fs_{fs_task_id}_{stamp}_{sanitize_filename(file_name)}"
        save_path.write_bytes(file_bytes)
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            conn.execute("UPDATE fs_source_files SET is_archived=1 WHERE fs_task_id=?", (int(fs_task_id),))
            conn.execute(
                """
                INSERT INTO fs_source_files (fs_task_id, file_name, file_path, record_count, is_archived, uploaded_by, created_at)
                VALUES (?, ?, ?, ?, 0, ?, ?)
                """,
                (int(fs_task_id), file_name, str(save_path), len(data_rows), int(admin_id), now_s),
            )
        self.audit.log(admin_id, "admin", "upload_fs_source", "fs_task", fs_task_id, {"rows": len(data_rows)})
        return True, f"FS Source saved ({len(data_rows)} records; previous source archived).", len(data_rows)

    def _matches_pattern(self, first_col: str, raw_line: str, pattern_type: str, custom_regex: str) -> bool:
        target = first_col.strip() or raw_line.strip()
        if pattern_type == "email":
            return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", target))
        if pattern_type == "phone":
            return bool(re.fullmatch(r"\+?\d[\d\-\s]{7,18}", target))
        if pattern_type == "regex" and custom_regex:
            try:
                return bool(re.search(custom_regex, raw_line))
            except re.error:
                return True
        return True

    def check_user_fs_limits(self, fs_task: sqlite3.Row, user_id: int) -> Tuple[bool, str]:
        if str(fs_task["status"]) != "active":
            return False, f"FS task is currently {fs_task['status']}."
        daily_lim = int(fs_task["daily_limit"] or 0)
        if daily_lim > 0:
            dhaka_start_utc = (
                now_dhaka().replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            )
            cnt = self.db.query_one(
                "SELECT COUNT(*) AS c FROM fs_submissions WHERE fs_task_id=? AND user_id=? AND created_at>=?",
                (int(fs_task["id"]), int(user_id), dhaka_start_utc),
            )
            if cnt and int(cnt["c"]) >= daily_lim:
                return False, f"Daily FS limit reached ({daily_lim}/day)."
        cd = int(fs_task["cooldown_sec"] or 0)
        if cd > 0:
            last_s = self.db.query_one(
                "SELECT created_at FROM fs_submissions WHERE fs_task_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
                (int(fs_task["id"]), int(user_id)),
            )
            if last_s:
                last_dt = parse_iso_dt(last_s["created_at"])
                if last_dt:
                    elapsed = (now_utc() - last_dt).total_seconds()
                    if elapsed < cd:
                        return False, f"Cooldown active: wait {int(cd - elapsed)}s."
        return True, ""

    def parse_and_preview_fs_submission(
        self,
        fs_task_id: int,
        user_id: int,
        file_bytes: bytes,
        file_name: str,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        fs_task = self.get_fs_task(fs_task_id)
        if fs_task is None:
            return False, "FS Task not found.", {}
        ok_lim, err_lim = self.check_user_fs_limits(fs_task, user_id)
        if not ok_lim:
            return False, err_lim, {}

        ext = Path(file_name).suffix.lower().lstrip(".") or "text"
        allowed_fmts = [f.lower() for f in safe_json_loads(fs_task["allowed_formats_json"], ["txt", "csv", "xls", "xlsx", "text"])]
        if ext not in allowed_fmts and not (ext == "txt" and "text" in allowed_fmts):
            return False, f"Format '.{ext}' is not allowed for this FS task.", {}

        ok_p, headers, data_rows, err_p = parse_tabular_file_bytes(
            file_bytes,
            file_name,
            delimiter=str(fs_task["delimiter"] or "auto"),
        )
        if not ok_p:
            return False, err_p, {}

        min_cols = max(1, int(fs_task["min_columns"] or 1))
        pat_type = str(fs_task["pattern_type"] or "any")
        cust_rx = str(fs_task["custom_regex"] or "")
        dup_scope = str(fs_task["duplicate_scope"] or "global")
        smart_skip = int(fs_task["smart_skip_invalid"]) == 1

        if dup_scope == "per_task":
            existing_hashes = {
                str(r["record_hash"])
                for r in self.db.query_all(
                    "SELECT record_hash FROM fs_records WHERE fs_task_id=? AND status != 'rejected'",
                    (int(fs_task_id),),
                )
            }
        else:
            existing_hashes = {
                str(r["record_hash"])
                for r in self.db.query_all(
                    "SELECT record_hash FROM fs_records WHERE status != 'rejected'"
                )
            }

        batch_seen: Set[str] = set()
        valid_records: List[Dict[str, Any]] = []
        skipped_invalid = 0
        skipped_dup = 0
        first_errors: List[str] = []

        for idx, cells in enumerate(data_rows, start=1):
            non_empty_cnt = sum(1 for c in cells if c.strip())
            raw_line = " | ".join(cells)
            if non_empty_cnt < min_cols:
                skipped_invalid += 1
                if len(first_errors) < 5:
                    first_errors.append(f"Line {idx}: fewer than {min_cols} columns")
                if not smart_skip:
                    return False, f"Line {idx} failed column check (min {min_cols} columns required).", {}
                continue

            if not self._matches_pattern(cells[0] if cells else "", raw_line, pat_type, cust_rx):
                skipped_invalid += 1
                if len(first_errors) < 5:
                    first_errors.append(f"Line {idx}: pattern mismatch ({pat_type})")
                if not smart_skip:
                    return False, f"Line {idx} failed pattern validation ({pat_type}).", {}
                continue

            rec_hash = sha256_text(raw_line.lower())
            if rec_hash in existing_hashes or rec_hash in batch_seen:
                skipped_dup += 1
                if len(first_errors) < 5:
                    first_errors.append(f"Line {idx}: duplicate record")
                if not smart_skip:
                    return False, f"Line {idx} is a duplicate record.", {}
                continue

            batch_seen.add(rec_hash)
            valid_records.append(
                {
                    "line_no": idx,
                    "raw_line": raw_line,
                    "columns": cells,
                    "record_hash": rec_hash,
                }
            )

        min_rec = max(1, int(fs_task["min_records"] or 1))
        max_rec = max(min_rec, int(fs_task["max_records"] or 1000))
        if len(valid_records) < min_rec:
            return (
                False,
                f"Only {len(valid_records)} valid unique records found (minimum required: {min_rec}). Skipped invalid={skipped_invalid}, dup={skipped_dup}.",
                {},
            )
        if len(valid_records) > max_rec:
            return False, f"Too many records ({len(valid_records)}). Maximum allowed per upload: {max_rec}.", {}

        return True, "Preview ready.", {
            "fs_task_id": int(fs_task_id),
            "file_name": file_name,
            "file_hash": sha256_bytes(file_bytes),
            "total_parsed": len(data_rows),
            "valid_count": len(valid_records),
            "skipped_invalid": skipped_invalid,
            "skipped_dup": skipped_dup,
            "skipped_total": skipped_invalid + skipped_dup,
            "errors_sample": first_errors,
            "records": valid_records,
            "unit_reward": float(fs_task["reward_per_record"]),
        }

    def commit_fs_submission(
        self,
        user_row: sqlite3.Row,
        preview_data: Dict[str, Any],
        file_bytes: bytes,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        fs_task_id = int(preview_data["fs_task_id"])
        fs_task = self.get_fs_task(fs_task_id)
        if fs_task is None:
            return False, "FS task not found.", {}

        user_id = int(user_row["user_id"])
        sub_uid = generate_uid("FS", 7)
        now_s = now_utc_iso()
        DATA_DIRS["user_files"].mkdir(parents=True, exist_ok=True)
        saved_path = DATA_DIRS["user_files"] / f"{sub_uid}_{sanitize_filename(preview_data['file_name'])}"
        saved_path.write_bytes(file_bytes)

        records = preview_data["records"]
        unit_reward = float(fs_task["reward_per_record"])

        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO fs_submissions (
                    sub_uid, fs_task_id, user_id, user_full_name, user_username,
                    file_name, file_path, file_hash, total_records,
                    approved_count, rejected_count, pending_count, skipped_count,
                    reward_per_record_snapshot, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, 'pending', ?)
                """,
                (
                    sub_uid,
                    fs_task_id,
                    user_id,
                    str(user_row["full_name"] or ""),
                    str(user_row["username"] or ""),
                    preview_data["file_name"],
                    str(saved_path),
                    preview_data["file_hash"],
                    len(records),
                    len(records),
                    int(preview_data["skipped_total"]),
                    unit_reward,
                    now_s,
                ),
            )
            sub_id = int(cur.lastrowid or 0)
            for rec in records:
                rec_uid = generate_uid("FSR", 7)
                conn.execute(
                    """
                    INSERT INTO fs_records
                    (fs_submission_id, fs_task_id, user_id, line_no, stable_uid, raw_line, columns_json, record_hash, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                    """,
                    (
                        sub_id,
                        fs_task_id,
                        user_id,
                        int(rec["line_no"]),
                        rec_uid,
                        rec["raw_line"],
                        safe_json_dumps(rec["columns"]),
                        rec["record_hash"],
                    ),
                )

        return True, "File submitted successfully.", {
            "id": sub_id,
            "sub_uid": sub_uid,
            "fs_task_id": fs_task_id,
            "fs_title_bn": str(fs_task["title_bn"]),
            "fs_title_en": str(fs_task["title_en"]),
            "total_records": len(records),
            "unit_reward": unit_reward,
        }

    def update_delivery_status(
        self,
        fs_sub_id: int,
        delivery_status: str,
        channel_id: str = "",
        message_id: int = 0,
        error_text: str = "",
    ) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                UPDATE fs_submissions
                SET delivery_status=?, review_channel_id=?, review_message_id=?, delivery_error=?
                WHERE id=?
                """,
                (delivery_status, str(channel_id), int(message_id), error_text[:400], int(fs_sub_id)),
            )

    def get_submission(self, fs_sub_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM fs_submissions WHERE id=?", (int(fs_sub_id),))

    def list_pending_submissions(self, limit: int = 20, offset: int = 0) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM fs_submissions WHERE pending_count > 0 ORDER BY id ASC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    def list_failed_deliveries(self) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM fs_submissions WHERE delivery_status='failed' ORDER BY id DESC LIMIT 30"
        )

    def list_submission_records(
        self,
        fs_sub_id: int,
        status_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[sqlite3.Row]:
        if status_filter:
            return self.db.query_all(
                "SELECT * FROM fs_records WHERE fs_submission_id=? AND status=? ORDER BY line_no ASC LIMIT ? OFFSET ?",
                (int(fs_sub_id), status_filter, limit, offset),
            )
        return self.db.query_all(
            "SELECT * FROM fs_records WHERE fs_submission_id=? ORDER BY line_no ASC LIMIT ? OFFSET ?",
            (int(fs_sub_id), limit, offset),
        )

    def acquire_review_lock(self, fs_sub_id: int, admin_id: int) -> Tuple[bool, str]:
        now_dt = now_utc()
        now_s = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        with self.db.atomic(immediate=True) as conn:
            sub = conn.execute(
                "SELECT locked_by_admin, locked_at FROM fs_submissions WHERE id=?",
                (int(fs_sub_id),),
            ).fetchone()
            if sub is None:
                return False, "FS submission not found."
            locker = int(sub["locked_by_admin"] or 0)
            if locker != 0 and locker != int(admin_id):
                lock_dt = parse_iso_dt(sub["locked_at"])
                if lock_dt and (now_dt - lock_dt).total_seconds() < 600:
                    return False, f"Currently being reviewed by Admin {locker}."
            conn.execute(
                "UPDATE fs_submissions SET locked_by_admin=?, locked_at=? WHERE id=?",
                (int(admin_id), now_s, int(fs_sub_id)),
            )
        return True, ""

    def release_review_lock(self, fs_sub_id: int, admin_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE fs_submissions SET locked_by_admin=0, locked_at='' WHERE id=? AND locked_by_admin=?",
                (int(fs_sub_id), int(admin_id)),
            )

    def review_fs_records(
        self,
        fs_sub_id: int,
        record_ids: List[int],
        action: str,
        admin_id: int,
        reject_reason: str = "",
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Reviews 1, 3, 5, 7, 10, 15, 20, or All pending FS records atomically in one transaction.
        Enforces Total = Approved + Rejected + Pending invariant, atomic reward credit,
        independent FS Commission, and report_versions (PARTIAL vs FINAL).
        """
        if action not in ("approve", "reject"):
            return False, "Invalid action.", {}
        if not record_ids:
            return False, "No records selected.", {}

        ok_lock, lock_err = self.acquire_review_lock(fs_sub_id, admin_id)
        if not ok_lock:
            return False, lock_err, {}

        new_rec_status = "approved" if action == "approve" else "rejected"
        clean_reason = str(reject_reason or "").strip() if action == "reject" else ""
        if action == "reject" and not clean_reason:
            clean_reason = "Rejected by reviewer"

        now_s = now_utc_iso()
        processed = 0
        with self.db.atomic(immediate=True) as conn:
            sub = conn.execute("SELECT * FROM fs_submissions WHERE id=?", (int(fs_sub_id),)).fetchone()
            if sub is None:
                return False, "FS submission not found.", {}

            for rid in record_ids:
                upd = conn.execute(
                    """
                    UPDATE fs_records
                    SET status=?, reject_reason=?, reviewed_by=?, reviewed_at=?
                    WHERE id=? AND fs_submission_id=? AND status='pending'
                    """,
                    (new_rec_status, clean_reason, int(admin_id), now_s, int(rid), int(fs_sub_id)),
                )
                processed += int(upd.rowcount or 0)

            if processed == 0:
                return False, "Selected records were already finalized.", {}

            cnts = conn.execute(
                """
                SELECT
                    COUNT(*) AS tot,
                    SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) AS app,
                    SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS rej,
                    SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pen
                FROM fs_records WHERE fs_submission_id=?
                """,
                (int(fs_sub_id),),
            ).fetchone()

            tot = int(cnts["tot"] or 0)
            app = int(cnts["app"] or 0)
            rej = int(cnts["rej"] or 0)
            pen = int(cnts["pen"] or 0)
            if tot != app + rej + pen:
                raise RuntimeError("Invariant violation: Total != Approved + Rejected + Pending")

            unit_reward = float(sub["reward_per_record_snapshot"])
            target_total_reward = round(app * unit_reward, 4)
            already_credited = float(sub["total_reward_credited"])
            delta_reward = round(target_total_reward - already_credited, 4)

            next_ver = int(sub["current_version"] or 0) + 1
            sub_uid = str(sub["sub_uid"])
            user_id = int(sub["user_id"])

            new_user_bal = 0.0
            if delta_reward > 0:
                ok_c, msg_c, _, new_user_bal = self.reward.credit_reward(
                    user_id=user_id,
                    tx_type="file_submit_reward",
                    amount=delta_reward,
                    idempotency_key=f"fs_rew:{sub_uid}:v{next_ver}",
                    ref_id=sub_uid,
                    reason=f"FS {sub_uid} v{next_ver} ({processed} approved)",
                    wallet_bucket="earned",
                )
                if not ok_c:
                    raise ValueError(msg_c)

                # Independent FS Commission (RULE 26)
                fs_task = conn.execute("SELECT * FROM fs_tasks WHERE id=?", (int(sub["fs_task_id"]),)).fetchone()
                if (
                    fs_task
                    and int(fs_task["commission_enabled"]) == 1
                    and self.config.get_bool("fs_commission_enabled", True)
                ):
                    u_row = conn.execute("SELECT referrer_id FROM users WHERE user_id=?", (user_id,)).fetchone()
                    if u_row and u_row["referrer_id"]:
                        ref_uid = int(u_row["referrer_id"])
                        ref_u = conn.execute("SELECT status FROM users WHERE user_id=?", (ref_uid,)).fetchone()
                        if ref_u and str(ref_u["status"]) != "blocked":
                            ctype = str(fs_task["commission_type"] or self.config.get_str("fs_commission_type", "percent"))
                            cval = float(fs_task["commission_value"] or self.config.get_float("fs_commission_value", 5.0))
                            comm_amt = round(delta_reward * (cval / 100.0), 4) if ctype == "percent" else round(cval, 4)
                            if comm_amt > 0:
                                self.ledger.apply_transaction(
                                    user_id=ref_uid,
                                    tx_type="file_submit_commission",
                                    amount=comm_amt,
                                    direction="credit",
                                    wallet_bucket="earned",
                                    idempotency_key=f"fs_comm:{sub_uid}:v{next_ver}",
                                    source="fs_commission",
                                    ref_id=sub_uid,
                                    reason=f"FS Commission from {sub_uid} v{next_ver}",
                                )

            if pen == 0:
                sub_status = "approved" if app > 0 and rej == 0 else ("rejected" if app == 0 else "reviewed")
                rep_kind = "FINAL"
                fin_at = now_s
            else:
                sub_status = "partial"
                rep_kind = "PARTIAL"
                fin_at = ""

            conn.execute(
                """
                UPDATE fs_submissions
                SET approved_count=?, rejected_count=?, pending_count=?,
                    total_reward_credited=?, status=?, current_version=?,
                    locked_by_admin=0, locked_at='', finalized_at=CASE WHEN ?!='' THEN ? ELSE finalized_at END
                WHERE id=?
                """,
                (app, rej, pen, target_total_reward, sub_status, next_ver, fin_at, fin_at, int(fs_sub_id)),
            )

            rej_lines = conn.execute(
                "SELECT line_no, stable_uid, reject_reason FROM fs_records WHERE fs_submission_id=? AND status='rejected' ORDER BY line_no ASC LIMIT 15",
                (int(fs_sub_id),),
            ).fetchall()
            rej_summary = "; ".join(f"L{r['line_no']}({r['stable_uid']}): {r['reject_reason']}" for r in rej_lines)

            summary_payload = {
                "total": tot,
                "approved": app,
                "rejected": rej,
                "pending": pen,
                "delta_reward": delta_reward,
                "total_reward": target_total_reward,
                "rejected_summary": rej_summary,
            }
            conn.execute(
                """
                INSERT INTO report_versions
                (submission_type, submission_id, version_no, report_kind, summary_json, message_text, sent_to_user, created_by, created_at)
                VALUES ('fs', ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (int(fs_sub_id), next_ver, rep_kind, safe_json_dumps(summary_payload), rej_summary, int(admin_id), now_s),
            )

        self.audit.log(
            admin_id,
            "admin",
            f"fs_review_{action}",
            "fs_submission",
            fs_sub_id,
            {"processed": processed, "version": next_ver, "kind": rep_kind},
        )
        return True, f"Processed {processed} record(s) [v{next_ver} {rep_kind}].", {
            "sub_uid": sub_uid,
            "user_id": user_id,
            "version": next_ver,
            "report_kind": rep_kind,
            "processed": processed,
            "total": tot,
            "approved": app,
            "rejected": rej,
            "pending": pen,
            "delta_reward": delta_reward,
            "total_reward": target_total_reward,
            "new_balance": new_user_bal,
            "rejected_summary": rej_summary,
        }

    def correct_fs_record(
        self,
        record_id: int,
        new_status: str,
        admin_id: int,
        reason: str,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        RULE 23 / 52 / 53 Correction Workflow for already finalized FS records:
        Adjusts reward delta via Ledger and writes CORRECTION report_version.
        """
        if new_status not in ("approved", "rejected"):
            return False, "Invalid target status.", {}
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            rec = conn.execute("SELECT * FROM fs_records WHERE id=?", (int(record_id),)).fetchone()
            if rec is None:
                return False, "Record not found.", {}
            if str(rec["status"]) == new_status:
                return False, f"Record is already {new_status}.", {}

            fs_sub_id = int(rec["fs_submission_id"])
            sub = conn.execute("SELECT * FROM fs_submissions WHERE id=?", (fs_sub_id,)).fetchone()
            if sub is None:
                return False, "Parent FS submission not found.", {}

            conn.execute(
                "UPDATE fs_records SET status=?, reject_reason=?, reviewed_by=?, reviewed_at=? WHERE id=?",
                (new_status, reason if new_status == "rejected" else "", int(admin_id), now_s, int(record_id)),
            )

            cnts = conn.execute(
                """
                SELECT COUNT(*) AS tot,
                       SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) AS app,
                       SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS rej,
                       SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pen
                FROM fs_records WHERE fs_submission_id=?
                """,
                (fs_sub_id,),
            ).fetchone()
            tot = int(cnts["tot"] or 0)
            app = int(cnts["app"] or 0)
            rej = int(cnts["rej"] or 0)
            pen = int(cnts["pen"] or 0)

            unit_reward = float(sub["reward_per_record_snapshot"])
            target_total = round(app * unit_reward, 4)
            prev_total = float(sub["total_reward_credited"])
            delta = round(target_total - prev_total, 4)
            next_ver = int(sub["current_version"] or 0) + 1
            sub_uid = str(sub["sub_uid"])
            user_id = int(sub["user_id"])

            if delta > 0:
                self.ledger.apply_transaction(
                    user_id=user_id,
                    tx_type="correction",
                    amount=delta,
                    direction="credit",
                    wallet_bucket="earned",
                    idempotency_key=f"fs_corr:{sub_uid}:v{next_ver}",
                    source="fs_correction",
                    ref_id=sub_uid,
                    admin_id=admin_id,
                    reason=f"FS Correction + ({reason})",
                )
            elif delta < 0:
                self.ledger.apply_transaction(
                    user_id=user_id,
                    tx_type="correction",
                    amount=abs(delta),
                    direction="debit",
                    wallet_bucket="earned",
                    idempotency_key=f"fs_corr:{sub_uid}:v{next_ver}",
                    source="fs_correction",
                    ref_id=sub_uid,
                    admin_id=admin_id,
                    reason=f"FS Correction - ({reason})",
                    allow_negative=True,
                )

            conn.execute(
                """
                UPDATE fs_submissions
                SET approved_count=?, rejected_count=?, pending_count=?, total_reward_credited=?, current_version=?
                WHERE id=?
                """,
                (app, rej, pen, target_total, next_ver, fs_sub_id),
            )
            summary = {"total": tot, "approved": app, "rejected": rej, "pending": pen, "delta": delta, "reason": reason}
            conn.execute(
                """
                INSERT INTO report_versions
                (submission_type, submission_id, version_no, report_kind, summary_json, message_text, sent_to_user, created_by, created_at)
                VALUES ('fs', ?, ?, 'CORRECTION', ?, ?, 0, ?, ?)
                """,
                (fs_sub_id, next_ver, safe_json_dumps(summary), reason, int(admin_id), now_s),
            )
        self.audit.log(admin_id, "admin", "correct_fs_record", "fs_record", record_id, {"new_status": new_status, "delta": delta})
        return True, f"Corrected record #{record_id} -> {new_status} (v{next_ver}).", {
            "user_id": user_id,
            "sub_uid": sub_uid,
            "version": next_ver,
            "delta": delta,
        }

    # --- Reject Templates CRUD ---

    def list_reject_templates(self, scope: Optional[str] = None, active_only: bool = True) -> List[sqlite3.Row]:
        clauses: List[str] = []
        params: List[Any] = []
        if active_only:
            clauses.append("is_active=1 AND is_hidden=0")
        if scope:
            clauses.append("(scope=? OR scope='all')")
            params.append(scope)
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM reject_templates {where_sql} ORDER BY sort_order, id", params)

    def add_reject_template(self, scope: str, title_bn: str, title_en: str, reason_bn: str, reason_en: str) -> int:
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO reject_templates (scope, title_bn, title_en, reason_bn, reason_en, is_active, is_hidden, created_at)
                VALUES (?, ?, ?, ?, ?, 1, 0, ?)
                """,
                (scope, title_bn.strip(), title_en.strip(), reason_bn.strip(), reason_en.strip(), now_utc_iso()),
            )
            return int(cur.lastrowid or 0)

    def delete_reject_template(self, tpl_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute("DELETE FROM reject_templates WHERE id=?", (int(tpl_id),))
# ==============================================================================
# DIGITAL PRODUCT STORE MANAGER (RULE 74, 84, 93)
# ==============================================================================

class StoreManager:
    """
    Full-featured Digital Product Store:
    - Categories & Products CRUD, Clone, Archive, ON/OFF & Hide/Unhide
    - 20+ Dynamic Per-Product Input Steps
    - Line-by-line Stock Upload with Duplicate Filtering & Auto-Pause/Resume
    - Bulk Price Tiers, Promo Coupons, Eligibility Rules & Concurrent Checkout Lock
    - Instant (.txt + message) vs Manual Approval Orders, Warranty & Stock Notify
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        ledger: LedgerManager,
        excel: ExcelManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.ledger = ledger
        self.excel = excel

    # --- Categories ---

    def create_category(self, name_bn: str, name_en: str = "", emoji: str = "🛍️", desc_bn: str = "", admin_id: int = 0) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO store_categories (name_bn, name_en, emoji, desc_bn, desc_en, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name_bn.strip(), (name_en or name_bn).strip(), emoji.strip() or "🛍️", desc_bn.strip(), desc_bn.strip(), now_s),
            )
            cid = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_store_category", "store_category", cid)
        return cid

    def list_categories(self, active_only: bool = False, include_archived: bool = False) -> List[sqlite3.Row]:
        clauses: List[str] = []
        if not include_archived:
            clauses.append("is_archived=0")
        if active_only:
            clauses.append("is_active=1 AND is_hidden=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM store_categories {where_sql} ORDER BY sort_order ASC, id ASC")

    def toggle_category_flag(self, cat_id: int, field: str) -> Tuple[bool, int]:
        if field not in ("is_active", "is_hidden", "is_archived"):
            return False, 0
        row = self.db.query_one("SELECT * FROM store_categories WHERE id=?", (int(cat_id),))
        if row is None:
            return False, 0
        new_val = 0 if int(row[field]) == 1 else 1
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE store_categories SET {field}=? WHERE id=?", (new_val, int(cat_id)))
        return True, new_val

    # --- Products ---

    def create_product(
        self,
        category_id: int,
        name_bn: str,
        name_en: str,
        price: float,
        desc_bn: str = "",
        desc_en: str = "",
        wallet_mode: str = "any",
        delivery_mode: str = "instant",
        warranty_hours: int = 0,
        admin_id: int = 0,
    ) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO store_products (
                    category_id, name_bn, name_en, desc_bn, desc_en, price,
                    wallet_mode, delivery_mode, warranty_hours, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(category_id),
                    name_bn.strip(),
                    (name_en or name_bn).strip(),
                    desc_bn.strip(),
                    (desc_en or desc_bn).strip(),
                    round(float(price), 4),
                    wallet_mode if wallet_mode in ("deposit_only", "any") else "any",
                    delivery_mode if delivery_mode in ("instant", "manual") else "instant",
                    max(0, int(warranty_hours)),
                    now_s,
                    now_s,
                ),
            )
            pid = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_product", "store_product", pid, {"name": name_bn})
        return pid

    def get_product(self, product_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM store_products WHERE id=?", (int(product_id),))

    def list_products(
        self,
        category_id: Optional[int] = None,
        active_only: bool = False,
        include_archived: bool = False,
    ) -> List[sqlite3.Row]:
        clauses: List[str] = []
        params: List[Any] = []
        if not include_archived:
            clauses.append("is_archived=0")
        if category_id is not None:
            clauses.append("category_id=?")
            params.append(int(category_id))
        if active_only:
            clauses.append("is_active=1 AND is_hidden=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM store_products {where_sql} ORDER BY sort_order ASC, id DESC", params)

    def update_product(self, product_id: int, updates: Dict[str, Any], admin_id: int) -> Tuple[bool, str]:
        allowed = {
            "category_id", "name_bn", "name_en", "desc_bn", "desc_en", "instruction_bn", "instruction_en",
            "price", "min_qty", "max_qty", "daily_limit", "lifetime_limit", "cooldown_sec",
            "wallet_mode", "delivery_mode", "min_approved_tasks", "min_deposit_total", "min_vip_tier",
            "warranty_hours", "low_stock_threshold", "auto_pause_on_empty", "auto_resume_on_stock",
            "payout_post_enabled", "payout_mask_buyer", "is_active", "is_hidden", "is_archived",
        }
        clean = {k: v for k, v in updates.items() if k in allowed}
        if not clean:
            return False, "No valid fields."
        clean["updated_at"] = now_utc_iso()
        set_sql = ", ".join(f"{k}=?" for k in clean.keys())
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE store_products SET {set_sql} WHERE id=?", list(clean.values()) + [int(product_id)])
        self.audit.log(admin_id, "admin", "update_product", "store_product", product_id, clean)
        return True, "Product updated."

    def clone_product(self, product_id: int, admin_id: int) -> Tuple[bool, str, int]:
        src = self.get_product(product_id)
        if src is None:
            return False, "Product not found.", 0
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO store_products (
                    category_id, name_bn, name_en, desc_bn, desc_en, instruction_bn, instruction_en,
                    price, min_qty, max_qty, daily_limit, lifetime_limit, cooldown_sec,
                    wallet_mode, delivery_mode, min_approved_tasks, min_deposit_total, min_vip_tier,
                    warranty_hours, low_stock_threshold, auto_pause_on_empty, auto_resume_on_stock,
                    payout_post_enabled, payout_mask_buyer, is_active, is_hidden, is_archived, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
                """,
                (
                    src["category_id"], f"{src['name_bn']} (কপি)", f"{src['name_en']} (Copy)",
                    src["desc_bn"], src["desc_en"], src["instruction_bn"], src["instruction_en"],
                    src["price"], src["min_qty"], src["max_qty"], src["daily_limit"], src["lifetime_limit"],
                    src["cooldown_sec"], src["wallet_mode"], src["delivery_mode"], src["min_approved_tasks"],
                    src["min_deposit_total"], src["min_vip_tier"], src["warranty_hours"], src["low_stock_threshold"],
                    src["auto_pause_on_empty"], src["auto_resume_on_stock"], src["payout_post_enabled"],
                    src["payout_mask_buyer"], now_s, now_s,
                ),
            )
            new_pid = int(cur.lastrowid or 0)
            for st in conn.execute("SELECT * FROM store_product_steps WHERE product_id=? ORDER BY step_order", (int(product_id),)).fetchall():
                conn.execute(
                    """
                    INSERT INTO store_product_steps (product_id, step_order, title_bn, title_en, instruction_bn, instruction_en, input_type, options_json, is_required, is_enabled, is_hidden, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (new_pid, st["step_order"], st["title_bn"], st["title_en"], st["instruction_bn"], st["instruction_en"], st["input_type"], st["options_json"], st["is_required"], st["is_enabled"], st["is_hidden"], now_s),
                )
            for tr in conn.execute("SELECT * FROM store_price_tiers WHERE product_id=?", (int(product_id),)).fetchall():
                conn.execute(
                    "INSERT INTO store_price_tiers (product_id, min_qty, unit_price, is_active, created_at) VALUES (?, ?, ?, ?, ?)",
                    (new_pid, tr["min_qty"], tr["unit_price"], tr["is_active"], now_s),
                )
        self.audit.log(admin_id, "admin", "clone_product", "store_product", product_id, {"new_product_id": new_pid})
        return True, f"Cloned as Product #{new_pid} (Inactive).", new_pid

    # --- 20+ Dynamic Product Steps ---

    def add_product_step(
        self,
        product_id: int,
        title_bn: str,
        title_en: str = "",
        instruction_bn: str = "",
        input_type: str = "text",
        is_required: bool = True,
    ) -> int:
        max_r = self.db.query_one("SELECT COALESCE(MAX(step_order), 0) AS m FROM store_product_steps WHERE product_id=?", (int(product_id),))
        next_ord = (int(max_r["m"]) if max_r else 0) + 1
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO store_product_steps
                (product_id, step_order, title_bn, title_en, instruction_bn, instruction_en, input_type, is_required, is_enabled, is_hidden, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
                """,
                (int(product_id), next_ord, title_bn.strip(), (title_en or title_bn).strip(), instruction_bn.strip(), instruction_bn.strip(), input_type, 1 if is_required else 0, now_utc_iso()),
            )
            return int(cur.lastrowid or 0)

    def list_product_steps(self, product_id: int, active_only: bool = False) -> List[sqlite3.Row]:
        extra = "AND is_enabled=1 AND is_hidden=0" if active_only else ""
        return self.db.query_all(
            f"SELECT * FROM store_product_steps WHERE product_id=? {extra} ORDER BY step_order ASC, id ASC",
            (int(product_id),),
        )

    def toggle_product_step(self, step_id: int, field: str) -> Tuple[bool, int]:
        if field not in ("is_enabled", "is_hidden", "is_required"):
            return False, 0
        r = self.db.query_one("SELECT * FROM store_product_steps WHERE id=?", (int(step_id),))
        if not r:
            return False, 0
        nv = 0 if int(r[field]) == 1 else 1
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE store_product_steps SET {field}=? WHERE id=?", (nv, int(step_id)))
        return True, nv

    def delete_product_step(self, step_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute("DELETE FROM store_product_steps WHERE id=?", (int(step_id),))

    # --- Stock Upload & Auto-Pause / Auto-Resume ---

    def get_stock_counts(self, product_id: int) -> Dict[str, int]:
        rows = self.db.query_all(
            "SELECT status, COUNT(*) AS c FROM product_stock_items WHERE product_id=? GROUP BY status",
            (int(product_id),),
        )
        res = {"available": 0, "sold": 0}
        for r in rows:
            res[str(r["status"])] = int(r["c"])
        res["total"] = res["available"] + res["sold"]
        return res

    def upload_product_stock(
        self,
        product_id: int,
        file_bytes: bytes,
        file_name: str,
        admin_id: int,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        prod = self.get_product(product_id)
        if prod is None:
            return False, "Product not found.", {}

        ok, _, data_rows, err = parse_tabular_file_bytes(file_bytes, file_name, delimiter="")
        if not ok:
            return False, err, {}

        DATA_DIRS["product_stock"].mkdir(parents=True, exist_ok=True)
        stamp = now_dhaka().strftime("%Y%m%d_%H%M%S")
        save_path = DATA_DIRS["product_stock"] / f"prod_{product_id}_{stamp}_{sanitize_filename(file_name)}"
        save_path.write_bytes(file_bytes)

        added = 0
        dups = 0
        now_s = now_utc_iso()
        notify_user_ids: List[int] = []
        auto_resumed = False

        with self.db.atomic(immediate=True) as conn:
            existing_hashes = {
                str(r["item_hash"])
                for r in conn.execute(
                    "SELECT item_hash FROM product_stock_items WHERE product_id=?",
                    (int(product_id),),
                ).fetchall()
            }
            for row_cells in data_rows:
                line = " | ".join(c for c in row_cells if c.strip()) if len(row_cells) > 1 else (row_cells[0] if row_cells else "")
                line = line.strip()
                if not line:
                    continue
                ihash = sha256_text(line)
                if ihash in existing_hashes:
                    dups += 1
                    continue
                existing_hashes.add(ihash)
                conn.execute(
                    """
                    INSERT INTO product_stock_items (product_id, item_line, item_hash, status, created_at)
                    VALUES (?, ?, ?, 'available', ?)
                    """,
                    (int(product_id), line, ihash, now_s),
                )
                added += 1

            if added > 0:
                if int(prod["is_active"]) == 0 and int(prod["auto_resume_on_stock"]) == 1 and int(prod["is_archived"]) == 0:
                    conn.execute("UPDATE store_products SET is_active=1, updated_at=? WHERE id=?", (now_s, int(product_id)))
                    auto_resumed = True
                waiters = conn.execute(
                    "SELECT user_id FROM store_stock_notify WHERE product_id=? AND notified=0",
                    (int(product_id),),
                ).fetchall()
                notify_user_ids = [int(w["user_id"]) for w in waiters]
                if notify_user_ids:
                    conn.execute(
                        "UPDATE store_stock_notify SET notified=1, notified_at=? WHERE product_id=? AND notified=0",
                        (now_s, int(product_id)),
                    )

        self.audit.log(admin_id, "admin", "upload_store_stock", "store_product", product_id, {"added": added, "dups": dups})
        return True, f"Stock added: {added} lines ({dups} duplicates skipped).", {
            "added": added,
            "duplicates": dups,
            "auto_resumed": auto_resumed,
            "notify_user_ids": notify_user_ids,
        }

    # --- Price Tiers & Coupons ---

    def add_price_tier(self, product_id: int, min_qty: int, unit_price: float) -> int:
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                "INSERT INTO store_price_tiers (product_id, min_qty, unit_price, is_active, created_at) VALUES (?, ?, ?, 1, ?)",
                (int(product_id), max(2, int(min_qty)), round(float(unit_price), 4), now_utc_iso()),
            )
            return int(cur.lastrowid or 0)

    def list_price_tiers(self, product_id: int) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM store_price_tiers WHERE product_id=? AND is_active=1 ORDER BY min_qty ASC",
            (int(product_id),),
        )

    def get_effective_unit_price(self, product: sqlite3.Row, qty: int) -> float:
        base = float(product["price"])
        tiers = self.list_price_tiers(int(product["id"]))
        for t in tiers:
            if qty >= int(t["min_qty"]):
                base = float(t["unit_price"])
        return round(base, 4)

    def create_coupon(
        self,
        code: str,
        discount_type: str,
        discount_value: float,
        max_uses: int = 0,
        per_user_limit: int = 1,
        min_order_amount: float = 0.0,
        product_id: int = 0,
        expires_at: str = "",
    ) -> Tuple[bool, str]:
        cleaned = code.strip().upper()
        if not cleaned:
            return False, "Coupon code cannot be empty."
        try:
            with self.db.atomic(immediate=True) as conn:
                conn.execute(
                    """
                    INSERT INTO store_coupons (code, discount_type, discount_value, max_uses, per_user_limit, min_order_amount, product_id, expires_at, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (
                        cleaned,
                        discount_type if discount_type in ("percent", "fixed") else "percent",
                        round(float(discount_value), 4),
                        int(max_uses),
                        max(1, int(per_user_limit)),
                        round(float(min_order_amount), 4),
                        int(product_id),
                        expires_at,
                        now_utc_iso(),
                    ),
                )
            return True, f"Coupon {cleaned} created."
        except sqlite3.IntegrityError:
            return False, "Coupon code already exists."

    def list_coupons(self) -> List[sqlite3.Row]:
        return self.db.query_all("SELECT * FROM store_coupons ORDER BY id DESC")

    def validate_coupon(self, code: str, product_id: int, user_id: int, subtotal: float) -> Tuple[bool, str, float]:
        cleaned = code.strip().upper()
        cp = self.db.query_one("SELECT * FROM store_coupons WHERE code=? AND is_active=1", (cleaned,))
        if cp is None:
            return False, "Invalid or inactive coupon code.", 0.0
        if int(cp["product_id"]) != 0 and int(cp["product_id"]) != int(product_id):
            return False, "Coupon is not valid for this product.", 0.0
        exp_dt = parse_iso_dt(cp["expires_at"])
        if exp_dt and now_utc() > exp_dt:
            return False, "Coupon has expired.", 0.0
        if int(cp["max_uses"]) > 0 and int(cp["used_count"]) >= int(cp["max_uses"]):
            return False, "Coupon usage limit reached.", 0.0
        if float(subtotal) < float(cp["min_order_amount"]):
            return False, f"Minimum order amount for this coupon is {format_money(cp['min_order_amount'])}.", 0.0
        u_used = self.db.query_one(
            "SELECT COUNT(*) AS c FROM store_orders WHERE user_id=? AND coupon_code=? AND status != 'rejected'",
            (int(user_id), cleaned),
        )
        if u_used and int(u_used["c"]) >= int(cp["per_user_limit"]):
            return False, "You have already used this coupon.", 0.0
        if str(cp["discount_type"]) == "percent":
            disc = round(subtotal * (float(cp["discount_value"]) / 100.0), 4)
        else:
            disc = round(float(cp["discount_value"]), 4)
        disc = min(subtotal, max(0.0, disc))
        return True, f"Coupon applied (-{format_money(disc)})", disc

    # --- Eligibility & Atomic Checkout ---

    def check_order_eligibility(self, product: sqlite3.Row, user_row: sqlite3.Row, qty: int) -> Tuple[bool, str]:
        pid = int(product["id"])
        uid = int(user_row["user_id"])
        if int(product["is_active"]) != 1 or int(product["is_archived"]) == 1:
            return False, "This product is currently unavailable."
        if qty < int(product["min_qty"]) or qty > int(product["max_qty"]):
            return False, f"Quantity must be between {product['min_qty']} and {product['max_qty']}."

        req_tasks = int(product["min_approved_tasks"] or 0)
        if req_tasks > 0:
            c = self.db.query_one("SELECT COUNT(*) AS c FROM task_submissions WHERE user_id=? AND status='approved'", (uid,))
            if (int(c["c"]) if c else 0) < req_tasks:
                return False, f"Requires at least {req_tasks} approved tasks."

        req_dep = float(product["min_deposit_total"] or 0.0)
        if req_dep > 0:
            d = self.db.query_one("SELECT COALESCE(SUM(net_credit),0) AS s FROM deposits WHERE user_id=? AND status='approved'", (uid,))
            if (float(d["s"]) if d else 0.0) < req_dep:
                return False, f"Requires at least {format_money(req_dep)} total deposits."

        req_tier = str(product["min_vip_tier"] or "Bronze")
        if VIP_TIER_RANK.get(str(user_row["vip_tier"]), 1) < VIP_TIER_RANK.get(req_tier, 1):
            return False, f"Requires {req_tier} tier or higher."

        daily_lim = int(product["daily_limit"] or 0)
        if daily_lim > 0:
            dhaka_start = now_dhaka().replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            cnt = self.db.query_one(
                "SELECT COALESCE(SUM(qty),0) AS q FROM store_orders WHERE product_id=? AND user_id=? AND created_at>=? AND status != 'rejected'",
                (pid, uid, dhaka_start),
            )
            if (int(cnt["q"]) if cnt else 0) + qty > daily_lim:
                return False, f"Daily buy limit exceeded ({daily_lim}/day)."

        life_lim = int(product["lifetime_limit"] or 0)
        if life_lim > 0:
            cnt_l = self.db.query_one(
                "SELECT COALESCE(SUM(qty),0) AS q FROM store_orders WHERE product_id=? AND user_id=? AND status != 'rejected'",
                (pid, uid),
            )
            if (int(cnt_l["q"]) if cnt_l else 0) + qty > life_lim:
                return False, f"Lifetime buy limit exceeded ({life_lim})."

        cd = int(product["cooldown_sec"] or 0)
        if cd > 0:
            last_o = self.db.query_one(
                "SELECT created_at FROM store_orders WHERE product_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
                (pid, uid),
            )
            if last_o:
                ldt = parse_iso_dt(last_o["created_at"])
                if ldt and (now_utc() - ldt).total_seconds() < cd:
                    return False, f"Cooldown active: wait {int(cd - (now_utc() - ldt).total_seconds())}s."
        return True, ""

    def checkout_order(
        self,
        product_id: int,
        user_row: sqlite3.Row,
        qty: int,
        coupon_code: str = "",
        step_answers: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        prod = self.get_product(product_id)
        if prod is None:
            return False, "Product not found.", {}
        ok_el, err_el = self.check_order_eligibility(prod, user_row, qty)
        if not ok_el:
            return False, err_el, {}

        user_id = int(user_row["user_id"])
        unit_price = self.get_effective_unit_price(prod, qty)
        subtotal = round(unit_price * qty, 4)
        discount = 0.0
        applied_coupon = ""
        if coupon_code.strip():
            ok_c, err_c, disc = self.validate_coupon(coupon_code, product_id, user_id, subtotal)
            if not ok_c:
                return False, err_c, {}
            discount = disc
            applied_coupon = coupon_code.strip().upper()

        total_paid = round(max(0.0, subtotal - discount), 4)
        order_uid = generate_uid("ORD", 7)
        now_dt = now_utc()
        now_s = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        war_hrs = int(prod["warranty_hours"] or 0)
        war_exp = (now_dt + timedelta(hours=war_hrs)).strftime("%Y-%m-%d %H:%M:%S") if war_hrs > 0 else ""
        delivery_mode = str(prod["delivery_mode"] or "instant")

        delivered_lines: List[str] = []
        delivery_file_path = ""
        low_stock_alert = False
        rem_stock = 0

        with self.db.atomic(immediate=True) as conn:
            if delivery_mode == "instant":
                items = conn.execute(
                    "SELECT id, item_line FROM product_stock_items WHERE product_id=? AND status='available' ORDER BY id ASC LIMIT ?",
                    (int(product_id), int(qty)),
                ).fetchall()
                if len(items) < qty:
                    if len(items) == 0 and int(prod["auto_pause_on_empty"]) == 1:
                        conn.execute("UPDATE store_products SET is_active=0, updated_at=? WHERE id=?", (now_s, int(product_id)))
                    return False, f"Insufficient stock (Available: {len(items)}).", {}
                item_ids = [int(it["id"]) for it in items]
                delivered_lines = [str(it["item_line"]) for it in items]
            else:
                item_ids = []

            ok_pay, msg_pay, bucket_used = self.ledger.spend_for_service(
                user_id=user_id,
                amount=total_paid,
                wallet_mode=str(prod["wallet_mode"] or "any"),
                tx_type="product_purchase",
                ref_id=order_uid,
                reason=f"Purchase {prod['name_en']} x{qty} ({order_uid})",
            )
            if not ok_pay:
                return False, msg_pay, {}

            if applied_coupon:
                conn.execute("UPDATE store_coupons SET used_count = used_count + 1 WHERE code=?", (applied_coupon,))

            status = "completed" if delivery_mode == "instant" else "pending_approval"
            comp_at = now_s if delivery_mode == "instant" else ""
            if delivered_lines:
                DATA_DIRS["exports"].mkdir(parents=True, exist_ok=True)
                fpath = DATA_DIRS["exports"] / f"{order_uid}.txt"
                fpath.write_text("\n".join(delivered_lines) + "\n", encoding="utf-8")
                delivery_file_path = str(fpath)

            cur = conn.execute(
                """
                INSERT INTO store_orders (
                    order_uid, product_id, user_id, qty, unit_price_snapshot, discount_amount,
                    total_paid, wallet_bucket_used, coupon_code, step_answers_json, delivered_lines_json,
                    delivery_file_path, status, warranty_expires_at, created_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    order_uid,
                    int(product_id),
                    user_id,
                    int(qty),
                    unit_price,
                    discount,
                    total_paid,
                    bucket_used,
                    applied_coupon,
                    safe_json_dumps(step_answers or []),
                    safe_json_dumps(delivered_lines),
                    delivery_file_path,
                    status,
                    war_exp,
                    now_s,
                    comp_at,
                ),
            )
            order_id = int(cur.lastrowid or 0)

            for iid in item_ids:
                upd = conn.execute(
                    "UPDATE product_stock_items SET status='sold', order_id=?, buyer_id=?, sold_at=? WHERE id=? AND status='available'",
                    (order_id, user_id, now_s, iid),
                )
                if int(upd.rowcount or 0) != 1:
                    raise RuntimeError("Concurrent stock collision during checkout.")

            rem_row = conn.execute(
                "SELECT COUNT(*) AS c FROM product_stock_items WHERE product_id=? AND status='available'",
                (int(product_id),),
            ).fetchone()
            rem_stock = int(rem_row["c"]) if rem_row else 0
            if delivery_mode == "instant":
                low_th = int(prod["low_stock_threshold"] or self.config.get_int("low_stock_threshold", 5))
                low_stock_alert = self.config.get_bool("low_stock_alert_enabled", True) and rem_stock <= low_th
                if rem_stock == 0 and int(prod["auto_pause_on_empty"]) == 1:
                    conn.execute("UPDATE store_products SET is_active=0, updated_at=? WHERE id=?", (now_s, int(product_id)))

        return True, "Order completed!" if delivery_mode == "instant" else "Order submitted for admin approval.", {
            "order_id": order_id,
            "order_uid": order_uid,
            "product": dict(prod),
            "qty": qty,
            "unit_price": unit_price,
            "discount": discount,
            "total_paid": total_paid,
            "bucket_used": bucket_used,
            "status": status,
            "delivered_lines": delivered_lines,
            "delivery_file_path": delivery_file_path,
            "warranty_hours": war_hrs,
            "remaining_stock": rem_stock,
            "low_stock_alert": low_stock_alert,
        }

    def approve_manual_order(self, order_id: int, admin_id: int, delivered_text: str = "") -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            ord_row = conn.execute("SELECT * FROM store_orders WHERE id=?", (int(order_id),)).fetchone()
            if ord_row is None:
                return False, "Order not found.", {}
            if str(ord_row["status"]) != "pending_approval":
                return False, f"Already {ord_row['status']}.", {}
            lines = [ln.strip() for ln in delivered_text.splitlines() if ln.strip()]
            fpath = ""
            if lines:
                DATA_DIRS["exports"].mkdir(parents=True, exist_ok=True)
                p = DATA_DIRS["exports"] / f"{ord_row['order_uid']}.txt"
                p.write_text("\n".join(lines) + "\n", encoding="utf-8")
                fpath = str(p)
            conn.execute(
                """
                UPDATE store_orders
                SET status='completed', delivered_lines_json=?, delivery_file_path=?, reviewed_by=?, completed_at=?
                WHERE id=?
                """,
                (safe_json_dumps(lines), fpath, int(admin_id), now_s, int(order_id)),
            )
        self.audit.log(admin_id, "admin", "approve_manual_order", "store_order", order_id)
        return True, "Manual order approved & delivered.", {"order": dict(ord_row), "lines": lines, "file_path": fpath}

    def reject_manual_order(self, order_id: int, admin_id: int, reason: str = "Rejected") -> Tuple[bool, str]:
        with self.db.atomic(immediate=True) as conn:
            ord_row = conn.execute("SELECT * FROM store_orders WHERE id=?", (int(order_id),)).fetchone()
            if ord_row is None:
                return False, "Order not found."
            if str(ord_row["status"]) != "pending_approval":
                return False, f"Already {ord_row['status']}."
            conn.execute(
                "UPDATE store_orders SET status='rejected', reviewed_by=? WHERE id=?",
                (int(admin_id), int(order_id)),
            )
            amt = float(ord_row["total_paid"])
            if amt > 0:
                bucket = "deposit" if "deposit" in str(ord_row["wallet_bucket_used"]) else "earned"
                self.ledger.apply_transaction(
                    user_id=int(ord_row["user_id"]),
                    tx_type="order_refund",
                    amount=amt,
                    direction="credit",
                    wallet_bucket=bucket,
                    idempotency_key=f"ord_ref:{ord_row['order_uid']}",
                    source="store_refund",
                    ref_id=str(ord_row["order_uid"]),
                    admin_id=admin_id,
                    reason=f"Order rejected: {reason}",
                )
        self.audit.log(admin_id, "admin", "reject_manual_order", "store_order", order_id, {"reason": reason})
        return True, "Order rejected & refunded."

    def subscribe_stock_notify(self, product_id: int, user_id: int) -> Tuple[bool, str]:
        existing = self.db.query_one(
            "SELECT id FROM store_stock_notify WHERE product_id=? AND user_id=? AND notified=0",
            (int(product_id), int(user_id)),
        )
        if existing:
            return True, "You are already subscribed for restock notification."
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "INSERT INTO store_stock_notify (product_id, user_id, notified, created_at) VALUES (?, ?, 0, ?)",
                (int(product_id), int(user_id), now_utc_iso()),
            )
        return True, "Restock notification enabled! We will alert you when stock arrives."

    def create_warranty_request(self, order_id: int, user_id: int, reason: str, proof_file_id: str = "") -> Tuple[bool, str, str]:
        ord_row = self.db.query_one("SELECT * FROM store_orders WHERE id=? AND user_id=?", (int(order_id), int(user_id)))
        if ord_row is None:
            return False, "Order not found.", ""
        if str(ord_row["status"]) != "completed":
            return False, "Warranty is only available on completed orders.", ""
        w_exp = parse_iso_dt(ord_row["warranty_expires_at"])
        if not w_exp or now_utc() > w_exp:
            return False, "Warranty period has expired or this product has no warranty.", ""
        existing = self.db.query_one(
            "SELECT warranty_uid FROM store_warranty_requests WHERE order_id=? AND status='pending'",
            (int(order_id),),
        )
        if existing:
            return False, f"A pending warranty request ({existing['warranty_uid']}) already exists.", ""
        w_uid = generate_uid("WAR", 6)
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO store_warranty_requests (warranty_uid, order_id, user_id, reason, proof_file_id, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (w_uid, int(order_id), int(user_id), reason.strip(), proof_file_id, now_utc_iso()),
            )
        return True, f"Warranty request {w_uid} submitted.", w_uid

    def resolve_warranty_request(
        self,
        warranty_id: int,
        action: str,
        admin_id: int,
        note: str = "",
        replace_qty: int = 1,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        if action not in ("replace", "refund", "reject"):
            return False, "Invalid warranty action.", {}
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            wr = conn.execute("SELECT * FROM store_warranty_requests WHERE id=?", (int(warranty_id),)).fetchone()
            if wr is None or str(wr["status"]) != "pending":
                return False, "Warranty request not found or already resolved.", {}
            ord_row = conn.execute("SELECT * FROM store_orders WHERE id=?", (int(wr["order_id"]),)).fetchone()
            if ord_row is None:
                return False, "Order missing.", {}

            rep_lines: List[str] = []
            ref_amt = 0.0
            if action == "replace":
                items = conn.execute(
                    "SELECT id, item_line FROM product_stock_items WHERE product_id=? AND status='available' ORDER BY id ASC LIMIT ?",
                    (int(ord_row["product_id"]), max(1, int(replace_qty))),
                ).fetchall()
                if not items:
                    return False, "No available stock lines for replacement.", {}
                for it in items:
                    conn.execute(
                        "UPDATE product_stock_items SET status='sold', order_id=?, buyer_id=?, sold_at=? WHERE id=?",
                        (int(ord_row["id"]), int(wr["user_id"]), now_s, int(it["id"])),
                    )
                    rep_lines.append(str(it["item_line"]))
            elif action == "refund":
                ref_amt = float(ord_row["total_paid"])
                bucket = "deposit" if "deposit" in str(ord_row["wallet_bucket_used"]) else "earned"
                self.ledger.apply_transaction(
                    user_id=int(wr["user_id"]),
                    tx_type="order_refund",
                    amount=ref_amt,
                    direction="credit",
                    wallet_bucket=bucket,
                    idempotency_key=f"war_ref:{wr['warranty_uid']}",
                    source="warranty_refund",
                    ref_id=str(wr["warranty_uid"]),
                    admin_id=admin_id,
                    reason=f"Warranty refund: {note}",
                )

            conn.execute(
                """
                UPDATE store_warranty_requests
                SET status=?, resolution_note=?, replacement_lines_json=?, refund_amount=?, admin_id=?, resolved_at=?
                WHERE id=?
                """,
                (action + "d" if action != "replace" else "replaced", note, safe_json_dumps(rep_lines), ref_amt, int(admin_id), now_s, int(warranty_id)),
            )
        self.audit.log(admin_id, "admin", f"warranty_{action}", "store_warranty", warranty_id)
        return True, f"Warranty resolved ({action}).", {
            "user_id": int(wr["user_id"]),
            "warranty_uid": str(wr["warranty_uid"]),
            "order_uid": str(ord_row["order_uid"]),
            "replacement_lines": rep_lines,
            "refund_amount": ref_amt,
        }

    def export_completed_orders(self, file_format: str = "xlsx", admin_id: int = 0) -> Tuple[bool, str, Optional[Path]]:
        rows = self.db.query_all(
            """
            SELECT o.*, p.name_en AS product_name, u.username, u.full_name
            FROM store_orders o
            LEFT JOIN store_products p ON p.id = o.product_id
            LEFT JOIN users u ON u.user_id = o.user_id
            ORDER BY o.id DESC
            """
        )
        if not rows:
            return False, "No orders to export.", None
        headers = ["Order_UID", "Product", "User_ID", "Full_Name", "Username", "Qty", "Total_Paid", "Coupon", "Wallet", "Status", "Created_Dhaka"]
        data = [
            [
                r["order_uid"],
                r["product_name"] or r["product_id"],
                int(r["user_id"]),
                r["full_name"] or "",
                f"@{r['username']}" if r["username"] else "",
                int(r["qty"]),
                float(r["total_paid"]),
                r["coupon_code"],
                r["wallet_bucket_used"],
                r["status"],
                format_dhaka_dt(r["created_at"]),
            ]
            for r in rows
        ]
        path, _ = self.excel.export_rows(headers, data, "Store_Orders", "all", file_format, "Orders", admin_id)
        return True, f"Exported {len(rows)} orders.", path
# ==============================================================================
# OTP RECEIVER MANAGER & HTTP SMS WEBHOOK RECEIVER (RULE 81, 82, 84, 86)
# ==============================================================================

def normalize_phone_digits(raw_phone: str) -> str:
    cleaned = re.sub(r"[^\d+]", "", str(raw_phone or "").strip())
    return cleaned.lstrip("+")


class OTPManager:
    """
    Multi-Country OTP Receiver:
    - Country CRUD & Live Stock Counts
    - Atomic 1/2/3/N number allocation (BEGIN IMMEDIATE) + Anti-Hoarding
    - 4 SMS Bridges (Relay Channel, Webhook, Provider API Polling, Quick-Push)
    - Smart Regex OTP Extraction, SMS Hash Deduplication, Multi-OTP, Swap & Auto-Refund
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        ledger: LedgerManager,
        excel: ExcelManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.ledger = ledger
        self.excel = excel
        self._cancel_stamps: Dict[int, float] = {}

    # --- Countries ---

    def create_country(
        self,
        name_bn: str,
        name_en: str,
        flag_emoji: str = "🏳️",
        country_code: str = "+1",
        numbers_per_click: int = 1,
        fee_amount: float = 0.0,
        wait_timeout_sec: int = 300,
        admin_id: int = 0,
    ) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO otp_countries (
                    name_bn, name_en, flag_emoji, country_code, numbers_per_click,
                    fee_amount, wait_timeout_sec, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name_bn.strip(),
                    (name_en or name_bn).strip(),
                    flag_emoji.strip() or "🏳️",
                    country_code.strip() or "+",
                    max(1, int(numbers_per_click)),
                    round(float(fee_amount), 4),
                    max(30, int(wait_timeout_sec)),
                    now_s,
                ),
            )
            cid = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_otp_country", "otp_country", cid)
        return cid

    def get_country(self, country_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM otp_countries WHERE id=?", (int(country_id),))

    def list_countries(self, active_only: bool = False, include_archived: bool = False) -> List[sqlite3.Row]:
        clauses: List[str] = []
        if not include_archived:
            clauses.append("is_archived=0")
        if active_only:
            clauses.append("is_active=1 AND is_hidden=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM otp_countries {where_sql} ORDER BY sort_order ASC, id ASC")

    def update_country(self, country_id: int, updates: Dict[str, Any], admin_id: int) -> Tuple[bool, str]:
        allowed = {
            "name_bn", "name_en", "flag_emoji", "country_code", "numbers_per_click",
            "fee_amount", "wait_timeout_sec", "service_filter", "multi_otp_enabled",
            "max_swaps_per_session", "recycle_after_hours", "burn_after_use",
            "auto_pause_on_empty", "auto_resume_on_stock", "low_stock_threshold",
            "is_active", "is_hidden", "is_archived",
        }
        clean = {k: v for k, v in updates.items() if k in allowed}
        if not clean:
            return False, "No valid country fields."
        set_sql = ", ".join(f"{k}=?" for k in clean.keys())
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE otp_countries SET {set_sql} WHERE id=?", list(clean.values()) + [int(country_id)])
        self.audit.log(admin_id, "admin", "update_otp_country", "otp_country", country_id, clean)
        return True, "Country updated."

    def get_country_stock_counts(self, country_id: int) -> Dict[str, int]:
        rows = self.db.query_all(
            "SELECT status, COUNT(*) AS c FROM otp_numbers WHERE country_id=? GROUP BY status",
            (int(country_id),),
        )
        res = {"available": 0, "assigned": 0, "burned": 0}
        for r in rows:
            res[str(r["status"])] = int(r["c"])
        res["total"] = res["available"] + res["assigned"] + res["burned"]
        return res

    # --- Number Upload & Auto-Resume ---

    def upload_country_numbers(
        self,
        country_id: int,
        file_bytes: bytes,
        file_name: str,
        admin_id: int,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        country = self.get_country(country_id)
        if country is None:
            return False, "Country not found.", {}

        ok, _, data_rows, err = parse_tabular_file_bytes(file_bytes, file_name, delimiter="")
        if not ok:
            return False, err, {}

        DATA_DIRS["otp_numbers"].mkdir(parents=True, exist_ok=True)
        stamp = now_dhaka().strftime("%Y%m%d_%H%M%S")
        save_path = DATA_DIRS["otp_numbers"] / f"otp_c{country_id}_{stamp}_{sanitize_filename(file_name)}"
        save_path.write_bytes(file_bytes)

        added = 0
        dups = 0
        now_s = now_utc_iso()
        auto_resumed = False

        with self.db.atomic(immediate=True) as conn:
            existing = {
                str(r["phone_normalized"])
                for r in conn.execute(
                    "SELECT phone_normalized FROM otp_numbers WHERE country_id=?",
                    (int(country_id),),
                ).fetchall()
            }
            for row_cells in data_rows:
                raw_num = str(row_cells[0] if row_cells else "").strip()
                if not raw_num:
                    continue
                norm = normalize_phone_digits(raw_num)
                if len(norm) < 6:
                    continue
                if norm in existing:
                    dups += 1
                    continue
                existing.add(norm)
                display_num = raw_num if raw_num.startswith("+") else ("+" + norm)
                conn.execute(
                    """
                    INSERT INTO otp_numbers (country_id, phone_number, phone_normalized, status, created_at)
                    VALUES (?, ?, ?, 'available', ?)
                    """,
                    (int(country_id), display_num, norm, now_s),
                )
                added += 1

            if added > 0 and int(country["is_active"]) == 0 and int(country["auto_resume_on_stock"]) == 1 and int(country["is_archived"]) == 0:
                conn.execute("UPDATE otp_countries SET is_active=1 WHERE id=?", (int(country_id),))
                auto_resumed = True

        self.audit.log(admin_id, "admin", "upload_otp_numbers", "otp_country", country_id, {"added": added, "dups": dups})
        return True, f"Added {added} numbers ({dups} duplicates skipped).", {
            "added": added,
            "duplicates": dups,
            "auto_resumed": auto_resumed,
        }

    # --- Atomic 1/2/3/N Allocation ---

    def allocate_numbers_for_user(
        self,
        country_id: int,
        user_id: int,
        service_name: str = "Any",
    ) -> Tuple[bool, str, Dict[str, Any]]:
        country = self.get_country(country_id)
        if country is None or int(country["is_active"]) != 1 or int(country["is_archived"]) == 1:
            return False, "This country is currently out of stock or unavailable.", {}

        # Anti-Hoarding checks
        max_active = max(1, self.config.get_int("otp_max_active_per_user", 3))
        active_row = self.db.query_one(
            "SELECT COUNT(*) AS c FROM otp_sessions WHERE user_id=? AND status IN ('waiting','received')",
            (int(user_id),),
        )
        if active_row and int(active_row["c"]) >= max_active:
            return False, f"Anti-Hoarding: you already have {max_active} active OTP session(s). Complete or cancel one first.", {}

        cd_sec = self.config.get_int("otp_cancel_cooldown_sec", 30)
        last_cancel = self._cancel_stamps.get(int(user_id))
        if cd_sec > 0 and last_cancel and (time.time() - last_cancel) < cd_sec:
            rem_cd = int(cd_sec - (time.time() - last_cancel))
            return False, f"Please wait {rem_cd}s after cancelling before requesting a new number.", {}

        qty = max(1, int(country["numbers_per_click"] or 1))
        fee = float(country["fee_amount"] or 0.0)
        timeout_sec = max(30, int(country["wait_timeout_sec"] or 300))
        now_dt = now_utc()
        now_s = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        exp_s = (now_dt + timedelta(seconds=timeout_sec)).strftime("%Y-%m-%d %H:%M:%S")
        otp_uid = generate_uid("OTP", 7)

        with self.db.atomic(immediate=True) as conn:
            nums = conn.execute(
                "SELECT id, phone_number FROM otp_numbers WHERE country_id=? AND status='available' ORDER BY id ASC LIMIT ?",
                (int(country_id), qty),
            ).fetchall()
            if len(nums) < qty:
                if len(nums) == 0 and int(country["auto_pause_on_empty"]) == 1:
                    conn.execute("UPDATE otp_countries SET is_active=0 WHERE id=?", (int(country_id),))
                return False, f"Insufficient numbers available (Needed {qty}, Available {len(nums)}).", {}

            wallet_bucket = "free"
            if fee > 0:
                ok_pay, msg_pay, wallet_bucket = self.ledger.spend_for_service(
                    user_id=user_id,
                    amount=fee,
                    wallet_mode="any",
                    tx_type="otp_fee",
                    ref_id=otp_uid,
                    reason=f"OTP number allocation {otp_uid}",
                )
                if not ok_pay:
                    return False, msg_pay, {}

            phone_ids = [int(n["id"]) for n in nums]
            phone_strs = [str(n["phone_number"]) for n in nums]
            cur = conn.execute(
                """
                INSERT INTO otp_sessions (
                    otp_uid, country_id, user_id, phone_ids_json, phone_numbers_json,
                    fee_paid_snapshot, wallet_bucket, service_name, status, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?)
                """,
                (
                    otp_uid,
                    int(country_id),
                    int(user_id),
                    safe_json_dumps(phone_ids),
                    safe_json_dumps(phone_strs),
                    fee,
                    wallet_bucket,
                    service_name or str(country["service_filter"] or "Any"),
                    exp_s,
                    now_s,
                ),
            )
            sess_id = int(cur.lastrowid or 0)
            for pid in phone_ids:
                upd = conn.execute(
                    "UPDATE otp_numbers SET status='assigned', assigned_to=?, session_id=?, assigned_at=? WHERE id=? AND status='available'",
                    (int(user_id), sess_id, now_s, pid),
                )
                if int(upd.rowcount or 0) != 1:
                    raise RuntimeError("Concurrent OTP number allocation conflict.")

            rem_row = conn.execute(
                "SELECT COUNT(*) AS c FROM otp_numbers WHERE country_id=? AND status='available'",
                (int(country_id),),
            ).fetchone()
            rem_cnt = int(rem_row["c"]) if rem_row else 0
            low_th = int(country["low_stock_threshold"] or self.config.get_int("low_stock_threshold", 5))
            low_alert = self.config.get_bool("low_stock_alert_enabled", True) and rem_cnt <= low_th
            if rem_cnt == 0 and int(country["auto_pause_on_empty"]) == 1:
                conn.execute("UPDATE otp_countries SET is_active=0 WHERE id=?", (int(country_id),))

        return True, "Number(s) allocated.", {
            "session_id": sess_id,
            "otp_uid": otp_uid,
            "country": dict(country),
            "numbers": phone_strs,
            "fee": fee,
            "wait_timeout_sec": timeout_sec,
            "expires_at": exp_s,
            "remaining_stock": rem_cnt,
            "low_stock_alert": low_alert,
        }

    # --- Smart Regex Extraction & 4-Bridge SMS Ingestion ---

    def extract_otp_code(self, raw_sms: str) -> str:
        text = str(raw_sms or "").strip()
        pattern = self.config.get_str("otp_regex", r"(?<!\d)(\d{3}-\d{3}|\d{4,8})(?!\d)")
        try:
            m = re.search(pattern, text)
            if m:
                code = m.group(1) if m.groups() else m.group(0)
                return code.strip()
        except re.error:
            pass
        fallback = re.search(r"(?<!\d)(\d{4,8})(?!\d)", text)
        return fallback.group(1) if fallback else ""

    def ingest_sms(
        self,
        phone_number: str,
        raw_sms: str,
        bridge_source: str = "manual",
        explicit_code: str = "",
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Matches incoming SMS from any of the 4 bridges against an active OTP session,
        deduplicates by SMS hash, extracts OTP code, and returns notification payload.
        """
        norm_phone = normalize_phone_digits(phone_number)
        if len(norm_phone) < 6:
            return False, "Invalid phone number.", {}

        extracted = explicit_code.strip() or self.extract_otp_code(raw_sms)
        now_dt = now_utc()
        now_s = now_dt.strftime("%Y-%m-%d %H:%M:%S")

        with self.db.atomic(immediate=True) as conn:
            num_row = conn.execute(
                """
                SELECT n.*, s.id AS sess_id, s.otp_uid, s.user_id, s.status AS sess_status,
                       s.expires_at, s.country_id, c.name_bn, c.name_en, c.flag_emoji,
                       c.multi_otp_enabled, c.burn_after_use, c.recycle_after_hours
                FROM otp_numbers n
                JOIN otp_sessions s ON s.id = n.session_id
                JOIN otp_countries c ON c.id = n.country_id
                WHERE (n.phone_normalized=? OR n.phone_normalized LIKE ?)
                  AND n.status='assigned'
                  AND s.status IN ('waiting', 'received')
                ORDER BY s.id DESC LIMIT 1
                """,
                (norm_phone, f"%{norm_phone[-8:]}"),
            ).fetchone()
            if num_row is None:
                return False, "No active waiting OTP session matched this phone number.", {}

            sess_id = int(num_row["sess_id"])
            sms_hash = sha256_text(f"{sess_id}:{raw_sms.strip()}:{extracted}")
            dup_sms = conn.execute(
                "SELECT id FROM otp_sms_logs WHERE session_id=? AND sms_hash=?",
                (sess_id, sms_hash),
            ).fetchone()
            if dup_sms is not None:
                return False, "Duplicate SMS ignored (hash deduplication).", {}

            conn.execute(
                """
                INSERT INTO otp_sms_logs
                (session_id, country_id, user_id, phone_number, bridge_source, raw_sms, extracted_code, sms_hash, pushed_to_user, posted_to_channel, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?)
                """,
                (
                    sess_id,
                    int(num_row["country_id"]),
                    int(num_row["user_id"]),
                    str(num_row["phone_number"]),
                    bridge_source,
                    raw_sms.strip(),
                    extracted,
                    sms_hash,
                    now_s,
                ),
            )

            multi_on = int(num_row["multi_otp_enabled"]) == 1
            new_sess_status = "received" if multi_on else "completed"
            closed_at = "" if multi_on else now_s
            conn.execute(
                """
                UPDATE otp_sessions
                SET otp_received_count = otp_received_count + 1,
                    last_otp_code = ?,
                    status = ?,
                    closed_at = ?
                WHERE id = ?
                """,
                (extracted, new_sess_status, closed_at, sess_id),
            )

            if not multi_on:
                burn = int(num_row["burn_after_use"]) == 1
                rec_hrs = int(num_row["recycle_after_hours"] or 0)
                rec_at = (now_dt + timedelta(hours=rec_hrs)).strftime("%Y-%m-%d %H:%M:%S") if (not burn and rec_hrs > 0) else ""
                conn.execute(
                    "UPDATE otp_numbers SET status='burned', burned_at=?, recycle_available_at=? WHERE session_id=?",
                    (now_s, rec_at, sess_id),
                )

        return True, "OTP matched & logged.", {
            "session_id": sess_id,
            "otp_uid": str(num_row["otp_uid"]),
            "user_id": int(num_row["user_id"]),
            "phone_number": str(num_row["phone_number"]),
            "otp_code": extracted or "N/A",
            "raw_sms": raw_sms.strip(),
            "country_flag": str(num_row["flag_emoji"]),
            "country_name": str(num_row["name_en"]),
            "multi_otp": bool(num_row["multi_otp_enabled"]),
        }

    def parse_relay_message_and_ingest(self, text: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Bridge 1 helper: extracts phone number & SMS body from relay channel message."""
        candidates = re.findall(r"\+?\d[\d\-\s]{7,16}\d", str(text or ""))
        for cand in candidates:
            ok, msg, payload = self.ingest_sms(cand, text, bridge_source="relay_channel")
            if ok:
                return True, msg, payload
        return False, "No active session matched relay message.", {}

    async def poll_provider_api(self) -> List[Dict[str, Any]]:
        """Bridge 3: Polls external Provider API using httpx if enabled."""
        if not self.config.get_bool("otp_provider_api_enabled", False):
            return []
        url = self.config.get_str("otp_provider_api_url", "").strip()
        api_key = self.config.get_str("otp_provider_api_key", "").strip()
        if not url:
            return []
        SECRET_FILTER.register_secret(api_key)

        ingested: List[Dict[str, Any]] = []
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    return []
                data = resp.json()
                items = data if isinstance(data, list) else data.get("messages", data.get("data", []))
                if not isinstance(items, list):
                    return []
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    phone = str(it.get("phone") or it.get("number") or it.get("to") or "")
                    sms = str(it.get("sms") or it.get("text") or it.get("message") or "")
                    code = str(it.get("code") or it.get("otp") or "")
                    if phone and (sms or code):
                        ok, _, payload = self.ingest_sms(phone, sms or f"OTP: {code}", bridge_source="provider_api", explicit_code=code)
                        if ok:
                            ingested.append(payload)
        except Exception as exc:
            LOGGER.warning("OTP Provider API polling error: %s", exc)
        return ingested

    # --- Dead Swap, Cancel, Timeout Auto-Refund & Recycle ---

    def swap_dead_number(self, session_id: int, user_id: int) -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            sess = conn.execute("SELECT * FROM otp_sessions WHERE id=? AND user_id=?", (int(session_id), int(user_id))).fetchone()
            if sess is None or str(sess["status"]) != "waiting":
                return False, "Session is not active or already received OTP.", {}
            if int(sess["otp_received_count"]) > 0:
                return False, "Cannot swap after OTP has already been received.", {}
            country = conn.execute("SELECT * FROM otp_countries WHERE id=?", (int(sess["country_id"]),)).fetchone()
            if country is None:
                return False, "Country not found.", {}
            max_swaps = int(country["max_swaps_per_session"] or 0)
            if int(sess["swap_count"]) >= max_swaps:
                return False, f"Maximum swap limit reached ({max_swaps}).", {}

            qty = max(1, int(country["numbers_per_click"] or 1))
            fresh = conn.execute(
                "SELECT id, phone_number FROM otp_numbers WHERE country_id=? AND status='available' ORDER BY id ASC LIMIT ?",
                (int(country["id"]), qty),
            ).fetchall()
            if len(fresh) < qty:
                return False, "No spare numbers available to swap right now.", {}

            # Burn old numbers
            conn.execute(
                "UPDATE otp_numbers SET status='burned', burned_at=? WHERE session_id=?",
                (now_s, int(session_id)),
            )
            new_ids = [int(n["id"]) for n in fresh]
            new_strs = [str(n["phone_number"]) for n in fresh]
            for pid in new_ids:
                conn.execute(
                    "UPDATE otp_numbers SET status='assigned', assigned_to=?, session_id=?, assigned_at=? WHERE id=?",
                    (int(user_id), int(session_id), now_s, pid),
                )
            conn.execute(
                """
                UPDATE otp_sessions
                SET phone_ids_json=?, phone_numbers_json=?, swap_count = swap_count + 1
                WHERE id=?
                """,
                (safe_json_dumps(new_ids), safe_json_dumps(new_strs), int(session_id)),
            )
        return True, "Swapped with fresh number(s).", {"numbers": new_strs, "otp_uid": str(sess["otp_uid"])}

    def cancel_session(self, session_id: int, user_id: int) -> Tuple[bool, str, float]:
        now_s = now_utc_iso()
        refund_amt = 0.0
        with self.db.atomic(immediate=True) as conn:
            sess = conn.execute("SELECT * FROM otp_sessions WHERE id=? AND user_id=?", (int(session_id), int(user_id))).fetchone()
            if sess is None:
                return False, "OTP session not found.", 0.0
            if str(sess["status"]) not in ("waiting", "received"):
                return False, "Session already closed.", 0.0
            if int(sess["otp_received_count"]) > 0:
                conn.execute("UPDATE otp_sessions SET status='completed', closed_at=? WHERE id=?", (now_s, int(session_id)))
                return True, "Session closed (OTP already received).", 0.0

            conn.execute("UPDATE otp_sessions SET status='cancelled', closed_at=? WHERE id=?", (now_s, int(session_id)))
            conn.execute(
                "UPDATE otp_numbers SET status='available', assigned_to=NULL, session_id=NULL, assigned_at='' WHERE session_id=?",
                (int(session_id),),
            )
            fee = float(sess["fee_paid_snapshot"] or 0.0)
            if fee > 0:
                bucket = "deposit" if "deposit" in str(sess["wallet_bucket"]) else "earned"
                self.ledger.apply_transaction(
                    user_id=user_id,
                    tx_type="otp_refund",
                    amount=fee,
                    direction="credit",
                    wallet_bucket=bucket,
                    idempotency_key=f"otp_cancel_ref:{sess['otp_uid']}",
                    source="otp_cancel",
                    ref_id=str(sess["otp_uid"]),
                    reason=f"OTP session {sess['otp_uid']} cancelled",
                )
                refund_amt = fee
        self._cancel_stamps[int(user_id)] = time.time()
        return True, "Session cancelled & refunded.", refund_amt

    def process_expired_sessions_and_recycles(self) -> List[Dict[str, Any]]:
        now_s = now_utc_iso()
        expired_refunds: List[Dict[str, Any]] = []
        with self.db.atomic(immediate=True) as conn:
            rows = conn.execute(
                "SELECT * FROM otp_sessions WHERE status IN ('waiting','received') AND expires_at < ?",
                (now_s,),
            ).fetchall()
            for sess in rows:
                sid = int(sess["id"])
                uid = int(sess["user_id"])
                otp_uid = str(sess["otp_uid"])
                got_cnt = int(sess["otp_received_count"] or 0)
                if got_cnt > 0:
                    conn.execute("UPDATE otp_sessions SET status='completed', closed_at=? WHERE id=?", (now_s, sid))
                    conn.execute("UPDATE otp_numbers SET status='burned', burned_at=? WHERE session_id=?", (now_s, sid))
                else:
                    conn.execute("UPDATE otp_sessions SET status='expired', closed_at=? WHERE id=?", (now_s, sid))
                    conn.execute(
                        "UPDATE otp_numbers SET status='available', assigned_to=NULL, session_id=NULL, assigned_at='' WHERE session_id=?",
                        (sid,),
                    )
                    fee = float(sess["fee_paid_snapshot"] or 0.0)
                    if fee > 0:
                        bucket = "deposit" if "deposit" in str(sess["wallet_bucket"]) else "earned"
                        self.ledger.apply_transaction(
                            user_id=uid,
                            tx_type="otp_refund",
                            amount=fee,
                            direction="credit",
                            wallet_bucket=bucket,
                            idempotency_key=f"otp_exp_ref:{otp_uid}",
                            source="otp_timeout",
                            ref_id=otp_uid,
                            reason=f"OTP timeout auto-refund ({otp_uid})",
                        )
                    expired_refunds.append({"user_id": uid, "otp_uid": otp_uid, "refund_amount": fee})

            # Recycle numbers whose cooldown passed
            conn.execute(
                """
                UPDATE otp_numbers
                SET status='available', assigned_to=NULL, session_id=NULL, assigned_at='', burned_at='', recycle_available_at=''
                WHERE status='burned' AND recycle_available_at != '' AND recycle_available_at < ?
                """,
                (now_s,),
            )
        return expired_refunds

    def get_session_messages(self, session_id: int) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM otp_sms_logs WHERE session_id=? ORDER BY id DESC",
            (int(session_id),),
        )

    def get_session(self, session_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM otp_sessions WHERE id=?", (int(session_id),))

    def export_otp_logs(self, file_format: str = "xlsx", admin_id: int = 0) -> Tuple[bool, str, Optional[Path]]:
        rows = self.db.query_all(
            """
            SELECT l.*, c.name_en AS country_name, s.otp_uid
            FROM otp_sms_logs l
            LEFT JOIN otp_countries c ON c.id = l.country_id
            LEFT JOIN otp_sessions s ON s.id = l.session_id
            ORDER BY l.id DESC
            """
        )
        if not rows:
            return False, "No OTP SMS logs to export.", None
        headers = ["OTP_UID", "Country", "User_ID", "Phone_Number", "Extracted_Code", "Bridge", "Raw_SMS", "Received_Dhaka"]
        data = [
            [
                r["otp_uid"] or "",
                r["country_name"] or "",
                int(r["user_id"]),
                r["phone_number"],
                r["extracted_code"],
                r["bridge_source"],
                r["raw_sms"],
                format_dhaka_dt(r["created_at"]),
            ]
            for r in rows
        ]
        path, _ = self.excel.export_rows(headers, data, "OTP_Logs", "all", file_format, "OTP_Logs", admin_id)
        return True, f"Exported {len(rows)} OTP logs.", path


class SMSWebhookReceiver:
    """
    Bridge 2: Optional background HTTP server for GSM/SMS-Forwarder webhooks.
    Note: On GSMApps Android Hosting without a Public IP/Tunnel, Relay Channel /
    Provider API / Admin Quick-Push work seamlessly without inbound ports.
    """

    def __init__(
        self,
        otp_mgr: OTPManager,
        config: ConfigManager,
        on_otp_matched: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.otp_mgr = otp_mgr
        self.config = config
        self.on_otp_matched = on_otp_matched
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> Tuple[bool, str]:
        if not self.config.get_bool("otp_webhook_bridge_enabled", False):
            return False, "Webhook bridge disabled in settings."
        if self._server is not None:
            return True, "Already running."
        port = max(1024, min(65535, self.config.get_int("otp_webhook_port", 8089)))
        otp_mgr = self.otp_mgr
        cfg = self.config
        callback = self.on_otp_matched

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                if self.path.rstrip("/") not in ("/sms", "/otp", ""):
                    self.send_response(404)
                    self.end_headers()
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(min(length, 65536)).decode("utf-8", errors="replace")
                    payload = safe_json_loads(body, {})
                    expected_secret = cfg.get_str("otp_webhook_secret", "").strip()
                    provided_secret = str(self.headers.get("X-Webhook-Secret", payload.get("secret", ""))).strip()
                    if expected_secret and not hmac.compare_digest(expected_secret, provided_secret):
                        self.send_response(403)
                        self.end_headers()
                        self.wfile.write(b'{"ok":false,"error":"forbidden"}')
                        return
                    phone = str(payload.get("phone") or payload.get("number") or "")
                    sms = str(payload.get("sms") or payload.get("message") or payload.get("text") or "")
                    ok, msg, matched = otp_mgr.ingest_sms(phone, sms, bridge_source="webhook")
                    if ok and callback is not None:
                        callback(matched)
                    resp_code = 200 if ok else 404
                    self.send_response(resp_code)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(safe_json_dumps({"ok": ok, "message": msg}).encode("utf-8"))
                except Exception as exc:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(safe_json_dumps({"ok": False, "error": str(exc)}).encode("utf-8"))

        try:
            self._server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            return True, f"SMS Webhook listening on port {port}."
        except Exception as exc:
            self._server = None
            return False, f"Failed to bind webhook port {port}: {exc}"

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
# ==============================================================================
# DEPOSIT MANAGER (CLASSIC PIPELINE + HYBRID OCR STRICT TXID MATCH)
# ==============================================================================

class DepositManager:
    """
    Handles Deposit Methods CRUD, Hybrid OCR (Cloud API via httpx + Local Tesseract),
    Strict TxID Mismatch Auto-Reject, Duplicate TxID/Hash Block, Bonus/Charge & Auto-Review.
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        security: SecurityManager,
        ledger: LedgerManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.security = security
        self.ledger = ledger

    # --- Deposit Methods CRUD ---

    def list_methods(self, active_only: bool = False, include_archived: bool = False) -> List[sqlite3.Row]:
        clauses: List[str] = []
        if not include_archived:
            clauses.append("is_archived=0")
        if active_only:
            clauses.append("is_active=1 AND is_hidden=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM deposit_methods {where_sql} ORDER BY sort_order ASC, id ASC")

    def get_method(self, method_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM deposit_methods WHERE id=?", (int(method_id),))

    def create_method(
        self,
        name_bn: str,
        name_en: str,
        account_number: str,
        method_type: str = "mobile_banking",
        min_amount: float = 20.0,
        max_amount: float = 25000.0,
        bonus_percent: float = 0.0,
        charge_percent: float = 0.0,
        instruction_bn: str = "",
        instruction_en: str = "",
        admin_id: int = 0,
    ) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO deposit_methods (
                    name_bn, name_en, method_type, account_number, min_amount, max_amount,
                    bonus_percent, charge_percent, instruction_bn, instruction_en, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name_bn.strip(),
                    (name_en or name_bn).strip(),
                    method_type,
                    account_number.strip(),
                    round(float(min_amount), 4),
                    round(float(max_amount), 4),
                    round(float(bonus_percent), 4),
                    round(float(charge_percent), 4),
                    instruction_bn.strip(),
                    (instruction_en or instruction_bn).strip(),
                    now_s,
                ),
            )
            mid = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_deposit_method", "deposit_method", mid)
        return mid

    def update_method(self, method_id: int, updates: Dict[str, Any], admin_id: int) -> Tuple[bool, str]:
        allowed = {
            "name_bn", "name_en", "method_type", "account_number", "account_label",
            "network_info", "account_holder_type", "min_amount", "max_amount",
            "bonus_percent", "charge_percent", "require_amount", "require_sender",
            "require_txid", "require_screenshot", "custom_fields_json",
            "instruction_bn", "instruction_en", "auto_approve_enabled", "auto_approve_sec",
            "auto_reject_enabled", "auto_reject_sec", "proof_auto_reject_enabled",
            "is_active", "is_hidden", "is_archived",
        }
        clean = {k: v for k, v in updates.items() if k in allowed}
        if not clean:
            return False, "No valid deposit method fields."
        set_sql = ", ".join(f"{k}=?" for k in clean.keys())
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE deposit_methods SET {set_sql} WHERE id=?", list(clean.values()) + [int(method_id)])
        self.audit.log(admin_id, "admin", "update_deposit_method", "deposit_method", method_id, clean)
        return True, "Deposit method updated."

    # --- Hybrid OCR Engine (Cloud HTTP OCR API + Local Tesseract Auto-Detect) ---

    async def run_ocr_on_image_bytes(self, img_bytes: bytes) -> Tuple[str, str, str]:
        """
        Extracts text & candidate TxID from a payment screenshot.
        Returns: (ocr_status, raw_text, extracted_txid)
        ocr_status in {'matched_ready', 'no_text', 'no_txid_found', 'ocr_unavailable'}
        """
        if not self.config.get_bool("ocr_enabled", True) or not img_bytes:
            return "ocr_unavailable", "", ""

        raw_text = ""
        api_url = self.config.get_str("ocr_cloud_api_url", "").strip()
        api_key = self.config.get_str("ocr_cloud_api_key", "").strip()
        if api_key:
            SECRET_FILTER.register_secret(api_key)

        # 1. Try Cloud HTTP OCR API if configured
        if api_url:
            try:
                async with httpx.AsyncClient(timeout=18.0) as client:
                    headers = {"apikey": api_key, "Authorization": f"Bearer {api_key}"} if api_key else {}
                    files = {"file": ("receipt.jpg", img_bytes, "image/jpeg")}
                    resp = await client.post(api_url, headers=headers, files=files)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict):
                            if "ParsedResults" in data and isinstance(data["ParsedResults"], list):
                                raw_text = "\n".join(str(x.get("ParsedText", "")) for x in data["ParsedResults"] if isinstance(x, dict))
                            elif "text" in data:
                                raw_text = str(data["text"])
                            elif "result" in data:
                                raw_text = str(data["result"])
            except Exception as exc:
                LOGGER.warning("Cloud OCR API failed: %s", exc)

        # 2. Fallback to Local Tesseract if installed
        if not raw_text.strip():
            tess_bin = shutil.which("tesseract")
            if tess_bin:
                tmp_path = None
                try:
                    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tf:
                        tf.write(img_bytes)
                        tmp_path = tf.name
                    proc = await asyncio.create_subprocess_exec(
                        tess_bin,
                        tmp_path,
                        "stdout",
                        "--psm",
                        "6",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
                    raw_text = stdout_b.decode("utf-8", errors="replace")
                except Exception as exc:
                    LOGGER.warning("Local Tesseract OCR failed: %s", exc)
                finally:
                    if tmp_path and os.path.exists(tmp_path):
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass

        if not raw_text.strip():
            status = "no_text" if (api_url or shutil.which("tesseract")) else "ocr_unavailable"
            return status, "", ""

        tx_regex = self.config.get_str("ocr_txid_regex", r"\b[A-Z0-9]{8,20}\b")
        extracted_txid = self.extract_txid_from_text(raw_text, tx_regex)
        if not extracted_txid:
            return "no_txid_found", raw_text.strip(), ""
        return "matched_ready", raw_text.strip(), extracted_txid

    @staticmethod
    def extract_txid_from_text(raw_text: str, tx_regex: str) -> str:
        text = str(raw_text or "").upper()
        # Priority 1: explicit label near TxID / TrxID / Transaction ID
        lbl_m = re.search(
            r"(?:TRX\s*ID|TXN\s*ID|TX\s*ID|TRANSACTION\s*ID|REF(?:ERENCE)?\s*NO?)\s*[:#\-]?\s*([A-Z0-9\-]{6,26})",
            text,
        )
        if lbl_m:
            cand = re.sub(r"[^A-Z0-9]", "", lbl_m.group(1))
            if len(cand) >= 6:
                return cand
        # Priority 2: Admin-configured regex requiring mix of digits/letters or length >= 8
        try:
            candidates = re.findall(tx_regex, text)
            for c in candidates:
                cs = c if isinstance(c, str) else c[0]
                cs_clean = re.sub(r"[^A-Z0-9]", "", cs)
                if len(cs_clean) >= 8 and any(ch.isdigit() for ch in cs_clean):
                    return cs_clean
        except re.error:
            pass
        return ""

    def calculate_net_credit(self, method: sqlite3.Row, amount: float) -> Tuple[float, float, float]:
        amt = round(float(amount), 4)
        bonus_pct = max(0.0, float(method["bonus_percent"] or 0.0))
        charge_pct = max(0.0, float(method["charge_percent"] or 0.0))
        bonus_amt = round(amt * (bonus_pct / 100.0), 4)
        charge_amt = round(amt * (charge_pct / 100.0), 4)
        net_credit = round(max(0.0, amt + bonus_amt - charge_amt), 4)
        return bonus_amt, charge_amt, net_credit

    def _compute_auto_review_schedule(self, method: sqlite3.Row, net_credit: float) -> Tuple[str, str]:
        if self.security.is_panic_frozen():
            return "manual", ""
        cap = self.config.get_float("deposit_max_auto_cap", 5000.0)
        m_app = int(method["auto_approve_enabled"]) == 1
        g_app = self.config.get_bool("deposit_auto_approve_global", False)
        if (m_app or g_app) and (cap <= 0 or net_credit <= cap):
            delay = int(method["auto_approve_sec"] or 0) if m_app else self.config.get_int("deposit_auto_approve_sec", 60)
            delay = max(5, delay)
            return "auto_approve", (now_utc() + timedelta(seconds=delay)).strftime("%Y-%m-%d %H:%M:%S")

        m_rej = int(method["auto_reject_enabled"]) == 1
        g_rej = self.config.get_bool("deposit_auto_reject_global", False)
        if m_rej or g_rej:
            delay = int(method["auto_reject_sec"] or 0) if m_rej else self.config.get_int("deposit_auto_reject_sec", 300)
            delay = max(5, delay)
            return "auto_reject", (now_utc() + timedelta(seconds=delay)).strftime("%Y-%m-%d %H:%M:%S")
        return "manual", ""

    async def submit_deposit(
        self,
        method_id: int,
        user_row: sqlite3.Row,
        amount: float,
        sender_number: str = "",
        txid_user: str = "",
        screenshot_file_id: str = "",
        screenshot_unique_id: str = "",
        screenshot_bytes: bytes = b"",
        custom_answers: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Full dual deposit submission:
        1. Validates method limits & required proofs (auto-rejecting missing proof if enabled).
        2. Blocks duplicate TxID / screenshot hash (RULE 77.1).
        3. Runs Hybrid OCR on screenshot bytes; if OCR TxID mismatches user TxID and strict mode is ON,
           IMMEDIATELY rejects (REJECTED_TXID_MISMATCH) without entering pending queue!
        """
        method = self.get_method(method_id)
        if method is None or int(method["is_active"]) != 1 or int(method["is_archived"]) == 1:
            return False, "Deposit method is not available.", {}

        amt = round(float(amount), 4)
        if amt < float(method["min_amount"]) or amt > float(method["max_amount"]):
            return False, f"Amount must be between {format_money(method['min_amount'])} and {format_money(method['max_amount'])}.", {}

        user_id = int(user_row["user_id"])
        tx_clean = re.sub(r"[^A-Z0-9\-]", "", str(txid_user or "").strip().upper())
        img_sha = sha256_bytes(screenshot_bytes) if screenshot_bytes else ""
        deposit_uid = generate_uid("DEP", 7)
        now_s = now_utc_iso()

        # Check mandatory proof fields (RULE 78.2)
        proof_auto_rej = int(method["proof_auto_reject_enabled"]) == 1 or self.config.get_bool("deposit_proof_auto_reject", True)
        if int(method["require_txid"]) == 1 and not tx_clean:
            if proof_auto_rej:
                return False, "Auto-Rejected: Transaction ID is required.", {"auto_rejected": True, "reason": "Missing TxID"}
            return False, "Transaction ID is required.", {}
        if int(method["require_screenshot"]) == 1 and not screenshot_file_id:
            if proof_auto_rej:
                return False, "Auto-Rejected: Payment screenshot is required.", {"auto_rejected": True, "reason": "Missing Screenshot"}
            return False, "Payment screenshot is required.", {}

        # Duplicate TxID & Screenshot Hash Check (RULE 77.1)
        is_dup, dup_msg = self.security.is_duplicate_deposit_proof(tx_clean, screenshot_unique_id, img_sha)
        if is_dup:
            return False, f"Auto-Rejected ({dup_msg})", {"auto_rejected": True, "reason": dup_msg}

        bonus_amt, charge_amt, net_credit = self.calculate_net_credit(method, amt)

        # Hybrid OCR Extraction & Strict Match
        ocr_status = "not_run"
        ocr_raw_text = ""
        txid_ocr = ""
        if screenshot_bytes and self.config.get_bool("ocr_enabled", True):
            ocr_status, ocr_raw_text, txid_ocr = await self.run_ocr_on_image_bytes(screenshot_bytes)

        strict_mismatch = self.config.get_bool("ocr_strict_mismatch_reject", True)
        unreadable_policy = self.config.get_str("ocr_unreadable_policy", "flag_manual")

        if tx_clean and txid_ocr:
            tx_norm_user = re.sub(r"[^A-Z0-9]", "", tx_clean)
            tx_norm_ocr = re.sub(r"[^A-Z0-9]", "", txid_ocr)
            if tx_norm_user != tx_norm_ocr and tx_norm_user not in ocr_raw_text.upper().replace(" ", ""):
                if strict_mismatch:
                    with self.db.atomic(immediate=True) as conn:
                        conn.execute(
                            """
                            INSERT INTO deposits (
                                deposit_uid, method_id, user_id, amount, bonus_amount, charge_amount, net_credit,
                                sender_number, txid_user, txid_ocr, ocr_raw_text, ocr_status,
                                screenshot_file_id, screenshot_unique_id, screenshot_sha256, custom_answers_json,
                                status, auto_review_mode, reject_reason, reviewed_at, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'mismatch_rejected', ?, ?, ?, ?, 'rejected', 'auto_reject', ?, ?, ?)
                            """,
                            (
                                deposit_uid, int(method_id), user_id, amt, bonus_amt, charge_amt, net_credit,
                                sender_number.strip(), tx_clean, txid_ocr, ocr_raw_text[:2000],
                                screenshot_file_id, screenshot_unique_id, img_sha,
                                safe_json_dumps(custom_answers or []),
                                f"REJECTED_TXID_MISMATCH (User={tx_clean}, OCR={txid_ocr})",
                                now_s, now_s,
                            ),
                        )
                    return False, "REJECTED_TXID_MISMATCH", {
                        "auto_rejected": True,
                        "code": "REJECTED_TXID_MISMATCH",
                        "deposit_uid": deposit_uid,
                        "txid_user": tx_clean,
                        "txid_ocr": txid_ocr,
                    }
            else:
                ocr_status = "txid_matched"

        elif screenshot_bytes and ocr_status in ("no_text", "no_txid_found") and unreadable_policy == "strict_reject":
            return False, "Auto-Rejected: Screenshot text/TxID unreadable. Please upload a clearer receipt.", {
                "auto_rejected": True,
                "reason": "Unreadable screenshot",
            }

        # Optional OCR Amount Match
        if self.config.get_bool("ocr_amount_match", False) and ocr_raw_text:
            amt_int_str = str(int(round(amt)))
            if amt_int_str not in ocr_raw_text.replace(",", ""):
                if strict_mismatch:
                    return False, f"Auto-Rejected: Amount {format_money(amt)} not detected in screenshot.", {
                        "auto_rejected": True,
                        "reason": "OCR Amount Mismatch",
                    }

        auto_mode, auto_action_at = self._compute_auto_review_schedule(method, net_credit)
        if ocr_status in ("no_text", "no_txid_found") and auto_mode == "auto_approve":
            # Do not auto-approve unreadable OCR; flag for manual review
            auto_mode = "manual"
            auto_action_at = ""
            ocr_status = "unreadable_flagged"

        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO deposits (
                    deposit_uid, method_id, user_id, amount, bonus_amount, charge_amount, net_credit,
                    sender_number, txid_user, txid_ocr, ocr_raw_text, ocr_status,
                    screenshot_file_id, screenshot_unique_id, screenshot_sha256, custom_answers_json,
                    status, auto_review_mode, auto_action_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                """,
                (
                    deposit_uid, int(method_id), user_id, amt, bonus_amt, charge_amt, net_credit,
                    sender_number.strip(), tx_clean, txid_ocr, ocr_raw_text[:2000], ocr_status,
                    screenshot_file_id, screenshot_unique_id, img_sha,
                    safe_json_dumps(custom_answers or []),
                    auto_mode, auto_action_at, now_s,
                ),
            )
            dep_id = int(cur.lastrowid or 0)

        return True, "Deposit submitted.", {
            "id": dep_id,
            "deposit_uid": deposit_uid,
            "method_name_bn": str(method["name_bn"]),
            "method_name_en": str(method["name_en"]),
            "amount": amt,
            "bonus": bonus_amt,
            "charge": charge_amt,
            "net_credit": net_credit,
            "sender": sender_number.strip(),
            "txid": tx_clean,
            "txid_ocr": txid_ocr,
            "ocr_status": ocr_status,
            "auto_mode": auto_mode,
        }

    def set_channel_ref(self, deposit_id: int, channel_id: str, message_id: int, is_media: bool) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE deposits SET channel_id=?, channel_message_id=?, is_media_msg=? WHERE id=?",
                (str(channel_id), int(message_id), 1 if is_media else 0, int(deposit_id)),
            )

    def get_deposit(self, deposit_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM deposits WHERE id=?", (int(deposit_id),))

    def list_pending_deposits(self, limit: int = 20) -> List[sqlite3.Row]:
        return self.db.query_all("SELECT * FROM deposits WHERE status='pending' ORDER BY id ASC LIMIT ?", (limit,))

    def approve_deposit(self, deposit_id: int, admin_id: int, is_auto: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            dep = conn.execute("SELECT * FROM deposits WHERE id=?", (int(deposit_id),)).fetchone()
            if dep is None:
                return False, "Deposit not found.", {}
            if str(dep["status"]) != "pending":
                return False, f"Already finalized ({dep['status']}).", {"already_status": str(dep["status"])}

            upd = conn.execute(
                "UPDATE deposits SET status='approved', reviewed_by=?, reviewed_at=?, auto_action_at='' WHERE id=? AND status='pending'",
                (int(admin_id), now_s, int(deposit_id)),
            )
            if int(upd.rowcount or 0) != 1:
                return False, "Concurrent review conflict.", {}

            dep_uid = str(dep["deposit_uid"])
            user_id = int(dep["user_id"])
            net_credit = float(dep["net_credit"])
            ok_c, msg_c, _, new_dep_bal = self.ledger.apply_transaction(
                user_id=user_id,
                tx_type="deposit_credit",
                amount=net_credit,
                direction="credit",
                wallet_bucket="deposit",
                idempotency_key=f"dep_app:{dep_uid}",
                source="deposit",
                ref_id=dep_uid,
                admin_id=admin_id,
                reason=f"Deposit {dep_uid} approved",
            )
            if not ok_c:
                raise ValueError(msg_c)

        self.audit.log(admin_id, "auto" if is_auto else "admin", "approve_deposit", "deposit", deposit_id)
        return True, "Deposit approved.", {"dep": dict(dep), "new_deposit_balance": new_dep_bal}

    def reject_deposit(self, deposit_id: int, admin_id: int, reason: str, is_auto: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        clean_reason = str(reason or "").strip() or "Deposit rejected"
        with self.db.atomic(immediate=True) as conn:
            dep = conn.execute("SELECT * FROM deposits WHERE id=?", (int(deposit_id),)).fetchone()
            if dep is None:
                return False, "Deposit not found.", {}
            if str(dep["status"]) != "pending":
                return False, f"Already finalized ({dep['status']}).", {"already_status": str(dep["status"])}
            upd = conn.execute(
                "UPDATE deposits SET status='rejected', reject_reason=?, reviewed_by=?, reviewed_at=?, auto_action_at='' WHERE id=? AND status='pending'",
                (clean_reason, int(admin_id), now_s, int(deposit_id)),
            )
            if int(upd.rowcount or 0) != 1:
                return False, "Concurrent review conflict.", {}

        self.audit.log(admin_id, "auto" if is_auto else "admin", "reject_deposit", "deposit", deposit_id, {"reason": clean_reason})
        return True, "Deposit rejected.", {"dep": dict(dep), "reason": clean_reason}


# ==============================================================================
# WITHDRAWAL MANAGER (WALLET VERIFICATION, CONDITIONS, HOLD/PAID/RELEASE)
# ==============================================================================

class WithdrawalManager:
    """
    Handles Withdrawal Methods CRUD, BD/Crypto Wallet Verification, Custom Conditions,
    Fee Previews, Atomic Hold (withdrawal_hold), Mark Paid (withdrawal_paid), and Release.
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        security: SecurityManager,
        ledger: LedgerManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.security = security
        self.ledger = ledger

    def list_methods(self, active_only: bool = False, include_archived: bool = False) -> List[sqlite3.Row]:
        clauses: List[str] = []
        if not include_archived:
            clauses.append("is_archived=0")
        if active_only:
            clauses.append("is_active=1 AND is_hidden=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM withdraw_methods {where_sql} ORDER BY sort_order ASC, id ASC")

    def get_method(self, method_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM withdraw_methods WHERE id=?", (int(method_id),))

    def create_method(
        self,
        name_bn: str,
        name_en: str,
        method_type: str = "bd_mobile",
        fee_type: str = "fixed",
        fee_value: float = 0.0,
        min_amount: float = 50.0,
        max_amount: float = 25000.0,
        wallet_regex: str = "",
        instruction_bn: str = "",
        instruction_en: str = "",
        admin_id: int = 0,
    ) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO withdraw_methods (
                    name_bn, name_en, method_type, fee_type, fee_value, min_amount, max_amount,
                    wallet_regex, instruction_bn, instruction_en, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name_bn.strip(),
                    (name_en or name_bn).strip(),
                    method_type,
                    fee_type if fee_type in ("fixed", "percent") else "fixed",
                    round(float(fee_value), 4),
                    round(float(min_amount), 4),
                    round(float(max_amount), 4),
                    wallet_regex.strip(),
                    instruction_bn.strip(),
                    (instruction_en or instruction_bn).strip(),
                    now_s,
                ),
            )
            mid = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_withdraw_method", "withdraw_method", mid)
        return mid

    def update_method(self, method_id: int, updates: Dict[str, Any], admin_id: int) -> Tuple[bool, str]:
        allowed = {
            "name_bn", "name_en", "method_type", "fee_type", "fee_value",
            "min_amount", "max_amount", "wallet_regex", "custom_conditions_json",
            "instruction_bn", "instruction_en", "is_active", "is_hidden", "is_archived",
        }
        clean = {k: v for k, v in updates.items() if k in allowed}
        if not clean:
            return False, "No valid withdraw method fields."
        set_sql = ", ".join(f"{k}=?" for k in clean.keys())
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE withdraw_methods SET {set_sql} WHERE id=?", list(clean.values()) + [int(method_id)])
        self.audit.log(admin_id, "admin", "update_withdraw_method", "withdraw_method", method_id, clean)
        return True, "Withdraw method updated."

    @staticmethod
    def format_fee_label(method: sqlite3.Row, lang: str = "bn") -> str:
        fval = float(method["fee_value"] or 0.0)
        if fval <= 0:
            return "ফি: ফ্রি (0)" if lang == "bn" else "Fee: Free (0)"
        if str(method["fee_type"]) == "percent":
            return f"ফি: {fval:g}%" if lang == "bn" else f"Fee: {fval:g}%"
        return f"ফি: {format_money(fval)}" if lang == "bn" else f"Fee: {format_money(fval)}"

    def calculate_fee_and_net(self, method: sqlite3.Row, gross_amount: float) -> Tuple[float, float]:
        gross = round(float(gross_amount), 4)
        fval = max(0.0, float(method["fee_value"] or 0.0))
        if str(method["fee_type"]) == "percent":
            fee = round(gross * (fval / 100.0), 4)
        else:
            fee = round(fval, 4)
        net = round(max(0.0, gross - fee), 4)
        return fee, net

    def check_conditions(self, method: sqlite3.Row, user_row: sqlite3.Row) -> Tuple[bool, str]:
        conds = safe_json_loads(method["custom_conditions_json"], {})
        uid = int(user_row["user_id"])

        min_tasks = int(conds.get("min_tasks", 0) or 0)
        if min_tasks > 0:
            r = self.db.query_one("SELECT COUNT(*) AS c FROM task_submissions WHERE user_id=? AND status='approved'", (uid,))
            if (int(r["c"]) if r else 0) < min_tasks:
                return False, f"Requires at least {min_tasks} approved task(s)."

        min_fs = int(conds.get("min_fs", 0) or 0)
        if min_fs > 0:
            r = self.db.query_one("SELECT COUNT(*) AS c FROM fs_records WHERE user_id=? AND status='approved'", (uid,))
            if (int(r["c"]) if r else 0) < min_fs:
                return False, f"Requires at least {min_fs} approved File Submit record(s)."

        min_refs = int(conds.get("min_referrals", 0) or 0)
        if min_refs > 0:
            r = self.db.query_one("SELECT COUNT(*) AS c FROM users WHERE referrer_id=?", (uid,))
            if (int(r["c"]) if r else 0) < min_refs:
                return False, f"Requires at least {min_refs} referral(s)."

        min_age_days = int(conds.get("min_account_age_days", 0) or 0)
        if min_age_days > 0:
            reg_dt = parse_iso_dt(user_row["registered_at"])
            if reg_dt and (now_utc() - reg_dt).days < min_age_days:
                return False, f"Account must be at least {min_age_days} day(s) old."

        daily_lim = int(conds.get("daily_limit", 0) or 0)
        if daily_lim > 0:
            dhaka_start = now_dhaka().replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            cnt = self.db.query_one(
                "SELECT COUNT(*) AS c FROM withdrawals WHERE user_id=? AND created_at>=? AND status != 'rejected'",
                (uid, dhaka_start),
            )
            if (int(cnt["c"]) if cnt else 0) >= daily_lim:
                return False, f"Daily withdrawal count limit reached ({daily_lim}/day)."

        cd_sec = int(conds.get("cooldown_sec", 0) or 0)
        if cd_sec > 0:
            last_w = self.db.query_one(
                "SELECT created_at FROM withdrawals WHERE user_id=? AND status != 'rejected' ORDER BY id DESC LIMIT 1",
                (uid,),
            )
            if last_w:
                ldt = parse_iso_dt(last_w["created_at"])
                if ldt and (now_utc() - ldt).total_seconds() < cd_sec:
                    return False, f"Withdrawal cooldown active: wait {int(cd_sec - (now_utc() - ldt).total_seconds())}s."

        return True, ""

    def request_withdrawal(
        self,
        method_id: int,
        user_row: sqlite3.Row,
        account_or_wallet: str,
        gross_amount: float,
        custom_answers: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        if self.security.is_panic_frozen():
            return False, "Emergency Panic Freeze is active. Withdrawals are temporarily paused.", {}

        method = self.get_method(method_id)
        if method is None or int(method["is_active"]) != 1 or int(method["is_archived"]) == 1:
            return False, "Withdrawal method unavailable.", {}

        ok_cond, err_cond = self.check_conditions(method, user_row)
        if not ok_cond:
            return False, err_cond, {}

        ok_wal, norm_wallet, err_wal = ValidationManager.validate_wallet_address(
            str(method["method_type"]),
            account_or_wallet,
            str(method["wallet_regex"] or ""),
        )
        if not ok_wal:
            return False, err_wal, {}

        user_id = int(user_row["user_id"])
        ok_multi, err_multi = self.security.check_shared_wallet_multi_account(user_id, norm_wallet)
        if not ok_multi:
            return False, err_multi, {}

        gross = round(float(gross_amount), 4)
        if gross < float(method["min_amount"]) or gross > float(method["max_amount"]):
            return False, f"Amount must be between {format_money(method['min_amount'])} and {format_money(method['max_amount'])}.", {}

        fee, net = self.calculate_fee_and_net(method, gross)
        if net <= 0:
            return False, "Net receivable amount must be greater than zero after fees.", {}

        earned_bal = float(user_row["earned_balance"])
        if earned_bal + 1e-6 < gross:
            return False, f"Insufficient Earned (withdrawable) balance. Available Earned: {format_money(earned_bal)}.", {}

        withdraw_uid = generate_uid("WDR", 7)
        is_big = self.security.is_big_withdraw(gross)
        init_status = "pending" if is_big else "requested"
        now_s = now_utc_iso()

        with self.db.atomic(immediate=True) as conn:
            ok_hold, msg_hold = self.ledger.hold_for_withdrawal(user_id, gross, withdraw_uid)
            if not ok_hold:
                return False, msg_hold, {}
            cur = conn.execute(
                """
                INSERT INTO withdrawals (
                    withdraw_uid, method_id, user_id, account_or_wallet, gross_amount, fee_amount, net_amount,
                    custom_answers_json, conditions_snapshot_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    withdraw_uid,
                    int(method_id),
                    user_id,
                    norm_wallet,
                    gross,
                    fee,
                    net,
                    safe_json_dumps(custom_answers or []),
                    str(method["custom_conditions_json"] or "{}"),
                    init_status,
                    now_s,
                ),
            )
            wd_id = int(cur.lastrowid or 0)

        return True, "Withdrawal request submitted.", {
            "id": wd_id,
            "withdraw_uid": withdraw_uid,
            "method_name_bn": str(method["name_bn"]),
            "method_name_en": str(method["name_en"]),
            "account": norm_wallet,
            "gross": gross,
            "fee": fee,
            "net": net,
            "is_big": is_big,
        }

    def set_channel_ref(self, wd_id: int, channel_id: str, message_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE withdrawals SET channel_id=?, channel_message_id=? WHERE id=?",
                (str(channel_id), int(message_id), int(wd_id)),
            )

    def set_payout_ref(self, wd_id: int, channel_id: str, message_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE withdrawals SET payout_channel_id=?, payout_message_id=? WHERE id=?",
                (str(channel_id), int(message_id), int(wd_id)),
            )

    def get_withdrawal(self, wd_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM withdrawals WHERE id=?", (int(wd_id),))

    def list_pending_withdrawals(self, limit: int = 20) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM withdrawals WHERE status IN ('requested','pending','approved') ORDER BY id ASC LIMIT ?",
            (limit,),
        )

    def approve_withdrawal(self, wd_id: int, admin_id: int) -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            wd = conn.execute("SELECT * FROM withdrawals WHERE id=?", (int(wd_id),)).fetchone()
            if wd is None:
                return False, "Withdrawal not found.", {}
            if str(wd["status"]) not in ("requested", "pending"):
                return False, f"Cannot approve in status '{wd['status']}'.", {}
            if self.security.is_big_withdraw(float(wd["gross_amount"])) and int(admin_id) != DEFAULT_MAIN_ADMIN_ID:
                return False, "Big Withdrawal Alert: Only Main Admin can approve this amount.", {}
            conn.execute(
                "UPDATE withdrawals SET status='approved', reviewed_by=?, reviewed_at=? WHERE id=?",
                (int(admin_id), now_s, int(wd_id)),
            )
        self.audit.log(admin_id, "admin", "approve_withdrawal", "withdrawal", wd_id)
        return True, "Approved! Now send payment and press Mark Paid.", {"wd": dict(wd)}

    def mark_paid_withdrawal(self, wd_id: int, admin_id: int) -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            wd = conn.execute("SELECT * FROM withdrawals WHERE id=?", (int(wd_id),)).fetchone()
            if wd is None:
                return False, "Withdrawal not found.", {}
            if str(wd["status"]) not in ("requested", "pending", "approved"):
                return False, f"Already finalized ({wd['status']}).", {}
            if self.security.is_big_withdraw(float(wd["gross_amount"])) and int(admin_id) != DEFAULT_MAIN_ADMIN_ID:
                return False, "Big Withdrawal Alert: Only Main Admin can mark paid.", {}

            ok_p, msg_p = self.ledger.finalize_withdrawal_paid(
                user_id=int(wd["user_id"]),
                gross_amount=float(wd["gross_amount"]),
                withdraw_uid=str(wd["withdraw_uid"]),
                admin_id=admin_id,
            )
            if not ok_p:
                return False, msg_p, {}

            conn.execute(
                "UPDATE withdrawals SET status='paid', paid_by=?, paid_at=?, reviewed_by=CASE WHEN reviewed_by=0 THEN ? ELSE reviewed_by END WHERE id=?",
                (int(admin_id), now_s, int(admin_id), int(wd_id)),
            )
        self.audit.log(admin_id, "admin", "mark_paid_withdrawal", "withdrawal", wd_id)
        return True, "Marked Paid successfully.", {"wd": dict(wd)}

    def reject_withdrawal(self, wd_id: int, admin_id: int, reason: str) -> Tuple[bool, str, Dict[str, Any]]:
        now_s = now_utc_iso()
        clean_reason = str(reason or "").strip() or "Withdrawal rejected"
        with self.db.atomic(immediate=True) as conn:
            wd = conn.execute("SELECT * FROM withdrawals WHERE id=?", (int(wd_id),)).fetchone()
            if wd is None:
                return False, "Withdrawal not found.", {}
            if str(wd["status"]) not in ("requested", "pending", "approved"):
                return False, f"Already finalized ({wd['status']}).", {}

            ok_r, msg_r = self.ledger.release_withdrawal_hold(
                user_id=int(wd["user_id"]),
                gross_amount=float(wd["gross_amount"]),
                withdraw_uid=str(wd["withdraw_uid"]),
                admin_id=admin_id,
                reason=clean_reason,
            )
            if not ok_r:
                return False, msg_r, {}

            conn.execute(
                "UPDATE withdrawals SET status='rejected', reject_reason=?, reviewed_by=?, reviewed_at=? WHERE id=?",
                (clean_reason, int(admin_id), now_s, int(wd_id)),
            )
        self.audit.log(admin_id, "admin", "reject_withdrawal", "withdrawal", wd_id, {"reason": clean_reason})
        return True, "Withdrawal rejected & refunded.", {"wd": dict(wd), "reason": clean_reason}
# ==============================================================================
# REFERRAL, BONUS, DAILY CHECK-IN & LEADERBOARD MANAGERS (RULE 27, 28, 31, 79.2, 94)
# ==============================================================================

class ReferralManager:
    def __init__(self, db: DatabaseManager, config: ConfigManager) -> None:
        self.db = db
        self.config = config

    def get_dashboard(self, user_id: int) -> Dict[str, Any]:
        uid = int(user_id)
        tot = self.db.query_one("SELECT COUNT(*) AS c FROM users WHERE referrer_id=?", (uid,))
        act = self.db.query_one("SELECT COUNT(*) AS c FROM users WHERE referrer_id=? AND status='active'", (uid,))
        earn = self.db.query_one(
            "SELECT COALESCE(SUM(amount),0) AS s FROM ledger_transactions WHERE user_id=? AND tx_type IN ('referral_commission','file_submit_commission') AND direction='credit'",
            (uid,),
        )
        bot_un = BOT_IDENTITY.get_username()
        ref_link = f"https://t.me/{bot_un}?start=ref_{uid}" if bot_un else f"/start ref_{uid}"
        ctype = self.config.get_str("referral_commission_type", "percent")
        cval = self.config.get_float("referral_commission_value", 10.0)
        rate_txt = f"{cval:g}%" if ctype == "percent" else format_money(cval)
        return {
            "ref_link": ref_link,
            "total_refs": int(tot["c"]) if tot else 0,
            "active_refs": int(act["c"]) if act else 0,
            "rate_text": rate_txt,
            "total_earnings": float(earn["s"]) if earn else 0.0,
        }


class BonusManager:
    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        ledger: LedgerManager,
        excel: ExcelManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.ledger = ledger
        self.excel = excel

    def list_bonuses(self, active_only: bool = False, include_archived: bool = False) -> List[sqlite3.Row]:
        clauses: List[str] = []
        if not include_archived:
            clauses.append("is_archived=0")
        if active_only:
            clauses.append("is_active=1 AND is_hidden=0")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.db.query_all(f"SELECT * FROM bonuses {where_sql} ORDER BY id DESC")

    def get_bonus(self, bonus_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM bonuses WHERE id=?", (int(bonus_id),))

    def create_bonus(
        self,
        title_bn: str,
        title_en: str,
        desc_bn: str,
        desc_en: str,
        reward_amount: float,
        max_claims: int = 0,
        min_tasks_required: int = 0,
        cooldown_sec: int = 0,
        wallet_bucket: str = "earned",
        admin_id: int = 0,
    ) -> int:
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO bonuses
                (title_bn, title_en, desc_bn, desc_en, reward_amount, wallet_bucket, min_tasks_required, max_claims, cooldown_sec, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    title_bn.strip(),
                    (title_en or title_bn).strip(),
                    desc_bn.strip(),
                    (desc_en or desc_bn).strip(),
                    round(float(reward_amount), 4),
                    wallet_bucket if wallet_bucket in ("earned", "deposit") else "earned",
                    max(0, int(min_tasks_required)),
                    max(0, int(max_claims)),
                    max(0, int(cooldown_sec)),
                    now_utc_iso(),
                ),
            )
            bid = int(cur.lastrowid or 0)
        self.audit.log(admin_id, "admin", "create_bonus", "bonus", bid)
        return bid

    def toggle_bonus_flag(self, bonus_id: int, field: str) -> Tuple[bool, int]:
        if field not in ("is_active", "is_hidden", "is_archived"):
            return False, 0
        row = self.get_bonus(bonus_id)
        if not row:
            return False, 0
        nv = 0 if int(row[field]) == 1 else 1
        with self.db.atomic(immediate=True) as conn:
            conn.execute(f"UPDATE bonuses SET {field}=? WHERE id=?", (nv, int(bonus_id)))
        return True, nv

    def claim_bonus(self, bonus_id: int, user_id: int) -> Tuple[bool, str, float]:
        now_dt = now_utc()
        now_s = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        with self.db.atomic(immediate=True) as conn:
            b = conn.execute("SELECT * FROM bonuses WHERE id=?", (int(bonus_id),)).fetchone()
            if b is None or int(b["is_active"]) != 1 or int(b["is_archived"]) == 1:
                return False, "Bonus campaign is not active.", 0.0
            st_dt = parse_iso_dt(b["start_at"])
            en_dt = parse_iso_dt(b["end_at"])
            if st_dt and now_dt < st_dt:
                return False, "Bonus campaign has not started yet.", 0.0
            if en_dt and now_dt > en_dt:
                return False, "Bonus campaign has ended.", 0.0
            max_c = int(b["max_claims"] or 0)
            if max_c > 0 and int(b["claimed_count"]) >= max_c:
                return False, "Bonus claim limit reached (sold out).", 0.0

            min_tasks = int(b["min_tasks_required"] or 0)
            if min_tasks > 0:
                cnt_t = conn.execute("SELECT COUNT(*) AS c FROM task_submissions WHERE user_id=? AND status='approved'", (int(user_id),)).fetchone()
                if (int(cnt_t["c"]) if cnt_t else 0) < min_tasks:
                    return False, f"Requires at least {min_tasks} approved tasks to claim.", 0.0

            prev = conn.execute(
                "SELECT created_at FROM bonus_claims WHERE bonus_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
                (int(bonus_id), int(user_id)),
            ).fetchone()
            cd = int(b["cooldown_sec"] or 0)
            if prev is not None:
                if cd <= 0:
                    return False, "You have already claimed this bonus.", 0.0
                pdt = parse_iso_dt(prev["created_at"])
                if pdt and (now_dt - pdt).total_seconds() < cd:
                    return False, f"Cooldown active: wait {int(cd - (now_dt - pdt).total_seconds())}s.", 0.0

            claim_uid = generate_uid("BON", 7)
            amt = float(b["reward_amount"])
            bucket = str(b["wallet_bucket"] or "earned")
            ok_l, msg_l, _, _ = self.ledger.apply_transaction(
                user_id=user_id,
                tx_type="bonus",
                amount=amt,
                direction="credit",
                wallet_bucket=bucket,
                idempotency_key=f"bonus:{bonus_id}:{user_id}:{claim_uid}",
                source="bonus_claim",
                ref_id=claim_uid,
                reason=f"Bonus claimed: {b['title_en']}",
            )
            if not ok_l:
                return False, msg_l, 0.0

            conn.execute(
                "INSERT INTO bonus_claims (bonus_id, user_id, amount_credited, claim_uid, created_at) VALUES (?, ?, ?, ?, ?)",
                (int(bonus_id), int(user_id), amt, claim_uid, now_s),
            )
            conn.execute("UPDATE bonuses SET claimed_count = claimed_count + 1 WHERE id=?", (int(bonus_id),))
        return True, "Bonus claimed successfully!", amt

    def export_bonus_claims(self, file_format: str = "xlsx", admin_id: int = 0) -> Tuple[bool, str, Optional[Path]]:
        rows = self.db.query_all(
            """
            SELECT c.*, b.title_en, u.username, u.full_name
            FROM bonus_claims c
            LEFT JOIN bonuses b ON b.id = c.bonus_id
            LEFT JOIN users u ON u.user_id = c.user_id
            ORDER BY c.id DESC
            """
        )
        if not rows:
            return False, "No bonus claims to export.", None
        headers = ["Claim_UID", "Bonus_Title", "User_ID", "Full_Name", "Username", "Amount", "Claimed_Dhaka"]
        data = [
            [
                r["claim_uid"],
                r["title_en"] or r["bonus_id"],
                int(r["user_id"]),
                r["full_name"] or "",
                f"@{r['username']}" if r["username"] else "",
                float(r["amount_credited"]),
                format_dhaka_dt(r["created_at"]),
            ]
            for r in rows
        ]
        path, _ = self.excel.export_rows(headers, data, "Bonus_Claims", "all", file_format, "Bonus_Claims", admin_id)
        return True, f"Exported {len(rows)} bonus claims.", path


class DailyCheckinManager:
    VIP_MULTIPLIER_MAP: Dict[str, float] = {
        "Bronze": 1.0,
        "Silver": 1.15,
        "Gold": 1.35,
        "VIP": 1.5,
    }

    def __init__(self, db: DatabaseManager, config: ConfigManager, ledger: LedgerManager) -> None:
        self.db = db
        self.config = config
        self.ledger = ledger

    def get_user_checkin_info(self, user_id: int) -> Dict[str, Any]:
        today = dhaka_today_str()
        today_row = self.db.query_one(
            "SELECT * FROM daily_checkins WHERE user_id=? AND checkin_date_dhaka=?",
            (int(user_id), today),
        )
        last_row = self.db.query_one(
            "SELECT * FROM daily_checkins WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (int(user_id),),
        )
        return {
            "claimed_today": today_row is not None,
            "current_streak": int(last_row["streak_day"]) if last_row else 0,
            "today_date": today,
        }

    def claim_daily_checkin(self, user_row: sqlite3.Row) -> Tuple[bool, str, Dict[str, Any]]:
        if not self.config.get_bool("daily_checkin_enabled", True):
            return False, "Daily Check-in is currently disabled.", {}

        uid = int(user_row["user_id"])
        dhaka_now = now_dhaka()
        today_str = dhaka_now.strftime("%Y-%m-%d")
        yesterday_str = (dhaka_now - timedelta(days=1)).strftime("%Y-%m-%d")

        with self.db.atomic(immediate=True) as conn:
            already = conn.execute(
                "SELECT id FROM daily_checkins WHERE user_id=? AND checkin_date_dhaka=?",
                (uid, today_str),
            ).fetchone()
            if already is not None:
                return False, "You have already claimed today's check-in! Come back after 12:00 AM Dhaka.", {}

            yest = conn.execute(
                "SELECT streak_day FROM daily_checkins WHERE user_id=? AND checkin_date_dhaka=?",
                (uid, yesterday_str),
            ).fetchone()
            streak_day = (int(yest["streak_day"]) + 1) if yest else 1

            base_amt = max(0.0, self.config.get_float("daily_checkin_amount", 2.0))
            streak_bonus = 0.0
            if streak_day % 30 == 0:
                streak_bonus = max(0.0, self.config.get_float("daily_checkin_streak30_bonus", 50.0))
            elif streak_day % 7 == 0:
                streak_bonus = max(0.0, self.config.get_float("daily_checkin_streak7_bonus", 10.0))

            vip_mult = self.VIP_MULTIPLIER_MAP.get(str(user_row["vip_tier"]), 1.0)
            total_credit = round((base_amt + streak_bonus) * vip_mult, 4)

            ok_l, msg_l, _, new_bal = self.ledger.apply_transaction(
                user_id=uid,
                tx_type="daily_checkin_bonus",
                amount=total_credit,
                direction="credit",
                wallet_bucket="earned",
                idempotency_key=f"checkin:{uid}:{today_str}",
                source="daily_checkin",
                ref_id=today_str,
                reason=f"Daily Check-in Day #{streak_day} ({today_str})",
            )
            if not ok_l:
                return False, msg_l, {}

            conn.execute(
                """
                INSERT INTO daily_checkins
                (user_id, checkin_date_dhaka, streak_day, base_amount, streak_bonus, vip_multiplier, total_credited, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (uid, today_str, streak_day, base_amt, streak_bonus, vip_mult, total_credit, now_utc_iso()),
            )

        return True, "Daily Check-in claimed!", {
            "streak_day": streak_day,
            "base_amount": base_amt,
            "streak_bonus": streak_bonus,
            "vip_multiplier": vip_mult,
            "total_credited": total_credit,
            "new_balance": new_bal,
        }


class LeaderboardManager:
    """
    Independent Task & File Submit (Approved-Records Only) Leaderboards:
    - Manual Score Add/Adjust (+N/-N with reason & audit, RULE 94)
    - Excludes 0-work users
    - Reset auto-awards prizes to Earned balance, saves history, and starts fresh at 0
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        audit: AuditManager,
        ledger: LedgerManager,
    ) -> None:
        self.db = db
        self.config = config
        self.audit = audit
        self.ledger = ledger

    def get_active_cycle(self, board_type: str) -> sqlite3.Row:
        row = self.db.query_one(
            "SELECT * FROM leaderboard_cycles WHERE board_type=? AND status='active' ORDER BY id DESC LIMIT 1",
            (board_type,),
        )
        if row is not None:
            return row
        with self.db.atomic(immediate=True) as conn:
            tiers = safe_json_dumps({"1": 100.0, "2": 60.0, "3": 40.0, "4": 20.0, "5": 10.0})
            conn.execute(
                "INSERT INTO leaderboard_cycles (board_type, cycle_no, status, started_at, prize_tiers_json, top_n) VALUES (?, 1, 'active', ?, ?, 10)",
                (board_type, now_utc_iso(), tiers),
            )
        refreshed = self.db.query_one(
            "SELECT * FROM leaderboard_cycles WHERE board_type=? AND status='active' ORDER BY id DESC LIMIT 1",
            (board_type,),
        )
        assert refreshed is not None
        return refreshed

    def get_rankings(self, board_type: str, limit: Optional[int] = None) -> Tuple[sqlite3.Row, List[Dict[str, Any]]]:
        cycle = self.get_active_cycle(board_type)
        cycle_id = int(cycle["id"])
        started_at = str(cycle["started_at"])
        top_n = limit if limit is not None else max(1, int(cycle["top_n"] or self.config.get_int("lb_top_n", 10)))

        work_counts: Dict[int, int] = {}
        if board_type == "task":
            rows = self.db.query_all(
                """
                SELECT user_id, COUNT(*) AS cnt
                FROM task_submissions
                WHERE status='approved' AND created_at >= ?
                GROUP BY user_id
                """,
                (started_at,),
            )
            for r in rows:
                work_counts[int(r["user_id"])] = int(r["cnt"])
        else:
            # FS Leaderboard: counts ONLY Approved records (not rejected, not file count)
            rows = self.db.query_all(
                """
                SELECT r.user_id, COUNT(*) AS cnt
                FROM fs_records r
                JOIN fs_submissions s ON s.id = r.fs_submission_id
                WHERE r.status='approved' AND s.created_at >= ?
                GROUP BY r.user_id
                """,
                (started_at,),
            )
            for r in rows:
                work_counts[int(r["user_id"])] = int(r["cnt"])

        adj_rows = self.db.query_all(
            """
            SELECT user_id, COALESCE(SUM(delta_score), 0) AS adj
            FROM leaderboard_adjustments
            WHERE cycle_id=? AND board_type=?
            GROUP BY user_id
            """,
            (cycle_id, board_type),
        )
        adj_map: Dict[int, int] = {int(r["user_id"]): int(r["adj"]) for r in adj_rows}

        all_uids = set(work_counts.keys()) | set(adj_map.keys())
        prize_tiers = safe_json_loads(cycle["prize_tiers_json"], {})
        ranked: List[Dict[str, Any]] = []

        for uid in all_uids:
            wc = work_counts.get(uid, 0)
            adj = adj_map.get(uid, 0)
            tot = wc + adj
            if tot <= 0:
                continue
            u = self.db.query_one("SELECT full_name, username, status FROM users WHERE user_id=?", (uid,))
            if u is None or str(u["status"]) == "blocked":
                continue
            ranked.append(
                {
                    "user_id": uid,
                    "full_name": str(u["full_name"] or ""),
                    "username": str(u["username"] or ""),
                    "work_count": wc,
                    "manual_adjust": adj,
                    "total_score": tot,
                }
            )

        ranked.sort(key=lambda x: (-x["total_score"], -x["work_count"], x["user_id"]))
        top_list = ranked[:top_n]
        for idx, item in enumerate(top_list, start=1):
            item["rank"] = idx
            item["prize"] = float(prize_tiers.get(str(idx), 0.0) or 0.0)
        return cycle, top_list

    def adjust_user_score(
        self,
        board_type: str,
        user_id: int,
        delta_score: int,
        reason: str,
        admin_id: int,
    ) -> Tuple[bool, str]:
        if board_type not in ("task", "fs"):
            return False, "Invalid board type."
        if int(delta_score) == 0:
            return False, "Delta score cannot be zero."
        u = self.db.query_one("SELECT user_id FROM users WHERE user_id=?", (int(user_id),))
        if u is None:
            return False, "User ID not found."
        cycle = self.get_active_cycle(board_type)
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO leaderboard_adjustments (cycle_id, board_type, user_id, delta_score, reason, admin_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (int(cycle["id"]), board_type, int(user_id), int(delta_score), reason.strip() or "Admin adjustment", int(admin_id), now_utc_iso()),
            )
        self.audit.log(admin_id, "admin", "lb_manual_adjust", board_type, user_id, {"delta": delta_score, "reason": reason})
        return True, f"Adjusted {board_type.upper()} leaderboard score by {delta_score:+d} for User {user_id}."

    def update_cycle_config(self, board_type: str, top_n: Optional[int] = None, prize_tiers: Optional[Dict[str, float]] = None) -> None:
        cycle = self.get_active_cycle(board_type)
        with self.db.atomic(immediate=True) as conn:
            if top_n is not None:
                conn.execute("UPDATE leaderboard_cycles SET top_n=? WHERE id=?", (max(1, min(100, int(top_n))), int(cycle["id"])))
            if prize_tiers is not None:
                conn.execute("UPDATE leaderboard_cycles SET prize_tiers_json=? WHERE id=?", (safe_json_dumps(prize_tiers), int(cycle["id"])))

    def reset_cycle_and_award(self, board_type: str, admin_id: int) -> Tuple[bool, str, List[Dict[str, Any]]]:
        cycle, rankings = self.get_rankings(board_type, limit=100)
        cycle_id = int(cycle["id"])
        cycle_no = int(cycle["cycle_no"])
        now_s = now_utc_iso()
        awarded_winners: List[Dict[str, Any]] = []

        with self.db.atomic(immediate=True) as conn:
            for item in rankings:
                uid = int(item["user_id"])
                prize = float(item["prize"])
                if prize > 0:
                    ok_l, _, _, _ = self.ledger.apply_transaction(
                        user_id=uid,
                        tx_type="leaderboard_prize",
                        amount=prize,
                        direction="credit",
                        wallet_bucket="earned",
                        idempotency_key=f"lb_prize:{board_type}:c{cycle_no}:u{uid}",
                        source="leaderboard_reset",
                        ref_id=f"{board_type}-c{cycle_no}-r{item['rank']}",
                        admin_id=admin_id,
                        reason=f"{board_type.upper()} Leaderboard Cycle #{cycle_no} Rank #{item['rank']}",
                    )
                    if ok_l:
                        awarded_winners.append({"user_id": uid, "rank": item["rank"], "prize": prize, "cycle_no": cycle_no})

                conn.execute(
                    """
                    INSERT INTO leaderboard_history
                    (cycle_id, board_type, cycle_no, rank_pos, user_id, work_count, manual_adjust, total_score, prize_amount, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (cycle_id, board_type, cycle_no, item["rank"], uid, item["work_count"], item["manual_adjust"], item["total_score"], prize, now_s),
                )

            conn.execute("UPDATE leaderboard_cycles SET status='closed', ended_at=? WHERE id=?", (now_s, cycle_id))
            conn.execute(
                """
                INSERT INTO leaderboard_cycles (board_type, cycle_no, status, started_at, prize_tiers_json, top_n)
                VALUES (?, ?, 'active', ?, ?, ?)
                """,
                (board_type, cycle_no + 1, now_s, cycle["prize_tiers_json"], cycle["top_n"]),
            )

        self.audit.log(admin_id, "admin", "reset_leaderboard", board_type, cycle_no, {"winners": len(awarded_winners)})
        return True, f"{board_type.upper()} Cycle #{cycle_no} reset! Awarded {len(awarded_winners)} winner(s); Cycle #{cycle_no + 1} started at 0.", awarded_winners

    def format_leaderboard_text(self, board_type: str, lang: str = "bn", viewer_user_id: Optional[int] = None) -> str:
        cycle, rankings = self.get_rankings(board_type)
        mask_on = self.config.get_bool("lb_mask_privacy", True)
        title = (
            ("🏆 টাস্ক লিডারবোর্ড" if board_type == "task" else "📊 ফাইল সাবমিট লিডারবোর্ড (সঠিক কাজ)")
            if lang == "bn"
            else ("🏆 Task Leaderboard" if board_type == "task" else "📊 File Submit Leaderboard (Approved Only)")
        )
        lines = [f"<b>{title}</b> — Cycle #{cycle['cycle_no']}", self.config.get_theme()["divider"]]
        if not rankings:
            lines.append("এখনো এই সাইকেলে কোনো সম্পন্ন কাজ নেই।" if lang == "bn" else "No completed work in this cycle yet.")
            return "\n".join(lines)

        medals = {1: "🥇", 2: "🥈", 3: "🥉"}
        for it in rankings:
            rk = int(it["rank"])
            medal = medals.get(rk, f"#{rk}")
            name_disp = mask_display_name(it["full_name"], it["user_id"]) if mask_on else (it["full_name"] or f"User {it['user_id']}")
            you_tag = " 👈" if viewer_user_id and int(viewer_user_id) == int(it["user_id"]) else ""
            prize_txt = f" | 🎁 {format_money(it['prize'])}" if it["prize"] > 0 else ""
            unit_lbl = "কাজ" if lang == "bn" else "works"
            lines.append(f"{medal} <b>{escape_html(name_disp)}</b>{you_tag} — <code>{it['total_score']}</code> {unit_lbl}{prize_txt}")
        return "\n".join(lines)


# ==============================================================================
# EXTENSIONS, TICKETS, APPEALS, NOTIFICATIONS & BROADCAST (RULE 37, 38, 55, 79, 80)
# ==============================================================================

class ExtensionsManager:
    """VIP Auto-Upgrade, Points-to-Currency Exchange & Payment Gateway Adapter hooks (RULE 80)."""

    def __init__(self, db: DatabaseManager, config: ConfigManager, ledger: LedgerManager) -> None:
        self.db = db
        self.config = config
        self.ledger = ledger

    def evaluate_vip_tier(self, user_id: int) -> str:
        cnt = self.db.query_one("SELECT COUNT(*) AS c FROM task_submissions WHERE user_id=? AND status='approved'", (int(user_id),))
        tasks = int(cnt["c"]) if cnt else 0
        new_tier = "Bronze"
        if tasks >= 100:
            new_tier = "VIP"
        elif tasks >= 50:
            new_tier = "Gold"
        elif tasks >= 15:
            new_tier = "Silver"
        with self.db.atomic(immediate=True) as conn:
            conn.execute("UPDATE users SET vip_tier=?, updated_at=? WHERE user_id=?", (new_tier, now_utc_iso(), int(user_id)))
        return new_tier

    def exchange_points_to_currency(self, user_id: int, points: float) -> Tuple[bool, str, float]:
        if not self.config.get_bool("points_exchange_enabled", False):
            return False, "Points exchange is currently disabled.", 0.0
        pts = round(float(points), 4)
        if pts <= 0:
            return False, "Points must be greater than zero.", 0.0
        rate = max(1.0, self.config.get_float("points_per_currency", 100.0))
        currency_amt = round(pts / rate, 4)
        if currency_amt <= 0:
            return False, "Amount too small to convert.", 0.0

        with self.db.atomic(immediate=True) as conn:
            u = conn.execute("SELECT points_balance FROM users WHERE user_id=?", (int(user_id),)).fetchone()
            if not u or float(u["points_balance"]) + 1e-6 < pts:
                return False, "Insufficient points balance.", 0.0
            conn.execute("UPDATE users SET points_balance = ROUND(points_balance - ?, 4) WHERE user_id=?", (pts, int(user_id)))
            ok_l, msg_l, _, _ = self.ledger.apply_transaction(
                user_id=user_id,
                tx_type="points_exchange",
                amount=currency_amt,
                direction="credit",
                wallet_bucket="earned",
                idempotency_key=f"pt_ex:{user_id}:{secrets.token_hex(6)}",
                source="points_exchange",
                ref_id=f"{pts}pts",
                reason=f"Exchanged {pts} points",
            )
            if not ok_l:
                raise ValueError(msg_l)
        return True, f"Converted {pts} points into {format_money(currency_amt)}.", currency_amt


class SupportTicketManager:
    def __init__(self, db: DatabaseManager, audit: AuditManager) -> None:
        self.db = db
        self.audit = audit

    def create_ticket(self, user_id: int, subject: str, message_text: str, photo_file_id: str = "") -> str:
        t_uid = generate_uid("TKT", 6)
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO support_tickets (ticket_uid, user_id, subject, message_text, photo_file_id, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'open', ?)
                """,
                (t_uid, int(user_id), subject.strip() or "Support", message_text.strip(), photo_file_id, now_utc_iso()),
            )
        return t_uid

    def list_user_tickets(self, user_id: int, limit: int = 10) -> List[sqlite3.Row]:
        return self.db.query_all("SELECT * FROM support_tickets WHERE user_id=? ORDER BY id DESC LIMIT ?", (int(user_id), limit))

    def list_open_tickets(self, limit: int = 20) -> List[sqlite3.Row]:
        return self.db.query_all("SELECT * FROM support_tickets WHERE status='open' ORDER BY id ASC LIMIT ?", (limit,))

    def get_ticket(self, ticket_id: int) -> Optional[sqlite3.Row]:
        return self.db.query_one("SELECT * FROM support_tickets WHERE id=?", (int(ticket_id),))

    def reply_ticket(self, ticket_id: int, admin_id: int, reply_text: str) -> Tuple[bool, str, Optional[sqlite3.Row]]:
        t = self.get_ticket(ticket_id)
        if t is None:
            return False, "Ticket not found.", None
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE support_tickets SET status='replied', admin_id=?, admin_reply=?, replied_at=? WHERE id=?",
                (int(admin_id), reply_text.strip(), now_s, int(ticket_id)),
            )
        self.audit.log(admin_id, "admin", "reply_ticket", "ticket", ticket_id)
        return True, "Reply sent.", self.get_ticket(ticket_id)

    def close_ticket(self, ticket_id: int, admin_id: int) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute("UPDATE support_tickets SET status='closed', closed_at=? WHERE id=?", (now_utc_iso(), int(ticket_id)))
        self.audit.log(admin_id, "admin", "close_ticket", "ticket", ticket_id)


class AppealManager:
    def __init__(self, db: DatabaseManager, audit: AuditManager) -> None:
        self.db = db
        self.audit = audit

    def submit_appeal(self, user_id: int, item_type: str, item_id: int, item_uid: str, reason_text: str) -> Tuple[bool, str, str]:
        if item_type not in ("task", "fs", "deposit"):
            return False, "Invalid appeal item type.", ""
        existing = self.db.query_one(
            "SELECT appeal_uid FROM appeals WHERE user_id=? AND item_type=? AND item_id=?",
            (int(user_id), item_type, int(item_id)),
        )
        if existing:
            return False, f"You have already submitted an appeal ({existing['appeal_uid']}) for this item.", ""
        a_uid = generate_uid("APL", 6)
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO appeals (appeal_uid, user_id, item_type, item_id, item_uid, reason_text, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
                """,
                (a_uid, int(user_id), item_type, int(item_id), item_uid, reason_text.strip(), now_utc_iso()),
            )
        return True, f"Appeal {a_uid} submitted.", a_uid

    def list_pending_appeals(self, limit: int = 20) -> List[sqlite3.Row]:
        return self.db.query_all("SELECT * FROM appeals WHERE status='pending' ORDER BY id ASC LIMIT ?", (limit,))

    def resolve_appeal(self, appeal_id: int, status: str, admin_id: int, note: str = "") -> Tuple[bool, Optional[sqlite3.Row]]:
        if status not in ("approved", "rejected"):
            return False, None
        row = self.db.query_one("SELECT * FROM appeals WHERE id=?", (int(appeal_id),))
        if not row or str(row["status"]) != "pending":
            return False, None
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE appeals SET status=?, admin_id=?, admin_note=?, resolved_at=? WHERE id=?",
                (status, int(admin_id), note.strip(), now_utc_iso(), int(appeal_id)),
            )
        self.audit.log(admin_id, "admin", f"appeal_{status}", "appeal", appeal_id)
        return True, self.db.query_one("SELECT * FROM appeals WHERE id=?", (int(appeal_id),))


class NotificationManager:
    """Persistent retry/backoff notification queue that never blocks financial transactions."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def enqueue(self, user_id: int, text_html: str, parse_mode: str = ParseMode.HTML) -> int:
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO notification_queue (user_id, text_html, parse_mode, status, retry_count, max_retries, next_retry_at, created_at)
                VALUES (?, ?, ?, 'pending', 0, 3, ?, ?)
                """,
                (int(user_id), truncate_text(text_html), parse_mode, now_s, now_s),
            )
            return int(cur.lastrowid or 0)

    def get_queue_stats(self) -> Dict[str, int]:
        rows = self.db.query_all("SELECT status, COUNT(*) AS c FROM notification_queue GROUP BY status")
        res = {"pending": 0, "retry_scheduled": 0, "sent": 0, "failed": 0}
        for r in rows:
            res[str(r["status"])] = int(r["c"])
        return res

    def retry_failed(self) -> int:
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                "UPDATE notification_queue SET status='pending', retry_count=0, next_retry_at=? WHERE status='failed'",
                (now_utc_iso(),),
            )
            return int(cur.rowcount or 0)

    def clear_failed(self) -> int:
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute("DELETE FROM notification_queue WHERE status IN ('failed','sent')")
            return int(cur.rowcount or 0)

    async def process_queue(self, bot: Bot, batch_size: int = 20) -> Tuple[int, int]:
        now_s = now_utc_iso()
        rows = self.db.query_all(
            """
            SELECT * FROM notification_queue
            WHERE status IN ('pending','retry_scheduled') AND next_retry_at <= ?
            ORDER BY id ASC LIMIT ?
            """,
            (now_s, batch_size),
        )
        sent = 0
        failed = 0
        for r in rows:
            nid = int(r["id"])
            uid = int(r["user_id"])
            try:
                await bot.send_message(
                    chat_id=uid,
                    text=str(r["text_html"]),
                    parse_mode=str(r["parse_mode"] or ParseMode.HTML),
                    disable_web_page_preview=True,
                )
                with self.db.atomic(immediate=True) as conn:
                    conn.execute("UPDATE notification_queue SET status='sent', sent_at=? WHERE id=?", (now_utc_iso(), nid))
                sent += 1
            except Forbidden as exc:
                # User blocked the bot -> stop retrying permanently (RULE 55)
                with self.db.atomic(immediate=True) as conn:
                    conn.execute(
                        "UPDATE notification_queue SET status='failed', last_error=? WHERE id=?",
                        (f"Forbidden (bot blocked): {exc}", nid),
                    )
                failed += 1
            except RetryAfter as exc:
                next_dt = (now_utc() + timedelta(seconds=float(exc.retry_after) + 2)).strftime("%Y-%m-%d %H:%M:%S")
                with self.db.atomic(immediate=True) as conn:
                    conn.execute(
                        "UPDATE notification_queue SET status='retry_scheduled', next_retry_at=?, last_error=? WHERE id=?",
                        (next_dt, str(exc)[:300], nid),
                    )
            except Exception as exc:
                rc = int(r["retry_count"]) + 1
                max_r = int(r["max_retries"] or 3)
                if rc >= max_r:
                    with self.db.atomic(immediate=True) as conn:
                        conn.execute(
                            "UPDATE notification_queue SET status='failed', retry_count=?, last_error=? WHERE id=?",
                            (rc, str(exc)[:300], nid),
                        )
                    failed += 1
                else:
                    backoff_sec = 30 * (2 ** rc)
                    next_dt = (now_utc() + timedelta(seconds=backoff_sec)).strftime("%Y-%m-%d %H:%M:%S")
                    with self.db.atomic(immediate=True) as conn:
                        conn.execute(
                            "UPDATE notification_queue SET status='retry_scheduled', retry_count=?, next_retry_at=?, last_error=? WHERE id=?",
                            (rc, next_dt, str(exc)[:300], nid),
                        )
        return sent, failed


class BroadcastManager:
    def __init__(self, db: DatabaseManager, audit: AuditManager) -> None:
        self.db = db
        self.audit = audit

    def get_target_user_ids(self, audience: str = "all", language: str = "all") -> List[int]:
        clauses: List[str] = []
        params: List[Any] = []
        if audience == "active":
            clauses.append("status='active'")
        elif audience == "non_blocked":
            clauses.append("status != 'blocked'")
        elif audience == "task_users":
            clauses.append("user_id IN (SELECT DISTINCT user_id FROM task_submissions)")
        elif audience == "fs_users":
            clauses.append("user_id IN (SELECT DISTINCT user_id FROM fs_submissions)")
        elif audience == "store_users":
            clauses.append("user_id IN (SELECT DISTINCT user_id FROM store_orders)")
        elif audience == "otp_users":
            clauses.append("user_id IN (SELECT DISTINCT user_id FROM otp_sessions)")
        elif audience == "deposit_users":
            clauses.append("user_id IN (SELECT DISTINCT user_id FROM deposits)")

        if language in ("bn", "en"):
            clauses.append("language=?")
            params.append(language)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.query_all(f"SELECT user_id FROM users {where_sql}", params)
        return [int(r["user_id"]) for r in rows]

    async def send_broadcast(
        self,
        bot: Bot,
        admin_id: int,
        audience: str,
        language: str,
        media_type: str,
        content_text: str,
        media_file_id: str = "",
    ) -> Dict[str, Any]:
        targets = self.get_target_user_ids(audience, language)
        b_uid = generate_uid("BRC", 6)
        now_s = now_utc_iso()
        with self.db.atomic(immediate=True) as conn:
            cur = conn.execute(
                """
                INSERT INTO broadcast_logs
                (broadcast_uid, admin_id, audience_filter, language_filter, media_type, content_text, media_file_id, target_count, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sending', ?)
                """,
                (b_uid, int(admin_id), audience, language, media_type, content_text, media_file_id, len(targets), now_s),
            )
            b_id = int(cur.lastrowid or 0)

        sent = 0
        failed = 0
        for uid in targets:
            try:
                if media_type == "photo" and media_file_id:
                    await bot.send_photo(chat_id=uid, photo=media_file_id, caption=truncate_text(content_text, 1024), parse_mode=ParseMode.HTML)
                elif media_type == "video" and media_file_id:
                    await bot.send_video(chat_id=uid, video=media_file_id, caption=truncate_text(content_text, 1024), parse_mode=ParseMode.HTML)
                elif media_type == "document" and media_file_id:
                    await bot.send_document(chat_id=uid, document=media_file_id, caption=truncate_text(content_text, 1024), parse_mode=ParseMode.HTML)
                else:
                    await bot.send_message(chat_id=uid, text=truncate_text(content_text), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
                sent += 1
                await asyncio.sleep(0.05)
            except RetryAfter as exc:
                await asyncio.sleep(float(exc.retry_after) + 0.5)
                try:
                    await bot.send_message(chat_id=uid, text=truncate_text(content_text), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
                    sent += 1
                except Exception:
                    failed += 1
            except Exception:
                failed += 1

        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                "UPDATE broadcast_logs SET sent_count=?, failed_count=?, status='completed', completed_at=? WHERE id=?",
                (sent, failed, now_utc_iso(), b_id),
            )
        self.audit.log(admin_id, "admin", "broadcast", "broadcast", b_uid, {"sent": sent, "failed": failed})
        return {"broadcast_uid": b_uid, "target": len(targets), "sent": sent, "failed": failed}
# ==============================================================================
# REPORT MANAGER & BACKUP / RESTORE MANAGER (RULE 14, 39, 41, 95.B)
# ==============================================================================

class ReportManager:
    def __init__(self, db: DatabaseManager, config: ConfigManager, excel: ExcelManager) -> None:
        self.db = db
        self.config = config
        self.excel = excel

    def get_live_dashboard_stats(self) -> Dict[str, Any]:
        def _cnt(sql: str, params: Sequence[Any] = ()) -> int:
            r = self.db.query_one(sql, params)
            return int(r[0]) if r and r[0] is not None else 0

        def _sum(sql: str, params: Sequence[Any] = ()) -> float:
            r = self.db.query_one(sql, params)
            return round(float(r[0] or 0.0), 2) if r else 0.0

        return {
            "total_users": _cnt("SELECT COUNT(*) FROM users"),
            "active_users": _cnt("SELECT COUNT(*) FROM users WHERE status='active'"),
            "blocked_users": _cnt("SELECT COUNT(*) FROM users WHERE status='blocked'"),
            "warned_users": _cnt("SELECT COUNT(*) FROM users WHERE warning_count > 0"),
            "active_tasks": _cnt("SELECT COUNT(*) FROM tasks WHERE status='active' AND is_archived=0"),
            "pending_tasks": _cnt("SELECT COUNT(*) FROM task_submissions WHERE status='pending'"),
            "pending_fs": _cnt("SELECT COUNT(*) FROM fs_submissions WHERE pending_count > 0"),
            "pending_deposits": _cnt("SELECT COUNT(*) FROM deposits WHERE status='pending'"),
            "pending_withdraws": _cnt("SELECT COUNT(*) FROM withdrawals WHERE status IN ('requested','pending','approved')"),
            "pending_appeals": _cnt("SELECT COUNT(*) FROM appeals WHERE status='pending'"),
            "open_tickets": _cnt("SELECT COUNT(*) FROM support_tickets WHERE status='open'"),
            "store_stock_avail": _cnt("SELECT COUNT(*) FROM product_stock_items WHERE status='available'"),
            "store_orders_done": _cnt("SELECT COUNT(*) FROM store_orders WHERE status='completed'"),
            "otp_avail": _cnt("SELECT COUNT(*) FROM otp_numbers WHERE status='available'"),
            "otp_active_sessions": _cnt("SELECT COUNT(*) FROM otp_sessions WHERE status IN ('waiting','received')"),
            "total_earned_liability": _sum("SELECT SUM(earned_balance) FROM users"),
            "total_deposit_liability": _sum("SELECT SUM(deposit_balance) FROM users"),
            "total_held_liability": _sum("SELECT SUM(held_balance) FROM users"),
            "total_paid_withdraw": _sum("SELECT SUM(net_amount) FROM withdrawals WHERE status='paid'"),
            "total_approved_deposits": _sum("SELECT SUM(net_credit) FROM deposits WHERE status='approved'"),
            "total_commissions": _sum("SELECT SUM(amount) FROM ledger_transactions WHERE tx_type IN ('referral_commission','file_submit_commission') AND direction='credit'"),
            "total_bonuses": _sum("SELECT SUM(amount) FROM ledger_transactions WHERE tx_type IN ('bonus','daily_checkin_bonus','leaderboard_prize') AND direction='credit'"),
        }

    def get_financial_summary(self, period: str = "all") -> Dict[str, Any]:
        now_d = now_dhaka()
        if period == "daily":
            start_utc = now_d.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        elif period == "weekly":
            start_utc = (now_d - timedelta(days=7)).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        elif period == "monthly":
            start_utc = (now_d - timedelta(days=30)).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        else:
            start_utc = ""

        where_t = "WHERE created_at >= ?" if start_utc else ""
        params = (start_utc,) if start_utc else ()
        rows = self.db.query_all(
            f"SELECT tx_type, direction, SUM(amount) AS total_amt, COUNT(*) AS cnt FROM ledger_transactions {where_t} GROUP BY tx_type, direction",
            params,
        )
        breakdown: Dict[str, float] = {}
        for r in rows:
            key = f"{r['tx_type']}_{r['direction']}"
            breakdown[key] = round(float(r["total_amt"] or 0.0), 2)
        return {"period": period, "since_utc": start_utc, "breakdown": breakdown}

    def build_daily_summary_text(self, lang: str = "bn") -> str:
        st = self.get_live_dashboard_stats()
        fin = self.get_financial_summary("daily")
        bd = fin["breakdown"]
        bot_name = self.config.get_bot_name(lang=lang)
        div = self.config.get_theme()["divider"]
        return (
            f"📊 <b>{escape_html(bot_name)} — দৈনিক রাত ১২টার সামারি রিপোর্ট</b>\n{div}\n"
            f"📅 তারিখ (ঢাকা): <code>{dhaka_today_str()}</code>\n\n"
            f"👥 ইউজার: মোট <b>{st['total_users']}</b> | সক্রিয় <b>{st['active_users']}</b> | ব্লকড <b>{st['blocked_users']}</b>\n"
            f"⏳ পেন্ডিং কিউ:\n"
            f"  • Task: <b>{st['pending_tasks']}</b> | FS: <b>{st['pending_fs']}</b>\n"
            f"  • Deposit: <b>{st['pending_deposits']}</b> | Withdraw: <b>{st['pending_withdraws']}</b>\n"
            f"  • Ticket: <b>{st['open_tickets']}</b> | Appeal: <b>{st['pending_appeals']}</b>\n\n"
            f"💰 আজকের লেনদেন:\n"
            f"  • টাস্ক রিওয়ার্ড: <code>{format_money(bd.get('task_reward_credit', 0))}</code>\n"
            f"  • FS রিওয়ার্ড: <code>{format_money(bd.get('file_submit_reward_credit', 0))}</code>\n"
            f"  • ডিপোজিট ক্রেডিট: <code>{format_money(bd.get('deposit_credit_credit', 0))}</code>\n"
            f"  • স্টোর বিক্রি: <code>{format_money(bd.get('product_purchase_debit', 0))}</code>\n"
            f"  • উইথড্র Paid: <code>{format_money(bd.get('withdrawal_paid_debit', 0))}</code>\n\n"
            f"🏦 বর্তমান মোট Liability:\n"
            f"  • Earned: <code>{format_money(st['total_earned_liability'])}</code> | Deposit: <code>{format_money(st['total_deposit_liability'])}</code> | Held: <code>{format_money(st['total_held_liability'])}</code>"
        )

    def export_financial_ledger(self, period: str = "all", file_format: str = "xlsx", admin_id: int = 0) -> Tuple[bool, str, Optional[Path]]:
        fin = self.get_financial_summary(period)
        since_utc = fin["since_utc"]
        if since_utc:
            rows = self.db.query_all("SELECT * FROM ledger_transactions WHERE created_at >= ? ORDER BY id DESC", (since_utc,))
        else:
            rows = self.db.query_all("SELECT * FROM ledger_transactions ORDER BY id DESC LIMIT 5000")
        if not rows:
            return False, "No ledger transactions found for selected period.", None
        headers = ["Tx_UID", "User_ID", "Type", "Direction", "Amount", "Prev_Bal", "New_Bal", "Wallet", "Ref_ID", "Reason", "Time_Dhaka"]
        data = [
            [
                r["tx_uid"], int(r["user_id"]), r["tx_type"], r["direction"],
                float(r["amount"]), float(r["prev_balance"]), float(r["new_balance"]),
                r["wallet_bucket"], r["ref_id"], r["reason"], format_dhaka_dt(r["created_at"]),
            ]
            for r in rows
        ]
        path, _ = self.excel.export_rows(headers, data, f"Ledger_{period}", period, file_format, "Ledger", admin_id)
        return True, f"Exported {len(rows)} ledger transactions.", path


class BackupManager:
    """
    Runtime-Only Reset, Manual/Auto .zip Backup (using SQLite .backup() API),
    and Integrity-Checked Restore with mandatory Pre-Restore Safety Backup.
    """

    def __init__(self, db: DatabaseManager, runtime: RuntimeDB, audit: AuditManager) -> None:
        self.db = db
        self.runtime = runtime
        self.audit = audit

    def runtime_only_reset(self, admin_id: int) -> Dict[str, int]:
        cleared_states = self.runtime.clear_all_runtime()
        with self.db.atomic(immediate=True) as conn:
            cur_n = conn.execute("DELETE FROM notification_queue WHERE status IN ('sent','failed')")
            cleared_notif = int(cur_n.rowcount or 0)
        self.audit.log(admin_id, "admin", "runtime_only_reset", "runtime", "all", {"states": cleared_states, "notif": cleared_notif})
        return {"runtime_states": cleared_states, "notification_cache": cleared_notif}

    def create_zip_backup(self, backup_type: str = "manual", admin_id: int = 0) -> Tuple[bool, str, Optional[Path], str]:
        DATA_DIRS["backups"].mkdir(parents=True, exist_ok=True)
        b_uid = generate_uid("BKP", 6)
        stamp = now_dhaka().strftime("%Y%m%d_%H%M%S")
        zip_path = DATA_DIRS["backups"] / f"backup_{backup_type}_{stamp}_{b_uid}.zip"

        tmp_db = self.db.create_raw_db_backup(label=f"snap_{backup_type}")
        try:
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                if tmp_db and tmp_db.exists():
                    zf.write(tmp_db, arcname="database/bot_platform.db")
                for log_file in (APP_LOG_PATH, ERROR_LOG_PATH):
                    if log_file.exists():
                        zf.write(log_file, arcname=f"logs/{log_file.name}")
                meta = {
                    "backup_uid": b_uid,
                    "backup_type": backup_type,
                    "engine_version": BOT_ENGINE_VERSION,
                    "schema_version": DB_SCHEMA_VERSION,
                    "created_at_dhaka": now_dhaka_iso(),
                }
                zf.writestr("backup_meta.json", safe_json_dumps(meta))
        finally:
            if tmp_db and tmp_db.exists():
                try:
                    tmp_db.unlink()
                except Exception:
                    pass

        size_b = zip_path.stat().st_size if zip_path.exists() else 0
        with self.db.atomic(immediate=True) as conn:
            conn.execute(
                """
                INSERT INTO backup_history (backup_uid, backup_type, file_path, size_bytes, status, admin_id, created_at)
                VALUES (?, ?, ?, ?, 'completed', ?, ?)
                """,
                (b_uid, backup_type, str(zip_path), size_b, int(admin_id), now_utc_iso()),
            )
        self.audit.log(admin_id, "admin", "create_backup", "backup", b_uid, {"type": backup_type, "size": size_b})
        return True, f"Backup created ({round(size_b / 1024, 1)} KB).", zip_path, b_uid

    def mark_backup_sent_to_telegram(self, backup_uid: str) -> None:
        with self.db.atomic(immediate=True) as conn:
            conn.execute("UPDATE backup_history SET sent_to_telegram=1 WHERE backup_uid=?", (backup_uid,))

    def restore_from_zip(self, zip_path: Path, admin_id: int) -> Tuple[bool, str]:
        if not zip_path.exists():
            return False, "Backup zip file not found."
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                db_member = "database/bot_platform.db" if "database/bot_platform.db" in names else next((n for n in names if n.endswith(".db")), "")
                if not db_member:
                    return False, "No SQLite .db file found inside backup archive."
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
                    tf.write(zf.read(db_member))
                    cand_path = Path(tf.name)
        except Exception as exc:
            return False, f"Invalid zip backup: {exc}"

        try:
            # Verify SQLite integrity before replacing live DB
            chk = sqlite3.connect(str(cand_path))
            res = chk.execute("PRAGMA integrity_check").fetchone()
            chk.close()
            if not res or str(res[0]).lower() != "ok":
                return False, "Backup database failed SQLite integrity check."

            # Mandatory Pre-Restore Safety Backup
            self.db.create_raw_db_backup(label="pre_restore_safety")
            self.db.close_thread_conn()

            for suffix in ("", "-wal", "-shm"):
                target = Path(str(self.db.db_path) + suffix)
                if suffix and target.exists():
                    target.unlink()
            shutil.copy2(cand_path, self.db.db_path)
            self.db.initialize_and_migrate()
            self.audit.log(admin_id, "admin", "restore_backup", "backup", zip_path.name)
            return True, "Database restored safely (Pre-Restore safety backup preserved)."
        except Exception as exc:
            return False, f"Restore failed: {exc}"
        finally:
            if cand_path.exists():
                try:
                    cand_path.unlink()
                except Exception:
                    pass


# ==============================================================================
# CENTRAL PLATFORM CONTEXT CONTAINER
# ==============================================================================

class PlatformContext:
    """Wires all managers, adapters, and shared UI/gating utilities cleanly."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self._bot_ref: Optional[Bot] = None
        self.db = DatabaseManager(db_path=db_path)
        self.migration_info = self.db.initialize_and_migrate()
        self.runtime = RuntimeDB(self.db)
        self.seeder = DefaultSeeder(self.db)
        self.seeder.seed_all()

        self.config = ConfigManager(self.db)
        self.config.reload_cache()
        self.text = TextManager(self.db, self.config)
        self.rules = RuleController(self.db, self.config)
        self.studio = MessageStudioManager(self.db, self.config)
        self.studio.seed_all_variants()

        self.validation = ValidationManager(self.config)
        self.audit = AuditManager(self.db)
        self.permissions = PermissionManager(self.db, self.audit)
        self.kb = DualKeyboardManager(self.db, self.config, self.audit)
        self.force_join = ForceJoinManager(self.db, self.config, self.kb)

        self.ledger = LedgerManager(self.db, self.config, self.audit)
        self.users = UserManager(self.db, self.config, self.ledger, self.audit)
        self.reward = RewardManager(self.config, self.ledger)
        self.security = SecurityManager(self.db, self.config, self.audit)

        self.tasks = TaskManager(self.db, self.config, self.audit, self.security, self.ledger)
        self.task_subs = TaskSubmissionEngine(self.db, self.config, self.audit, self.security, self.ledger, self.reward, self.tasks, self.studio)

        self.excel = ExcelManager(self.db, self.config)
        self.fs = FileSubmitManager(self.db, self.config, self.audit, self.ledger, self.reward, self.excel)
        self.store = StoreManager(self.db, self.config, self.audit, self.ledger, self.excel)
        self.otp = OTPManager(self.db, self.config, self.audit, self.ledger, self.excel)
        self.webhook = SMSWebhookReceiver(self.otp, self.config)

        self.deposits = DepositManager(self.db, self.config, self.audit, self.security, self.ledger)
        self.withdrawals = WithdrawalManager(self.db, self.config, self.audit, self.security, self.ledger)

        self.referral = ReferralManager(self.db, self.config)
        self.bonuses = BonusManager(self.db, self.config, self.audit, self.ledger, self.excel)
        self.checkin = DailyCheckinManager(self.db, self.config, self.ledger)
        self.leaderboard = LeaderboardManager(self.db, self.config, self.audit, self.ledger)
        self.extensions = ExtensionsManager(self.db, self.config, self.ledger)
        self.tickets = SupportTicketManager(self.db, self.audit)
        self.appeals = AppealManager(self.db, self.audit)
        self.notifications = NotificationManager(self.db)
        self.broadcast = BroadcastManager(self.db, self.audit)
        self.reports = ReportManager(self.db, self.config, self.excel)
        self.backup = BackupManager(self.db, self.runtime, self.audit)

        # Register any configured API secrets in log masker
        SECRET_FILTER.register_secret(self.config.get_str("ocr_cloud_api_key", ""))
        SECRET_FILTER.register_secret(self.config.get_str("otp_webhook_secret", ""))
        SECRET_FILTER.register_secret(self.config.get_str("otp_provider_api_key", ""))
        SECRET_FILTER.register_secret(self.config.get_str("admin_panel_password", ""))

    def get_channels(self, purpose: str) -> List[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM channels WHERE purpose=? AND is_active=1 AND is_hidden=0 ORDER BY sort_order, id",
            (purpose,),
        )

    def get_primary_channel_id(self, purpose: str) -> Optional[str]:
        rows = self.get_channels(purpose)
        return str(rows[0]["chat_id"]) if rows else None

    def format_message_size(
        self,
        text_html: str,
        override_key: str = "",
        preserve_full_lines: bool = False,
    ) -> str:
        mode = self.config.get_str(override_key, "global") if override_key else "global"
        if mode == "global":
            mode = self.config.get_str("message_size_mode", "current")
        return apply_message_size_style(
            text_html,
            mode,
            divider=self.config.get_theme()["divider"],
            preserve_full_lines=preserve_full_lines,
        )

    async def reply_user_screen(
        self,
        update: Update,
        text_html: str,
        inline_markup: Optional[InlineKeyboardMarkup] = None,
        include_reply_kb: bool = False,
        user_id: Optional[int] = None,
        lang: str = "bn",
        apply_size: bool = True,
    ) -> Optional[Message]:
        """Renders cleanly for both Inline callbacks and Reply text messages."""
        if apply_size:
            text_html = self.format_message_size(text_html)
        uid = user_id or (update.effective_user.id if update.effective_user else 0)
        is_adm = self.permissions.is_any_admin(uid)
        reply_kb = self.kb.build_user_reply_keyboard(lang=lang, is_admin=is_adm) if include_reply_kb else None

        if update.callback_query and update.callback_query.message:
            try:
                if inline_markup is not None or not include_reply_kb:
                    msg = await update.callback_query.message.edit_text(
                        text=truncate_text(text_html),
                        parse_mode=ParseMode.HTML,
                        reply_markup=inline_markup,
                        disable_web_page_preview=True,
                    )
                    return msg if isinstance(msg, Message) else update.callback_query.message
            except BadRequest as exc:
                if "message is not modified" in str(exc).lower():
                    return update.callback_query.message
            chat_id = update.effective_chat.id if update.effective_chat else uid
            msg, _ = await safe_send_message_to_chat(
                update.get_bot(),
                chat_id,
                text_html,
                reply_markup=inline_markup if inline_markup is not None else reply_kb,
            )
            return msg

        if update.message:
            markup = reply_kb if (include_reply_kb and inline_markup is None) else inline_markup
            msg = await update.message.reply_text(
                text=truncate_text(text_html),
                parse_mode=ParseMode.HTML,
                reply_markup=markup,
                disable_web_page_preview=True,
            )
            return msg
        return None

    async def gatekeep_user(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
        module_key: str = "general",
        referrer_id: Optional[int] = None,
    ) -> Optional[sqlite3.Row]:
        """
        Ensures user registration, rate-limit, module lock/block checks, and Strict Force Join.
        Returns user sqlite3.Row if permitted, or None if blocked (after notifying user).
        """
        tg_user = update.effective_user
        if tg_user is None:
            return None
        uid = int(tg_user.id)
        is_adm = self.permissions.is_any_admin(uid)

        # Registration lock check for brand-new users
        existing = self.users.get_user(uid)
        if existing is None and not is_adm and self.config.get_bool("lock_registration", False):
            msg = self.text.get_text("system_locked_msg", "bn", feature_name="New Registration")
            await self.reply_user_screen(update, msg, user_id=uid)
            return None

        user_row, is_new = self.users.ensure_user_registered(
            user_id=uid,
            full_name=tg_user.full_name,
            username=tg_user.username or "",
            referrer_id=referrer_id,
        )
        lang = str(user_row["language"] or "bn")

        # Notify referrer on brand-new referral join (RULE 96 event)
        if is_new and user_row["referrer_id"]:
            ref_uid = int(user_row["referrer_id"])
            ref_u = self.users.get_user(ref_uid)
            if ref_u:
                r_dash = self.referral.get_dashboard(ref_uid)
                ref_msg, silent, enabled = self.studio.render_event_message(
                    "referral_new_join_alert",
                    lang=str(ref_u["language"] or "bn"),
                    name=str(ref_u["full_name"]),
                    ref_name=str(user_row["full_name"]),
                    ref_id_masked=str(uid),
                    total_refs=r_dash["total_refs"],
                    rate=r_dash["rate_text"],
                )
                if enabled and ref_msg:
                    self.notifications.enqueue(ref_uid, ref_msg)

        # Rate-limit check
        ok_rl, wait_s = self.security.check_rate_limit(uid)
        if not ok_rl:
            warn = f"⏳ অনুগ্রহ করে {wait_s} সেকেন্ড পর আবার চেষ্টা করুন।" if lang == "bn" else f"⏳ Too fast! Please wait {wait_s}s."
            await self.reply_user_screen(update, warn, user_id=uid, lang=lang)
            return None

        # Module lock & block check
        ok_acc, err_acc = self.security.check_module_access(uid, module_key, is_admin=is_adm)
        if not ok_acc:
            await self.reply_user_screen(update, f"🔒 {escape_html(err_acc)}", user_id=uid, lang=lang)
            return None

        # Strict Multi-Channel Force Join (RULE 5)
        if not is_adm:
            joined_all, statuses, _ = await self.force_join.verify_user_membership(context.bot, uid)
            if not joined_all:
                ch_lines = self.force_join.format_status_lines(statuses, lang=lang)
                fj_msg = self.text.get_text("force_join_required", lang, channels_status=ch_lines)
                fj_kb = self.force_join.build_force_join_markup(statuses, lang=lang)
                await self.reply_user_screen(update, fj_msg, inline_markup=fj_kb, user_id=uid, lang=lang)
                return None

        return user_row


# ==============================================================================
# USER HANDLERS — PART 1 (START, MENU, FORCE JOIN, PROFILE, BALANCE, GROWTH, SUPPORT)
# ==============================================================================

async def show_main_menu(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
    send_welcome_card: bool = False,
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    is_adm = pctx.permissions.is_any_admin(uid)
    avail = float(user_row["earned_balance"]) + float(user_row["deposit_balance"])

    if send_welcome_card:
        w_text, _, w_en = pctx.studio.render_event_message(
            "start_welcome",
            lang=lang,
            name=str(user_row["full_name"]),
            user_id=str(uid),
            balance=format_money(avail),
        )
        body = w_text if (w_en and w_text) else pctx.text.get_text(
            "welcome_header",
            lang,
            name=str(user_row["full_name"]),
            user_id=str(uid),
        )
    else:
        body = pctx.text.get_text(
            "main_menu_header",
            lang,
            name=str(user_row["full_name"]),
            balance=format_money(avail),
        )

    inline_menu = pctx.kb.build_user_inline_menu(lang=lang, is_admin=is_adm)
    reply_kb = pctx.kb.build_user_reply_keyboard(lang=lang, is_admin=is_adm)

    if update.callback_query:
        # Ensure ReplyKeyboard stays synchronized if enabled
        if isinstance(reply_kb, ReplyKeyboardRemove):
            pass
        await pctx.reply_user_screen(update, body, inline_markup=inline_menu, user_id=uid, lang=lang)
    elif update.message:
        if pctx.config.get_bool("reply_keyboard_enabled", True) and not pctx.config.get_bool("reply_keyboard_hidden", False):
            await update.message.reply_text(
                text=truncate_text(body),
                parse_mode=ParseMode.HTML,
                reply_markup=reply_kb,
                disable_web_page_preview=True,
            )
            if inline_menu is not None:
                hint = "👇 কুইক মেনু বাটন:" if lang == "bn" else "👇 Quick Menu:"
                await update.message.reply_text(hint, reply_markup=inline_menu)
        else:
            await update.message.reply_text(
                text=truncate_text(body),
                parse_mode=ParseMode.HTML,
                reply_markup=inline_menu if inline_menu is not None else reply_kb,
                disable_web_page_preview=True,
            )


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pctx: PlatformContext = context.application.bot_data["pctx"]
    tg_user = update.effective_user
    if tg_user is None:
        return
    pctx.runtime.clear_state(int(tg_user.id))

    referrer_id: Optional[int] = None
    if context.args:
        arg = str(context.args[0]).strip()
        if arg.startswith("ref_") and arg[4:].isdigit():
            referrer_id = int(arg[4:])
        elif arg.isdigit():
            referrer_id = int(arg)

    user_row = await pctx.gatekeep_user(update, context, module_key="general", referrer_id=referrer_id)
    if user_row is None:
        return
    await show_main_menu(pctx, update, context, user_row, send_welcome_card=True)


async def cmd_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pctx: PlatformContext = context.application.bot_data["pctx"]
    if update.effective_user:
        pctx.runtime.clear_state(int(update.effective_user.id))
    user_row = await pctx.gatekeep_user(update, context, module_key="general")
    if user_row is None:
        return
    await show_main_menu(pctx, update, context, user_row, send_welcome_card=False)


async def handle_force_join_verify(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pctx: PlatformContext = context.application.bot_data["pctx"]
    q = update.callback_query
    if q is None or update.effective_user is None:
        return
    uid = int(update.effective_user.id)
    lang = pctx.users.get_lang(uid)
    joined_all, statuses, api_errs = await pctx.force_join.verify_user_membership(context.bot, uid)
    if not joined_all:
        alert_txt = "❌ এখনো সব চ্যানেলে জয়েন করা হয়নি!" if lang == "bn" else "❌ You have not joined all required channels yet!"
        await q.answer(alert_txt, show_alert=True)
        ch_lines = pctx.force_join.format_status_lines(statuses, lang=lang)
        fj_msg = pctx.text.get_text("force_join_required", lang, channels_status=ch_lines)
        if api_errs:
            LOGGER.warning("Force Join API errors: %s", "; ".join(api_errs))
        await pctx.reply_user_screen(update, fj_msg, inline_markup=pctx.force_join.build_force_join_markup(statuses, lang), user_id=uid, lang=lang)
        return

    await q.answer("✅ Verified!", show_alert=False)
    user_row = pctx.users.get_user(uid)
    if user_row:
        await show_main_menu(pctx, update, context, user_row, send_welcome_card=True)


async def show_user_profile(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    stats = pctx.users.get_profile_stats(uid)
    max_str = pctx.config.get_int("warning_auto_block_strikes", 3)
    msg = pctx.text.get_text(
        "profile_template",
        lang,
        user_id=str(uid),
        name=str(user_row["full_name"]),
        username=f"@{user_row['username']}" if user_row["username"] else "-",
        reg_date=format_dhaka_dt(user_row["registered_at"]),
        vip_tier=str(user_row["vip_tier"]),
        warnings=str(user_row["warning_count"]),
        max_strikes=str(max_str),
        status=str(user_row["status"]).upper(),
        tasks_ok=str(stats["tasks_ok"]),
        fs_ok=str(stats["fs_ok"]),
        orders_ok=str(stats["orders_ok"]),
        deposits_ok=str(stats["deposits_ok"]),
        refs_count=str(stats["refs_count"]),
    )
    kb = InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, include_home=True)])
    await pctx.reply_user_screen(update, msg, inline_markup=kb, user_id=uid, lang=lang)


async def show_user_balance(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, page: int = 0) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    earned = float(user_row["earned_balance"])
    dep = float(user_row["deposit_balance"])
    held = float(user_row["held_balance"])
    avail = earned + dep

    msg = pctx.text.get_text(
        "balance_template",
        lang,
        available=format_money(avail),
        earned=format_money(earned),
        deposit=format_money(dep),
        held=format_money(held),
        withdrawn=format_money(user_row["total_withdrawn"]),
        total_earnings=format_money(user_row["total_earnings"]),
    )
    txs, total_tx = pctx.ledger.get_user_transactions(uid, limit=6, offset=page * 6)
    if txs:
        msg += "\n\n🧾 <b>সাম্প্রতিক লেনদেন:</b>\n" if lang == "bn" else "\n\n🧾 <b>Recent Transactions:</b>\n"
        for t in txs:
            sign = "+" if str(t["direction"]) == "credit" else "-"
            msg += f"• <code>{t['tx_uid']}</code> | {sign}{format_money(t['amount'])} ({t['tx_type']}) [{t['wallet_bucket']}]\n"

    rows: List[List[InlineKeyboardButton]] = []
    pag_row: List[InlineKeyboardButton] = []
    if page > 0:
        pag_row.append(pctx.kb.ibtn("◀️ Prev", callback_data=f"bal:p:{page - 1}", action_kind="default"))
    if (page + 1) * 6 < total_tx:
        pag_row.append(pctx.kb.ibtn("Next ▶️", callback_data=f"bal:p:{page + 1}", action_kind="default"))
    if pag_row:
        rows.append(pag_row)
    if pctx.config.get_bool("points_exchange_enabled", False):
        pts = float(user_row["points_balance"] or 0.0)
        rows.append([pctx.kb.ibtn(f"🔄 Points Exchange ({pts:g})", callback_data="ext:pts", action_kind="bonus")])
    rows.append(pctx.kb.nav_row(lang=lang, include_home=True))
    await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def show_user_rules(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    msg = pctx.text.get_text("rules_content", lang)
    if not msg.strip():
        msg = "📜 Rules are currently hidden by Admin." if lang == "en" else "📜 নিয়মাবলী বর্তমানে প্রদর্শিত নয়।"
    kb = InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, include_home=True)])
    await pctx.reply_user_screen(update, msg, inline_markup=kb, user_id=uid, lang=lang)


async def show_language_selector(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    prompt = pctx.text.get_text("choose_language_prompt", lang)
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("🇧🇩 বাংলা (BN)", callback_data="lang:set:bn", action_kind="primary"),
            pctx.kb.ibtn("🇺🇸 English (EN)", callback_data="lang:set:en", action_kind="primary"),
        ],
        pctx.kb.nav_row(lang=lang, include_home=True),
    ])
    await pctx.reply_user_screen(update, prompt, inline_markup=kb, user_id=uid, lang=lang)


async def show_referral_dashboard(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    if not pctx.config.get_bool("referral_enabled", True):
        await pctx.reply_user_screen(update, "🔒 Referral is currently disabled.", user_id=uid, lang=lang)
        return
    dash = pctx.referral.get_dashboard(uid)
    msg = pctx.text.get_text(
        "referral_dashboard_header",
        lang,
        ref_link=dash["ref_link"],
        total_refs=str(dash["total_refs"]),
        rate_text=dash["rate_text"],
        ref_earnings=format_money(dash["total_earnings"]),
    )
    kb = InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, include_home=True)])
    await pctx.reply_user_screen(update, msg, inline_markup=kb, user_id=uid, lang=lang)


async def show_bonuses_menu(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    items = pctx.bonuses.list_bonuses(active_only=True)
    div = pctx.config.get_theme()["divider"]
    if not items:
        msg = f"🎁 <b>ক্যাম্পেইন বোনাস</b>\n{div}\nবর্তমানে কোনো সক্রিয় বোনাস ক্যাম্পেইন নেই।" if lang == "bn" else f"🎁 <b>Campaign Bonuses</b>\n{div}\nNo active bonus campaigns right now."
        await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return

    lines = [f"🎁 <b>{'ক্যাম্পেইন ও মাইলস্টোন বোনাস' if lang == 'bn' else 'Milestone & Campaign Bonuses'}</b>", div]
    rows: List[List[InlineKeyboardButton]] = []
    for b in items:
        title = b["title_bn"] if lang == "bn" else b["title_en"]
        desc = b["desc_bn"] if lang == "bn" else b["desc_en"]
        rem = f"{b['claimed_count']}/{b['max_claims']}" if int(b["max_claims"]) > 0 else f"{b['claimed_count']}/∞"
        lines.append(f"• <b>{escape_html(title)}</b> — <code>{format_money(b['reward_amount'])}</code> ({rem})\n  <i>{escape_html(desc)}</i>")
        btn_lbl = f"🎁 Claim: {title[:18]} ({format_money(b['reward_amount'])})"
        rows.append([pctx.kb.ibtn(btn_lbl, callback_data=f"bon:claim:{b['id']}", action_kind="bonus")])
    rows.append(pctx.kb.nav_row(lang=lang))
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def show_daily_checkin(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    info = pctx.checkin.get_user_checkin_info(uid)
    div = pctx.config.get_theme()["divider"]
    base_amt = pctx.config.get_float("daily_checkin_amount", 2.0)
    if info["claimed_today"]:
        msg = (
            f"📅 <b>ডেইলি চেক-ইন</b>\n{div}\n✅ আজকের ({info['today_date']}) বোনাস ইতিমধ্যেই নেওয়া হয়েছে!\n🔥 বর্তমান স্ট্রিক: <b>{info['current_streak']} দিন</b>"
            if lang == "bn"
            else f"📅 <b>Daily Check-in</b>\n{div}\n✅ Today's ({info['today_date']}) bonus already claimed!\n🔥 Current Streak: <b>{info['current_streak']} day(s)</b>"
        )
        kb = InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)])
    else:
        msg = (
            f"📅 <b>ডেইলি চেক-ইন</b>\n{div}\n💰 আজকের বেস বোনাস: <code>{format_money(base_amt)}</code>\n🔥 বর্তমান স্ট্রিক: <b>{info['current_streak']} দিন</b>\n🏅 VIP: {user_row['vip_tier']}"
            if lang == "bn"
            else f"📅 <b>Daily Check-in</b>\n{div}\n💰 Today's Base Reward: <code>{format_money(base_amt)}</code>\n🔥 Current Streak: <b>{info['current_streak']} day(s)</b>\n🏅 VIP: {user_row['vip_tier']}"
        )
        claim_lbl = "🎁 আজকের বোনাস নিন" if lang == "bn" else "🎁 Claim Daily Bonus"
        kb = InlineKeyboardMarkup([
            [pctx.kb.ibtn(claim_lbl, callback_data="chk:claim", action_kind="checkin")],
            pctx.kb.nav_row(lang=lang),
        ])
    await pctx.reply_user_screen(update, msg, inline_markup=kb, user_id=uid, lang=lang)


async def show_leaderboard_screen(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, board_type: str) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    text = pctx.leaderboard.format_leaderboard_text(board_type, lang=lang, viewer_user_id=uid)
    other = "fs" if board_type == "task" else "task"
    other_lbl = ("📊 FS লিডারবোর্ড দেখুন" if other == "fs" else "🏆 টাস্ক লিডারবোর্ড দেখুন") if lang == "bn" else ("📊 FS Leaderboard" if other == "fs" else "🏆 Task Leaderboard")
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("🔄 Refresh", callback_data=f"lb:view:{board_type}", action_kind="default"),
            pctx.kb.ibtn(other_lbl, callback_data=f"lb:view:{other}", action_kind="primary"),
        ],
        pctx.kb.nav_row(lang=lang),
    ])
    await pctx.reply_user_screen(update, text, inline_markup=kb, user_id=uid, lang=lang)


async def show_support_and_tickets(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    contacts = pctx.db.query_all("SELECT * FROM support_contacts WHERE is_active=1 AND is_hidden=0 ORDER BY sort_order, id")
    c_lines = []
    for c in contacts:
        desc = c["description_bn"] if lang == "bn" else c["description_en"]
        c_lines.append(f"• <b>{escape_html(c['name'])}</b>: {escape_html(c['username_or_link'])}\n  <i>{escape_html(desc)}</i>")
    c_str = "\n".join(c_lines) if c_lines else DEFAULT_SUPPORT_USERNAME

    msg = pctx.text.get_text("ticket_intro_prompt", lang, contacts=c_str)
    my_tkts = pctx.tickets.list_user_tickets(uid, limit=5)
    if my_tkts:
        msg += "\n\n🗂️ <b>আপনার সাম্প্রতিক টিকেট:</b>\n" if lang == "bn" else "\n\n🗂️ <b>Your Recent Tickets:</b>\n"
        for t in my_tkts:
            msg += f"• <code>{t['ticket_uid']}</code> [{t['status']}] — {escape_html(t['subject'])}\n"
            if t["admin_reply"]:
                msg += f"  💬 <i>{escape_html(t['admin_reply'][:120])}</i>\n"

    kb = InlineKeyboardMarkup([
        [pctx.kb.ibtn("➕ নতুন টিকেট খুলুন" if lang == "bn" else "➕ Open New Ticket", callback_data="tkt:new", action_kind="primary")],
        pctx.kb.nav_row(lang=lang),
    ])
    await pctx.reply_user_screen(update, msg, inline_markup=kb, user_id=uid, lang=lang)


async def handle_custom_dynamic_button(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, btn_id: int) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    btn = pctx.kb.get_button_by_id(btn_id)
    if btn is None or int(btn["is_enabled"]) != 1 or int(btn["is_archived"]) == 1:
        await pctx.reply_user_screen(update, "⚠️ This button is currently unavailable.", user_id=uid, lang=lang)
        return
    atype = str(btn["action_type"])
    target = str(btn["action_target"])
    if atype == "url" and target.startswith(("http://", "https://", "tg://")):
        lbl = btn["label_bn"] if lang == "bn" else btn["label_en"]
        kb = InlineKeyboardMarkup([
            [pctx.kb.ibtn(f"🔗 {lbl}", url=target, action_kind="primary")],
            pctx.kb.nav_row(lang=lang),
        ])
        await pctx.reply_user_screen(update, f"🔗 <b>{escape_html(lbl)}</b>", inline_markup=kb, user_id=uid, lang=lang)
    elif atype == "info":
        title = btn["label_bn"] if lang == "bn" else btn["label_en"]
        body = (btn["instruction_bn"] or btn["description_bn"]) if lang == "bn" else (btn["instruction_en"] or btn["description_en"])
        await pctx.reply_user_screen(
            update,
            f"📌 <b>{escape_html(title)}</b>\n{pctx.config.get_theme()['divider']}\n{escape_html(body)}",
            inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]),
            user_id=uid,
            lang=lang,
        )
    elif atype == "task" and target.isdigit():
        await start_user_task_flow(pctx, update, user_row, int(target))
    elif atype == "store_cat" and target.isdigit():
        await show_store_products_list(pctx, update, user_row, int(target))
    elif atype == "fs" and target.isdigit():
        await start_user_fs_flow(pctx, update, user_row, int(target))
    else:
        await show_main_menu(pctx, update, context=None, user_row=user_row, send_welcome_card=False)  # type: ignore[arg-type]
# ==============================================================================
# USER HANDLERS — PART 2 (U-01 TASK FLOW, U-02 FILE SUBMIT, U-04 ORDERS/APPEAL)
# ==============================================================================

async def show_tasks_list(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    tasks = pctx.tasks.list_tasks(active_only=True)
    div = pctx.config.get_theme()["divider"]
    if not tasks:
        msg = (
            f"📋 <b>উপলব্ধ কাজ (Tasks)</b>\n{div}\nবর্তমানে কোনো সক্রিয় কাজ নেই। পরে আবার দেখুন!"
            if lang == "bn"
            else f"📋 <b>Available Tasks</b>\n{div}\nNo active tasks right now. Check back soon!"
        )
        await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return

    size_mode = pctx.config.get_str("message_size_mode", "current")
    header = f"📋 <b>{'কাজসমূহ নির্বাচন করুন' if lang == 'bn' else 'Select a Task'}</b>"
    lines = [header] if size_mode in ("short", "medium") else [header, div]
    rows: List[List[InlineKeyboardButton]] = []
    for t in tasks:
        tid = int(t["id"])
        title = str(t["title_bn"] if lang == "bn" else t["title_en"])
        rew = format_money(t["reward_amount"])
        if size_mode == "short":
            lines.append(f"• <b>{escape_html(title)}</b> — <code>{rew}</code>")
        else:
            stock_txt = ""
            if int(t["source_enabled"]) == 1:
                cnts = pctx.tasks.get_source_counts(tid)
                stock_txt = f" | 📦 {cnts['available']}"
            lim_txt = f" | ডেইলি: {t['daily_limit']}" if int(t["daily_limit"]) > 0 else ""
            lines.append(f"• <b>{escape_html(title)}</b> — 💰 <code>{rew}</code>{stock_txt}{lim_txt}")
        rows.append([pctx.kb.ibtn(f"▶️ {title[:26]} ({rew})", callback_data=f"tsk:go:{tid}", action_kind="task")])

    rows.append(pctx.kb.nav_row(lang=lang))
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def start_user_task_flow(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, task_id: int) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    task = pctx.tasks.get_task(task_id)
    if task is None:
        await pctx.reply_user_screen(update, "⚠️ Task not found.", user_id=uid, lang=lang)
        return

    ok_alloc, err_alloc, alloc = pctx.tasks.allocate_source_for_user(task_id, user_row)
    if not ok_alloc or alloc is None:
        await pctx.reply_user_screen(
            update,
            f"⚠️ {escape_html(err_alloc)}",
            inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, back_cb="um:u_tasks")]),
            user_id=uid,
            lang=lang,
        )
        return

    if alloc.get("low_stock_alert"):
        msg_low = f"⚠️ <b>Low Stock Alert (Task #{task_id}):</b> {escape_html(task['title_en'])} has only <b>{alloc.get('remaining_stock', 0)}</b> source record(s) left!"
        pctx.notifications.enqueue(DEFAULT_MAIN_ADMIN_ID, msg_low)

    wf_uid = generate_uid("WF", 5)
    state_data: Dict[str, Any] = {
        "workflow_uid": wf_uid,
        "task_id": task_id,
        "allocation_id": alloc["allocation_id"],
        "source_record_id": alloc["source_record_id"],
        "source_fields": alloc["fields"],
        "assigned_password": alloc["assigned_password"],
        "internal_test_code": alloc["internal_test_code"],
        "pre_steps": [dict(s) for s in pctx.tasks.list_task_steps(task_id, "pre_code", active_only=True)],
        "post_steps": [dict(s) for s in pctx.tasks.list_task_steps(task_id, "post_code", active_only=True)],
        "pre_idx": 0,
        "post_idx": 0,
        "answers": [],
        "totp_data": {},
        "cookie_data": {},
        "submitting": False,
    }
    pctx.runtime.set_state(uid, flow="task", step="init", data=state_data, ttl_seconds=3600)

    # Layer 1: Mandatory Dedicated Source Data Card
    title = str(task["title_bn"] if lang == "bn" else task["title_en"])
    instr = str(task["instruction_bn"] if lang == "bn" else task["instruction_en"])
    div = pctx.config.get_theme()["divider"]
    card_lines = [f"📋 <b>{escape_html(title)}</b>", div]
    if instr:
        card_lines.append(f"📝 <i>{escape_html(instr)}</i>\n")

    if alloc["fields"] or alloc["internal_test_code"]:
        card_lines.append("🔐 <b>আপনার বরাদ্দকৃত তথ্য (ট্যাপ করে কপি করুন):</b>" if lang == "bn" else "🔐 <b>Allocated Source Data (Tap to copy):</b>")
        for fk, fv in alloc["fields"].items():
            card_lines.append(f"• <b>{escape_html(fk)}:</b> <code>{escape_html(fv)}</code>")
        if alloc["internal_test_code"]:
            card_lines.append(f"• <b>Test Code:</b> <code>{escape_html(alloc['internal_test_code'])}</code>")
        if alloc["expires_at"]:
            card_lines.append(f"⏳ মেয়াদ: {format_dhaka_dt(alloc['expires_at'])}")

    chat_id = update.effective_chat.id if update.effective_chat else uid
    if alloc["fields"]:
        sent_card, _ = await safe_send_message_to_chat(update.get_bot(), chat_id, "\n".join(card_lines))
        if sent_card:
            pctx.task_subs.track_workflow_message(wf_uid, uid, chat_id, sent_card.message_id, task_id, is_bot_msg=True)
    elif instr:
        sent_ins, _ = await safe_send_message_to_chat(update.get_bot(), chat_id, "\n".join(card_lines))
        if sent_ins:
            pctx.task_subs.track_workflow_message(wf_uid, uid, chat_id, sent_ins.message_id, task_id, is_bot_msg=True)

    await advance_user_task_flow(pctx, update, user_row)


async def advance_user_task_flow(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    st = pctx.runtime.get_state(uid)
    if not st or st["flow"] != "task":
        return

    data = st["data"]
    task_id = int(data["task_id"])
    task = pctx.tasks.get_task(task_id)
    if task is None:
        pctx.runtime.clear_state(uid)
        return

    wf_uid = data["workflow_uid"]
    chat_id = update.effective_chat.id if update.effective_chat else uid
    pre_steps: List[Dict[str, Any]] = data["pre_steps"]
    post_steps: List[Dict[str, Any]] = data["post_steps"]
    pre_idx = int(data["pre_idx"])
    post_idx = int(data["post_idx"])

    # 1. Layer 2: Pre-Code Dynamic Steps
    if pre_idx < len(pre_steps):
        step_obj = pre_steps[pre_idx]
        pctx.runtime.update_data(uid, {"current_step_obj": step_obj, "current_phase": "pre"}, new_step="await_step_input")
        await _send_task_step_prompt(pctx, chat_id, wf_uid, uid, task_id, step_obj, pre_idx + 1, len(pre_steps), lang)
        return

    # 2. Layer 3a: 16/32 Key -> 6-Digit TOTP Step
    if pctx.task_subs.is_totp_required(task) and not data.get("totp_data"):
        pctx.runtime.set_state(uid, flow="task", step="await_totp", data=data)
        prompt = pctx.text.get_text("task_totp_prompt", lang)
        kb = InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang, cancel_cb="tsk:cancel")])
        sent, _ = await safe_send_message_to_chat(pctx._bot_ref if hasattr(pctx, "_bot_ref") else update.get_bot(), chat_id, prompt, reply_markup=kb)
        if sent:
            pctx.task_subs.track_workflow_message(wf_uid, uid, chat_id, sent.message_id, task_id, is_bot_msg=True)
        return

    # 3. Layer 3b: Account Cookie Verification Step
    if pctx.task_subs.is_cookie_required(task) and not data.get("cookie_data"):
        req_keys = pctx.task_subs.get_effective_cookie_keys(task)
        pctx.runtime.set_state(uid, flow="task", step="await_cookie", data=data)
        prompt = pctx.text.get_text("task_cookie_prompt", lang, required_keys=req_keys)
        kb = InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang, cancel_cb="tsk:cancel")])
        sent, _ = await safe_send_message_to_chat(update.get_bot(), chat_id, prompt, reply_markup=kb)
        if sent:
            pctx.task_subs.track_workflow_message(wf_uid, uid, chat_id, sent.message_id, task_id, is_bot_msg=True)
        return

    # 4. Layer 4a: Post-Code Dynamic Steps
    if post_idx < len(post_steps):
        step_obj = post_steps[post_idx]
        pctx.runtime.update_data(uid, {"current_step_obj": step_obj, "current_phase": "post"}, new_step="await_step_input")
        await _send_task_step_prompt(pctx, chat_id, wf_uid, uid, task_id, step_obj, post_idx + 1, len(post_steps), lang)
        return

    # 5. Layer 4b: Preview & Final Confirm
    pctx.runtime.set_state(uid, flow="task", step="await_confirm", data=data)
    await _send_task_preview(pctx, update, user_row, task, data)


async def _send_task_step_prompt(
    pctx: PlatformContext,
    chat_id: int,
    wf_uid: str,
    user_id: int,
    task_id: int,
    step_obj: Dict[str, Any],
    idx_disp: int,
    total_disp: int,
    lang: str,
) -> None:
    title = step_obj["title_bn"] if lang == "bn" else step_obj["title_en"]
    instr = step_obj["instruction_bn"] if lang == "bn" else step_obj["instruction_en"]
    text = f"📌 <b>ধাপ {idx_disp}/{total_disp}: {escape_html(title)}</b>" if lang == "bn" else f"📌 <b>Step {idx_disp}/{total_disp}: {escape_html(title)}</b>"
    if instr:
        text += f"\n<i>{escape_html(instr)}</i>"

    rows: List[List[InlineKeyboardButton]] = []
    if step_obj.get("input_type") == "select":
        opts = safe_json_loads(step_obj.get("options_json"), [])
        for oi, opt in enumerate(opts[:10]):
            rows.append([pctx.kb.ibtn(str(opt), callback_data=f"tsk:opt:{oi}", action_kind="primary")])

    nav_r: List[InlineKeyboardButton] = []
    if int(step_obj.get("allow_skip", 0)) == 1 or int(step_obj.get("is_required", 1)) == 0:
        nav_r.append(pctx.kb.ibtn("⏭️ Skip", callback_data="tsk:skip", action_kind="default"))
    nav_r.append(pctx.kb.ibtn("❌ বাতিল" if lang == "bn" else "❌ Cancel", callback_data="tsk:cancel", action_kind="cancel"))
    rows.append(nav_r)

    bot = pctx._bot_ref  # set in application startup
    sent, _ = await safe_send_message_to_chat(bot, chat_id, text, reply_markup=InlineKeyboardMarkup(rows))
    if sent:
        pctx.task_subs.track_workflow_message(wf_uid, user_id, chat_id, sent.message_id, task_id, is_bot_msg=True)


async def _send_task_preview(
    pctx: PlatformContext,
    update: Update,
    user_row: sqlite3.Row,
    task: sqlite3.Row,
    data: Dict[str, Any],
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    title = str(task["title_bn"] if lang == "bn" else task["title_en"])
    div = pctx.config.get_theme()["divider"]
    uname = f"@{user_row['username']}" if user_row["username"] else "-"

    lines = [
        f"🧾 <b>{'সাবমিশন প্রিভিউ' if lang == 'bn' else 'Submission Preview'}</b>",
        div,
        f"📋 <b>Task:</b> {escape_html(title)}",
        f"👤 <b>User:</b> {escape_html(user_row['full_name'])} ({escape_html(uname)})",
        f"💰 <b>Reward:</b> <code>{format_money(task['reward_amount'])}</code>",
    ]
    if data.get("source_fields"):
        lines.append("\n🔐 <b>Allocated Source:</b>")
        for k, v in data["source_fields"].items():
            lines.append(f"  • {escape_html(k)}: <code>{escape_html(v)}</code>")
    if data.get("totp_data"):
        td = data["totp_data"]
        lines.append(f"\n🔑 <b>TOTP Key:</b> <code>{escape_html(td.get('totp_secret',''))}</code> → <code>{escape_html(td.get('totp_6digit_code',''))}</code>")
    if data.get("cookie_data"):
        cd = data["cookie_data"]
        lines.append(f"🍪 <b>Cookie:</b> ✅ Verified ({cd.get('cookie_pairs_count', 0)} keys)")
    if data.get("answers"):
        lines.append("\n📝 <b>Steps:</b>")
        for ans in data["answers"]:
            lines.append(f"  • {escape_html(ans['label'])}: <code>{escape_html(str(ans['value'])[:120])}</code>")

    kb = InlineKeyboardMarkup([
        [pctx.kb.ibtn("✅ Final Confirm" if lang == "en" else "✅ চূড়ান্ত জমা দিন", callback_data="tsk:conf", action_kind="confirm")],
        [
            pctx.kb.ibtn("🔄 পুনরায় শুরু" if lang == "bn" else "🔄 Edit / Restart", callback_data=f"tsk:go:{task['id']}", action_kind="default"),
            pctx.kb.ibtn("❌ বাতিল" if lang == "bn" else "❌ Cancel", callback_data="tsk:cancel", action_kind="cancel"),
        ],
    ])
    chat_id = update.effective_chat.id if update.effective_chat else uid
    sent, _ = await safe_send_message_to_chat(update.get_bot(), chat_id, "\n".join(lines), reply_markup=kb)
    if sent:
        pctx.task_subs.track_workflow_message(data["workflow_uid"], uid, chat_id, sent.message_id, int(task["id"]), is_bot_msg=True)


async def handle_task_runtime_input(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
    st: Dict[str, Any],
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    msg = update.message
    if msg is None:
        return
    data = st["data"]
    step = st["step"]
    task_id = int(data["task_id"])
    wf_uid = data["workflow_uid"]
    chat_id = msg.chat_id
    pctx.task_subs.track_workflow_message(wf_uid, uid, chat_id, msg.message_id, task_id, is_bot_msg=False)

    task = pctx.tasks.get_task(task_id)
    if task is None:
        pctx.runtime.clear_state(uid)
        return

    text_val = (msg.text or msg.caption or "").strip()

    if step == "await_step_input":
        step_obj = data.get("current_step_obj", {})
        itype = str(step_obj.get("input_type", "text"))
        val_to_store = text_val

        if itype in ("photo", "file"):
            if msg.photo:
                val_to_store = f"photo:{msg.photo[-1].file_id}"
            elif msg.document:
                ok_f, err_f = pctx.validation.validate_upload_file(msg.document.file_name or "file", msg.document.file_size or 0)
                if not ok_f:
                    await msg.reply_text(f"⚠️ {err_f}")
                    return
                val_to_store = f"doc:{msg.document.file_id}:{msg.document.file_name or 'doc'}"
            elif not text_val:
                await msg.reply_text("⚠️ অনুগ্রহ করে ছবি বা ফাইল পাঠান।" if lang == "bn" else "⚠️ Please send a photo or file.")
                return
        else:
            opts = safe_json_loads(step_obj.get("options_json"), [])
            ok_v, err_v = ValidationManager.validate_step_input(
                itype,
                text_val,
                min_len=int(step_obj.get("min_len", 0)),
                max_len=int(step_obj.get("max_len", 2000)),
                regex_pattern=str(step_obj.get("regex_pattern", "")),
                options=opts,
            )
            if not ok_v:
                await msg.reply_text(pctx.text.get_text("invalid_input_error", lang, detail=err_v), parse_mode=ParseMode.HTML)
                return

        answers = list(data.get("answers", []))
        answers.append({"label": step_obj.get("title_en") or step_obj.get("title_bn") or "Step", "value": val_to_store})
        phase = data.get("current_phase", "pre")
        patch: Dict[str, Any] = {"answers": answers}
        if phase == "pre":
            patch["pre_idx"] = int(data["pre_idx"]) + 1
        else:
            patch["post_idx"] = int(data["post_idx"]) + 1
        pctx.runtime.update_data(uid, patch)
        await advance_user_task_flow(pctx, update, user_row)
        return

    if step == "await_totp":
        ok_t, err_t, t_info = pctx.task_subs.validate_totp_submission(task, text_val)
        if not ok_t:
            if "Duplicate" in err_t:
                err_msg = pctx.text.get_text("task_totp_duplicate_err", lang)
            else:
                err_msg = pctx.text.get_text("invalid_input_error", lang, detail=err_t)
            sent_e = await msg.reply_text(err_msg, parse_mode=ParseMode.HTML)
            pctx.task_subs.track_workflow_message(wf_uid, uid, chat_id, sent_e.message_id, task_id, is_bot_msg=True)
            return

        pctx.runtime.update_data(uid, {"totp_data": t_info}, new_step="totp_generated")
        code_6 = t_info["totp_6digit_code"]
        rem = t_info["remaining_sec"]
        msg_code = (
            f"🔐 <b>৬-ডিজিট TOTP কোড প্রস্তুত!</b>\n"
            f"👉 কোড: <code>{code_6}</code> (বাকি {rem} সেকেন্ড)\n"
            f"<i>ট্যাপ করে কপি করুন এবং নিচে Continue চাপুন।</i>"
            if lang == "bn"
            else f"🔐 <b>6-Digit TOTP Code Ready!</b>\n👉 Code: <code>{code_6}</code> ({rem}s remaining)\n<i>Tap to copy, then press Continue.</i>"
        )
        kb = InlineKeyboardMarkup([
            [
                pctx.kb.ibtn("🔄 Refresh Code", callback_data="tsk:totpref", action_kind="default"),
                pctx.kb.ibtn("➡️ Continue", callback_data="tsk:totpok", action_kind="confirm"),
            ],
            pctx.kb.cancel_row(lang=lang, cancel_cb="tsk:cancel"),
        ])
        sent_c = await msg.reply_text(msg_code, parse_mode=ParseMode.HTML, reply_markup=kb)
        pctx.task_subs.track_workflow_message(wf_uid, uid, chat_id, sent_c.message_id, task_id, is_bot_msg=True)
        return

    if step == "await_cookie":
      cookie_input = text_val
      if not cookie_input and msg.document:
          doc_name = (msg.document.file_name or "").lower()
          if doc_name.endswith((".txt", ".json", ".cookie")) and (msg.document.file_size or 0) <= 512 * 1024:
              tg_doc = await context.bot.get_file(msg.document.file_id)
              buf = io.BytesIO()
              await tg_doc.download_to_memory(buf)
              cookie_input = buf.getvalue().decode("utf-8-sig", errors="replace").strip()

      ok_ck, err_ck, ck_info = pctx.task_subs.validate_cookie_submission(task, cookie_input)
      if not ok_ck:
          err_msg = pctx.text.get_text("task_cookie_duplicate_err", lang, reason=err_ck)
          sent_e = await msg.reply_text(err_msg, parse_mode=ParseMode.HTML)
          pctx.task_subs.track_workflow_message(wf_uid, uid, chat_id, sent_e.message_id, task_id, is_bot_msg=True)
          return
      pctx.runtime.update_data(uid, {"cookie_data": ck_info})
      await advance_user_task_flow(pctx, update, user_row)


async def finalize_user_task_submission(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    st = pctx.runtime.get_state(uid)
    if not st or st["flow"] != "task" or st["step"] != "await_confirm":
        return
    data = st["data"]
    if data.get("submitting"):
        return
    pctx.runtime.update_data(uid, {"submitting": True})

    task_id = int(data["task_id"])
    task = pctx.tasks.get_task(task_id)
    ok_sub, msg_sub, res = pctx.task_subs.submit_task(
        task_id=task_id,
        user_row=user_row,
        allocation_id=int(data.get("allocation_id", 0)),
        source_record_id=int(data.get("source_record_id", 0)),
        source_snapshot=data.get("source_fields", {}),
        step_answers=data.get("answers", []),
        totp_data=data.get("totp_data"),
        cookie_data=data.get("cookie_data"),
    )
    wf_uid = data["workflow_uid"]
    pctx.runtime.clear_state(uid)

    if not ok_sub:
        await pctx.reply_user_screen(update, f"❌ {escape_html(msg_sub)}", inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return

    # Post to Task Review Channel (-1004422832745)
    rev_ch = pctx.get_primary_channel_id("task_fs_review")
    if rev_ch:
        uname = f"@{user_row['username']}" if user_row["username"] else "-"
        susp = f"\n⚠️ <b>Suspicious:</b> {escape_html(res['suspicious_note'])}" if res["is_suspicious"] else ""
        totp_str = f"\n🔑 <b>TOTP:</b> <code>{escape_html(data.get('totp_data',{}).get('totp_6digit_code','-'))}</code>" if data.get("totp_data") else ""
        ck_str = f"\n🍪 <b>Cookie:</b> Verified ({data.get('cookie_data',{}).get('cookie_pairs_count',0)} keys)" if data.get("cookie_data") else ""
        ch_text = (
            f"📋 <b>New Task Submission</b> | <code>{res['sub_uid']}</code>\n"
            f"📌 <b>Task:</b> {escape_html(res['task_title_en'])}\n"
            f"👤 <b>User:</b> {escape_html(user_row['full_name'])} ({escape_html(uname)}) [<code>{uid}</code>]\n"
            f"💰 <b>Reward:</b> <code>{format_money(res['reward'])}</code> | Mode: <code>{res['auto_mode']}</code>"
            f"{totp_str}{ck_str}{susp}\n"
            f"🕒 {now_dhaka_iso()}"
        )
        ch_kb = InlineKeyboardMarkup([[
            pctx.kb.ibtn("✅ Approve", callback_data=f"ch:tsk:app:{res['id']}", action_kind="approve"),
            pctx.kb.ibtn("❌ Reject", callback_data=f"ch:tsk:rej:{res['id']}", action_kind="reject"),
        ]])
        ch_msg, ch_err = await safe_send_message_to_chat(context.bot, rev_ch, ch_text, reply_markup=ch_kb)
        if ch_msg:
            pctx.task_subs.set_review_channel_ref(int(res["id"]), rev_ch, ch_msg.message_id)
        else:
            LOGGER.error("Task review channel send failed (%s): %s", rev_ch, ch_err)

    # RULE 69: Auto-Delete Workflow Messages
    if task and int(task["auto_delete_messages"]) == 1:
        await pctx.task_subs.cleanup_workflow_messages(context.bot, wf_uid)

    # RULE 96 Confirmation Card
    task_title = res["task_title_bn"] if lang == "bn" else res["task_title_en"]
    conf_msg, _, enabled = pctx.studio.render_event_message(
        "task_submitted_confirm",
        lang=lang,
        name=str(user_row["full_name"]),
        sub_uid=res["sub_uid"],
        task_title=task_title,
        reward=format_money(res["reward"]),
    )
    final_txt = conf_msg if (enabled and conf_msg) else f"✅ Submitted! ID: <code>{res['sub_uid']}</code>"
    chat_id = update.effective_chat.id if update.effective_chat else uid
    await safe_send_message_to_chat(
        context.bot,
        chat_id,
        final_txt,
        reply_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]),
    )


# --- U-02: Independent File Submit Flow ---

async def show_fs_tasks_list(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    fs_list = pctx.fs.list_fs_tasks(active_only=True)
    div = pctx.config.get_theme()["divider"]
    if not fs_list:
        msg = f"📁 <b>ফাইল সাবমিট</b>\n{div}\nবর্তমানে কোনো সক্রিয় FS কাজ নেই।" if lang == "bn" else f"📁 <b>File Submit</b>\n{div}\nNo active File Submit tasks right now."
        await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return

    lines = [f"📁 <b>{'ফাইল সাবমিট কাজসমূহ' if lang == 'bn' else 'File Submit Tasks'}</b>", div]
    rows: List[List[InlineKeyboardButton]] = []
    for f in fs_list:
        title = str(f["title_bn"] if lang == "bn" else f["title_en"])
        rate = format_money(f["reward_per_record"])
        lines.append(f"• <b>{escape_html(title)}</b> — <code>{rate}</code> / রেকর্ড")
        rows.append([pctx.kb.ibtn(f"📤 {title[:26]} ({rate})", callback_data=f"fs:go:{f['id']}", action_kind="primary")])
    rows.append(pctx.kb.nav_row(lang=lang))
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def start_user_fs_flow(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, fs_task_id: int) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    fs_t = pctx.fs.get_fs_task(fs_task_id)
    if fs_t is None:
        await pctx.reply_user_screen(update, "⚠️ FS Task not found.", user_id=uid, lang=lang)
        return
    ok_l, err_l = pctx.fs.check_user_fs_limits(fs_t, uid)
    if not ok_l:
        await pctx.reply_user_screen(update, f"⚠️ {escape_html(err_l)}", inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, back_cb="um:u_file_submit")]), user_id=uid, lang=lang)
        return

    pctx.runtime.set_state(uid, flow="fs", step="await_upload", data={"fs_task_id": fs_task_id})
    title = fs_t["title_bn"] if lang == "bn" else fs_t["title_en"]
    instr = fs_t["instruction_bn"] if lang == "bn" else fs_t["instruction_en"]
    fmts = ", ".join(safe_json_loads(fs_t["allowed_formats_json"], ["txt", "csv", "xls", "xlsx"]))
    msg = (
        f"📁 <b>{escape_html(title)}</b>\n{pctx.config.get_theme()['divider']}\n"
        f"💰 প্রতি বৈধ রেকর্ড: <code>{format_money(fs_t['reward_per_record'])}</code>\n"
        f"📄 অনুমোদিত ফরম্যাট: <code>{escape_html(fmts)}</code>\n"
        f"📏 সর্বনিম্ন কলাম: <b>{fs_t['min_columns']}</b> | প্যাটার্ন: <code>{fs_t['pattern_type']}</code>\n"
        + (f"\n📝 <i>{escape_html(instr)}</i>\n" if instr else "")
        + ("\n📤 এখন আপনার ফাইল আপলোড করুন অথবা টেক্সট পেস্ট করে পাঠান:" if lang == "bn" else "\n📤 Upload your file or paste lines directly:")
    )
    kb = InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang, cancel_cb="flow:cancel")])
    await pctx.reply_user_screen(update, msg, inline_markup=kb, user_id=uid, lang=lang)


async def handle_fs_runtime_input(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
    st: Dict[str, Any],
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    msg = update.message
    if msg is None:
        return
    fs_task_id = int(st["data"]["fs_task_id"])

    if msg.document:
        ok_f, err_f = pctx.validation.validate_upload_file(msg.document.file_name or "upload.txt", msg.document.file_size or 0)
        if not ok_f:
            await msg.reply_text(f"❌ {err_f}")
            return
        tg_file = await context.bot.get_file(msg.document.file_id)
        buf = io.BytesIO()
        await tg_file.download_to_memory(buf)
        file_bytes = buf.getvalue()
        file_name = msg.document.file_name or "upload.txt"
    elif msg.text and msg.text.strip():
        file_bytes = msg.text.strip().encode("utf-8")
        file_name = "pasted_text.txt"
    else:
        await msg.reply_text("⚠️ অনুগ্রহ করে ফাইল আপলোড করুন অথবা টেক্সট পাঠান।" if lang == "bn" else "⚠️ Please upload a file or paste text lines.")
        return

    ok_p, err_p, prev = pctx.fs.parse_and_preview_fs_submission(fs_task_id, uid, file_bytes, file_name)
    if not ok_p:
        await msg.reply_text(f"❌ {escape_html(err_p)}", parse_mode=ParseMode.HTML)
        return

    # Save bytes temporarily in temp dir referenced in runtime_states
    DATA_DIRS["temp"].mkdir(parents=True, exist_ok=True)
    tmp_path = DATA_DIRS["temp"] / f"fs_tmp_{uid}_{secrets.token_hex(4)}_{sanitize_filename(file_name)}"
    tmp_path.write_bytes(file_bytes)
    prev_lite = dict(prev)
    prev_lite["tmp_path"] = str(tmp_path)
    pctx.runtime.set_state(uid, flow="fs", step="await_confirm", data=prev_lite)

    max_rew = round(prev["valid_count"] * prev["unit_reward"], 2)
    preview_txt = (
        f"📊 <b>{'ফাইল সাবমিট প্রিভিউ' if lang == 'bn' else 'File Submit Preview'}</b>\n"
        f"{pctx.config.get_theme()['divider']}\n"
        f"📄 ফাইল: <code>{escape_html(file_name)}</code>\n"
        f"• মোট লাইন: <b>{prev['total_parsed']}</b>\n"
        f"• ✅ বৈধ ও ইউনিক: <b>{prev['valid_count']}</b>\n"
        f"• ⏭️ বাদ (অবৈধ/ডুপ্লিকেট): <b>{prev['skipped_total']}</b> (Invalid: {prev['skipped_invalid']}, Dup: {prev['skipped_dup']})\n"
        f"• 💰 সর্বোচ্চ সম্ভাব্য আয়: <code>{format_money(max_rew)}</code>"
    )
    kb = InlineKeyboardMarkup([
        [pctx.kb.ibtn("✅ Confirm Submit" if lang == "en" else "✅ সাবমিট কনফার্ম করুন", callback_data="fs:conf", action_kind="confirm")],
        [
            pctx.kb.ibtn("🔄 Re-upload", callback_data=f"fs:go:{fs_task_id}", action_kind="default"),
            pctx.kb.ibtn("❌ Cancel", callback_data="flow:cancel", action_kind="cancel"),
        ],
    ])
    await msg.reply_text(preview_txt, parse_mode=ParseMode.HTML, reply_markup=kb)


async def confirm_user_fs_submission(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    st = pctx.runtime.get_state(uid)
    if not st or st["flow"] != "fs" or st["step"] != "await_confirm":
        return
    data = st["data"]
    tmp_path = Path(str(data.get("tmp_path", "")))
    if not tmp_path.exists():
        pctx.runtime.clear_state(uid)
        await pctx.reply_user_screen(update, "⚠️ Session expired, please upload again.", user_id=uid, lang=lang)
        return
    file_bytes = tmp_path.read_bytes()
    try:
        tmp_path.unlink()
    except Exception:
        pass

    pctx.runtime.clear_state(uid)
    ok_c, msg_c, res = pctx.fs.commit_fs_submission(user_row, data, file_bytes)
    if not ok_c:
        await pctx.reply_user_screen(update, f"❌ {escape_html(msg_c)}", user_id=uid, lang=lang)
        return

    # Send to FS Review Channel (-1004422832745)
    rev_ch = pctx.get_primary_channel_id("task_fs_review")
    if rev_ch:
        uname = f"@{user_row['username']}" if user_row["username"] else "-"
        ch_txt = (
            f"📁 <b>New File Submit</b> | <code>{res['sub_uid']}</code>\n"
            f"📌 <b>FS Task:</b> {escape_html(res['fs_title_en'])}\n"
            f"👤 <b>User:</b> {escape_html(user_row['full_name'])} ({escape_html(uname)}) [<code>{uid}</code>]\n"
            f"📊 <b>Valid Records:</b> <b>{res['total_records']}</b> | Unit: <code>{format_money(res['unit_reward'])}</code>\n"
            f"🕒 {now_dhaka_iso()}"
        )
        ch_kb = InlineKeyboardMarkup([[
            pctx.kb.ibtn("📋 Review in Bot Queue", callback_data=f"ch:fs:open:{res['id']}", action_kind="primary"),
        ]])
        ch_msg, ch_err = await safe_send_message_to_chat(context.bot, rev_ch, ch_txt, reply_markup=ch_kb)
        if ch_msg:
            pctx.fs.update_delivery_status(int(res["id"]), "sent", rev_ch, ch_msg.message_id)
        else:
            pctx.fs.update_delivery_status(int(res["id"]), "failed", rev_ch, 0, ch_err)

    fs_title = res["fs_title_bn"] if lang == "bn" else res["fs_title_en"]
    conf_msg, _, enabled = pctx.studio.render_event_message(
        "fs_submitted_complete",
        lang=lang,
        name=str(user_row["full_name"]),
        sub_uid=res["sub_uid"],
        fs_title=fs_title,
        total_records=res["total_records"],
        unit_reward=format_money(res["unit_reward"]),
    )
    txt = conf_msg if (enabled and conf_msg) else f"✅ FS Submitted: <code>{res['sub_uid']}</code> ({res['total_records']} records)"
    await pctx.reply_user_screen(update, txt, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)


# --- U-04: My Orders & Activity (History, Re-download, Warranty, Appeal) ---

async def show_my_orders_activity(
    pctx: PlatformContext,
    update: Update,
    user_row: sqlite3.Row,
    tab: str = "orders",
    page: int = 0,
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    div = pctx.config.get_theme()["divider"]
    rows_kb: List[List[InlineKeyboardButton]] = [[
        pctx.kb.ibtn("🛒 Orders", callback_data="act:tab:orders:0", action_kind="primary" if tab == "orders" else "default"),
        pctx.kb.ibtn("📋 Tasks", callback_data="act:tab:tasks:0", action_kind="primary" if tab == "tasks" else "default"),
        pctx.kb.ibtn("📁 FS", callback_data="act:tab:fs:0", action_kind="primary" if tab == "fs" else "default"),
    ], [
        pctx.kb.ibtn("💳 Deposits", callback_data="act:tab:dep:0", action_kind="primary" if tab == "dep" else "default"),
        pctx.kb.ibtn("💸 Withdraws", callback_data="act:tab:wd:0", action_kind="primary" if tab == "wd" else "default"),
    ]]
    lines = [f"📦 <b>{'আমার অর্ডার ও কাজের হিস্ট্রি' if lang == 'bn' else 'My Orders & Activity'}</b> [{tab.upper()}]", div]
    offset = page * 5

    if tab == "orders":
        items = pctx.db.query_all(
            """
            SELECT o.*, p.name_bn, p.name_en FROM store_orders o
            LEFT JOIN store_products p ON p.id=o.product_id
            WHERE o.user_id=? ORDER BY o.id DESC LIMIT 5 OFFSET ?
            """,
            (uid, offset),
        )
        if not items:
            lines.append("কোনো স্টোর অর্ডার পাওয়া যায়নি।" if lang == "bn" else "No store orders yet.")
        for it in items:
            pname = (it["name_bn"] if lang == "bn" else it["name_en"]) or f"#{it['product_id']}"
            lines.append(f"• <code>{it['order_uid']}</code> | {escape_html(pname)} x{it['qty']} | <code>{format_money(it['total_paid'])}</code> [{it['status']}]")
            act_r: List[InlineKeyboardButton] = []
            if it["delivery_file_path"]:
                act_r.append(pctx.kb.ibtn(f"📥 {it['order_uid']}", callback_data=f"ord:dl:{it['id']}", action_kind="copy"))
            w_exp = parse_iso_dt(it["warranty_expires_at"])
            if w_exp and now_utc() <= w_exp and str(it["status"]) == "completed":
                act_r.append(pctx.kb.ibtn("🛡️ Warranty", callback_data=f"ord:war:{it['id']}", action_kind="default"))
            if act_r:
                rows_kb.append(act_r)

    elif tab == "tasks":
        items = pctx.db.query_all(
            "SELECT * FROM task_submissions WHERE user_id=? ORDER BY id DESC LIMIT 5 OFFSET ?",
            (uid, offset),
        )
        if not items:
            lines.append("কোনো টাস্ক সাবমিশন নেই।" if lang == "bn" else "No task submissions yet.")
        for it in items:
            lines.append(f"• <code>{it['sub_uid']}</code> | <code>{format_money(it['reward_snapshot'])}</code> [{it['status']}]")
            if str(it["status"]) == "rejected":
                lines.append(f"  ❌ <i>{escape_html(it['reject_reason'])}</i>")
                rows_kb.append([pctx.kb.ibtn(f"⚖️ Appeal {it['sub_uid']}", callback_data=f"apl:new:task:{it['id']}", action_kind="default")])

    elif tab == "fs":
        items = pctx.db.query_all(
            "SELECT * FROM fs_submissions WHERE user_id=? ORDER BY id DESC LIMIT 5 OFFSET ?",
            (uid, offset),
        )
        if not items:
            lines.append("কোনো ফাইল সাবমিট নেই।" if lang == "bn" else "No File Submits yet.")
        for it in items:
            lines.append(
                f"• <code>{it['sub_uid']}</code> | ✅{it['approved_count']} ❌{it['rejected_count']} ⏳{it['pending_count']} | <code>{format_money(it['total_reward_credited'])}</code>"
            )
            r_btns = [pctx.kb.ibtn(f"🔍 Lines ({it['sub_uid']})", callback_data=f"fs:lines:{it['id']}:0", action_kind="default")]
            if int(it["rejected_count"]) > 0:
                r_btns.append(pctx.kb.ibtn("⚖️ Appeal", callback_data=f"apl:new:fs:{it['id']}", action_kind="default"))
            rows_kb.append(r_btns)

    elif tab == "dep":
        items = pctx.db.query_all("SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC LIMIT 5 OFFSET ?", (uid, offset))
        if not items:
            lines.append("কোনো ডিপোজিট নেই।" if lang == "bn" else "No deposits yet.")
        for it in items:
            lines.append(f"• <code>{it['deposit_uid']}</code> | <code>{format_money(it['amount'])}</code> | TxID: <code>{escape_html(it['txid_user'])}</code> [{it['status']}]")
            if str(it["status"]) == "rejected":
                lines.append(f"  ❌ <i>{escape_html(it['reject_reason'])}</i>")
                rows_kb.append([pctx.kb.ibtn(f"⚖️ Appeal {it['deposit_uid']}", callback_data=f"apl:new:deposit:{it['id']}", action_kind="default")])

    elif tab == "wd":
        items = pctx.db.query_all("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 5 OFFSET ?", (uid, offset))
        if not items:
            lines.append("কোনো উইথড্রয়াল নেই।" if lang == "bn" else "No withdrawals yet.")
        for it in items:
            lines.append(f"• <code>{it['withdraw_uid']}</code> | Net: <code>{format_money(it['net_amount'])}</code> | {escape_html(it['account_or_wallet'])} [{it['status']}]")
            if str(it["status"]) == "rejected" and it["reject_reason"]:
                lines.append(f"  ❌ <i>{escape_html(it['reject_reason'])}</i>")

    rows_kb.append([
        pctx.kb.ibtn("◀️", callback_data=f"act:tab:{tab}:{max(0, page - 1)}", action_kind="default"),
        pctx.kb.ibtn("▶️", callback_data=f"act:tab:{tab}:{page + 1}", action_kind="default"),
    ])
    rows_kb.append(pctx.kb.nav_row(lang=lang))
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=InlineKeyboardMarkup(rows_kb), user_id=uid, lang=lang)


async def show_fs_line_viewer(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, fs_sub_id: int, page: int = 0) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    sub = pctx.fs.get_submission(fs_sub_id)
    if sub is None or int(sub["user_id"]) != uid:
        await pctx.reply_user_screen(update, "⚠️ Not found.", user_id=uid, lang=lang)
        return
    recs = pctx.fs.list_submission_records(fs_sub_id, limit=10, offset=page * 10)
    lines = [f"🔍 <b>{sub['sub_uid']} — Line-by-Line Status</b> (Page {page + 1})", pctx.config.get_theme()["divider"]]
    for r in recs:
        icon = "✅" if r["status"] == "approved" else ("❌" if r["status"] == "rejected" else "⏳")
        rsn = f" — <i>{escape_html(r['reject_reason'])}</i>" if r["reject_reason"] else ""
        lines.append(f"L{r['line_no']} {icon} <code>{escape_html(r['raw_line'][:38])}</code>{rsn}")
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("◀️ Prev", callback_data=f"fs:lines:{fs_sub_id}:{max(0, page - 1)}", action_kind="default"),
            pctx.kb.ibtn("Next ▶️", callback_data=f"fs:lines:{fs_sub_id}:{page + 1}", action_kind="default"),
        ],
        pctx.kb.nav_row(lang=lang, back_cb="act:tab:fs:0"),
    ])
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=kb, user_id=uid, lang=lang)
# ==============================================================================
# USER HANDLERS — PART 3 (U-03 STORE, U-05 OTP, U-06 DEPOSIT OCR, U-07 WITHDRAW)
# ==============================================================================

# --- U-03: Product Store Flow ---

async def show_store_categories(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    cats = pctx.store.list_categories(active_only=True)
    if not cats:
        await show_store_products_list(pctx, update, user_row, category_id=None)
        return
    msg = pctx.text.get_text("store_intro_prompt", lang)
    rows: List[List[InlineKeyboardButton]] = []
    for c in cats:
        cname = c["name_bn"] if lang == "bn" else c["name_en"]
        rows.append([pctx.kb.ibtn(f"{c['emoji']} {cname}", callback_data=f"st:cat:{c['id']}", action_kind="store")])
    rows.append([pctx.kb.ibtn("🛍️ সব পণ্য দেখুন" if lang == "bn" else "🛍️ View All Products", callback_data="st:cat:0", action_kind="default")])
    rows.append(pctx.kb.nav_row(lang=lang))
    await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def show_store_products_list(
    pctx: PlatformContext,
    update: Update,
    user_row: sqlite3.Row,
    category_id: Optional[int] = None,
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    prods = pctx.store.list_products(category_id=category_id if category_id else None, active_only=True)
    div = pctx.config.get_theme()["divider"]
    if not prods:
        msg = f"🛒 <b>প্রোডাক্ট স্টোর</b>\n{div}\nএই ক্যাটাগরিতে বর্তমানে কোনো পণ্য নেই।" if lang == "bn" else f"🛒 <b>Product Store</b>\n{div}\nNo active products found."
        await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, back_cb="um:u_store")]), user_id=uid, lang=lang)
        return

    lines = [f"🛒 <b>{'পণ্য তালিকা' if lang == 'bn' else 'Available Products'}</b>", div]
    rows: List[List[InlineKeyboardButton]] = []
    for p in prods:
        pid = int(p["id"])
        pname = p["name_bn"] if lang == "bn" else p["name_en"]
        price_str = format_money(p["price"])
        if str(p["delivery_mode"]) == "instant":
            cnts = pctx.store.get_stock_counts(pid)
            stk = f"{cnts['available']}টি 🟢" if cnts["available"] > 0 else "0 🔴"
        else:
            stk = "Manual 🔵"
        lines.append(f"• <b>{escape_html(pname)}</b> — <code>{price_str}</code> | স্টক: {stk}")
        rows.append([pctx.kb.ibtn(f"🛍️ {pname[:22]} ({price_str}) [{stk}]", callback_data=f"st:prod:{pid}", action_kind="store")])
    rows.append(pctx.kb.nav_row(lang=lang, back_cb="um:u_store"))
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def show_store_product_detail(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, product_id: int) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    prod = pctx.store.get_product(product_id)
    if prod is None or int(prod["is_active"]) != 1:
        await pctx.reply_user_screen(update, "⚠️ Product unavailable.", user_id=uid, lang=lang)
        return
    pname = prod["name_bn"] if lang == "bn" else prod["name_en"]
    desc = prod["desc_bn"] if lang == "bn" else prod["desc_en"]
    cnts = pctx.store.get_stock_counts(product_id)
    tiers = pctx.store.list_price_tiers(product_id)
    div = pctx.config.get_theme()["divider"]

    lines = [
        f"🛍️ <b>{escape_html(pname)}</b>",
        div,
        f"💰 মূল্য: <code>{format_money(prod['price'])}</code> | সীমা: {prod['min_qty']}–{prod['max_qty']}",
        f"💼 ওয়ালেট: <code>{prod['wallet_mode']}</code> | ডেলিভারি: <code>{prod['delivery_mode']}</code>",
        f"🛡️ ওয়ারেন্টি: <b>{prod['warranty_hours']} ঘণ্টা</b>" if int(prod["warranty_hours"]) > 0 else "🛡️ ওয়ারেন্টি: নেই",
    ]
    if str(prod["delivery_mode"]) == "instant":
        lines.append(f"📦 লাইভ স্টক: <b>{cnts['available']}টি</b>")
    if desc:
        lines.append(f"\n📝 <i>{escape_html(desc)}</i>")
    if tiers:
        lines.append("\n🏷️ <b>Bulk Discounts:</b>")
        for t in tiers:
            lines.append(f"  • {t['min_qty']}+ qty → <code>{format_money(t['unit_price'])}</code> / unit")

    rows: List[List[InlineKeyboardButton]] = []
    if str(prod["delivery_mode"]) == "instant" and cnts["available"] <= 0:
        rows.append([pctx.kb.ibtn("🔔 স্টক এলে জানাও (Stock Notify)" if lang == "bn" else "🔔 Notify When Restocked", callback_data=f"st:notify:{product_id}", action_kind="primary")])
    else:
        rows.append([pctx.kb.ibtn("🛒 এখনই কিনুন (Order Now)" if lang == "bn" else "🛒 Order Now", callback_data=f"st:buy:{product_id}", action_kind="confirm")])
    rows.append(pctx.kb.nav_row(lang=lang, back_cb="um:u_store"))
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def start_store_order_flow(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, product_id: int) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    prod = pctx.store.get_product(product_id)
    if prod is None:
        return
    steps = [dict(s) for s in pctx.store.list_product_steps(product_id, active_only=True)]
    pctx.runtime.set_state(
        uid,
        flow="store",
        step="await_qty",
        data={"product_id": product_id, "steps": steps, "step_idx": 0, "step_answers": [], "coupon": ""},
    )
    msg = (
        f"🔢 <b>{escape_html(prod['name_bn'] if lang == 'bn' else prod['name_en'])}</b>\n"
        + (f"কত পিস কিনতে চান? সংখ্যা লিখুন ({prod['min_qty']} থেকে {prod['max_qty']}):" if lang == "bn" else f"Enter quantity ({prod['min_qty']} to {prod['max_qty']}):")
    )
    await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang)]), user_id=uid, lang=lang)


async def handle_store_runtime_input(
    pctx: PlatformContext,
    update: Update,
    user_row: sqlite3.Row,
    st: Dict[str, Any],
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    msg = update.message
    if msg is None or not msg.text:
        return
    txt = msg.text.strip()
    data = st["data"]
    step = st["step"]
    prod = pctx.store.get_product(int(data["product_id"]))
    if prod is None:
        pctx.runtime.clear_state(uid)
        return

    if step == "await_qty":
        qty = parse_positive_int(txt)
        if qty is None or qty <= 0:
            await msg.reply_text("⚠️ অনুগ্রহ করে সঠিক সংখ্যা লিখুন।" if lang == "bn" else "⚠️ Enter a valid positive integer.")
            return
        ok_el, err_el = pctx.store.check_order_eligibility(prod, user_row, qty)
        if not ok_el:
            await msg.reply_text(f"❌ {escape_html(err_el)}", parse_mode=ParseMode.HTML)
            return
        pctx.runtime.update_data(uid, {"qty": qty}, new_step="await_coupon")
        kb = InlineKeyboardMarkup([
            [pctx.kb.ibtn("⏭️ কুপন নেই / Skip", callback_data="st:skipcp", action_kind="default")],
            pctx.kb.cancel_row(lang=lang),
        ])
        await msg.reply_text(
            "🎟️ প্রোমো কুপন কোড থাকলে লিখুন, অথবা Skip চাপুন:" if lang == "bn" else "🎟️ Enter a promo coupon code, or tap Skip:",
            reply_markup=kb,
        )
        return

    if step == "await_coupon":
        unit_p = pctx.store.get_effective_unit_price(prod, int(data["qty"]))
        subtotal = unit_p * int(data["qty"])
        ok_cp, msg_cp, _ = pctx.store.validate_coupon(txt, int(prod["id"]), uid, subtotal)
        if not ok_cp:
            await msg.reply_text(f"❌ {escape_html(msg_cp)} — পুনরায় দিন বা Skip চাপুন।", parse_mode=ParseMode.HTML)
            return
        pctx.runtime.update_data(uid, {"coupon": txt.upper()})
        await advance_store_checkout_steps(pctx, update, user_row)
        return

    if step == "await_prod_step":
        steps = data.get("steps", [])
        idx = int(data.get("step_idx", 0))
        if idx < len(steps):
            sobj = steps[idx]
            ans = list(data.get("step_answers", []))
            ans.append({"label": sobj.get("title_en") or sobj.get("title_bn"), "value": txt})
            pctx.runtime.update_data(uid, {"step_answers": ans, "step_idx": idx + 1})
        await advance_store_checkout_steps(pctx, update, user_row)


async def advance_store_checkout_steps(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    st = pctx.runtime.get_state(uid)
    if not st or st["flow"] != "store":
        return
    data = st["data"]
    prod = pctx.store.get_product(int(data["product_id"]))
    if prod is None:
        return
    steps = data.get("steps", [])
    idx = int(data.get("step_idx", 0))
    if idx < len(steps):
        sobj = steps[idx]
        pctx.runtime.set_state(uid, flow="store", step="await_prod_step", data=data)
        t_lbl = sobj["title_bn"] if lang == "bn" else sobj["title_en"]
        i_lbl = sobj["instruction_bn"] if lang == "bn" else sobj["instruction_en"]
        prompt = f"📌 <b>ধাপ {idx + 1}/{len(steps)}: {escape_html(t_lbl)}</b>\n<i>{escape_html(i_lbl)}</i>"
        await pctx.reply_user_screen(update, prompt, inline_markup=InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang)]), user_id=uid, lang=lang)
        return

    pctx.runtime.set_state(uid, flow="store", step="await_confirm", data=data)
    qty = int(data["qty"])
    unit_p = pctx.store.get_effective_unit_price(prod, qty)
    subtotal = round(unit_p * qty, 4)
    disc = 0.0
    if data.get("coupon"):
        _, _, disc = pctx.store.validate_coupon(data["coupon"], int(prod["id"]), uid, subtotal)
    total_pay = round(max(0.0, subtotal - disc), 4)
    pname = prod["name_bn"] if lang == "bn" else prod["name_en"]
    prev_txt = (
        f"🧾 <b>{'অর্ডার প্রিভিউ' if lang == 'bn' else 'Order Preview'}</b>\n"
        f"{pctx.config.get_theme()['divider']}\n"
        f"🛍️ পণ্য: <b>{escape_html(pname)}</b>\n"
        f"🔢 পরিমাণ: <b>{qty}</b> x <code>{format_money(unit_p)}</code>\n"
        f"🏷️ ছাড়: <code>-{format_money(disc)}</code>\n"
        f"💳 মোট মূল্য: <b><code>{format_money(total_pay)}</code></b>"
    )
    kb = InlineKeyboardMarkup([
        [pctx.kb.ibtn("✅ Confirm Purchase" if lang == "en" else "✅ অর্ডার কনফার্ম করুন", callback_data="st:conf", action_kind="confirm")],
        pctx.kb.cancel_row(lang=lang),
    ])
    await pctx.reply_user_screen(update, prev_txt, inline_markup=kb, user_id=uid, lang=lang)


async def confirm_store_checkout(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    st = pctx.runtime.get_state(uid)
    if not st or st["flow"] != "store" or st["step"] != "await_confirm":
        return
    data = st["data"]
    pctx.runtime.clear_state(uid)

    ok_c, msg_c, res = pctx.store.checkout_order(
        product_id=int(data["product_id"]),
        user_row=user_row,
        qty=int(data["qty"]),
        coupon_code=str(data.get("coupon", "")),
        step_answers=data.get("step_answers", []),
    )
    if not ok_c:
        await pctx.reply_user_screen(update, f"❌ {escape_html(msg_c)}", inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return

    prod = res["product"]
    pname = prod["name_bn"] if lang == "bn" else prod["name_en"]
    chat_id = update.effective_chat.id if update.effective_chat else uid

    if res["status"] == "completed":
        card, _, en = pctx.studio.render_event_message(
            "store_order_success_delivery",
            lang=lang,
            name=str(user_row["full_name"]),
            order_uid=res["order_uid"],
            product_name=pname,
            qty=res["qty"],
            total_paid=format_money(res["total_paid"]),
            discount=format_money(res["discount"]),
            warranty_hours=res["warranty_hours"],
        )
        text_out = card if (en and card) else f"✅ Order <code>{res['order_uid']}</code> Completed!"
        lines_preview = "\n".join(f"<code>{escape_html(ln)}</code>" for ln in res["delivered_lines"][:15])
        if lines_preview:
            text_out += f"\n\n📦 <b>Delivered Items:</b>\n{lines_preview}"
        await safe_send_message_to_chat(context.bot, chat_id, text_out, reply_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]))
        fpath = Path(str(res.get("delivery_file_path", "")))
        if fpath.exists():
            try:
                with open(fpath, "rb") as fp:
                    await context.bot.send_document(chat_id=chat_id, document=fp, filename=fpath.name, caption=f"📦 {res['order_uid']}")
            except Exception as exc:
                LOGGER.warning("Order file send failed: %s", exc)
    else:
        await safe_send_message_to_chat(
            context.bot,
            chat_id,
            f"⏳ অর্ডার <code>{res['order_uid']}</code> জমা হয়েছে এবং এডমিন অনুমোদনের অপেক্ষায় রয়েছে।",
            reply_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]),
        )

    # RULE 93: Auto-Post to Payout Channel (-1004376755344) & Order Review Channel
    if int(prod["payout_post_enabled"]) == 1:
        payout_ch = pctx.get_primary_channel_id("payout_order")
        if payout_ch:
            buyer_disp = mask_display_name(user_row["full_name"], uid) if int(prod["payout_mask_buyer"]) == 1 else str(user_row["full_name"])
            post_txt = (
                f"🛒 <b>Product Order Completed!</b>\n"
                f"🆔 Order: <code>{res['order_uid']}</code>\n"
                f"📦 Product: <b>{escape_html(prod['name_en'])}</b> x{res['qty']}\n"
                f"👤 Buyer: <b>{escape_html(buyer_disp)}</b>\n"
                f"💰 Paid: <code>{format_money(res['total_paid'])}</code> | Status: <b>{res['status'].upper()}</b>"
            )
            await safe_send_message_to_chat(context.bot, payout_ch, post_txt)

    if res.get("low_stock_alert"):
        pctx.notifications.enqueue(
            DEFAULT_MAIN_ADMIN_ID,
            f"⚠️ <b>Store Low Stock Alert:</b> {escape_html(prod['name_en'])} has <b>{res['remaining_stock']}</b> unit(s) remaining!",
        )


# --- U-05: OTP Receiver Flow & 4-Bridge Delivery Helper ---

async def deliver_otp_match_to_user_and_channel(pctx: PlatformContext, bot: Bot, matched: Dict[str, Any]) -> None:
    """Shared real-time OTP delivery for Relay Channel, Webhook, Provider API & Quick-Push."""
    uid = int(matched["user_id"])
    u_row = pctx.users.get_user(uid)
    lang = str(u_row["language"] or "bn") if u_row else "bn"
    card, silent, enabled = pctx.studio.render_event_message(
        "otp_code_received_push",
        lang=lang,
        name=str(u_row["full_name"]) if u_row else "",
        country_flag=matched["country_flag"],
        country_name=matched["country_name"],
        phone_number=matched["phone_number"],
        otp_code=matched["otp_code"],
        otp_uid=matched["otp_uid"],
        sms_text=matched["raw_sms"],
    )
    text_out = card if (enabled and card) else f"📲 OTP: <code>{escape_html(matched['otp_code'])}</code>\nNumber: <code>{escape_html(matched['phone_number'])}</code>"
    kb_rows = [
        [pctx.kb.ibtn("🔄 Check / Refresh OTP", callback_data=f"otp:ref:{matched['session_id']}", action_kind="default")],
        pctx.kb.nav_row(lang=lang),
    ]
    await safe_send_message_to_chat(bot, uid, text_out, reply_markup=InlineKeyboardMarkup(kb_rows), disable_notification=silent)

    otp_ch = pctx.get_primary_channel_id("otp_notify")
    if otp_ch:
        mask_on = pctx.config.get_bool("otp_channel_mask_privacy", True)
        p_disp = mask_phone_or_account(matched["phone_number"]) if mask_on else matched["phone_number"]
        ch_txt = (
            f"📲 <b>OTP Received</b>\n"
            f"🌍 {matched['country_flag']} {escape_html(matched['country_name'])}\n"
            f"📞 Number: <code>{escape_html(p_disp)}</code>\n"
            f"🔑 Code: <code>{escape_html(matched['otp_code'])}</code>"
        )
        await safe_send_message_to_chat(bot, otp_ch, ch_txt)


async def show_otp_countries(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    countries = pctx.otp.list_countries(active_only=True)
    div = pctx.config.get_theme()["divider"]
    if not countries:
        msg = f"📲 <b>OTP রিসিভার</b>\n{div}\nবর্তমানে কোনো দেশ সক্রিয় নেই।" if lang == "bn" else f"📲 <b>OTP Receiver</b>\n{div}\nNo active countries right now."
        await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return

    lines = [pctx.text.get_text("otp_intro_prompt", lang), ""]
    rows: List[List[InlineKeyboardButton]] = []
    for c in countries:
        cid = int(c["id"])
        cnts = pctx.otp.get_country_stock_counts(cid)
        avail = cnts["available"]
        live_tag = f"Live: {avail}টি 🟢" if avail > 0 else "0 🔴 Out of Stock"
        cname = c["name_bn"] if lang == "bn" else c["name_en"]
        fee_lbl = format_money(c["fee_amount"]) if float(c["fee_amount"]) > 0 else ("ফ্রি" if lang == "bn" else "Free")
        lines.append(f"{c['flag_emoji']} <b>{escape_html(cname)}</b> ({c['country_code']}) — {live_tag} | {fee_lbl} ({c['numbers_per_click']}x)")
        rows.append([pctx.kb.ibtn(f"{c['flag_emoji']} {cname} ({live_tag})", callback_data=f"otp:get:{cid}", action_kind="otp" if avail > 0 else "default")])
    rows.append(pctx.kb.nav_row(lang=lang))
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def allocate_user_otp_session(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, country_id: int) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    ok, msg, res = pctx.otp.allocate_numbers_for_user(country_id, uid)
    if not ok:
        await pctx.reply_user_screen(
            update,
            f"⚠️ {escape_html(msg)}",
            inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, back_cb="um:u_otp")]),
            user_id=uid,
            lang=lang,
        )
        return

    if res.get("low_stock_alert"):
        pctx.notifications.enqueue(
            DEFAULT_MAIN_ADMIN_ID,
            f"⚠️ <b>OTP Low Stock Alert:</b> {res['country']['flag_emoji']} {escape_html(res['country']['name_en'])} has {res['remaining_stock']} number(s) left!",
        )

    sess_id = int(res["session_id"])
    country = res["country"]
    cname = country["name_bn"] if lang == "bn" else country["name_en"]
    wait_txt = format_duration_seconds(res["wait_timeout_sec"], lang=lang)
    card, _, en = pctx.studio.render_event_message(
        "otp_number_allocated",
        lang=lang,
        country_flag=country["flag_emoji"],
        country_name=cname,
        otp_uid=res["otp_uid"],
        wait_text=wait_txt,
    )
    nums_txt = "\n".join(f"📞 <code>{escape_html(n)}</code>" for n in res["numbers"])
    body = (card if (en and card) else f"📲 <b>{escape_html(cname)}</b> | <code>{res['otp_uid']}</code>") + f"\n\n{nums_txt}\n\n⏳ মেয়াদ: {wait_txt}"
    kb = InlineKeyboardMarkup([
        [pctx.kb.ibtn("🔄 Check / Refresh OTP", callback_data=f"otp:ref:{sess_id}", action_kind="primary")],
        [
            pctx.kb.ibtn("🚫 Report Dead & Swap", callback_data=f"otp:swap:{sess_id}", action_kind="cancel"),
            pctx.kb.ibtn("❌ Cancel", callback_data=f"otp:can:{sess_id}", action_kind="cancel"),
        ],
        pctx.kb.nav_row(lang=lang, back_cb="um:u_otp"),
    ])
    await pctx.reply_user_screen(update, body, inline_markup=kb, user_id=uid, lang=lang)


# --- U-06: Add Money / Deposit (Dual Classic + Hybrid OCR) ---

async def show_deposit_methods(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    methods = pctx.deposits.list_methods(active_only=True)
    div = pctx.config.get_theme()["divider"]
    if not methods:
        await pctx.reply_user_screen(update, "⚠️ No active deposit methods available.", inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return
    lines = [f"💳 <b>{'টাকা অ্যাড / ডিপোজিট মেথড' if lang == 'bn' else 'Add Money / Deposit Methods'}</b>", div]
    rows: List[List[InlineKeyboardButton]] = []
    for m in methods:
        mname = m["name_bn"] if lang == "bn" else m["name_en"]
        bonus_txt = f" (+{m['bonus_percent']:g}% Bonus)" if float(m["bonus_percent"]) > 0 else ""
        lines.append(f"• <b>{escape_html(mname)}</b> — {format_money(m['min_amount'])}–{format_money(m['max_amount'])}{bonus_txt}")
        rows.append([pctx.kb.ibtn(f"💳 {mname}{bonus_txt}", callback_data=f"dep:m:{m['id']}", action_kind="deposit")])
    rows.append(pctx.kb.nav_row(lang=lang))
    await pctx.reply_user_screen(update, "\n".join(lines), inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def start_deposit_method(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, method_id: int) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    m = pctx.deposits.get_method(method_id)
    if m is None or int(m["is_active"]) != 1:
        return
    pctx.runtime.set_state(uid, flow="deposit", step="await_amount", data={"method_id": method_id})
    mname = m["name_bn"] if lang == "bn" else m["name_en"]
    instr = m["instruction_bn"] if lang == "bn" else m["instruction_en"]
    div = pctx.config.get_theme()["divider"]
    msg = (
        f"💳 <b>{escape_html(mname)}</b> ({escape_html(m['account_holder_type'])})\n{div}\n"
        f"📲 নম্বর / PayID: <code>{escape_html(m['account_number'])}</code>\n"
        + (f"🌐 নেটওয়ার্ক: <code>{escape_html(m['network_info'])}</code>\n" if m["network_info"] else "")
        + f"📏 সীমা: {format_money(m['min_amount'])} – {format_money(m['max_amount'])}\n"
        + (f"\n📝 <i>{escape_html(instr)}</i>\n" if instr else "")
        + ("\n💵 আপনি কত টাকা পাঠিয়েছেন তা লিখুন:" if lang == "bn" else "\n💵 Enter the deposit amount you sent:")
    )
    await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang)]), user_id=uid, lang=lang)


async def handle_deposit_runtime_input(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
    st: Dict[str, Any],
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    msg = update.message
    if msg is None:
        return
    data = st["data"]
    step = st["step"]
    m = pctx.deposits.get_method(int(data["method_id"]))
    if m is None:
        pctx.runtime.clear_state(uid)
        return

    async def _go_next_deposit_step(cur_data: Dict[str, Any], from_step: str) -> None:
        if from_step == "await_amount":
            if int(m["require_sender"]) == 1:
                pctx.runtime.update_data(uid, cur_data, new_step="await_sender")
                await msg.reply_text("📱 আপনার সেন্ডার নম্বর / PayID লিখুন:" if lang == "bn" else "📱 Enter your Sender number / PayID:")
                return
            cur_data["sender"] = ""
            from_step = "await_sender"
        if from_step == "await_sender":
            if int(m["require_txid"]) == 1:
                pctx.runtime.update_data(uid, cur_data, new_step="await_txid")
                await msg.reply_text("🧾 ট্রানজ্যাকশন আইডি (TxID) লিখুন:" if lang == "bn" else "🧾 Enter Transaction ID (TxID):")
                return
            cur_data["txid"] = ""
            from_step = "await_txid"
        if from_step == "await_txid":
            if int(m["require_screenshot"]) == 1:
                pctx.runtime.update_data(uid, cur_data, new_step="await_screenshot")
                await msg.reply_text("📸 পেমেন্টের পরিষ্কার স্ক্রিনশট (Photo) পাঠান:" if lang == "bn" else "📸 Send a clear Payment Screenshot (Photo):")
                return
            pctx.runtime.update_data(uid, cur_data)
            merged_data = pctx.runtime.get_state(uid)["data"]  # type: ignore[index]
            await _finalize_deposit_submission(pctx, update, context, user_row, merged_data, "", "", b"")

    if step == "await_amount":
        amt = parse_positive_float(msg.text or "")
        if amt is None or amt < float(m["min_amount"]) or amt > float(m["max_amount"]):
            await msg.reply_text(f"⚠️ Amount must be between {format_money(m['min_amount'])} and {format_money(m['max_amount'])}.")
            return
        await _go_next_deposit_step({"amount": amt}, "await_amount")
        return

    if step == "await_sender":
        sender = (msg.text or "").strip()
        if len(sender) < 4:
            await msg.reply_text("⚠️ সঠিক সেন্ডার নম্বর দিন।" if lang == "bn" else "⚠️ Enter a valid sender number.")
            return
        await _go_next_deposit_step({"sender": sender}, "await_sender")
        return

    if step == "await_txid":
        txid = (msg.text or "").strip()
        if len(txid) < 4:
            await msg.reply_text("⚠️ সঠিক TxID লিখুন।" if lang == "bn" else "⚠️ Enter a valid TxID.")
            return
        await _go_next_deposit_step({"txid": txid}, "await_txid")
        return

    if step == "await_screenshot":
        if msg.photo:
            ph = msg.photo[-1]
            tg_f = await context.bot.get_file(ph.file_id)
            buf = io.BytesIO()
            await tg_f.download_to_memory(buf)
            await _finalize_deposit_submission(pctx, update, context, user_row, data, ph.file_id, ph.file_unique_id, buf.getvalue())
        else:
            await msg.reply_text("📸 অনুগ্রহ করে ছবি (Photo) হিসেবে পেমেন্ট স্ক্রিনশট পাঠান।" if lang == "bn" else "📸 Please send the payment screenshot as a Photo.")


async def _finalize_deposit_submission(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
    data: Dict[str, Any],
    file_id: str,
    file_uid: str,
    img_bytes: bytes,
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    pctx.runtime.clear_state(uid)

    ok_d, msg_d, res = await pctx.deposits.submit_deposit(
        method_id=int(data["method_id"]),
        user_row=user_row,
        amount=float(data["amount"]),
        sender_number=str(data.get("sender", "")),
        txid_user=str(data.get("txid", "")),
        screenshot_file_id=file_id,
        screenshot_unique_id=file_uid,
        screenshot_bytes=img_bytes,
    )
    if not ok_d:
        if res.get("code") == "REJECTED_TXID_MISMATCH":
            err_txt = pctx.text.get_text("deposit_ocr_mismatch_reject", lang, txid_user=res["txid_user"], txid_ocr=res["txid_ocr"])
        else:
            err_txt = f"❌ {escape_html(msg_d)}"
        await pctx.reply_user_screen(update, err_txt, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return

    # Post to Finance Review Channel (-1004418032153)
    rev_ch = pctx.get_primary_channel_id("finance_review")
    if rev_ch:
        uname = f"@{user_row['username']}" if user_row["username"] else "-"
        ocr_line = f"\n🤖 <b>OCR TxID:</b> <code>{escape_html(res['txid_ocr'] or res['ocr_status'])}</code>"
        caption = (
            f"💳 <b>Deposit Request</b> | <code>{res['deposit_uid']}</code>\n"
            f"🏦 <b>Method:</b> {escape_html(res['method_name_en'])}\n"
            f"👤 <b>User:</b> {escape_html(user_row['full_name'])} ({escape_html(uname)}) [<code>{uid}</code>]\n"
            f"💵 <b>Amount:</b> <code>{format_money(res['amount'])}</code> | Net: <code>{format_money(res['net_credit'])}</code>\n"
            f"📱 <b>Sender:</b> <code>{escape_html(res['sender'])}</code>\n"
            f"🧾 <b>User TxID:</b> <code>{escape_html(res['txid'])}</code>{ocr_line}\n"
            f"⚙️ Mode: <code>{res['auto_mode']}</code>"
        )
        ch_kb = InlineKeyboardMarkup([[
            pctx.kb.ibtn("✅ Approve", callback_data=f"ch:dep:app:{res['id']}", action_kind="approve"),
            pctx.kb.ibtn("❌ Reject", callback_data=f"ch:dep:rej:{res['id']}", action_kind="reject"),
        ]])
        try:
            if file_id:
                sent_m = await context.bot.send_photo(chat_id=rev_ch, photo=file_id, caption=truncate_text(caption, 1024), parse_mode=ParseMode.HTML, reply_markup=ch_kb)
                pctx.deposits.set_channel_ref(int(res["id"]), rev_ch, sent_m.message_id, is_media=True)
            else:
                sent_m, _ = await safe_send_message_to_chat(context.bot, rev_ch, caption, reply_markup=ch_kb)
                if sent_m:
                    pctx.deposits.set_channel_ref(int(res["id"]), rev_ch, sent_m.message_id, is_media=False)
        except Exception as exc:
            LOGGER.error("Deposit review channel send failed: %s", exc)

    mname = res["method_name_bn"] if lang == "bn" else res["method_name_en"]
    card, _, en = pctx.studio.render_event_message(
        "deposit_request_submitted",
        lang=lang,
        name=str(user_row["full_name"]),
        deposit_uid=res["deposit_uid"],
        method=mname,
        amount=format_money(res["amount"]),
        bonus=format_money(res["bonus"]),
        net_credit=format_money(res["net_credit"]),
        sender=res["sender"],
        txid=res["txid"],
    )
    txt = card if (en and card) else f"⏳ Deposit <code>{res['deposit_uid']}</code> submitted!"
    await pctx.reply_user_screen(update, txt, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)


# --- U-07: Withdrawal Flow ---

async def show_withdraw_methods(pctx: PlatformContext, update: Update, user_row: sqlite3.Row) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    methods = pctx.withdrawals.list_methods(active_only=True)
    earned = float(user_row["earned_balance"])
    msg = pctx.text.get_text("withdraw_intro_prompt", lang, earned=format_money(earned))
    rows: List[List[InlineKeyboardButton]] = []
    for m in methods:
        mname = m["name_bn"] if lang == "bn" else m["name_en"]
        fee_lbl = pctx.withdrawals.format_fee_label(m, lang=lang)
        lim_lbl = f"{format_money(m['min_amount'])}–{format_money(m['max_amount'])}"
        rows.append([pctx.kb.ibtn(f"💸 {mname} | {fee_lbl} ({lim_lbl})", callback_data=f"wd:m:{m['id']}", action_kind="withdraw")])
    rows.append(pctx.kb.nav_row(lang=lang))
    await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup(rows), user_id=uid, lang=lang)


async def start_withdraw_method(pctx: PlatformContext, update: Update, user_row: sqlite3.Row, method_id: int) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    m = pctx.withdrawals.get_method(method_id)
    if m is None or int(m["is_active"]) != 1:
        return
    ok_c, err_c = pctx.withdrawals.check_conditions(m, user_row)
    if not ok_c:
        await pctx.reply_user_screen(update, f"🔒 {escape_html(err_c)}", inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, back_cb="um:u_withdraw")]), user_id=uid, lang=lang)
        return
    pctx.runtime.set_state(uid, flow="withdraw", step="await_wallet", data={"method_id": method_id})
    mname = m["name_bn"] if lang == "bn" else m["name_en"]
    instr = m["instruction_bn"] if lang == "bn" else m["instruction_en"]
    fee_lbl = pctx.withdrawals.format_fee_label(m, lang=lang)
    msg = (
        f"💸 <b>{escape_html(mname)}</b> | {fee_lbl}\n"
        f"📏 সীমা: {format_money(m['min_amount'])} – {format_money(m['max_amount'])}\n"
        f"📝 <i>{escape_html(instr)}</i>\n\n"
        + ("📲 আপনার অ্যাকাউন্ট নম্বর / ওয়ালেট অ্যাড্রেস লিখুন:" if lang == "bn" else "📲 Enter your personal Account Number / Wallet Address:")
    )
    await pctx.reply_user_screen(update, msg, inline_markup=InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang)]), user_id=uid, lang=lang)


async def handle_withdraw_runtime_input(
    pctx: PlatformContext,
    update: Update,
    user_row: sqlite3.Row,
    st: Dict[str, Any],
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    msg = update.message
    if msg is None or not msg.text:
        return
    txt = msg.text.strip()
    data = st["data"]
    step = st["step"]
    m = pctx.withdrawals.get_method(int(data["method_id"]))
    if m is None:
        pctx.runtime.clear_state(uid)
        return

    if step == "await_wallet":
        ok_w, norm_w, err_w = ValidationManager.validate_wallet_address(str(m["method_type"]), txt, str(m["wallet_regex"] or ""))
        if not ok_w:
            await msg.reply_text(f"❌ {escape_html(err_w)}", parse_mode=ParseMode.HTML)
            return
        ok_m, err_m = pctx.security.check_shared_wallet_multi_account(uid, norm_w)
        if not ok_m:
            await msg.reply_text(f"🛡️ {escape_html(err_m)}", parse_mode=ParseMode.HTML)
            return
        pctx.runtime.update_data(uid, {"wallet": norm_w}, new_step="await_amount")
        await msg.reply_text(
            f"💵 কত টাকা উত্তোলন করতে চান? (Earned: <code>{format_money(user_row['earned_balance'])}</code>):"
            if lang == "bn"
            else f"💵 Enter withdrawal amount (Earned: <code>{format_money(user_row['earned_balance'])}</code>):",
            parse_mode=ParseMode.HTML,
        )
        return

    if step == "await_amount":
        gross = parse_positive_float(txt)
        if gross is None or gross < float(m["min_amount"]) or gross > float(m["max_amount"]):
            await msg.reply_text(f"⚠️ Amount must be between {format_money(m['min_amount'])} and {format_money(m['max_amount'])}.")
            return
        earned = float(user_row["earned_balance"])
        if gross > earned + 1e-6:
            await msg.reply_text(f"❌ Insufficient Earned Balance ({format_money(earned)}).")
            return
        fee, net = pctx.withdrawals.calculate_fee_and_net(m, gross)
        if net <= 0:
            await msg.reply_text("❌ Net amount must be positive after fees.")
            return
        rem = round(earned - gross, 2)
        pctx.runtime.update_data(uid, {"gross": gross, "fee": fee, "net": net}, new_step="await_confirm")

        mname = m["name_bn"] if lang == "bn" else m["name_en"]
        prev = (
            f"🧾 <b>{'উইথড্র প্রিভিউ' if lang == 'bn' else 'Withdrawal Preview'}</b>\n"
            f"{pctx.config.get_theme()['divider']}\n"
            f"🏦 মেথড: <b>{escape_html(mname)}</b>\n"
            f"📲 অ্যাকাউন্ট: <code>{escape_html(data['wallet'])}</code>\n"
            f"💵 মোট (Gross): <code>{format_money(gross)}</code>\n"
            f"💸 ফি (Fee): <code>{format_money(fee)}</code>\n"
            f"✅ নিট প্রাপ্য (Net): <b><code>{format_money(net)}</code></b>\n"
            f"💼 অবশিষ্ট Earned: <code>{format_money(rem)}</code>"
        )
        kb = InlineKeyboardMarkup([
            [pctx.kb.ibtn("✅ Confirm Withdrawal" if lang == "en" else "✅ উইথড্র কনফার্ম করুন", callback_data="wd:conf", action_kind="confirm")],
            pctx.kb.cancel_row(lang=lang),
        ])
        await msg.reply_text(prev, parse_mode=ParseMode.HTML, reply_markup=kb)


async def confirm_withdraw_request(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_row: sqlite3.Row,
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    st = pctx.runtime.get_state(uid)
    if not st or st["flow"] != "withdraw" or st["step"] != "await_confirm":
        return
    data = st["data"]
    pctx.runtime.clear_state(uid)

    ok_w, msg_w, res = pctx.withdrawals.request_withdrawal(
        method_id=int(data["method_id"]),
        user_row=user_row,
        account_or_wallet=str(data["wallet"]),
        gross_amount=float(data["gross"]),
    )
    if not ok_w:
        await pctx.reply_user_screen(update, f"❌ {escape_html(msg_w)}", inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
        return

    # Post to Withdrawal Review Channel (-1004418032153)
    rev_ch = pctx.get_primary_channel_id("finance_review")
    if rev_ch:
        uname = f"@{user_row['username']}" if user_row["username"] else "-"
        big_tag = "\n🚨 <b>BIG WITHDRAW (Main-Admin Only)</b>" if res["is_big"] else ""
        ch_txt = (
            f"💸 <b>Withdrawal Request</b> | <code>{res['withdraw_uid']}</code>\n"
            f"🏦 <b>Method:</b> {escape_html(res['method_name_en'])}\n"
            f"👤 <b>User:</b> {escape_html(user_row['full_name'])} ({escape_html(uname)}) [<code>{uid}</code>]\n"
            f"📲 <b>Wallet:</b> <code>{escape_html(res['account'])}</code>\n"
            f"💵 Gross: <code>{format_money(res['gross'])}</code> | Fee: <code>{format_money(res['fee'])}</code> | Net: <b><code>{format_money(res['net'])}</code></b>"
            f"{big_tag}\n🕒 {now_dhaka_iso()}"
        )
        ch_kb = InlineKeyboardMarkup([
            [
                pctx.kb.ibtn("✅ Approve", callback_data=f"ch:wd:app:{res['id']}", action_kind="primary"),
                pctx.kb.ibtn("💸 Mark Paid", callback_data=f"ch:wd:paid:{res['id']}", action_kind="confirm"),
            ],
            [pctx.kb.ibtn("❌ Reject & Refund", callback_data=f"ch:wd:rej:{res['id']}", action_kind="reject")],
        ])
        ch_msg, _ = await safe_send_message_to_chat(context.bot, rev_ch, ch_txt, reply_markup=ch_kb)
        if ch_msg:
            pctx.withdrawals.set_channel_ref(int(res["id"]), rev_ch, ch_msg.message_id)

    mname = res["method_name_bn"] if lang == "bn" else res["method_name_en"]
    card, _, en = pctx.studio.render_event_message(
        "withdraw_request_submitted",
        lang=lang,
        name=str(user_row["full_name"]),
        withdraw_uid=res["withdraw_uid"],
        method=mname,
        account=res["account"],
        gross=format_money(res["gross"]),
        fee=format_money(res["fee"]),
        net_amount=format_money(res["net"]),
    )
    txt = card if (en and card) else f"⏳ Withdrawal <code>{res['withdraw_uid']}</code> submitted!"
    await pctx.reply_user_screen(update, txt, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)


# --- Misc User Runtime Inputs (Tickets, Appeals, Warranty, Points Exchange) ---

async def handle_misc_user_runtime_input(
    pctx: PlatformContext,
    update: Update,
    user_row: sqlite3.Row,
    st: Dict[str, Any],
) -> None:
    uid = int(user_row["user_id"])
    lang = str(user_row["language"] or "bn")
    msg = update.message
    if msg is None:
        return
    flow = st["flow"]
    text = (msg.text or msg.caption or "").strip()
    photo_id = msg.photo[-1].file_id if msg.photo else ""

    if flow == "ticket":
        if not text:
            await msg.reply_text("⚠️ অনুগ্রহ করে আপনার সমস্যার বিবরণ লিখুন।" if lang == "bn" else "⚠️ Please describe your issue.")
            return
        t_uid = pctx.tickets.create_ticket(uid, "Support Ticket", text, photo_id)
        pctx.runtime.clear_state(uid)
        pctx.notifications.enqueue(DEFAULT_MAIN_ADMIN_ID, f"🎫 <b>New Support Ticket:</b> <code>{t_uid}</code> from User <code>{uid}</code>\n{escape_html(text[:300])}")
        await msg.reply_text(
            f"✅ আপনার টিকেট <code>{t_uid}</code> জমা হয়েছে! এডমিন উত্তর দিলে ইনবক্সে পাবেন।" if lang == "bn" else f"✅ Ticket <code>{t_uid}</code> created!",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]),
        )
        return

    if flow == "appeal":
        if not text:
            await msg.reply_text("⚠️ আপিলের কারণ লিখুন।" if lang == "bn" else "⚠️ Enter your appeal reason.")
            return
        d = st["data"]
        pctx.runtime.clear_state(uid)
        ok_a, msg_a, a_uid = pctx.appeals.submit_appeal(uid, d["item_type"], int(d["item_id"]), d["item_uid"], text)
        if ok_a:
            pctx.notifications.enqueue(DEFAULT_MAIN_ADMIN_ID, f"⚖️ <b>New Appeal:</b> <code>{a_uid}</code> ({d['item_uid']}) from <code>{uid}</code>")
        await msg.reply_text(("✅ " if ok_a else "❌ ") + escape_html(msg_a), parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]))
        return

    if flow == "warranty":
        if not text:
            await msg.reply_text("⚠️ ওয়ারেন্টির সমস্যার কারণ লিখুন।" if lang == "bn" else "⚠️ Explain the warranty issue.")
            return
        d = st["data"]
        pctx.runtime.clear_state(uid)
        ok_w, msg_w, w_uid = pctx.store.create_warranty_request(int(d["order_id"]), uid, text, photo_id)
        if ok_w:
            pctx.notifications.enqueue(DEFAULT_MAIN_ADMIN_ID, f"🛡️ <b>Warranty Claim:</b> <code>{w_uid}</code> from <code>{uid}</code>")
        await msg.reply_text(("✅ " if ok_w else "❌ ") + escape_html(msg_w), parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]))
        return

    if flow == "points_exchange":
        pts = parse_positive_float(text)
        pctx.runtime.clear_state(uid)
        if pts is None:
            await msg.reply_text("⚠️ Invalid points amount.")
            return
        ok_e, msg_e, _ = pctx.extensions.exchange_points_to_currency(uid, pts)
        await msg.reply_text(("✅ " if ok_e else "❌ ") + escape_html(msg_e), parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]))
# ==============================================================================
# ADMIN PANEL HANDLERS — PART 1 (SECTIONS A-01 TO A-08)
# ==============================================================================

async def send_or_edit_admin(
    pctx: PlatformContext,
    update: Update,
    text_html: str,
    markup: InlineKeyboardMarkup,
) -> None:
    if update.callback_query and update.callback_query.message:
        try:
            await update.callback_query.message.edit_text(
                text=truncate_text(text_html),
                parse_mode=ParseMode.HTML,
                reply_markup=markup,
                disable_web_page_preview=True,
            )
            return
        except BadRequest as exc:
            if "message is not modified" in str(exc).lower():
                return
    chat_id = update.effective_chat.id if update.effective_chat else (update.effective_user.id if update.effective_user else 0)
    if chat_id:
        await safe_send_message_to_chat(update.get_bot(), chat_id, text_html, reply_markup=markup)


def admin_back_row(pctx: PlatformContext, back_cb: str = "adm:home") -> List[InlineKeyboardButton]:
    return [
        pctx.kb.ibtn("⬅️ Back", callback_data=back_cb, action_kind="default"),
        pctx.kb.ibtn("⚙️ Admin Home", callback_data="adm:home", action_kind="primary"),
    ]


# --- [A-01] Live Dashboard ---

async def ensure_admin_panel_ready(pctx: PlatformContext, update: Update, uid: int) -> bool:
    block_reason = pctx.permissions.get_access_block_reason(uid)
    if block_reason:
        if update.callback_query and update.callback_query.message:
            await send_or_edit_admin(pctx, update, block_reason, InlineKeyboardMarkup([[pctx.kb.ibtn("🏠 User Home", callback_data="um:home", action_kind="default")]]))
        elif update.message:
            await update.message.reply_text(block_reason)
        return False

    if pctx.permissions.is_password_required_for(uid, pctx.config) and not pctx.permissions.is_admin_session_unlocked(uid):
        pctx.runtime.set_state(uid, flow="admin_auth", step="await_password", data={"tries": 0})
        prompt = "🔐 <b>এডমিন প্যানেল পাসওয়ার্ড দিন</b>\nএডমিন প্যানেলে প্রবেশ করতে অনুগ্রহ করে পাসওয়ার্ড লিখুন:"
        kb = InlineKeyboardMarkup([pctx.kb.cancel_row(lang="bn", cancel_cb="flow:cancel")])
        if update.callback_query and update.callback_query.message:
            await send_or_edit_admin(pctx, update, prompt, kb)
        elif update.message:
            await update.message.reply_text(prompt, parse_mode=ParseMode.HTML, reply_markup=kb)
        return False
    return True


async def send_assistant_approval_request(
    pctx: PlatformContext,
    bot: Bot,
    target_aid: int,
    full_name: str,
    added_by: int,
) -> None:
    card = (
        f"🛂 <b>নতুন এডমিন অনুমোদন রিকোয়েস্ট</b>\n"
        f"{pctx.config.get_theme()['divider']}\n"
        f"🆔 Admin ID: <code>{target_aid}</code>\n"
        f"📛 নাম: <b>{escape_html(full_name or '-')}</b>\n"
        f"👤 রিকোয়েস্টকারী: <code>{added_by}</code>\n"
        f"⏳ স্ট্যাটাস: <b>PENDING APPROVAL</b>\n"
        f"🕒 {now_dhaka_iso()}"
    )
    kb = InlineKeyboardMarkup([[
        pctx.kb.ibtn("✅ Approve Admin", callback_data=f"admapp:yes:{target_aid}", action_kind="approve"),
        pctx.kb.ibtn("❌ Reject Admin", callback_data=f"admapp:no:{target_aid}", action_kind="reject"),
    ]])
    bk_ch = pctx.get_primary_channel_id("auto_backup")
    if bk_ch:
        await safe_send_message_to_chat(bot, bk_ch, card, reply_markup=kb)
    await safe_send_message_to_chat(bot, DEFAULT_MAIN_ADMIN_ID, card, reply_markup=kb)


async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pctx: PlatformContext = context.application.bot_data["pctx"]
    if update.effective_user is None:
        return
    uid = int(update.effective_user.id)
    if not await ensure_admin_panel_ready(pctx, update, uid):
        return
    pctx.runtime.clear_state(uid)
    await show_admin_dashboard(pctx, update, uid)


async def show_admin_dashboard(pctx: PlatformContext, update: Update, admin_id: int) -> None:
    st = pctx.reports.get_live_dashboard_stats()
    bot_name = pctx.config.get_bot_name("bn")
    div = pctx.config.get_theme()["divider"]
    panic_tag = "\n🚨 <b>EMERGENCY PANIC FREEZE IS ACTIVE!</b>" if pctx.security.is_panic_frozen() else ""
    maint_tag = "\n🛠️ <b>MAINTENANCE MODE IS ON</b>" if pctx.config.get_bool("maintenance_mode", False) else ""

    text = (
        f"⚙️ <b>{escape_html(bot_name)} — Admin Panel</b>{panic_tag}{maint_tag}\n{div}\n"
        f"👥 Users: <b>{st['total_users']}</b> (Active: {st['active_users']} | Blocked: {st['blocked_users']})\n"
        f"⏳ Pending: Task <b>{st['pending_tasks']}</b> | FS <b>{st['pending_fs']}</b> | Dep <b>{st['pending_deposits']}</b> | WD <b>{st['pending_withdraws']}</b>\n"
        f"📦 Store Stock: <b>{st['store_stock_avail']}</b> | 📲 OTP Live: <b>{st['otp_avail']}</b> (Active: {st['otp_active_sessions']})\n"
        f"🎫 Tickets: <b>{st['open_tickets']}</b> | ⚖️ Appeals: <b>{st['pending_appeals']}</b>\n"
        f"💰 Liability — Earned: <code>{format_money(st['total_earned_liability'])}</code> | Dep: <code>{format_money(st['total_deposit_liability'])}</code> | Held: <code>{format_money(st['total_held_liability'])}</code>"
    )

    sec_buttons: List[Tuple[str, str, str, str]] = [
        ("dashboard", "🔄 A-01 Refresh", "adm:home", "primary"),
        ("diagnostics", "🖥️ A-02 System & Test", "adm:s02", "default"),
        ("channels", "📢 A-03 Channels/Support", "adm:s03", "default"),
        ("force_join", "🔐 A-04 Force Join", "adm:s04", "primary"),
        ("texts", "📝 A-05 Texts & Rules", "adm:s05", "default"),
        ("buttons_colors", "⌨️ A-06 KB/Btns/Colors", "adm:s06", "default"),
        ("message_studio", "🎨 A-07 Msg Studio (96)", "adm:s07", "primary"),
        ("rules_controller", "🎛️ A-08 Sector & Rules", "adm:s08", "default"),
        ("tasks", "📋 A-09 Tasks/TOTP/Ck", "adm:s09", "primary"),
        ("auto_review", "⏱️ A-10 Auto-Review", "adm:s10", "default"),
        ("file_submit", "📁 A-11 File Submit", "adm:s11", "primary"),
        ("product_store", "🛒 A-12 Product Store", "adm:s12", "primary"),
        ("otp_system", "📲 A-13 OTP Receiver", "adm:s13", "primary"),
        ("deposits", "💳 A-14 Deposit & OCR", "adm:s14", "primary"),
        ("withdrawals", "💸 A-15 Withdrawal", "adm:s15", "confirm"),
        ("growth_lb", "🏆 A-16 Growth & LB", "adm:s16", "confirm"),
        ("users_finance", "👥 A-17 Users/Finance", "adm:s17", "default"),
        ("tickets_broadcast", "🎫 A-18 Ticket/BC/Que", "adm:s18", "default"),
        ("security_locks", "🛡️ A-19 Security/Locks", "adm:s19", "cancel"),
        ("backup_ledger", "👑 A-20 Perm/Bak/Ledg", "adm:s20", "default"),
        ("backup_ledger", "🆕 সিস্টেম ও অটো-ব্যাকআপ", "adm:sys", "confirm"),
    ]

    grid: List[List[InlineKeyboardButton]] = []
    row: List[InlineKeyboardButton] = []
    for perm_k, lbl, cb, kind in sec_buttons:
        if pctx.permissions.has_permission(admin_id, perm_k):
            row.append(pctx.kb.ibtn(lbl, callback_data=cb, action_kind=kind))
            if len(row) == 2:
                grid.append(row)
                row = []
    if row:
        grid.append(row)
    if pctx.permissions.is_password_required_for(admin_id, pctx.config):
        grid.append([pctx.kb.ibtn("🔒 Lock Admin Panel", callback_data="adm:lock", action_kind="cancel")])
    grid.append([pctx.kb.ibtn("🏠 User Main Menu", callback_data="um:home", action_kind="default")])
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(grid))


# --- [A-02] System Status & Diagnostics ---

async def show_adm_s02_diagnostics(pctx: PlatformContext, update: Update) -> None:
    counts = pctx.db.get_table_counts()
    top_tables = ", ".join(f"{k}:{v}" for k, v in list(counts.items())[:10])
    err_tail = ""
    if ERROR_LOG_PATH.exists():
        lines = ERROR_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        err_tail = "\n".join(lines[-5:]) if lines else "No errors logged."
    else:
        err_tail = "No errors.log yet."

    text = (
        f"🖥️ <b>A-02 System Status & Diagnostics</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Python: <code>{sys.version.split()[0]}</code> | Engine: <code>v{BOT_ENGINE_VERSION}</code> | DB Schema: <code>v{DB_SCHEMA_VERSION}</code>\n"
        f"• Bot Name: <b>{escape_html(pctx.config.get_bot_name('bn'))}</b> (@{escape_html(BOT_IDENTITY.get_username() or '-')})\n"
        f"• DB Path: <code>{escape_html(DB_PATH.name)}</code> | Tables: <b>{len(counts)}</b>\n"
        f"• Sample Counts: <code>{escape_html(top_tables)}</code>\n\n"
        f"📜 <b>Recent Errors (Secret-Masked):</b>\n<pre>{escape_html(err_tail[:700])}</pre>"
    )
    kb = InlineKeyboardMarkup([
        [pctx.kb.ibtn("🧪 Run Full Self-Test & Channel Check", callback_data="adm:s02:test", action_kind="confirm")],
        admin_back_row(pctx),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


async def run_adm_s02_self_test(pctx: PlatformContext, update: Update) -> None:
    results: List[str] = []
    # 1. SQLite integrity
    chk = pctx.db.query_one("PRAGMA integrity_check")
    results.append(f"• SQLite WAL Integrity: {'✅ OK' if chk and str(chk[0]).lower() == 'ok' else '❌ FAIL'}")
    # 2. TOTP RFC-6238 test
    ok_t, code_t, _, _, _ = compute_rfc6238_totp("JBSWY3DPEHPK3PXP")
    results.append(f"• RFC-6238 TOTP Engine: {'✅ OK (' + code_t + ')' if ok_t and len(code_t) == 6 else '❌ FAIL'}")
    # 3. Cookie Canonicalizer test
    ok_c1, _, _, h1, _ = parse_and_canonicalize_cookie("c_user=12345; xs=abcde;", "c_user,xs")
    ok_c2, _, _, h2, _ = parse_and_canonicalize_cookie('[{"name":"xs","value":"abcde"},{"name":"c_user","value":"12345"}]', "c_user,xs")
    results.append(f"• Cookie Reorder-Proof Dup Check: {'✅ OK' if ok_c1 and ok_c2 and h1 == h2 else '❌ FAIL'}")
    # 4. Channel Bot Access check
    bot = update.get_bot()
    for ch in pctx.db.query_all("SELECT purpose, chat_id FROM channels WHERE is_active=1"):
        try:
            chat_obj = await bot.get_chat(chat_id=str(ch["chat_id"]))
            results.append(f"• Channel [{ch['purpose']}] ({ch['chat_id']}): ✅ {escape_html(chat_obj.title or 'OK')}")
        except Exception as exc:
            results.append(f"• Channel [{ch['purpose']}] ({ch['chat_id']}): ❌ {escape_html(str(exc)[:60])}")

    text = "🧪 <b>One-Click Self-Test Report</b>\n" + "\n".join(results)
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup([admin_back_row(pctx, "adm:s02")]))


# --- [A-03] Channels & Support ---

async def show_adm_s03_channels(pctx: PlatformContext, update: Update) -> None:
    chs = pctx.db.query_all("SELECT * FROM channels ORDER BY purpose, sort_order, id")
    sups = pctx.db.query_all("SELECT * FROM support_contacts ORDER BY sort_order, id")
    lines = [f"📢 <b>A-03 Channels & Support Settings</b>\n{pctx.config.get_theme()['divider']}"]
    kb_rows: List[List[InlineKeyboardButton]] = []

    lines.append("<b>Channels:</b>")
    for ch in chs:
        st_i = "🟢" if int(ch["is_active"]) == 1 else "🔴"
        hd_i = "🙈" if int(ch["is_hidden"]) == 1 else "👁️"
        lines.append(f"• #{ch['id']} [{ch['purpose']}] <code>{escape_html(ch['chat_id'])}</code> {st_i}{hd_i}")
        kb_rows.append([
            pctx.kb.ibtn(f"{st_i} #{ch['id']} {ch['purpose'][:10]}", callback_data=f"adm:s03:chtog:{ch['id']}", action_kind="default"),
            pctx.kb.ibtn("📤 Test", callback_data=f"adm:s03:chtest:{ch['id']}", action_kind="primary"),
            pctx.kb.ibtn("🗑️", callback_data=f"adm:s03:chdel:{ch['id']}", action_kind="cancel"),
        ])

    lines.append("\n<b>Support Contacts:</b>")
    for sp in sups:
        st_s = "🟢" if int(sp["is_active"]) == 1 else "🔴"
        lines.append(f"• #{sp['id']} {escape_html(sp['name'])}: <code>{escape_html(sp['username_or_link'])}</code> {st_s}")
        kb_rows.append([
            pctx.kb.ibtn(f"{st_s} Sup #{sp['id']} {sp['username_or_link'][:14]}", callback_data=f"adm:s03:sptog:{sp['id']}", action_kind="default"),
            pctx.kb.ibtn("🗑️", callback_data=f"adm:s03:spdel:{sp['id']}", action_kind="cancel"),
        ])

    kb_rows.append([
        pctx.kb.ibtn("➕ Add Channel", callback_data="adm:s03:chadd", action_kind="confirm"),
        pctx.kb.ibtn("➕ Add Support", callback_data="adm:s03:spadd", action_kind="confirm"),
    ])
    kb_rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, "\n".join(lines), InlineKeyboardMarkup(kb_rows))


# --- [A-04] Force Join Control ---

async def show_adm_s04_force_join(pctx: PlatformContext, update: Update) -> None:
    fj_on = pctx.config.get_bool("force_join_enabled", True)
    fj_hid = pctx.config.get_bool("force_join_hidden", False)
    fj_str = pctx.config.get_bool("force_join_strict", True)
    chs = pctx.force_join.list_force_join_channels(active_only=False)

    lines = [
        f"🔐 <b>A-04 Strict Force Join Control</b>\n{pctx.config.get_theme()['divider']}",
        f"• Master Switch: <b>{'ON 🟢' if fj_on else 'OFF 🔴'}</b> | Hidden: <b>{'YES' if fj_hid else 'NO'}</b>",
        f"• Strict Lock (All Active Required): <b>{'ON 🔒' if fj_str else 'OFF'}</b>",
        "\n<b>Force Join Channels:</b>",
    ]
    kb_rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn(f"Master: {'ON 🟢' if fj_on else 'OFF 🔴'}", callback_data="adm:s04:tog:force_join_enabled", action_kind="confirm" if fj_on else "cancel"),
            pctx.kb.ibtn(f"Strict: {'ON 🔒' if fj_str else 'OFF'}", callback_data="adm:s04:tog:force_join_strict", action_kind="primary"),
        ],
    ]
    for ch in chs:
        st_i = "🟢" if int(ch["is_active"]) == 1 else "🔴"
        lines.append(f"• #{ch['id']} <b>{escape_html(ch['title'])}</b> (<code>{escape_html(ch['chat_id'])}</code>) {st_i}")
        kb_rows.append([
            pctx.kb.ibtn(f"{st_i} Toggle #{ch['id']}", callback_data=f"adm:s03:chtog:{ch['id']}", action_kind="default"),
            pctx.kb.ibtn("🗑️ Remove", callback_data=f"adm:s03:chdel:{ch['id']}", action_kind="cancel"),
        ])
    kb_rows.append([pctx.kb.ibtn("➕ Add Force Join Channel", callback_data="adm:s04:add", action_kind="confirm")])
    kb_rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, "\n".join(lines), InlineKeyboardMarkup(kb_rows))


# --- [A-05] Text, Language & Rules Manager ---

async def show_adm_s05_texts(pctx: PlatformContext, update: Update) -> None:
    def_lang = pctx.config.get_str("default_language", "bn")
    sw_on = pctx.config.get_bool("language_switcher_enabled", True)
    bn_name = pctx.config.get_str("bot_name_bn", "AUTO")
    en_name = pctx.config.get_str("bot_name_en", "AUTO")

    text = (
        f"📝 <b>A-05 Text, Language & Rules Manager (RULE 90.A)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Bot Name BN: <code>{escape_html(bn_name)}</code> | EN: <code>{escape_html(en_name)}</code>\n"
        f"• Default Lang: <b>{def_lang.upper()}</b> | Switcher: <b>{'ON 🟢' if sw_on else 'OFF 🔴'}</b>\n\n"
        f"১৮টি ক্যাটাগরির যেকোনো লেখা বা ইউজার রুলস দুই ভাষায় এডিট ও প্রিভিউ করুন:"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn("📜 Edit User Rules (BN/EN)", callback_data="adm:s05:key:rules_content", action_kind="confirm"),
            pctx.kb.ibtn("🔍 Search Any Text", callback_data="adm:s05:search", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn("🏷️ Edit Bot Name (BN/EN)", callback_data="adm:s05:botname", action_kind="default"),
            pctx.kb.ibtn(f"🌐 Switcher: {'ON' if sw_on else 'OFF'}", callback_data="adm:s05:togsw", action_kind="default"),
        ],
    ]
    cats = pctx.text.list_categories()
    cur_r: List[InlineKeyboardButton] = []
    for cat_key, cbn, _, cnt in cats:
        cur_r.append(pctx.kb.ibtn(f"{cbn[:18]} ({cnt})", callback_data=f"adm:s05:cat:{cat_key}", action_kind="default"))
        if len(cur_r) == 2:
            rows.append(cur_r)
            cur_r = []
    if cur_r:
        rows.append(cur_r)
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s05_category(pctx: PlatformContext, update: Update, cat_key: str) -> None:
    items = pctx.text.list_by_category(cat_key)
    lines = [f"📂 <b>Category: {escape_html(cat_key)}</b>", pctx.config.get_theme()["divider"]]
    rows: List[List[InlineKeyboardButton]] = []
    for it in items:
        st_i = "🟢" if int(it["is_active"]) == 1 else "🔴"
        hd_i = "🙈" if int(it["is_hidden"]) == 1 else "👁️"
        lines.append(f"• <code>{it['text_key']}</code> {st_i}{hd_i} — {escape_html(it['label_bn'])}")
        rows.append([pctx.kb.ibtn(f"{st_i} {it['label_bn'][:24]}", callback_data=f"adm:s05:key:{it['text_key']}", action_kind="primary")])
    rows.append(admin_back_row(pctx, "adm:s05"))
    await send_or_edit_admin(pctx, update, "\n".join(lines), InlineKeyboardMarkup(rows))


async def show_adm_s05_key_detail(pctx: PlatformContext, update: Update, text_key: str) -> None:
    row = pctx.text.get_raw_row(text_key)
    if row is None:
        return
    st_i = "ON 🟢" if int(row["is_active"]) == 1 else "OFF 🔴"
    hd_i = "Hidden 🙈" if int(row["is_hidden"]) == 1 else "Visible 👁️"
    text = (
        f"📝 <b>Key:</b> <code>{escape_html(text_key)}</code>\n"
        f"Status: <b>{st_i}</b> | Visibility: <b>{hd_i}</b>\n"
        f"Placeholders: <code>{escape_html(row['placeholders_json'])}</code>\n\n"
        f"🇧🇩 <b>BN:</b>\n<pre>{escape_html(str(row['text_bn'])[:600])}</pre>\n\n"
        f"🇺🇸 <b>EN:</b>\n<pre>{escape_html(str(row['text_en'])[:600])}</pre>"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("✏️ Edit BN", callback_data=f"adm:s05:ebn:{text_key}", action_kind="primary"),
            pctx.kb.ibtn("✏️ Edit EN", callback_data=f"adm:s05:een:{text_key}", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn(f"Toggle {st_i}", callback_data=f"adm:s05:tact:{text_key}", action_kind="default"),
            pctx.kb.ibtn(f"Toggle {hd_i}", callback_data=f"adm:s05:thid:{text_key}", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("🌐 Global", callback_data=f"adm:s05:sz:{text_key}:global", action_kind="confirm" if pctx.config.get_str(f"msg_size_txt_{text_key}", "global") == "global" else "default"),
            pctx.kb.ibtn("🔹 ছোট", callback_data=f"adm:s05:sz:{text_key}:short", action_kind="confirm" if pctx.config.get_str(f"msg_size_txt_{text_key}", "global") == "short" else "default"),
            pctx.kb.ibtn("🔸 মাঝারি", callback_data=f"adm:s05:sz:{text_key}:medium", action_kind="confirm" if pctx.config.get_str(f"msg_size_txt_{text_key}", "global") == "medium" else "default"),
            pctx.kb.ibtn("💎 বড়", callback_data=f"adm:s05:sz:{text_key}:current", action_kind="confirm" if pctx.config.get_str(f"msg_size_txt_{text_key}", "global") == "current" else "default"),
        ],
        [
            pctx.kb.ibtn("👁️ Live Preview", callback_data=f"adm:s05:prev:{text_key}", action_kind="confirm"),
            pctx.kb.ibtn("🔄 Reset Default", callback_data=f"adm:s05:rst:{text_key}", action_kind="cancel"),
        ],
        admin_back_row(pctx, f"adm:s05:cat:{row['category']}"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-06] Keyboard, Menu, Dynamic Buttons & RULE 88 Colors ---

async def show_adm_s06_buttons(pctx: PlatformContext, update: Update) -> None:
    rk_on = pctx.config.get_bool("reply_keyboard_enabled", True)
    rk_hd = pctx.config.get_bool("reply_keyboard_hidden", False)
    ik_on = pctx.config.get_bool("inline_keyboard_enabled", True)
    ik_hd = pctx.config.get_bool("inline_keyboard_hidden", False)
    col_on = pctx.config.get_bool("button_colors_enabled", True)
    cols = pctx.config.get_int("menu_columns", 2)

    btns = pctx.kb.list_menu_buttons(include_hidden=True, include_disabled=True)
    lines = [
        f"⌨️ <b>A-06 Keyboard, Buttons & Colors (RULE 88–89)</b>\n{pctx.config.get_theme()['divider']}",
        f"• Reply KB: <b>{'ON' if rk_on else 'OFF'}</b> ({'Hidden' if rk_hd else 'Shown'}) | Inline KB: <b>{'ON' if ik_on else 'OFF'}</b> ({'Hidden' if ik_hd else 'Shown'})",
        f"• API 9.4 Colors: <b>{'ON 🎨' if col_on else 'OFF'}</b> | Columns: <b>{cols}</b>",
    ]
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn(f"Reply: {'ON' if rk_on else 'OFF'}", callback_data="adm:s06:kb:reply_keyboard_enabled", action_kind="primary"),
            pctx.kb.ibtn(f"Reply Hide: {'YES' if rk_hd else 'NO'}", callback_data="adm:s06:kb:reply_keyboard_hidden", action_kind="default"),
        ],
        [
            pctx.kb.ibtn(f"Inline: {'ON' if ik_on else 'OFF'}", callback_data="adm:s06:kb:inline_keyboard_enabled", action_kind="primary"),
            pctx.kb.ibtn(f"Inline Hide: {'YES' if ik_hd else 'NO'}", callback_data="adm:s06:kb:inline_keyboard_hidden", action_kind="default"),
        ],
        [
            pctx.kb.ibtn(f"🎨 Colors: {'ON' if col_on else 'OFF'}", callback_data="adm:s06:coltog", action_kind="confirm" if col_on else "default"),
            pctx.kb.ibtn("🔄 Reset Colors", callback_data="adm:s06:colrst", action_kind="cancel"),
        ],
        [
            pctx.kb.ibtn("➕ Add Custom Button", callback_data="adm:s06:add", action_kind="confirm"),
            pctx.kb.ibtn("🎭 Edit Theme", callback_data="adm:s06:theme", action_kind="default"),
        ],
    ]
    for b in btns:
        st_i = "🟢" if int(b["is_enabled"]) == 1 else "🔴"
        hd_i = "🙈" if int(b["is_hidden"]) == 1 else "👁️"
        c_em = STYLE_EMOJI_MAP.get(str(b["button_style"]), "⚪")
        rows.append([
            pctx.kb.ibtn(f"{st_i}{hd_i} {b['emoji']} {b['label_bn'][:16]}", callback_data=f"adm:s06:btn:{b['id']}", action_kind="default"),
            pctx.kb.ibtn(f"{c_em} Color", callback_data=f"adm:s06:cyc:{b['id']}", action_kind="primary"),
        ])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, "\n".join(lines), InlineKeyboardMarkup(rows))


async def show_adm_s06_btn_detail(pctx: PlatformContext, update: Update, btn_id: int) -> None:
    b = pctx.kb.get_button_by_id(btn_id)
    if b is None:
        return
    c_em = STYLE_EMOJI_MAP.get(str(b["button_style"]), "⚪")
    text = (
        f"🔘 <b>Button #{b['id']}:</b> {escape_html(b['emoji'])} {escape_html(b['label_bn'])} / {escape_html(b['label_en'])}\n"
        f"• Key: <code>{b['button_key']}</code> | Action: <code>{b['action_type']}:{b['action_target']}</code>\n"
        f"• Enabled: <b>{'ON' if b['is_enabled'] else 'OFF'}</b> | Hidden: <b>{'YES' if b['is_hidden'] else 'NO'}</b>\n"
        f"• Style: {c_em} <code>{b['button_style']}</code> | Placement: <code>{b['placement']}</code>"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("Toggle ON/OFF", callback_data=f"adm:s06:ben:{btn_id}", action_kind="primary"),
            pctx.kb.ibtn("Toggle Hide/Unhide", callback_data=f"adm:s06:bhid:{btn_id}", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("⚪ default", callback_data=f"adm:s06:sc:{btn_id}:default", action_kind="default"),
            pctx.kb.ibtn("🔵 primary", callback_data=f"adm:s06:sc:{btn_id}:primary", action_kind="primary"),
            pctx.kb.ibtn("🟢 success", callback_data=f"adm:s06:sc:{btn_id}:success", action_kind="confirm"),
            pctx.kb.ibtn("🔴 danger", callback_data=f"adm:s06:sc:{btn_id}:danger", action_kind="cancel"),
        ],
        [
            pctx.kb.ibtn("✏️ Edit Labels (BN|EN|Emoji)", callback_data=f"adm:s06:bed:{btn_id}", action_kind="default"),
        ],
        admin_back_row(pctx, "adm:s06"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-07] Central Message Studio (RULE 96) ---

async def show_adm_s07_studio(pctx: PlatformContext, update: Update, page: int = 0) -> None:
    evs = pctx.studio.list_events()
    per_page = 8
    chunk = evs[page * per_page : (page + 1) * per_page]
    sz = pctx.config.get_str("message_size_mode", "current")
    sz_lbl = {"short": "ছোট", "medium": "মাঝারি", "current": "বড় / বর্তমান"}.get(sz, sz)
    text = f"🎨 <b>A-07 Central Message Studio (RULE 96)</b>\n{pctx.config.get_theme()['divider']}\n📏 গ্লোবাল মেসেজ সাইজ: <b>{sz_lbl}</b>\n২৫+ ইভেন্ট এবং প্রতিটি ইভেন্টে ৩০+ ডিজাইন:"
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn("🔹 ছোট", callback_data="adm:s07:sz:short", action_kind="confirm" if sz == "short" else "default"),
            pctx.kb.ibtn("🔸 মাঝারি", callback_data="adm:s07:sz:medium", action_kind="confirm" if sz == "medium" else "default"),
            pctx.kb.ibtn("💎 বড়/বর্তমান", callback_data="adm:s07:sz:current", action_kind="confirm" if sz == "current" else "default"),
        ],
        [pctx.kb.ibtn("➕ Add New Custom Event", callback_data="adm:s07:addev", action_kind="confirm")],
    ]
    for ev in chunk:
        st_i = "🟢" if int(ev["is_enabled"]) == 1 else "🔴"
        rows.append([pctx.kb.ibtn(f"{st_i} {ev['title_bn']} [{ev['delivery_mode']}]", callback_data=f"adm:s07:ev:{ev['event_key']}", action_kind="primary")])
    pag: List[InlineKeyboardButton] = []
    if page > 0:
        pag.append(pctx.kb.ibtn("◀️ Prev", callback_data=f"adm:s07:p:{page - 1}", action_kind="default"))
    if (page + 1) * per_page < len(evs):
        pag.append(pctx.kb.ibtn("Next ▶️", callback_data=f"adm:s07:p:{page + 1}", action_kind="default"))
    if pag:
        rows.append(pag)
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s07_event(pctx: PlatformContext, update: Update, event_key: str, page: int = 0) -> None:
    ev = pctx.studio.get_event(event_key)
    if ev is None:
        return
    variants = pctx.studio.list_variants(event_key)
    chunk = variants[page * 10 : (page + 1) * 10]
    text = (
        f"🎨 <b>Event:</b> {escape_html(ev['title_bn'])} (<code>{event_key}</code>)\n"
        f"• Enabled: <b>{'ON 🟢' if ev['is_enabled'] else 'OFF 🔴'}</b> | Hidden: <b>{'YES' if ev['is_hidden'] else 'NO'}</b>\n"
        f"• Mode: <b>{ev['delivery_mode'].upper()}</b> | Silent: <b>{'YES' if ev['silent_mode'] else 'NO'}</b> | Mask Privacy: <b>{'ON' if ev['mask_privacy'] else 'OFF'}</b>\n"
        f"• Total Variants: <b>{len(variants)}</b>"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn("Toggle ON/OFF", callback_data=f"adm:s07:ef:{event_key}:is_enabled", action_kind="primary"),
            pctx.kb.ibtn("Toggle Hide", callback_data=f"adm:s07:ef:{event_key}:is_hidden", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("Fixed", callback_data=f"adm:s07:md:{event_key}:fixed", action_kind="confirm" if ev["delivery_mode"] == "fixed" else "default"),
            pctx.kb.ibtn("Rotate", callback_data=f"adm:s07:md:{event_key}:rotate", action_kind="confirm" if ev["delivery_mode"] == "rotate" else "default"),
            pctx.kb.ibtn("Random", callback_data=f"adm:s07:md:{event_key}:random", action_kind="confirm" if ev["delivery_mode"] == "random" else "default"),
        ],
        [
            pctx.kb.ibtn("🌐 Global", callback_data=f"adm:s07:evsz:{event_key}:global", action_kind="confirm" if pctx.config.get_str(f"msg_size_ev_{event_key}", "global") == "global" else "default"),
            pctx.kb.ibtn("🔹 ছোট", callback_data=f"adm:s07:evsz:{event_key}:short", action_kind="confirm" if pctx.config.get_str(f"msg_size_ev_{event_key}", "global") == "short" else "default"),
            pctx.kb.ibtn("🔸 মাঝারি", callback_data=f"adm:s07:evsz:{event_key}:medium", action_kind="confirm" if pctx.config.get_str(f"msg_size_ev_{event_key}", "global") == "medium" else "default"),
            pctx.kb.ibtn("💎 বড়", callback_data=f"adm:s07:evsz:{event_key}:current", action_kind="confirm" if pctx.config.get_str(f"msg_size_ev_{event_key}", "global") == "current" else "default"),
        ],
        [
            pctx.kb.ibtn("🔇 Silent Toggle", callback_data=f"adm:s07:ef:{event_key}:silent_mode", action_kind="default"),
            pctx.kb.ibtn("➕ Add Variant (31+)", callback_data=f"adm:s07:addv:{event_key}", action_kind="confirm"),
        ],
    ]
    cur_r: List[InlineKeyboardButton] = []
    for v in chunk:
        vi = "🟢" if int(v["is_enabled"]) == 1 else "🔴"
        cur_r.append(pctx.kb.ibtn(f"{vi} #{v['variant_no']}", callback_data=f"adm:s07:v:{v['id']}", action_kind="default"))
        if len(cur_r) == 2:
            rows.append(cur_r)
            cur_r = []
    if cur_r:
        rows.append(cur_r)
    pag: List[InlineKeyboardButton] = []
    if page > 0:
        pag.append(pctx.kb.ibtn("◀️", callback_data=f"adm:s07:evp:{event_key}:{page - 1}", action_kind="default"))
    if (page + 1) * 10 < len(variants):
        pag.append(pctx.kb.ibtn("▶️", callback_data=f"adm:s07:evp:{event_key}:{page + 1}", action_kind="default"))
    if pag:
        rows.append(pag)
    rows.append(admin_back_row(pctx, "adm:s07"))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s07_variant(pctx: PlatformContext, update: Update, variant_id: int) -> None:
    v = pctx.studio.get_variant(variant_id)
    if v is None:
        return
    prev_bn, _, _ = pctx.studio.render_event_message(str(v["event_key"]), lang="bn", variant_id=variant_id, name="Demo User", user_id="12345", balance="৳500")
    text = (
        f"🖼️ <b>Variant #{v['variant_no']}</b> (<code>{v['event_key']}</code>)\n"
        f"• Enabled: <b>{'ON 🟢' if v['is_enabled'] else 'OFF 🔴'}</b> | Hidden: <b>{'YES' if v['is_hidden'] else 'NO'}</b>\n\n"
        f"<b>Preview (BN):</b>\n{prev_bn}"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("Toggle ON/OFF", callback_data=f"adm:s07:vf:{variant_id}:is_enabled", action_kind="primary"),
            pctx.kb.ibtn("Toggle Hide", callback_data=f"adm:s07:vf:{variant_id}:is_hidden", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("✏️ Edit BN", callback_data=f"adm:s07:ve:{variant_id}:bn", action_kind="primary"),
            pctx.kb.ibtn("✏️ Edit EN", callback_data=f"adm:s07:ve:{variant_id}:en", action_kind="primary"),
        ],
        [pctx.kb.ibtn("🗄️ Archive Variant", callback_data=f"adm:s07:vf:{variant_id}:is_archived", action_kind="cancel")],
        admin_back_row(pctx, f"adm:s07:ev:{v['event_key']}"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-08] Sector, Role & Rule Controller (Sectors 1-17 Line-by-Line BN/EN) ---

async def show_adm_s08_sectors(pctx: PlatformContext, update: Update) -> None:
    sectors = pctx.rules.list_sectors()
    text = f"🎛️ <b>A-08 Sector & Rule Controller (Sectors 1–17)</b>\n{pctx.config.get_theme()['divider']}\nযেকোনো সেক্টরে ঢুকে তার প্রতিটি রুল দুই ভাষায় নিয়ন্ত্রণ করুন:"
    rows: List[List[InlineKeyboardButton]] = []
    for s_no, s_bn, _, tot, act in sectors:
        rows.append([pctx.kb.ibtn(f"{s_bn[:28]} ({act}/{tot})", callback_data=f"adm:s08:sec:{s_no}", action_kind="primary")])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s08_sector_rules(pctx: PlatformContext, update: Update, sector_no: int) -> None:
    rules = pctx.rules.list_rules_by_sector(sector_no)
    text = f"📂 <b>Sector {sector_no} Rules</b>\n{pctx.config.get_theme()['divider']}"
    rows: List[List[InlineKeyboardButton]] = []
    for r in rules:
        st_i = "🔒" if int(r["is_locked"]) == 1 else ("🟢" if int(r["is_enabled"]) == 1 else "🔴")
        rows.append([pctx.kb.ibtn(f"{st_i} {r['rule_code']}: {r['title_bn'][:20]}", callback_data=f"adm:s08:r:{r['rule_key']}", action_kind="default")])
    rows.append(admin_back_row(pctx, "adm:s08"))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s08_rule_detail(pctx: PlatformContext, update: Update, rule_key: str) -> None:
    r = pctx.rules.get_rule(rule_key)
    if r is None:
        return
    st_i = "LOCKED 🔒" if int(r["is_locked"]) == 1 else ("ON 🟢" if int(r["is_enabled"]) == 1 else "OFF 🔴")
    hd_i = "Hidden 🙈" if int(r["is_hidden"]) == 1 else "Visible 👁️"
    text = (
        f"🎛️ <b>{escape_html(r['rule_code'])}</b> (<code>{rule_key}</code>)\n"
        f"Status: <b>{st_i}</b> | {hd_i}\n\n"
        f"🇧🇩 <b>{escape_html(r['title_bn'])}</b>\n{escape_html(r['desc_bn'])}\n\n"
        f"🇺🇸 <b>{escape_html(r['title_en'])}</b>\n{escape_html(r['desc_en'])}\n\n"
        f"📘 <b>ব্যবহার নির্দেশিকা:</b>\n<blockquote>{escape_html(r['usage_guide_bn'])}</blockquote>"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("Toggle ON/OFF", callback_data=f"adm:s08:rtog:{rule_key}:is_enabled", action_kind="primary"),
            pctx.kb.ibtn("Toggle Hide", callback_data=f"adm:s08:rtog:{rule_key}:is_hidden", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("✏️ Edit BN", callback_data=f"adm:s08:red:{rule_key}:bn", action_kind="default"),
            pctx.kb.ibtn("✏️ Edit EN", callback_data=f"adm:s08:red:{rule_key}:en", action_kind="default"),
        ],
        [pctx.kb.ibtn("🔄 Reset Rule", callback_data=f"adm:s08:rrst:{rule_key}", action_kind="cancel")],
        admin_back_row(pctx, f"adm:s08:sec:{r['sector_no']}"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)
# ==============================================================================
# ADMIN PANEL HANDLERS — PART 2 (SECTIONS A-09 TO A-14)
# ==============================================================================

# --- [A-09] Task, TOTP Dup & Cookie Manager ---

async def show_adm_s09_tasks(pctx: PlatformContext, update: Update) -> None:
    totp_dup = pctx.config.get_bool("global_totp_dup_block", True)
    ck_step = pctx.config.get_bool("global_cookie_step_enabled", True)
    ck_dup = pctx.config.get_bool("global_cookie_dup_block", True)
    ck_keys = pctx.config.get_str("global_cookie_required_keys", "none")

    tasks = pctx.tasks.list_tasks(active_only=False, include_archived=False)
    lines = [
        f"📋 <b>A-09 Task, TOTP & Cookie Manager</b>\n{pctx.config.get_theme()['divider']}",
        f"• Global TOTP Dup Blk: <b>{'ON 🟢' if totp_dup else 'OFF 🔴'}</b>",
        f"• Global Cookie Step: <b>{'ON 🟢' if ck_step else 'OFF 🔴'}</b> | Dup Blk: <b>{'ON 🟢' if ck_dup else 'OFF 🔴'}</b>",
        f"• Global Cookie Keys: <code>{escape_html(ck_keys)}</code>",
        f"\nমোট টাস্ক: <b>{len(tasks)}</b>",
    ]
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn(f"🔁 TOTP Dup Blk: {'ON' if totp_dup else 'OFF'}", callback_data="adm:s09:gtog:global_totp_dup_block", action_kind="confirm" if totp_dup else "cancel"),
            pctx.kb.ibtn(f"🍪 Cookie Step: {'ON' if ck_step else 'OFF'}", callback_data="adm:s09:gtog:global_cookie_step_enabled", action_kind="confirm" if ck_step else "cancel"),
        ],
        [
            pctx.kb.ibtn(f"🍪 Cookie Dup Blk: {'ON' if ck_dup else 'OFF'}", callback_data="adm:s09:gtog:global_cookie_dup_block", action_kind="confirm" if ck_dup else "cancel"),
            pctx.kb.ibtn("⚙️ Cookie Keys", callback_data="adm:s09:gkeys", action_kind="primary"),
        ],
        [pctx.kb.ibtn("➕ 6-Step Add New Task Wizard", callback_data="adm:s09:add", action_kind="confirm")],
    ]
    for t in tasks[:15]:
        st_i = "🟢" if str(t["status"]) == "active" else ("⏸️" if str(t["status"]) == "auto_paused" else "🔴")
        rows.append([pctx.kb.ibtn(f"{st_i} #{t['id']} {t['title_bn'][:20]} ({format_money(t['reward_amount'])})", callback_data=f"adm:s09:t:{t['id']}", action_kind="default")])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, "\n".join(lines), InlineKeyboardMarkup(rows))


async def show_adm_s09_task_detail(pctx: PlatformContext, update: Update, task_id: int) -> None:
    t = pctx.tasks.get_task(task_id)
    if t is None:
        return
    cnts = pctx.tasks.get_source_counts(task_id)
    text = (
        f"📌 <b>Task #{t['id']}: {escape_html(t['title_bn'])}</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Status: <b>{str(t['status']).upper()}</b> | Reward: <code>{format_money(t['reward_amount'])}</code>\n"
        f"• Source: {'ON' if t['source_enabled'] else 'OFF'} (Avail: {cnts['available']}/{cnts['total']}) | Combo: <code>{t['field_combo_mode']}</code> | PW: <code>{t['password_mode']}</code>\n"
        f"• 🔑 TOTP: <b>{'ON' if t['require_totp'] else 'OFF'}</b> | 🔁 TOTP Dup: <b>{'ON' if t['totp_dup_block'] else 'OFF'}</b>\n"
        f"• 🍪 Cookie: <b>{'ON' if t['require_cookie'] else 'OFF'}</b> | 🍪 Ck-Dup: <b>{'ON' if t['cookie_dup_block'] else 'OFF'}</b> | Keys: <code>{escape_html(t['cookie_required_keys'])}</code>\n"
        f"• Auto-Del: {'ON' if t['auto_delete_messages'] else 'OFF'} | Auto-App: {'ON ('+str(t['auto_approve_sec'])+'s)' if t['auto_approve_enabled'] else 'OFF'}"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn(f"🔑 Toggle TOTP: {'ON' if t['require_totp'] else 'OFF'}", callback_data=f"adm:s09:ttog:{task_id}:require_totp", action_kind="confirm" if t["require_totp"] else "default"),
            pctx.kb.ibtn(f"🔁 TOTP Dup: {'ON' if t['totp_dup_block'] else 'OFF'}", callback_data=f"adm:s09:ttog:{task_id}:totp_dup_block", action_kind="confirm" if t["totp_dup_block"] else "cancel"),
        ],
        [
            pctx.kb.ibtn(f"🍪 Cookie: {'ON' if t['require_cookie'] else 'OFF'}", callback_data=f"adm:s09:ttog:{task_id}:require_cookie", action_kind="confirm" if t["require_cookie"] else "default"),
            pctx.kb.ibtn(f"🍪 Ck-Dup: {'ON' if t['cookie_dup_block'] else 'OFF'}", callback_data=f"adm:s09:ttog:{task_id}:cookie_dup_block", action_kind="confirm" if t["cookie_dup_block"] else "cancel"),
        ],
        [
            pctx.kb.ibtn("🎛️ Combo & PW Wizard", callback_data=f"adm:s09:wiz:{task_id}", action_kind="primary"),
            pctx.kb.ibtn("⚙️ Task Ck-Keys", callback_data=f"adm:s09:tkeys:{task_id}", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("📤 Upload Source File", callback_data=f"adm:s09:upsrc:{task_id}", action_kind="primary"),
            pctx.kb.ibtn("🪜 Steps & Rules", callback_data=f"adm:s09:steps:{task_id}", action_kind="default"),
        ],
        [
            pctx.kb.ibtn(f"🗑️ AutoDel: {'ON' if t['auto_delete_messages'] else 'OFF'}", callback_data=f"adm:s09:ttog:{task_id}:auto_delete_messages", action_kind="default"),
            pctx.kb.ibtn(f"⚡ AutoApp: {'ON' if t['auto_approve_enabled'] else 'OFF'}", callback_data=f"adm:s09:ttog:{task_id}:auto_approve_enabled", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("👁️ Test as User", callback_data=f"adm:s09:testu:{task_id}", action_kind="primary"),
            pctx.kb.ibtn("📋 Clone", callback_data=f"adm:s09:clone:{task_id}", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("📥 XLSX All", callback_data=f"adm:s09:expa:{task_id}", action_kind="confirm"),
            pctx.kb.ibtn("📥 XLSX New", callback_data=f"adm:s09:expn:{task_id}", action_kind="confirm"),
        ],
        [
            pctx.kb.ibtn("⏯️ Toggle Active/Pause", callback_data=f"adm:s09:stog:{task_id}", action_kind="default"),
            pctx.kb.ibtn("🗄️ Archive", callback_data=f"adm:s09:arch:{task_id}", action_kind="cancel"),
        ],
        admin_back_row(pctx, "adm:s09"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


async def show_adm_s09_wizard(pctx: PlatformContext, update: Update, task_id: int) -> None:
    t = pctx.tasks.get_task(task_id)
    if t is None:
        return
    text = (
        f"🎛️ <b>Button-Click Combo & Password Wizard (RULE 91)</b> — Task #{task_id}\n"
        f"• Current Field Combo: <code>{t['field_combo_mode']}</code>\n"
        f"• Current Password Mode: <code>{t['password_mode']}</code>\n"
        f"• Static PW: <code>{escape_html(t['static_password'] or '-')}</code> | Pattern: <code>{escape_html(t['password_pattern'])}</code>\n\n"
        f"বাটনে চাপ দিয়ে কম্বিনেশন ও পাসওয়ার্ড মোড সেট করুন:"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("🔑 Only Password", callback_data=f"adm:s09:scmb:{task_id}:only_pass", action_kind="confirm" if t["field_combo_mode"] == "only_pass" else "default"),
            pctx.kb.ibtn("👤 User + Pass", callback_data=f"adm:s09:scmb:{task_id}:user_pass", action_kind="confirm" if t["field_combo_mode"] == "user_pass" else "default"),
        ],
        [
            pctx.kb.ibtn("📋 User+Pass+Full", callback_data=f"adm:s09:scmb:{task_id}:user_pass_full", action_kind="confirm" if t["field_combo_mode"] == "user_pass_full" else "default"),
            pctx.kb.ibtn("⚙️ Custom Combo", callback_data=f"adm:s09:scmb:{task_id}:custom", action_kind="confirm" if t["field_combo_mode"] == "custom" else "default"),
        ],
        [
            pctx.kb.ibtn("🪪 Full Name + Pass", callback_data=f"adm:s09:scmb:{task_id}:full_pass", action_kind="confirm" if t["field_combo_mode"] == "full_pass" else "default"),
            pctx.kb.ibtn("✏️ Set Custom Fields", callback_data=f"adm:s09:setcmb:{task_id}", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("📁 File PW", callback_data=f"adm:s09:spwm:{task_id}:file_only", action_kind="primary" if t["password_mode"] == "file_only" else "default"),
            pctx.kb.ibtn("🔒 Static", callback_data=f"adm:s09:spwm:{task_id}:static", action_kind="primary" if t["password_mode"] == "static" else "default"),
            pctx.kb.ibtn("🎲 Pattern", callback_data=f"adm:s09:spwm:{task_id}:pattern", action_kind="primary" if t["password_mode"] == "pattern" else "default"),
            pctx.kb.ibtn("🔀 Hybrid", callback_data=f"adm:s09:spwm:{task_id}:hybrid", action_kind="primary" if t["password_mode"] == "hybrid" else "default"),
        ],
        [pctx.kb.ibtn("✏️ Set Static/Pattern Value", callback_data=f"adm:s09:setpw:{task_id}", action_kind="default")],
        admin_back_row(pctx, f"adm:s09:t:{task_id}"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


async def show_adm_s09_steps(pctx: PlatformContext, update: Update, task_id: int) -> None:
    steps = pctx.tasks.list_task_steps(task_id, active_only=False)
    lines = [f"🪜 <b>Task #{task_id} Button & Rule Steps</b>", pctx.config.get_theme()["divider"]]
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn("➕ Pre-Code Step", callback_data=f"adm:s09:addst:{task_id}:pre_code", action_kind="confirm"),
            pctx.kb.ibtn("➕ Post-Code Step", callback_data=f"adm:s09:addst:{task_id}:post_code", action_kind="confirm"),
        ]
    ]
    for s in steps:
        st_i = "🟢" if int(s["is_enabled"]) == 1 else "🔴"
        lines.append(f"• [{s['phase']}] #{s['step_order']} {st_i} <b>{escape_html(s['title_bn'])}</b> ({s['input_type']})")
        rows.append([
            pctx.kb.ibtn(f"{st_i} {s['title_bn'][:16]}", callback_data=f"adm:s09:sttog:{s['id']}:{task_id}", action_kind="default"),
            pctx.kb.ibtn("⬆️", callback_data=f"adm:s09:stup:{s['id']}:{task_id}", action_kind="default"),
            pctx.kb.ibtn("⬇️", callback_data=f"adm:s09:stdn:{s['id']}:{task_id}", action_kind="default"),
            pctx.kb.ibtn("🗑️", callback_data=f"adm:s09:stdel:{s['id']}:{task_id}", action_kind="cancel"),
        ])
    rows.append(admin_back_row(pctx, f"adm:s09:t:{task_id}"))
    await send_or_edit_admin(pctx, update, "\n".join(lines), InlineKeyboardMarkup(rows))


# --- [A-10] Auto-Review & Scheduler ---

async def show_adm_s10_auto_review(pctx: PlatformContext, update: Update) -> None:
    t_app = pctx.config.get_bool("task_auto_approve_global", False)
    t_app_s = pctx.config.get_int("task_auto_approve_sec", 60)
    t_rej = pctx.config.get_bool("task_auto_reject_global", False)
    t_rej_s = pctx.config.get_int("task_auto_reject_sec", 300)
    d_app = pctx.config.get_bool("deposit_auto_approve_global", False)
    d_app_s = pctx.config.get_int("deposit_auto_approve_sec", 60)
    d_rej = pctx.config.get_bool("deposit_auto_reject_global", False)
    d_prf = pctx.config.get_bool("deposit_proof_auto_reject", True)
    d_cap = pctx.config.get_float("deposit_max_auto_cap", 5000.0)
    mid_sum = pctx.config.get_bool("daily_summary_enabled", True)

    text = (
        f"⏱️ <b>A-10 Auto-Review & Scheduler (RULE 15, 16, 78, 95.B)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"📋 <b>Tasks:</b> Auto-App: <b>{'ON' if t_app else 'OFF'}</b> ({format_duration_seconds(t_app_s)}) | Auto-Rej: <b>{'ON' if t_rej else 'OFF'}</b> ({format_duration_seconds(t_rej_s)})\n"
        f"💳 <b>Deposits:</b> Auto-App: <b>{'ON' if d_app else 'OFF'}</b> ({format_duration_seconds(d_app_s)}) | Auto-Rej: <b>{'ON' if d_rej else 'OFF'}</b>\n"
        f"🛡️ Proof Auto-Rej: <b>{'ON' if d_prf else 'OFF'}</b> | Max Cap: <code>{format_money(d_cap)}</code>\n"
        f"🌙 Midnight Summary (12 AM Dhaka): <b>{'ON' if mid_sum else 'OFF'}</b>"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn(f"Task AutoApp: {'ON' if t_app else 'OFF'}", callback_data="adm:s10:tog:task_auto_approve_global", action_kind="confirm" if t_app else "default"),
            pctx.kb.ibtn("⏱️ Set Delay (30s/2m)", callback_data="adm:s10:set:task_auto_approve_sec", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn(f"Task AutoRej: {'ON' if t_rej else 'OFF'}", callback_data="adm:s10:tog:task_auto_reject_global", action_kind="cancel" if t_rej else "default"),
            pctx.kb.ibtn("⏱️ Set Rej Delay", callback_data="adm:s10:set:task_auto_reject_sec", action_kind="default"),
        ],
        [
            pctx.kb.ibtn(f"Dep AutoApp: {'ON' if d_app else 'OFF'}", callback_data="adm:s10:tog:deposit_auto_approve_global", action_kind="confirm" if d_app else "default"),
            pctx.kb.ibtn("⏱️ Set Dep Delay", callback_data="adm:s10:set:deposit_auto_approve_sec", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn(f"Dep AutoRej: {'ON' if d_rej else 'OFF'}", callback_data="adm:s10:tog:deposit_auto_reject_global", action_kind="cancel" if d_rej else "default"),
            pctx.kb.ibtn(f"Proof AutoRej: {'ON' if d_prf else 'OFF'}", callback_data="adm:s10:tog:deposit_proof_auto_reject", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn("💰 Set Max Auto Cap", callback_data="adm:s10:set:deposit_max_auto_cap", action_kind="default"),
            pctx.kb.ibtn("📤 Send Summary Now", callback_data="adm:s10:sumnow", action_kind="confirm"),
        ],
        admin_back_row(pctx),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-11] File Submit Manager & 1 / 3 / 5 / 7 / 10 / 15 / 20 Batch Review UI ---

async def show_adm_s11_fs(pctx: PlatformContext, update: Update) -> None:
    fs_list = pctx.fs.list_fs_tasks(active_only=False, include_archived=False)
    pending = pctx.fs.list_pending_submissions(limit=10)
    failed = pctx.fs.list_failed_deliveries()
    text = (
        f"📁 <b>A-11 File Submit Manager (1 / 3 / 5 / 7 / 10 / 15 / 20 Batch Review)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• সক্রিয় FS টাস্ক: <b>{len(fs_list)}</b> | পেন্ডিং সাবমিশন: <b>{len(pending)}</b> | ফেইলড ডেলিভারি: <b>{len(failed)}</b>"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn(f"📥 Review Queue ({len(pending)})", callback_data="adm:s11:queue", action_kind="primary"),
            pctx.kb.ibtn("➕ Add FS Task", callback_data="adm:s11:add", action_kind="confirm"),
        ],
        [
            pctx.kb.ibtn("🚫 Reject Templates", callback_data="adm:s11:tpls", action_kind="default"),
            pctx.kb.ibtn("📥 Export All FS (.xlsx)", callback_data="adm:s11:expall", action_kind="confirm"),
        ],
    ]
    for f in fs_list[:10]:
        st_i = "🟢" if str(f["status"]) == "active" else "🔴"
        rows.append([pctx.kb.ibtn(f"{st_i} #{f['id']} {f['title_bn'][:20]} ({format_money(f['reward_per_record'])})", callback_data=f"adm:s11:t:{f['id']}", action_kind="default")])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s11_queue(pctx: PlatformContext, update: Update) -> None:
    pending = pctx.fs.list_pending_submissions(limit=15)
    lines = [f"📥 <b>FS Pending Review Queue ({len(pending)})</b>", pctx.config.get_theme()["divider"]]
    rows: List[List[InlineKeyboardButton]] = []
    if not pending:
        lines.append("✅ কোনো পেন্ডিং ফাইল সাবমিট নেই!")
    for s in pending:
        lines.append(f"• <code>{s['sub_uid']}</code> | User <code>{s['user_id']}</code> | Pending: <b>{s['pending_count']}/{s['total_records']}</b>")
        rows.append([pctx.kb.ibtn(f"🔍 Review {s['sub_uid']} ({s['pending_count']} pending)", callback_data=f"adm:s11:rev:{s['id']}", action_kind="primary")])
    rows.append(admin_back_row(pctx, "adm:s11"))
    await send_or_edit_admin(pctx, update, "\n".join(lines), InlineKeyboardMarkup(rows))


async def show_adm_s11_review_sub(pctx: PlatformContext, update: Update, fs_sub_id: int) -> None:
    sub = pctx.fs.get_submission(fs_sub_id)
    if sub is None:
        return
    pending_recs = pctx.fs.list_submission_records(fs_sub_id, status_filter="pending", limit=25)
    lines = [
        f"🔍 <b>Review: {sub['sub_uid']}</b> (User: <code>{sub['user_id']}</code>)",
        f"✅ {sub['approved_count']} | ❌ {sub['rejected_count']} | ⏳ <b>{sub['pending_count']}</b> (Total: {sub['total_records']})",
        pctx.config.get_theme()["divider"],
    ]
    for r in pending_recs[:10]:
        lines.append(f"L{r['line_no']} [<code>{r['stable_uid']}</code>]: <code>{escape_html(r['raw_line'][:45])}</code>")

    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("✅ 1", callback_data=f"adm:s11:ba:{fs_sub_id}:1", action_kind="approve"),
            pctx.kb.ibtn("✅ 3", callback_data=f"adm:s11:ba:{fs_sub_id}:3", action_kind="approve"),
            pctx.kb.ibtn("✅ 5", callback_data=f"adm:s11:ba:{fs_sub_id}:5", action_kind="approve"),
            pctx.kb.ibtn("✅ 7", callback_data=f"adm:s11:ba:{fs_sub_id}:7", action_kind="approve"),
        ],
        [
            pctx.kb.ibtn("✅ 10", callback_data=f"adm:s11:ba:{fs_sub_id}:10", action_kind="approve"),
            pctx.kb.ibtn("✅ 15", callback_data=f"adm:s11:ba:{fs_sub_id}:15", action_kind="approve"),
            pctx.kb.ibtn("✅ 20", callback_data=f"adm:s11:ba:{fs_sub_id}:20", action_kind="approve"),
            pctx.kb.ibtn("✅ ALL", callback_data=f"adm:s11:ba:{fs_sub_id}:9999", action_kind="approve"),
        ],
        [
            pctx.kb.ibtn("❌ 1", callback_data=f"adm:s11:br:{fs_sub_id}:1", action_kind="reject"),
            pctx.kb.ibtn("❌ 3", callback_data=f"adm:s11:br:{fs_sub_id}:3", action_kind="reject"),
            pctx.kb.ibtn("❌ 5", callback_data=f"adm:s11:br:{fs_sub_id}:5", action_kind="reject"),
            pctx.kb.ibtn("❌ 7", callback_data=f"adm:s11:br:{fs_sub_id}:7", action_kind="reject"),
        ],
        [
            pctx.kb.ibtn("❌ 10", callback_data=f"adm:s11:br:{fs_sub_id}:10", action_kind="reject"),
            pctx.kb.ibtn("❌ 15", callback_data=f"adm:s11:br:{fs_sub_id}:15", action_kind="reject"),
            pctx.kb.ibtn("❌ 20", callback_data=f"adm:s11:br:{fs_sub_id}:20", action_kind="reject"),
            pctx.kb.ibtn("❌ ALL", callback_data=f"adm:s11:br:{fs_sub_id}:9999", action_kind="reject"),
        ],
        admin_back_row(pctx, "adm:s11:queue"),
    ])
    await send_or_edit_admin(pctx, update, "\n".join(lines), kb)


# --- [A-12] Product Store Manager ---

async def show_adm_s12_store(pctx: PlatformContext, update: Update) -> None:
    cats = pctx.store.list_categories(active_only=False)
    prods = pctx.store.list_products(active_only=False)
    war_cnt = pctx.db.query_one("SELECT COUNT(*) AS c FROM store_warranty_requests WHERE status='pending'")
    man_cnt = pctx.db.query_one("SELECT COUNT(*) AS c FROM store_orders WHERE status='pending_approval'")
    text = (
        f"🛒 <b>A-12 Product Store Manager (RULE 74, 84, 93)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Categories: <b>{len(cats)}</b> | Products: <b>{len(prods)}</b>\n"
        f"• Pending Manual Orders: <b>{man_cnt['c'] if man_cnt else 0}</b> | Warranty Claims: <b>{war_cnt['c'] if war_cnt else 0}</b>"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn("➕ Add Category", callback_data="adm:s12:addcat", action_kind="confirm"),
            pctx.kb.ibtn("➕ Add Product", callback_data="adm:s12:addprod", action_kind="confirm"),
        ],
        [
            pctx.kb.ibtn("🎟️ Coupons", callback_data="adm:s12:coupons", action_kind="primary"),
            pctx.kb.ibtn("🛡️ Warranty Queue", callback_data="adm:s12:warr", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("📥 Export Orders (.xlsx)", callback_data="adm:s12:expord", action_kind="confirm"),
        ],
    ]
    for p in prods[:12]:
        cnts = pctx.store.get_stock_counts(int(p["id"]))
        st_i = "🟢" if int(p["is_active"]) == 1 else "🔴"
        rows.append([pctx.kb.ibtn(f"{st_i} #{p['id']} {p['name_bn'][:18]} (Stk:{cnts['available']})", callback_data=f"adm:s12:p:{p['id']}", action_kind="default")])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s12_prod_detail(pctx: PlatformContext, update: Update, product_id: int) -> None:
    p = pctx.store.get_product(product_id)
    if p is None:
        return
    cnts = pctx.store.get_stock_counts(product_id)
    steps = pctx.store.list_product_steps(product_id)
    text = (
        f"🛍️ <b>Product #{p['id']}: {escape_html(p['name_bn'])}</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Price: <code>{format_money(p['price'])}</code> | Stock: <b>{cnts['available']}</b> (Sold: {cnts['sold']})\n"
        f"• Status: <b>{'ACTIVE 🟢' if p['is_active'] else 'PAUSED 🔴'}</b> | Hidden: {'YES' if p['is_hidden'] else 'NO'}\n"
        f"• Wallet: <code>{p['wallet_mode']}</code> | Delivery: <code>{p['delivery_mode']}</code> | Warranty: {p['warranty_hours']}h\n"
        f"• Payout Auto-Post: {'ON' if p['payout_post_enabled'] else 'OFF'} | Dynamic Steps: <b>{len(steps)}</b>"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("📤 Upload Stock File", callback_data=f"adm:s12:upstk:{product_id}", action_kind="confirm"),
            pctx.kb.ibtn("➕ Add Step (20+)", callback_data=f"adm:s12:addst:{product_id}", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn("🏷️ Add Price Tier", callback_data=f"adm:s12:addtr:{product_id}", action_kind="default"),
            pctx.kb.ibtn("📋 Clone Product", callback_data=f"adm:s12:clone:{product_id}", action_kind="default"),
        ],
        [
            pctx.kb.ibtn(f"Toggle {'OFF' if p['is_active'] else 'ON'}", callback_data=f"adm:s12:ptog:{product_id}:is_active", action_kind="primary"),
            pctx.kb.ibtn(f"Wallet: {p['wallet_mode']}", callback_data=f"adm:s12:wal:{product_id}", action_kind="default"),
        ],
        [pctx.kb.ibtn("🗄️ Archive Product", callback_data=f"adm:s12:ptog:{product_id}:is_archived", action_kind="cancel")],
        admin_back_row(pctx, "adm:s12"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-13] OTP Receiver Manager ---

async def show_adm_s13_otp(pctx: PlatformContext, update: Update) -> None:
    otp_on = pctx.config.get_bool("otp_system_enabled", True)
    b_rel = pctx.config.get_bool("otp_relay_bridge_enabled", True)
    b_wh = pctx.config.get_bool("otp_webhook_bridge_enabled", False)
    b_api = pctx.config.get_bool("otp_provider_api_enabled", False)
    mask_on = pctx.config.get_bool("otp_channel_mask_privacy", True)
    countries = pctx.otp.list_countries(active_only=False)

    text = (
        f"📲 <b>A-13 OTP Receiver Manager (RULE 81, 82, 84)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• System: <b>{'ON 🟢' if otp_on else 'OFF 🔴'}</b> | Channel Masking: <b>{'ON' if mask_on else 'OFF'}</b>\n"
        f"• Bridges: Relay={'ON' if b_rel else 'OFF'} | Webhook={'ON' if b_wh else 'OFF'} | API={'ON' if b_api else 'OFF'}"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn(f"OTP System: {'ON' if otp_on else 'OFF'}", callback_data="adm:s13:tog:otp_system_enabled", action_kind="confirm" if otp_on else "cancel"),
            pctx.kb.ibtn("⚡ Quick-Push OTP", callback_data="adm:s13:qpush", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn(f"Relay: {'ON' if b_rel else 'OFF'}", callback_data="adm:s13:tog:otp_relay_bridge_enabled", action_kind="default"),
            pctx.kb.ibtn(f"Webhook: {'ON' if b_wh else 'OFF'}", callback_data="adm:s13:tog:otp_webhook_bridge_enabled", action_kind="default"),
            pctx.kb.ibtn(f"API: {'ON' if b_api else 'OFF'}", callback_data="adm:s13:tog:otp_provider_api_enabled", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("➕ Add Country", callback_data="adm:s13:addc", action_kind="confirm"),
            pctx.kb.ibtn("📥 Export OTP Logs", callback_data="adm:s13:exp", action_kind="default"),
        ],
    ]
    for c in countries[:12]:
        cnts = pctx.otp.get_country_stock_counts(int(c["id"]))
        st_i = "🟢" if int(c["is_active"]) == 1 else "🔴"
        rows.append([pctx.kb.ibtn(f"{st_i} {c['flag_emoji']} {c['name_en']} (Avail:{cnts['available']} | {c['numbers_per_click']}x)", callback_data=f"adm:s13:c:{c['id']}", action_kind="default")])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s13_country_detail(pctx: PlatformContext, update: Update, country_id: int) -> None:
    c = pctx.otp.get_country(country_id)
    if c is None:
        return
    cnts = pctx.otp.get_country_stock_counts(country_id)
    text = (
        f"{c['flag_emoji']} <b>Country #{c['id']}: {escape_html(c['name_en'])}</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Available: <b>{cnts['available']}</b> | Assigned: {cnts['assigned']} | Burned: {cnts['burned']}\n"
        f"• Numbers/Click: <b>{c['numbers_per_click']}</b> | Fee: <code>{format_money(c['fee_amount'])}</code> | Wait: {c['wait_timeout_sec']}s\n"
        f"• Multi-OTP: {'ON' if c['multi_otp_enabled'] else 'OFF'} | Active: {'YES' if c['is_active'] else 'NO'}"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("📤 Upload Numbers File", callback_data=f"adm:s13:upn:{country_id}", action_kind="confirm"),
            pctx.kb.ibtn("🔢 Set Numbers/Click", callback_data=f"adm:s13:setn:{country_id}", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn(f"Toggle {'OFF' if c['is_active'] else 'ON'}", callback_data=f"adm:s13:ctog:{country_id}:is_active", action_kind="default"),
            pctx.kb.ibtn(f"Multi-OTP: {'ON' if c['multi_otp_enabled'] else 'OFF'}", callback_data=f"adm:s13:ctog:{country_id}:multi_otp_enabled", action_kind="default"),
        ],
        admin_back_row(pctx, "adm:s13"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-14] Deposit & OCR Manager ---

async def show_adm_s14_deposit(pctx: PlatformContext, update: Update) -> None:
    ocr_on = pctx.config.get_bool("ocr_enabled", True)
    strict_mm = pctx.config.get_bool("ocr_strict_mismatch_reject", True)
    fallback = pctx.config.get_str("ocr_unreadable_policy", "flag_manual")
    methods = pctx.deposits.list_methods(active_only=False)
    pending = pctx.deposits.list_pending_deposits(limit=8)

    text = (
        f"💳 <b>A-14 Deposit & Hybrid OCR Manager (RULE 75 + OCR)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Hybrid OCR: <b>{'ON 🟢' if ocr_on else 'OFF 🔴'}</b> | Strict Mismatch Auto-Reject: <b>{'ON 🔒' if strict_mm else 'OFF'}</b>\n"
        f"• Unreadable Fallback: <code>{fallback}</code>\n"
        f"• Pending Deposits: <b>{len(pending)}</b>"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn(f"OCR: {'ON' if ocr_on else 'OFF'}", callback_data="adm:s14:tog:ocr_enabled", action_kind="confirm" if ocr_on else "cancel"),
            pctx.kb.ibtn(f"Strict Mismatch: {'ON' if strict_mm else 'OFF'}", callback_data="adm:s14:tog:ocr_strict_mismatch_reject", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn("🔑 Set Cloud OCR URL/Key", callback_data="adm:s14:ocrapi", action_kind="default"),
            pctx.kb.ibtn("➕ Add Deposit Method", callback_data="adm:s14:addm", action_kind="confirm"),
        ],
    ]
    for m in methods:
        st_i = "🟢" if int(m["is_active"]) == 1 else "🔴"
        rows.append([pctx.kb.ibtn(f"{st_i} {m['name_en']} ({m['account_number']})", callback_data=f"adm:s14:m:{m['id']}", action_kind="default")])
    for p in pending[:5]:
        rows.append([
            pctx.kb.ibtn(f"✅ {p['deposit_uid']} ({format_money(p['amount'])})", callback_data=f"adm:s14:app:{p['id']}", action_kind="approve"),
            pctx.kb.ibtn("❌ Reject", callback_data=f"adm:s14:rej:{p['id']}", action_kind="reject"),
        ])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))

# ==============================================================================
# ADMIN PANEL HANDLERS — PART 3 (SECTIONS A-15 TO A-20)
# ==============================================================================

# --- [A-15] Withdrawal Manager ---

async def show_adm_s15_withdraw(pctx: PlatformContext, update: Update) -> None:
    methods = pctx.withdrawals.list_methods(active_only=False)
    pending = pctx.withdrawals.list_pending_withdrawals(limit=10)
    text = (
        f"💸 <b>A-15 Withdrawal Manager (RULE 29, 30, 70)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Methods: <b>{len(methods)}</b> | Pending/Approved Queue: <b>{len(pending)}</b>"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [pctx.kb.ibtn("➕ Add Withdraw Method", callback_data="adm:s15:addm", action_kind="confirm")]
    ]
    for m in methods:
        st_i = "🟢" if int(m["is_active"]) == 1 else "🔴"
        rows.append([pctx.kb.ibtn(f"{st_i} {m['name_en']} ({pctx.withdrawals.format_fee_label(m,'en')})", callback_data=f"adm:s15:m:{m['id']}", action_kind="default")])
    for w in pending[:6]:
        rows.append([
            pctx.kb.ibtn(f"💸 Paid {w['withdraw_uid']} ({format_money(w['net_amount'])})", callback_data=f"adm:s15:paid:{w['id']}", action_kind="confirm"),
            pctx.kb.ibtn("❌ Rej", callback_data=f"adm:s15:rej:{w['id']}", action_kind="reject"),
        ])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))
async def show_adm_s14_method_detail(pctx: PlatformContext, update: Update, method_id: int) -> None:
    m = pctx.deposits.get_method(method_id)
    if m is None:
        return
    st_i = "ON 🟢" if int(m["is_active"]) == 1 else "OFF 🔴"
    hd_i = "Hidden 🙈" if int(m["is_hidden"]) == 1 else "Visible 👁️"
    text = (
        f"💳 <b>Edit Deposit Method #{m['id']}</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Name BN: <b>{escape_html(m['name_bn'])}</b> | EN: <b>{escape_html(m['name_en'])}</b>\n"
        f"• Account/PayID: <code>{escape_html(m['account_number'])}</code> ({escape_html(m['account_holder_type'])})\n"
        f"• Network: <code>{escape_html(m['network_info'] or '-')}</code>\n"
        f"• Limits: {format_money(m['min_amount'])} – {format_money(m['max_amount'])} | Bonus: {m['bonus_percent']:g}% | Charge: {m['charge_percent']:g}%\n"
        f"• Status: <b>{st_i}</b> | <b>{hd_i}</b>\n"
        f"• Require: TxID={'ON' if m['require_txid'] else 'OFF'} | SS={'ON' if m['require_screenshot'] else 'OFF'} | Sender={'ON' if m['require_sender'] else 'OFF'}"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn(f"Toggle {st_i}", callback_data=f"adm:s14:mtog:{method_id}:is_active", action_kind="primary"),
            pctx.kb.ibtn(f"Toggle {hd_i}", callback_data=f"adm:s14:mtog:{method_id}:is_hidden", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("✏️ Edit Name (BN|EN)", callback_data=f"adm:s14:med:{method_id}:name", action_kind="default"),
            pctx.kb.ibtn("📲 Edit Number/PayID", callback_data=f"adm:s14:med:{method_id}:acc", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn("💰 Edit Min/Max/Bonus", callback_data=f"adm:s14:med:{method_id}:limits", action_kind="default"),
            pctx.kb.ibtn("📝 Edit Instructions", callback_data=f"adm:s14:med:{method_id}:instr", action_kind="default"),
        ],
        [
            pctx.kb.ibtn(f"TxID: {'ON' if m['require_txid'] else 'OFF'}", callback_data=f"adm:s14:mtog:{method_id}:require_txid", action_kind="default"),
            pctx.kb.ibtn(f"Photo: {'ON' if m['require_screenshot'] else 'OFF'}", callback_data=f"adm:s14:mtog:{method_id}:require_screenshot", action_kind="default"),
            pctx.kb.ibtn(f"Sender: {'ON' if m['require_sender'] else 'OFF'}", callback_data=f"adm:s14:mtog:{method_id}:require_sender", action_kind="default"),
        ],
        [pctx.kb.ibtn("🗄️ Archive / Delete Method", callback_data=f"adm:s14:march:{method_id}", action_kind="cancel")],
        admin_back_row(pctx, "adm:s14"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


async def show_adm_s15_method_detail(pctx: PlatformContext, update: Update, method_id: int) -> None:
    m = pctx.withdrawals.get_method(method_id)
    if m is None:
        return
    st_i = "ON 🟢" if int(m["is_active"]) == 1 else "OFF 🔴"
    hd_i = "Hidden 🙈" if int(m["is_hidden"]) == 1 else "Visible 👁️"
    text = (
        f"💸 <b>Edit Withdraw Method #{m['id']}</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Name BN: <b>{escape_html(m['name_bn'])}</b> | EN: <b>{escape_html(m['name_en'])}</b>\n"
        f"• Type: <code>{escape_html(m['method_type'])}</code> | {pctx.withdrawals.format_fee_label(m, 'en')}\n"
        f"• Limits: {format_money(m['min_amount'])} – {format_money(m['max_amount'])}\n"
        f"• Regex: <code>{escape_html(m['wallet_regex'] or '-')}</code>\n"
        f"• Status: <b>{st_i}</b> | <b>{hd_i}</b>"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn(f"Toggle {st_i}", callback_data=f"adm:s15:mtog:{method_id}:is_active", action_kind="primary"),
            pctx.kb.ibtn(f"Toggle {hd_i}", callback_data=f"adm:s15:mtog:{method_id}:is_hidden", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("✏️ Edit Name (BN|EN)", callback_data=f"adm:s15:med:{method_id}:name", action_kind="default"),
            pctx.kb.ibtn("💸 Edit Fee Type & Val", callback_data=f"adm:s15:med:{method_id}:fee", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn("💰 Edit Min/Max", callback_data=f"adm:s15:med:{method_id}:limits", action_kind="default"),
            pctx.kb.ibtn("🔐 Edit Type & Regex", callback_data=f"adm:s15:med:{method_id}:regex", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("📝 Edit Instructions", callback_data=f"adm:s15:med:{method_id}:instr", action_kind="default"),
            pctx.kb.ibtn("🗄️ Archive / Delete", callback_data=f"adm:s15:march:{method_id}", action_kind="cancel"),
        ],
        admin_back_row(pctx, "adm:s15"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


async def execute_full_auto_backup_delivery(
    pctx: PlatformContext,
    bot: Bot,
    admin_id: int = 0,
) -> Dict[str, Any]:
    bk_type = "auto" if admin_id == 0 else "manual_hub"
    ok_z, _, zip_path, b_uid = pctx.backup.create_zip_backup(bk_type, admin_id=admin_id)
    target_mode = pctx.config.get_str("auto_backup_target", "channel")
    bk_ch = pctx.get_primary_channel_id("auto_backup")

    recipients: List[Union[int, str]] = []
    if target_mode in ("channel", "both") and bk_ch:
        recipients.append(bk_ch)
    if target_mode in ("main_admin", "both") or not recipients:
        recipients.append(DEFAULT_MAIN_ADMIN_ID)

    files_to_send: List[Tuple[Path, str]] = []
    if ok_z and zip_path and zip_path.exists():
        files_to_send.append((zip_path, f"💾 Auto-Backup DB+Logs <code>{b_uid}</code>\n🕒 {now_dhaka_iso()}"))

    if pctx.config.get_bool("auto_backup_send_individual_files", True):
        rows_u = pctx.users.list_all_for_export()
        if rows_u:
            hdrs = list(rows_u[0].keys())
            fp_u, _ = pctx.excel.export_rows(hdrs, [[r[h] for h in hdrs] for r in rows_u], "Auto_All_Users", "auto", "xlsx", "Users", admin_id)
            files_to_send.append((fp_u, f"👥 All Users ({len(rows_u)} rows)"))

        for t in pctx.tasks.list_tasks(active_only=False, include_archived=False):
            ok_t, _, fp_t, sids = pctx.task_subs.export_task_master_file(
                int(t["id"]), "xlsx", incremental_only=False, admin_id=admin_id, bypass_cooldown=True
            )
            if ok_t and fp_t and fp_t.exists():
                files_to_send.append((fp_t, f"📋 Task #{t['id']} ({t['title_en']}) — {len(sids)} submissions"))

        ok_fs, _, fp_fs, rids = pctx.excel.export_fs_master(None, False, "xlsx", admin_id)
        if ok_fs and fp_fs and fp_fs.exists():
            files_to_send.append((fp_fs, f"📁 File Submit Master ({len(rids)} records)"))

        ok_st, _, fp_st = pctx.store.export_completed_orders("xlsx", admin_id)
        if ok_st and fp_st and fp_st.exists():
            files_to_send.append((fp_st, "🛒 Store Orders Export"))

        ok_otp, _, fp_otp = pctx.otp.export_otp_logs("xlsx", admin_id)
        if ok_otp and fp_otp and fp_otp.exists():
            files_to_send.append((fp_otp, "📲 OTP SMS Logs Export"))

        ok_bon, _, fp_bon = pctx.bonuses.export_bonus_claims("xlsx", admin_id)
        if ok_bon and fp_bon and fp_bon.exists():
            files_to_send.append((fp_bon, "🎁 Bonus Claims Export"))

        ok_ledg, _, fp_ledg = pctx.reports.export_financial_ledger("all", "xlsx", admin_id)
        if ok_ledg and fp_ledg and fp_ledg.exists():
            files_to_send.append((fp_ledg, "🧾 Financial Ledger Export"))

    sent_count = 0
    errors: List[str] = []
    for fpath, cap in files_to_send:
        for dest in recipients:
            try:
                with open(fpath, "rb") as fp:
                    await bot.send_document(chat_id=dest, document=fp, filename=fpath.name, caption=cap, parse_mode=ParseMode.HTML)
                sent_count += 1
                await asyncio.sleep(0.45)
            except RetryAfter as exc:
                await asyncio.sleep(min(float(exc.retry_after) + 1.0, 20.0))
                try:
                    with open(fpath, "rb") as fp:
                        await bot.send_document(chat_id=dest, document=fp, filename=fpath.name, caption=cap, parse_mode=ParseMode.HTML)
                    sent_count += 1
                except Exception as inner_e:
                    errors.append(f"{fpath.name} -> {dest}: {inner_e}")
            except Exception as exc:
                errors.append(f"{fpath.name} -> {dest}: {exc}")

    if sent_count > 0:
        pctx.backup.mark_backup_sent_to_telegram(b_uid)
    pctx.config.set_setting("last_auto_backup_ts", str(int(time.time())), admin_id=admin_id, reason="auto_backup_run")
    return {"backup_uid": b_uid, "total_files": len(files_to_send), "sent_count": sent_count, "errors": errors}


async def show_adm_sys_hub(pctx: PlatformContext, update: Update) -> None:
    bk_on = pctx.config.get_bool("auto_backup_enabled", True)
    interval_h = max(1, pctx.config.get_int("auto_backup_interval_hours", 24))
    target = pctx.config.get_str("auto_backup_target", "channel")
    send_files = pctx.config.get_bool("auto_backup_send_individual_files", True)
    sz = pctx.config.get_str("message_size_mode", "current")
    sz_lbl = {"short": "ছোট (Short)", "medium": "মাঝারি (Medium)", "current": "বড় / বর্তমান (Current)"}.get(sz, sz)

    ch = pctx.db.query_one("SELECT * FROM channels WHERE purpose='auto_backup' ORDER BY id ASC LIMIT 1")
    ch_id_txt = str(ch["chat_id"]) if ch else "Not Set"
    ch_link_txt = str(ch["join_link"] or "Not Set") if ch else "Not Set"
    bk_fj_on = bool(ch and int(ch["join_required"]) == 1)

    last_ts = pctx.config.get_float("last_auto_backup_ts", 0.0)
    last_str = datetime.fromtimestamp(last_ts, tz=DHAKA_TZ).strftime("%Y-%m-%d %I:%M %p") if last_ts > 0 else "Never"
    fj_warn = "\n⚠️ <i>Force-Join ON থাকলে নিচে Join Link অবশ্যই সেট করুন!</i>" if (bk_fj_on and ch_link_txt == "Not Set") else ""

    text = (
        f"🆕 <b>সিস্টেম ও অটো-ব্যাকআপ কন্ট্রোল</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Auto-Backup: <b>{'ON 🟢' if bk_on else 'OFF 🔴'}</b> | সময়: প্রতি <b>{interval_h} ঘণ্টা</b> পরপর\n"
        f"• Target: <code>{target}</code> | সব এক্সপোর্ট ফাইল পাঠানো: <b>{'ON 🟢' if send_files else 'OFF 🔴'}</b>\n"
        f"• Backup Channel: <code>{escape_html(ch_id_txt)}</code>\n"
        f"• Channel Join Link: <code>{escape_html(ch_link_txt)}</code>\n"
        f"• ব্যাকআপ চ্যানেলে জয়েন বাধ্যতামূলক: <b>{'ON 🔒' if bk_fj_on else 'OFF 🔓'}</b>{fj_warn}\n"
        f"• সর্বশেষ ব্যাকআপ: <code>{last_str}</code>\n"
        f"• গ্লোবাল মেসেজ সাইজ: <b>{sz_lbl}</b>"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn(f"Auto-Backup: {'ON 🟢' if bk_on else 'OFF 🔴'}", callback_data="adm:sys:tog", action_kind="confirm" if bk_on else "cancel"),
            pctx.kb.ibtn(f"Target: {target}", callback_data="adm:sys:tgt", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn("1h", callback_data="adm:sys:int:1", action_kind="confirm" if interval_h == 1 else "default"),
            pctx.kb.ibtn("2h", callback_data="adm:sys:int:2", action_kind="confirm" if interval_h == 2 else "default"),
            pctx.kb.ibtn("3h", callback_data="adm:sys:int:3", action_kind="confirm" if interval_h == 3 else "default"),
            pctx.kb.ibtn("6h", callback_data="adm:sys:int:6", action_kind="confirm" if interval_h == 6 else "default"),
            pctx.kb.ibtn("24h", callback_data="adm:sys:int:24", action_kind="confirm" if interval_h == 24 else "default"),
            pctx.kb.ibtn("⏱️ Custom", callback_data="adm:sys:intc", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn(f"Auto-Send All Files: {'ON 🟢' if send_files else 'OFF 🔴'}", callback_data="adm:sys:files", action_kind="confirm" if send_files else "default"),
        ],
        [
            pctx.kb.ibtn(f"Backup Ch Force-Join: {'ON 🔒' if bk_fj_on else 'OFF 🔓'}", callback_data="adm:sys:bkfj", action_kind="confirm" if bk_fj_on else "cancel"),
        ],
        [
            pctx.kb.ibtn("📢 Set Channel ID|Link", callback_data="adm:sys:ch", action_kind="primary"),
            pctx.kb.ibtn("🔗 Set Join Link", callback_data="adm:sys:bklink", action_kind="default"),
            pctx.kb.ibtn("🧪 Test", callback_data="adm:sys:chtest", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("🔹 ছোট", callback_data="adm:sys:msg:short", action_kind="confirm" if sz == "short" else "default"),
            pctx.kb.ibtn("🔸 মাঝারি", callback_data="adm:sys:msg:medium", action_kind="confirm" if sz == "medium" else "default"),
            pctx.kb.ibtn("💎 বড়/বর্তমান", callback_data="adm:sys:msg:current", action_kind="confirm" if sz == "current" else "default"),
        ],
        [pctx.kb.ibtn("📤 এখনই ব্যাকআপ ও সব ফাইল পাঠান", callback_data="adm:sys:runnow", action_kind="confirm")],
        admin_back_row(pctx),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-16] Growth, Rewards & Manual Leaderboard Score (RULE 94) ---

async def show_adm_s16_growth(pctx: PlatformContext, update: Update) -> None:
    ref_on = pctx.config.get_bool("referral_enabled", True)
    ref_val = pctx.config.get_float("referral_commission_value", 10.0)
    fs_on = pctx.config.get_bool("fs_commission_enabled", True)
    fs_val = pctx.config.get_float("fs_commission_value", 5.0)
    chk_on = pctx.config.get_bool("daily_checkin_enabled", True)
    hh_on = pctx.config.get_bool("happy_hour_enabled", False)
    pts_on = pctx.config.get_bool("points_exchange_enabled", False)

    text = (
        f"🏆 <b>A-16 Growth, Rewards & Manual LB (RULE 27–31, 94)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Referral: <b>{'ON' if ref_on else 'OFF'}</b> ({ref_val:g}%) | FS Comm: <b>{'ON' if fs_on else 'OFF'}</b> ({fs_val:g}%)\n"
        f"• Check-in: <b>{'ON' if chk_on else 'OFF'}</b> | Happy-Hour: <b>{'ON' if hh_on else 'OFF'}</b> | Points: <b>{'ON' if pts_on else 'OFF'}</b>"
    )
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn(f"Referral: {'ON' if ref_on else 'OFF'}", callback_data="adm:s16:tog:referral_enabled", action_kind="primary"),
            pctx.kb.ibtn("✏️ Set Ref %", callback_data="adm:s16:set:referral_commission_value", action_kind="default"),
        ],
        [
            pctx.kb.ibtn(f"Check-in: {'ON' if chk_on else 'OFF'}", callback_data="adm:s16:tog:daily_checkin_enabled", action_kind="primary"),
            pctx.kb.ibtn(f"Happy-Hr: {'ON' if hh_on else 'OFF'}", callback_data="adm:s16:tog:happy_hour_enabled", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("➕ Add Bonus", callback_data="adm:s16:addbon", action_kind="confirm"),
            pctx.kb.ibtn("📥 Bonus Export", callback_data="adm:s16:expbon", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("➕ Manual LB Score (+N/-N)", callback_data="adm:s16:lbadj", action_kind="primary"),
            pctx.kb.ibtn("📢 Publish LB", callback_data="adm:s16:lbpub", action_kind="confirm"),
        ],
        [
            pctx.kb.ibtn("🔄 Reset Task LB (Award)", callback_data="adm:s16:lbrst:task", action_kind="cancel"),
            pctx.kb.ibtn("🔄 Reset FS LB (Award)", callback_data="adm:s16:lbrst:fs", action_kind="cancel"),
        ],
        admin_back_row(pctx),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-17] Users, Finance Adjust, Warnings & All-Users Export ---

async def show_adm_s17_users(pctx: PlatformContext, update: Update) -> None:
    recent = pctx.db.query_all("SELECT user_id, full_name, username, earned_balance, status FROM users ORDER BY registered_at DESC LIMIT 8")
    text = f"👥 <b>A-17 Users, Finance & Warnings (RULE 4, 17, 73)</b>\n{pctx.config.get_theme()['divider']}\nসার্চ করে প্রোফাইল, Credit/Deduct, Warning বা All-Users Export করুন:"
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn("🔍 Search User", callback_data="adm:s17:search", action_kind="primary"),
            pctx.kb.ibtn("📥 Export All Users (.xlsx)", callback_data="adm:s17:expall", action_kind="confirm"),
        ],
        [
            pctx.kb.ibtn("⚠️ Warn All Active Users", callback_data="adm:s17:warnall", action_kind="cancel"),
        ],
    ]
    for u in recent:
        st_i = "🔴" if str(u["status"]) == "blocked" else "🟢"
        rows.append([pctx.kb.ibtn(f"{st_i} {u['full_name'][:18]} ({u['user_id']}) | {format_money(u['earned_balance'])}", callback_data=f"adm:s17:u:{u['user_id']}", action_kind="default")])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s17_user_detail(pctx: PlatformContext, update: Update, target_uid: int) -> None:
    u = pctx.users.get_user(target_uid)
    if u is None:
        return
    stats = pctx.users.get_profile_stats(target_uid)
    text = (
        f"👤 <b>User #{u['user_id']}: {escape_html(u['full_name'])}</b> (@{escape_html(u['username'] or '-')})\n"
        f"• Status: <b>{u['status'].upper()}</b> | VIP: <b>{u['vip_tier']}</b> | Strikes: <b>{u['warning_count']}</b>\n"
        f"• Earned: <code>{format_money(u['earned_balance'])}</code> | Deposit: <code>{format_money(u['deposit_balance'])}</code> | Held: <code>{format_money(u['held_balance'])}</code>\n"
        f"• Tasks: {stats['tasks_ok']} | FS: {stats['fs_ok']} | Orders: {stats['orders_ok']} | Refs: {stats['refs_count']}"
    )
    blk_lbl = "🔓 Unblock User" if str(u["status"]) == "blocked" else "🔒 Block User"
    kb = InlineKeyboardMarkup([
        [
            pctx.kb.ibtn("➕ Credit Balance", callback_data=f"adm:s17:cred:{target_uid}", action_kind="confirm"),
            pctx.kb.ibtn("➖ Deduct Balance", callback_data=f"adm:s17:ded:{target_uid}", action_kind="cancel"),
        ],
        [
            pctx.kb.ibtn("⚠️ Send Warning", callback_data=f"adm:s17:warn:{target_uid}", action_kind="cancel"),
            pctx.kb.ibtn(blk_lbl, callback_data=f"adm:s17:blk:{target_uid}", action_kind="primary"),
        ],
        admin_back_row(pctx, "adm:s17"),
    ])
    await send_or_edit_admin(pctx, update, text, kb)


# --- [A-18] Tickets, Appeals, Broadcast & Notification Queue ---

async def show_adm_s18_support(pctx: PlatformContext, update: Update) -> None:
    tkts = pctx.tickets.list_open_tickets(limit=6)
    apls = pctx.appeals.list_pending_appeals(limit=6)
    qst = pctx.notifications.get_queue_stats()
    text = (
        f"🎫 <b>A-18 Tickets, Appeals & Broadcast</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Open Tickets: <b>{len(tkts)}</b> | Pending Appeals: <b>{len(apls)}</b>\n"
        f"• Notification Queue — Pending: {qst['pending']} | Failed: {qst['failed']} | Sent: {qst['sent']}"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [pctx.kb.ibtn("📢 Send Broadcast", callback_data="adm:s18:bc", action_kind="primary")],
        [
            pctx.kb.ibtn("🔁 Retry Failed Queue", callback_data="adm:s18:qretry", action_kind="default"),
            pctx.kb.ibtn("🧹 Clear Queue", callback_data="adm:s18:qclr", action_kind="cancel"),
        ],
    ]
    for t in tkts:
        rows.append([pctx.kb.ibtn(f"💬 Reply {t['ticket_uid']} (U:{t['user_id']})", callback_data=f"adm:s18:tkt:{t['id']}", action_kind="primary")])
    for a in apls:
        rows.append([
            pctx.kb.ibtn(f"⚖️ App {a['appeal_uid']}", callback_data=f"adm:s18:apl:{a['id']}:approved", action_kind="approve"),
            pctx.kb.ibtn("❌ Rej", callback_data=f"adm:s18:apl:{a['id']}:rejected", action_kind="reject"),
        ])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


# --- [A-19] Security, Locks & Panic Freeze ---

async def show_adm_s19_security(pctx: PlatformContext, update: Update, admin_id: int) -> None:
    panic = pctx.security.is_panic_frozen()
    maint = pctx.config.get_bool("maintenance_mode", False)
    anti_wash = pctx.config.get_bool("anti_wash_enabled", True)
    dup_tx = pctx.config.get_bool("anti_dup_txid_hash", True)
    multi_w = pctx.config.get_bool("anti_multi_wallet_block", True)
    text = (
        f"🛡️ <b>A-19 Security, Locks & Panic Freeze (RULE 77)</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• 🚨 Emergency Panic Freeze: <b>{'ACTIVE 🔴' if panic else 'OFF 🟢'}</b>\n"
        f"• 🛠️ Maintenance Mode: <b>{'ON' if maint else 'OFF'}</b> | Anti-Wash: <b>{'ON' if anti_wash else 'OFF'}</b>\n"
        f"• Dup TxID/Hash Block: <b>{'ON' if dup_tx else 'OFF'}</b> | Shared Wallet Block: <b>{'ON' if multi_w else 'OFF'}</b>"
    )
    rows: List[List[InlineKeyboardButton]] = []
    if pctx.permissions.is_main_admin(admin_id):
        rows.append([pctx.kb.ibtn("🚨 UNLOCK PANIC FREEZE" if panic else "🚨 ACTIVATE PANIC FREEZE", callback_data="adm:s19:panic", action_kind="cancel" if not panic else "confirm")])
    rows.extend([
        [
            pctx.kb.ibtn(f"Maintenance: {'ON' if maint else 'OFF'}", callback_data="adm:s19:tog:maintenance_mode", action_kind="cancel" if maint else "default"),
            pctx.kb.ibtn(f"Anti-Wash: {'ON' if anti_wash else 'OFF'}", callback_data="adm:s19:tog:anti_wash_enabled", action_kind="primary"),
        ],
        [
            pctx.kb.ibtn(f"Lock Task: {'🔒' if pctx.config.get_bool('lock_task') else '🔓'}", callback_data="adm:s19:tog:lock_task", action_kind="default"),
            pctx.kb.ibtn(f"Lock FS: {'🔒' if pctx.config.get_bool('lock_fs') else '🔓'}", callback_data="adm:s19:tog:lock_fs", action_kind="default"),
            pctx.kb.ibtn(f"Lock Store: {'🔒' if pctx.config.get_bool('lock_store') else '🔓'}", callback_data="adm:s19:tog:lock_store", action_kind="default"),
        ],
        [
            pctx.kb.ibtn(f"Lock OTP: {'🔒' if pctx.config.get_bool('lock_otp') else '🔓'}", callback_data="adm:s19:tog:lock_otp", action_kind="default"),
            pctx.kb.ibtn(f"Lock Dep: {'🔒' if pctx.config.get_bool('lock_deposit') else '🔓'}", callback_data="adm:s19:tog:lock_deposit", action_kind="default"),
            pctx.kb.ibtn(f"Lock WD: {'🔒' if pctx.config.get_bool('lock_withdraw') else '🔓'}", callback_data="adm:s19:tog:lock_withdraw", action_kind="default"),
        ],
        admin_back_row(pctx),
    ])
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


# --- [A-20] Admin Permissions, Ledger Reconciliation, Audit & Backup ---

async def show_adm_s20_admin_backup(pctx: PlatformContext, update: Update, admin_id: int) -> None:
    auto_bk = pctx.config.get_bool("auto_backup_enabled", True)
    assts = pctx.permissions.list_assistants()
    pass_on = pctx.config.get_bool("admin_panel_password_enabled", False)
    pass_set = bool(pctx.config.get_str("admin_panel_password", "").strip())
    pass_main = pctx.config.get_bool("admin_panel_password_main", False)
    pass_info = (
        f"\n🔐 Admin Password Lock: <b>{'ON 🟢' if pass_on else 'OFF 🔴'}</b> ({'Set ✅' if pass_set else 'Not Set ⚠️'})"
        if pctx.permissions.is_main_admin(admin_id)
        else ""
    )
    text = (
        f"👑 <b>A-20 Permissions, Ledger, Audit & Backup</b>\n{pctx.config.get_theme()['divider']}\n"
        f"• Assistant Admins: <b>{len(assts)}</b> | Telegram Auto-Backup: <b>{'ON 🟢' if auto_bk else 'OFF 🔴'}</b>{pass_info}"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn("⚖️ Run Reconciliation", callback_data="adm:s20:recon", action_kind="primary"),
            pctx.kb.ibtn("📥 Export Ledger (.xlsx)", callback_data="adm:s20:expledg", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("💾 Create & Send .zip Backup", callback_data="adm:s20:bkp", action_kind="confirm"),
            pctx.kb.ibtn(f"Auto-Backup: {'ON' if auto_bk else 'OFF'}", callback_data="adm:s20:autobk", action_kind="default"),
        ],
        [
            pctx.kb.ibtn("📜 Recent Audit Logs", callback_data="adm:s20:audit", action_kind="default"),
            pctx.kb.ibtn("🧹 Runtime-Only Reset", callback_data="adm:s20:rtrst", action_kind="cancel"),
        ],
    ]
    if pctx.permissions.is_main_admin(admin_id):
        rows.append([
            pctx.kb.ibtn(f"🔐 Admin Pass: {'ON 🟢' if pass_on else 'OFF 🔴'}", callback_data="adm:s20:passtog", action_kind="confirm" if pass_on else "cancel"),
            pctx.kb.ibtn("✏️ Set/Edit Pass", callback_data="adm:s20:passset", action_kind="primary"),
        ])
        rows.append([
            pctx.kb.ibtn("👁️ View Pass", callback_data="adm:s20:passview", action_kind="default"),
            pctx.kb.ibtn(f"👑 Main Pass: {'ON' if pass_main else 'OFF'}", callback_data="adm:s20:passmain", action_kind="default"),
        ])
        rows.append([pctx.kb.ibtn("➕ Add Assistant Admin", callback_data="adm:s20:addasst", action_kind="primary")])
        for a in assts[:6]:
            app_st = str(a["approval_status"] or "approved")
            st_i = "⏳" if app_st == "pending" else ("⛔" if app_st == "rejected" else ("🟢" if int(a["is_active"]) == 1 else "🔴"))
            rows.append([pctx.kb.ibtn(f"{st_i} Asst #{a['admin_id']} {a['full_name'][:14]}", callback_data=f"adm:s20:asst:{a['admin_id']}", action_kind="default")])
    rows.append(admin_back_row(pctx))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


async def show_adm_s20_assistant_perms(pctx: PlatformContext, update: Update, target_aid: int) -> None:
    row = pctx.permissions.get_assistant(target_aid)
    if row is None:
        return
    perms = safe_json_loads(row["permissions_json"], {})
    app_st = str(row["approval_status"] or "approved").upper()
    text = (
        f"👮 <b>Assistant Admin #{target_aid} Permissions</b>\n"
        f"Approval: <b>{app_st}</b> | Status: <b>{'ACTIVE 🟢' if row['is_active'] else 'DISABLED 🔴'}</b>"
    )
    rows: List[List[InlineKeyboardButton]] = [
        [
            pctx.kb.ibtn("✅ Approve", callback_data=f"adm:s20:aapp:{target_aid}", action_kind="approve"),
            pctx.kb.ibtn("❌ Reject", callback_data=f"adm:s20:arej:{target_aid}", action_kind="reject"),
        ],
        [
            pctx.kb.ibtn("Toggle Active", callback_data=f"adm:s20:atog:{target_aid}", action_kind="primary"),
            pctx.kb.ibtn("🗑️ Remove", callback_data=f"adm:s20:arem:{target_aid}", action_kind="cancel"),
        ],
    ]
    cur_r: List[InlineKeyboardButton] = []
    for pk, lbn, _ in PERMISSION_GROUPS:
        on = bool(perms.get(pk, False))
        cur_r.append(pctx.kb.ibtn(f"{'✅' if on else '❌'} {lbn[:15]}", callback_data=f"adm:s20:ap:{target_aid}:{pk}", action_kind="confirm" if on else "default"))
        if len(cur_r) == 2:
            rows.append(cur_r)
            cur_r = []
    if cur_r:
        rows.append(cur_r)
    rows.append(admin_back_row(pctx, "adm:s20"))
    await send_or_edit_admin(pctx, update, text, InlineKeyboardMarkup(rows))


# ==============================================================================
# CHANNEL REVIEW CALLBACK SYNC (RULE 95.A — TEXT & PHOTO CAPTION SAFE)
# ==============================================================================

async def handle_channel_review_callback(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    parts: List[str],
) -> None:
    q = update.callback_query
    if q is None or update.effective_user is None:
        return
    admin_id = int(update.effective_user.id)
    if not pctx.permissions.is_any_admin(admin_id):
        await q.answer("⛔ Admins only!", show_alert=True)
        return

    kind = parts[1] if len(parts) > 1 else ""
    action = parts[2] if len(parts) > 2 else ""
    item_id = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
    msg_obj = q.message
    orig_body = (msg_obj.caption or msg_obj.text or "") if msg_obj else ""
    is_media = bool(msg_obj and (msg_obj.photo or msg_obj.document))
    admin_tag = f"Admin {admin_id} | {now_dhaka().strftime('%I:%M %p')}"

    if kind == "tsk":
        if not pctx.permissions.has_permission(admin_id, "tasks"):
            await q.answer("⛔ No Task permission.", show_alert=True)
            return
        if action == "app":
            ok, msg_r, res = pctx.task_subs.approve_submission(item_id, admin_id)
            if not ok:
                await q.answer(msg_r, show_alert=True)
                if res.get("already_status"):
                    await safe_edit_channel_message(context.bot, msg_obj.chat_id, msg_obj.message_id, orig_body + f"\n\n🔒 Already {res['already_status'].upper()}", None, is_media)
                return
            await safe_edit_channel_message(
                context.bot, msg_obj.chat_id, msg_obj.message_id,
                orig_body + f"\n\n✅ <b>APPROVED</b> ({admin_tag})",
                InlineKeyboardMarkup([[pctx.kb.ibtn("✅ Approved (Locked)", callback_data="noop", action_kind="approve")]]),
                is_media=is_media,
            )
            sub = res["sub"]
            u_row = pctx.users.get_user(int(sub["user_id"]))
            lang = str(u_row["language"] or "bn") if u_row else "bn"
            card, _, en = pctx.studio.render_event_message(
                "task_approved_msg", lang=lang,
                name=str(u_row["full_name"]) if u_row else "",
                sub_uid=sub["sub_uid"],
                reward=format_money(sub["reward_snapshot"]),
                new_balance=format_money(res["new_balance"]),
            )
            pctx.notifications.enqueue(int(sub["user_id"]), card if (en and card) else f"✅ Task <code>{sub['sub_uid']}</code> Approved!")
            if res.get("referral"):
                rf = res["referral"]
                rcard, _, ren = pctx.studio.render_event_message(
                    "referral_commission_msg", lang=rf["ref_lang"],
                    ref_name=rf["ref_name"], source_label="Task",
                    amount=format_money(rf["comm_amount"]), new_balance=format_money(rf["ref_new_balance"]),
                    tx_uid=rf["tx_uid"],
                )
                if ren and rcard:
                    pctx.notifications.enqueue(rf["referrer_id"], rcard)
            await q.answer("✅ Task Approved!")
            return

        if action == "rej":
            reason = pctx.text.get_text("default_reject_reason", "bn")
            ok, msg_r, res = pctx.task_subs.reject_submission(item_id, admin_id, reason)
            if not ok:
                await q.answer(msg_r, show_alert=True)
                return
            await safe_edit_channel_message(
                context.bot, msg_obj.chat_id, msg_obj.message_id,
                orig_body + f"\n\n❌ <b>REJECTED</b> ({admin_tag})",
                InlineKeyboardMarkup([[pctx.kb.ibtn("❌ Rejected (Locked)", callback_data="noop", action_kind="reject")]]),
                is_media=is_media,
            )
            sub = res["sub"]
            u_row = pctx.users.get_user(int(sub["user_id"]))
            lang = str(u_row["language"] or "bn") if u_row else "bn"
            card, _, en = pctx.studio.render_event_message("task_rejected_msg", lang=lang, name=str(u_row["full_name"]) if u_row else "", sub_uid=sub["sub_uid"], reject_reason=reason)
            pctx.notifications.enqueue(int(sub["user_id"]), card if (en and card) else f"❌ Task <code>{sub['sub_uid']}</code> Rejected: {reason}")
            await q.answer("❌ Task Rejected!")
            return

    if kind == "dep":
        if not pctx.permissions.has_permission(admin_id, "deposits"):
            await q.answer("⛔ No Deposit permission.", show_alert=True)
            return
        if action == "app":
            ok, msg_r, res = pctx.deposits.approve_deposit(item_id, admin_id)
            if not ok:
                await q.answer(msg_r, show_alert=True)
                return
            await safe_edit_channel_message(
                context.bot, msg_obj.chat_id, msg_obj.message_id,
                orig_body + f"\n\n✅ <b>APPROVED</b> ({admin_tag})",
                InlineKeyboardMarkup([[pctx.kb.ibtn("✅ Approved (Locked)", callback_data="noop", action_kind="approve")]]),
                is_media=is_media,
            )
            dep = res["dep"]
            u_row = pctx.users.get_user(int(dep["user_id"]))
            lang = str(u_row["language"] or "bn") if u_row else "bn"
            card, _, en = pctx.studio.render_event_message(
                "deposit_approved_success", lang=lang, name=str(u_row["full_name"]) if u_row else "",
                deposit_uid=dep["deposit_uid"], net_credit=format_money(dep["net_credit"]),
                new_deposit_balance=format_money(res["new_deposit_balance"]),
            )
            pctx.notifications.enqueue(int(dep["user_id"]), card if (en and card) else f"✅ Deposit <code>{dep['deposit_uid']}</code> Approved!")
            await q.answer("✅ Deposit Approved!")
            return

        if action == "rej":
            reason = "TxID or payment screenshot could not be verified."
            ok, msg_r, res = pctx.deposits.reject_deposit(item_id, admin_id, reason)
            if not ok:
                await q.answer(msg_r, show_alert=True)
                return
            await safe_edit_channel_message(
                context.bot, msg_obj.chat_id, msg_obj.message_id,
                orig_body + f"\n\n❌ <b>REJECTED</b> ({admin_tag})",
                InlineKeyboardMarkup([[pctx.kb.ibtn("❌ Rejected (Locked)", callback_data="noop", action_kind="reject")]]),
                is_media=is_media,
            )
            dep = res["dep"]
            u_row = pctx.users.get_user(int(dep["user_id"]))
            lang = str(u_row["language"] or "bn") if u_row else "bn"
            card, _, en = pctx.studio.render_event_message("deposit_rejected_msg", lang=lang, deposit_uid=dep["deposit_uid"], reject_reason=reason)
            pctx.notifications.enqueue(int(dep["user_id"]), card if (en and card) else f"❌ Deposit <code>{dep['deposit_uid']}</code> Rejected.")
            await q.answer("❌ Deposit Rejected!")
            return

    if kind == "wd":
        if not pctx.permissions.has_permission(admin_id, "withdrawals"):
            await q.answer("⛔ No Withdrawal permission.", show_alert=True)
            return
        if action == "app":
            ok, msg_r, _ = pctx.withdrawals.approve_withdrawal(item_id, admin_id)
            if not ok:
                await q.answer(msg_r, show_alert=True)
                return
            await safe_edit_channel_message(
                context.bot, msg_obj.chat_id, msg_obj.message_id,
                orig_body + f"\n\n⏳ <b>APPROVED (Awaiting Mark Paid)</b> ({admin_tag})",
                InlineKeyboardMarkup([[
                    pctx.kb.ibtn("💸 Mark Paid", callback_data=f"ch:wd:paid:{item_id}", action_kind="confirm"),
                    pctx.kb.ibtn("❌ Reject", callback_data=f"ch:wd:rej:{item_id}", action_kind="reject"),
                ]]),
                is_media=is_media,
            )
            await q.answer("✅ Approved! Send money then press Mark Paid.")
            return

        if action == "paid":
            ok, msg_r, res = pctx.withdrawals.mark_paid_withdrawal(item_id, admin_id)
            if not ok:
                await q.answer(msg_r, show_alert=True)
                return
            await safe_edit_channel_message(
                context.bot, msg_obj.chat_id, msg_obj.message_id,
                orig_body + f"\n\n💸 <b>PAID</b> ({admin_tag})",
                InlineKeyboardMarkup([[pctx.kb.ibtn("💸 Paid (Completed)", callback_data="noop", action_kind="confirm")]]),
                is_media=is_media,
            )
            wd = res["wd"]
            u_row = pctx.users.get_user(int(wd["user_id"]))
            lang = str(u_row["language"] or "bn") if u_row else "bn"
            card, _, en = pctx.studio.render_event_message(
                "withdraw_paid_success", lang=lang, name=str(u_row["full_name"]) if u_row else "",
                withdraw_uid=wd["withdraw_uid"], method=f"Method #{wd['method_id']}",
                account=wd["account_or_wallet"], net_amount=format_money(wd["net_amount"]),
            )
            pctx.notifications.enqueue(int(wd["user_id"]), card if (en and card) else f"💸 Withdrawal <code>{wd['withdraw_uid']}</code> Paid!")
            payout_ch = pctx.get_primary_channel_id("payout_order")
            if payout_ch:
                mask_u = pctx.config.get_bool("payout_mask_user", True)
                u_disp = mask_display_name(u_row["full_name"] if u_row else "", int(wd["user_id"])) if mask_u else str(wd["user_id"])
                acc_disp = mask_phone_or_account(wd["account_or_wallet"]) if mask_u else wd["account_or_wallet"]
                p_txt = (
                    f"💸 <b>Withdrawal Paid!</b>\n"
                    f"🆔 ID: <code>{wd['withdraw_uid']}</code>\n"
                    f"👤 User: <b>{escape_html(u_disp)}</b>\n"
                    f"📲 Account: <code>{escape_html(acc_disp)}</code>\n"
                    f"✅ Net Paid: <b><code>{format_money(wd['net_amount'])}</code></b>"
                )
                await safe_send_message_to_chat(context.bot, payout_ch, p_txt)
            await q.answer("💸 Marked Paid & Posted!")
            return

        if action == "rej":
            reason = "Rejected by admin review"
            ok, msg_r, res = pctx.withdrawals.reject_withdrawal(item_id, admin_id, reason)
            if not ok:
                await q.answer(msg_r, show_alert=True)
                return
            await safe_edit_channel_message(
                context.bot, msg_obj.chat_id, msg_obj.message_id,
                orig_body + f"\n\n❌ <b>REJECTED & REFUNDED</b> ({admin_tag})",
                InlineKeyboardMarkup([[pctx.kb.ibtn("❌ Rejected & Refunded", callback_data="noop", action_kind="reject")]]),
                is_media=is_media,
            )
            wd = res["wd"]
            u_row = pctx.users.get_user(int(wd["user_id"]))
            lang = str(u_row["language"] or "bn") if u_row else "bn"
            card, _, en = pctx.studio.render_event_message("withdraw_rejected_refund", lang=lang, withdraw_uid=wd["withdraw_uid"], gross=format_money(wd["gross_amount"]), reject_reason=reason)
            pctx.notifications.enqueue(int(wd["user_id"]), card if (en and card) else f"❌ Withdrawal <code>{wd['withdraw_uid']}</code> Rejected & Refunded.")
            await q.answer("❌ Rejected & Refunded!")
            return

    if kind == "fs" and action == "open":
        bot_un = BOT_IDENTITY.get_username()
        await q.answer(f"Open @{bot_un} -> /admin -> A-11 to batch review #{item_id}.", show_alert=True)


# ==============================================================================
# UNIFIED CALLBACK & TEXT/MEDIA ROUTERS (USER + ADMIN + RELAY CHANNEL)
# ==============================================================================

async def handle_all_callbacks(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pctx: PlatformContext = context.application.bot_data["pctx"]
    q = update.callback_query
    if q is None or update.effective_user is None:
        return
    cb = str(q.data or "")
    uid = int(update.effective_user.id)

    if cb == "noop":
        await q.answer("Locked.", show_alert=False)
        return

    parts = cb.split(":")
    prefix = parts[0]

    if prefix == "ch":
        await handle_channel_review_callback(pctx, update, context, parts)
        return

    if prefix == "fj" and len(parts) > 1 and parts[1] == "verify":
        await handle_force_join_verify(update, context)
        return

    if prefix == "flow" and len(parts) > 1 and parts[1] == "cancel":
        pctx.runtime.clear_state(uid)
        await q.answer("Cancelled")
        user_row = pctx.users.get_user(uid)
        if user_row:
            await show_main_menu(pctx, update, context, user_row)
        return

    if prefix == "tsk" and len(parts) > 1 and parts[1] == "cancel":
        pctx.runtime.clear_state(uid)
        await q.answer("Task Cancelled")
        user_row = pctx.users.get_user(uid)
        if user_row:
            await show_main_menu(pctx, update, context, user_row)
        return

    if prefix == "admapp" and len(parts) > 2:
        if not pctx.permissions.is_main_admin(uid):
            await q.answer("⛔ শুধুমাত্র মূল এডমিন অনুমোদন দিতে পারবেন!", show_alert=True)
            return
        act_app = parts[1]
        target_aid = int(parts[2]) if parts[2].isdigit() else 0
        msg_obj = q.message
        orig_body = (msg_obj.caption or msg_obj.text or "") if msg_obj else ""
        if act_app == "yes":
            ok_ap, msg_ap = pctx.permissions.approve_assistant(uid, target_aid)
            if ok_ap and msg_obj:
                await safe_edit_channel_message(
                    context.bot, msg_obj.chat_id, msg_obj.message_id,
                    orig_body + f"\n\n✅ <b>APPROVED by Main Admin</b> ({now_dhaka().strftime('%I:%M %p')})",
                    InlineKeyboardMarkup([[pctx.kb.ibtn("✅ Approved (Locked)", callback_data="noop", action_kind="approve")]]),
                    is_media=False,
                )
            if ok_ap:
                pass_req = pctx.permissions.is_password_required_for(target_aid, pctx.config)
                extra = "\n🔐 এডমিন প্যানেলে ঢুকতে /admin লিখে পাসওয়ার্ড দিন।" if pass_req else "\n⚙️ এডমিন প্যানেলে ঢুকতে /admin চাপুন।"
                pctx.notifications.enqueue(target_aid, f"🎉 আপনার এডমিন অ্যাক্সেস মূল এডমিন <b>Approve</b> করেছেন!{extra}")
            await q.answer(msg_ap, show_alert=True)
        elif act_app == "no":
            ok_rj, msg_rj = pctx.permissions.reject_assistant(uid, target_aid)
            if ok_rj and msg_obj:
                await safe_edit_channel_message(
                    context.bot, msg_obj.chat_id, msg_obj.message_id,
                    orig_body + f"\n\n❌ <b>REJECTED by Main Admin</b> ({now_dhaka().strftime('%I:%M %p')})",
                    InlineKeyboardMarkup([[pctx.kb.ibtn("❌ Rejected (Locked)", callback_data="noop", action_kind="reject")]]),
                    is_media=False,
                )
            if ok_rj:
                pctx.notifications.enqueue(target_aid, "⛔ আপনার এডমিন অ্যাক্সেস মূল এডমিন কর্তৃক <b>Reject</b> করা হয়েছে।")
            await q.answer(msg_rj, show_alert=True)
        return

    if prefix == "adm":
        await q.answer()
        if not await ensure_admin_panel_ready(pctx, update, uid):
            return
        await route_admin_callback(pctx, update, context, uid, parts)
        return

    # User callbacks pass through strict Force Join & Module Access Gatekeeper
    mod_map = {"um": "general", "tsk": "task", "fs": "fs", "st": "store", "otp": "otp", "dep": "deposit", "wd": "withdraw", "bon": "reward", "chk": "reward"}
    mod_key = mod_map.get(prefix, "general")
    if prefix == "um" and len(parts) > 1:
        um_mods = {"u_tasks": "task", "u_file_submit": "fs", "u_store": "store", "u_otp": "otp", "u_deposit": "deposit", "u_withdraw": "withdraw", "u_bonus": "reward", "u_checkin": "reward"}
        mod_key = um_mods.get(parts[1], "general")

    user_row = await pctx.gatekeep_user(update, context, module_key=mod_key)
    if user_row is None:
        await q.answer()
        return
    await q.answer()
    lang = str(user_row["language"] or "bn")

    if prefix == "um" and len(parts) > 1:
        target = parts[1]
        if target == "home":
            pctx.runtime.clear_state(uid)
            await show_main_menu(pctx, update, context, user_row)
        elif target == "u_tasks":
            await show_tasks_list(pctx, update, user_row)
        elif target == "u_file_submit":
            await show_fs_tasks_list(pctx, update, user_row)
        elif target == "u_store":
            await show_store_categories(pctx, update, user_row)
        elif target == "u_otp":
            await show_otp_countries(pctx, update, user_row)
        elif target == "u_deposit":
            await show_deposit_methods(pctx, update, user_row)
        elif target == "u_withdraw":
            await show_withdraw_methods(pctx, update, user_row)
        elif target == "u_profile":
            await show_user_profile(pctx, update, user_row)
        elif target == "u_balance":
            await show_user_balance(pctx, update, user_row, page=0)
        elif target == "u_orders":
            await show_my_orders_activity(pctx, update, user_row, tab="orders", page=0)
        elif target == "u_referral":
            await show_referral_dashboard(pctx, update, user_row)
        elif target == "u_task_lb":
            await show_leaderboard_screen(pctx, update, user_row, "task")
        elif target == "u_fs_lb":
            await show_leaderboard_screen(pctx, update, user_row, "fs")
        elif target == "u_bonus":
            await show_bonuses_menu(pctx, update, user_row)
        elif target == "u_checkin":
            await show_daily_checkin(pctx, update, user_row)
        elif target == "u_support":
            await show_support_and_tickets(pctx, update, user_row)
        elif target == "u_rules":
            await show_user_rules(pctx, update, user_row)
        elif target == "u_language":
            await show_language_selector(pctx, update, user_row)
        return

    if prefix == "ucb" and len(parts) > 1 and parts[1].isdigit():
        await handle_custom_dynamic_button(pctx, update, user_row, int(parts[1]))
    elif prefix == "bal" and len(parts) > 2:
        await show_user_balance(pctx, update, user_row, page=int(parts[2]))
    elif prefix == "ext" and len(parts) > 1 and parts[1] == "pts":
        pctx.runtime.set_state(uid, flow="points_exchange", step="await_pts", data={})
        await pctx.reply_user_screen(update, f"🔄 কত Points কনভার্ট করতে চান? (Your Points: <code>{user_row['points_balance']:g}</code>):", inline_markup=InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang)]), user_id=uid, lang=lang)
    elif prefix == "lang" and len(parts) > 2:
        pctx.users.set_language(uid, parts[2])
        u2 = pctx.users.get_user(uid)
        if u2:
            await show_main_menu(pctx, update, context, u2, send_welcome_card=True)
    elif prefix == "bon" and len(parts) > 2 and parts[1] == "claim":
        ok_b, msg_b, amt_b = pctx.bonuses.claim_bonus(int(parts[2]), uid)
        await pctx.reply_user_screen(update, ("✅ " if ok_b else "❌ ") + escape_html(msg_b) + (f" (+{format_money(amt_b)})" if ok_b else ""), inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
    elif prefix == "chk" and len(parts) > 1 and parts[1] == "claim":
        ok_c, msg_c, res_c = pctx.checkin.claim_daily_checkin(user_row)
        if ok_c:
            card, _, en = pctx.studio.render_event_message("daily_checkin_bonus", lang=lang, streak_day=res_c["streak_day"], total_credited=format_money(res_c["total_credited"]), new_balance=format_money(res_c["new_balance"]))
            out = card if (en and card) else f"✅ {msg_c} (+{format_money(res_c['total_credited'])})"
        else:
            out = f"⚠️ {escape_html(msg_c)}"
        await pctx.reply_user_screen(update, out, inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang)]), user_id=uid, lang=lang)
    elif prefix == "lb" and len(parts) > 2:
        await show_leaderboard_screen(pctx, update, user_row, parts[2])
    elif prefix == "tkt" and len(parts) > 1 and parts[1] == "new":
        pctx.runtime.set_state(uid, flow="ticket", step="await_msg", data={})
        await pctx.reply_user_screen(update, "🎫 অনুগ্রহ করে আপনার সমস্যার বিবরণ লিখুন (চাইলে স্ক্রিনশটসহ):" if lang == "bn" else "🎫 Describe your issue (with optional screenshot):", inline_markup=InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang)]), user_id=uid, lang=lang)
    elif prefix == "tsk":
        sub_cmd = parts[1] if len(parts) > 1 else ""
        if sub_cmd == "go" and len(parts) > 2:
            await start_user_task_flow(pctx, update, user_row, int(parts[2]))
        elif sub_cmd == "skip":
            st = pctx.runtime.get_state(uid)
            if st and st["flow"] == "task":
                ph = st["data"].get("current_phase", "pre")
                patch = {"pre_idx": int(st["data"]["pre_idx"]) + 1} if ph == "pre" else {"post_idx": int(st["data"]["post_idx"]) + 1}
                pctx.runtime.update_data(uid, patch)
                await advance_user_task_flow(pctx, update, user_row)
        elif sub_cmd == "opt" and len(parts) > 2:
            st = pctx.runtime.get_state(uid)
            if st and st["flow"] == "task":
                sobj = st["data"].get("current_step_obj", {})
                opts = safe_json_loads(sobj.get("options_json"), [])
                oi = int(parts[2])
                if 0 <= oi < len(opts):
                    ans = list(st["data"].get("answers", []))
                    ans.append({"label": sobj.get("title_en") or "Option", "value": opts[oi]})
                    ph = st["data"].get("current_phase", "pre")
                    patch = {"answers": ans}
                    patch["pre_idx" if ph == "pre" else "post_idx"] = int(st["data"]["pre_idx" if ph == "pre" else "post_idx"]) + 1
                    pctx.runtime.update_data(uid, patch)
                    await advance_user_task_flow(pctx, update, user_row)
        elif sub_cmd == "totpref":
            st = pctx.runtime.get_state(uid)
            if st and st["flow"] == "task" and st["data"].get("totp_data"):
                sec = st["data"]["totp_data"]["totp_secret"]
                ok_t, c6, rem, _, _ = compute_rfc6238_totp(sec)
                if ok_t:
                    td = dict(st["data"]["totp_data"])
                    td["totp_6digit_code"] = c6
                    pctx.runtime.update_data(uid, {"totp_data": td})
                    kb = InlineKeyboardMarkup([[pctx.kb.ibtn("🔄 Refresh Code", callback_data="tsk:totpref", action_kind="default"), pctx.kb.ibtn("➡️ Continue", callback_data="tsk:totpok", action_kind="confirm")], pctx.kb.cancel_row(lang=lang, cancel_cb="tsk:cancel")])
                    await pctx.reply_user_screen(update, f"🔐 কোড: <code>{c6}</code> ({rem}s remaining)", inline_markup=kb, user_id=uid, lang=lang)
        elif sub_cmd == "totpok":
            await advance_user_task_flow(pctx, update, user_row)
        elif sub_cmd == "conf":
            await finalize_user_task_submission(pctx, update, context, user_row)
    elif prefix == "fs":
        if parts[1] == "go" and len(parts) > 2:
            await start_user_fs_flow(pctx, update, user_row, int(parts[2]))
        elif parts[1] == "conf":
            await confirm_user_fs_submission(pctx, update, context, user_row)
        elif parts[1] == "lines" and len(parts) > 3:
            await show_fs_line_viewer(pctx, update, user_row, int(parts[2]), int(parts[3]))
    elif prefix == "act" and len(parts) > 3:
        await show_my_orders_activity(pctx, update, user_row, parts[2], int(parts[3]))
    elif prefix == "ord" and len(parts) > 2:
        oid = int(parts[2])
        if parts[1] == "dl":
            o = pctx.db.query_one("SELECT * FROM store_orders WHERE id=? AND user_id=?", (oid, uid))
            if o and o["delivery_file_path"] and Path(o["delivery_file_path"]).exists():
                with open(o["delivery_file_path"], "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=f"{o['order_uid']}.txt")
        elif parts[1] == "war":
            pctx.runtime.set_state(uid, flow="warranty", step="await_reason", data={"order_id": oid})
            await pctx.reply_user_screen(update, "🛡️ পণ্যের সমস্যার বিবরণ লিখুন:" if lang == "bn" else "🛡️ Describe the issue for warranty:", inline_markup=InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang)]), user_id=uid, lang=lang)
    elif prefix == "apl" and len(parts) > 3 and parts[1] == "new":
        itype, iid = parts[2], int(parts[3])
        pctx.runtime.set_state(uid, flow="appeal", step="await_reason", data={"item_type": itype, "item_id": iid, "item_uid": f"{itype.upper()}-{iid}"})
        await pctx.reply_user_screen(update, "⚖️ আপনার আপিলের যুক্তিসঙ্গত কারণ লিখুন (সর্বোচ্চ ১ বার):" if lang == "bn" else "⚖️ Enter your appeal reason (1 attempt allowed):", inline_markup=InlineKeyboardMarkup([pctx.kb.cancel_row(lang=lang)]), user_id=uid, lang=lang)
    elif prefix == "st":
        if parts[1] == "cat" and len(parts) > 2:
            await show_store_products_list(pctx, update, user_row, int(parts[2]))
        elif parts[1] == "prod" and len(parts) > 2:
            await show_store_product_detail(pctx, update, user_row, int(parts[2]))
        elif parts[1] == "notify" and len(parts) > 2:
            _, msg_n = pctx.store.subscribe_stock_notify(int(parts[2]), uid)
            await pctx.reply_user_screen(update, f"🔔 {escape_html(msg_n)}", inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, back_cb="um:u_store")]), user_id=uid, lang=lang)
        elif parts[1] == "buy" and len(parts) > 2:
            await start_store_order_flow(pctx, update, user_row, int(parts[2]))
        elif parts[1] == "skipcp":
            await advance_store_checkout_steps(pctx, update, user_row)
        elif parts[1] == "conf":
            await confirm_store_checkout(pctx, update, context, user_row)
    elif prefix == "otp":
        sid = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        if parts[1] == "get":
            await allocate_user_otp_session(pctx, update, user_row, sid)
        elif parts[1] == "ref":
            sess = pctx.otp.get_session(sid)
            logs = pctx.otp.get_session_messages(sid)
            if sess and int(sess["user_id"]) == uid:
                if logs:
                    msg_l = "\n".join(f"• Code: <code>{escape_html(l['extracted_code'])}</code> | {escape_html(l['raw_sms'][:80])}" for l in logs[:5])
                else:
                    msg_l = "⏳ এখনো কোনো SMS আসেনি। অপেক্ষা করুন..." if lang == "bn" else "⏳ No SMS received yet. Please wait..."
                await pctx.reply_user_screen(update, f"📲 <b>{sess['otp_uid']}</b>\n{msg_l}", inline_markup=InlineKeyboardMarkup([[pctx.kb.ibtn("🔄 Refresh", callback_data=f"otp:ref:{sid}", action_kind="primary")], pctx.kb.nav_row(lang=lang, back_cb="um:u_otp")]), user_id=uid, lang=lang)
        elif parts[1] == "swap":
            ok_sw, msg_sw, res_sw = pctx.otp.swap_dead_number(sid, uid)
            txt = (f"🔄 {msg_sw}\n" + "\n".join(f"📞 <code>{escape_html(n)}</code>" for n in res_sw.get("numbers", []))) if ok_sw else f"⚠️ {escape_html(msg_sw)}"
            await pctx.reply_user_screen(update, txt, inline_markup=InlineKeyboardMarkup([[pctx.kb.ibtn("🔄 Refresh", callback_data=f"otp:ref:{sid}", action_kind="primary")], pctx.kb.nav_row(lang=lang, back_cb="um:u_otp")]), user_id=uid, lang=lang)
        elif parts[1] == "can":
            _, msg_c, ref_c = pctx.otp.cancel_session(sid, uid)
            await pctx.reply_user_screen(update, f"❌ {escape_html(msg_c)} (Refund: {format_money(ref_c)})", inline_markup=InlineKeyboardMarkup([pctx.kb.nav_row(lang=lang, back_cb="um:u_otp")]), user_id=uid, lang=lang)
    elif prefix == "dep" and parts[1] == "m" and len(parts) > 2:
        await start_deposit_method(pctx, update, user_row, int(parts[2]))
    elif prefix == "wd":
        if parts[1] == "m" and len(parts) > 2:
            await start_withdraw_method(pctx, update, user_row, int(parts[2]))
        elif parts[1] == "conf":
            await confirm_withdraw_request(pctx, update, context, user_row)


ADMIN_SEC_PERM_MAP: Dict[str, str] = {
    "home": "dashboard",
    "s02": "diagnostics",
    "s03": "channels",
    "s04": "force_join",
    "s05": "texts",
    "s06": "buttons_colors",
    "s07": "message_studio",
    "s08": "rules_controller",
    "s09": "tasks",
    "s10": "auto_review",
    "s11": "file_submit",
    "s12": "product_store",
    "s13": "otp_system",
    "s14": "deposits",
    "s15": "withdrawals",
    "s16": "growth_lb",
    "s17": "users_finance",
    "s18": "tickets_broadcast",
    "s19": "security_locks",
    "s20": "backup_ledger",
    "sys": "backup_ledger",
}


async def route_admin_callback(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    uid: int,
    parts: List[str],
) -> None:
    sec = parts[1] if len(parts) > 1 else "home"
    req_perm = ADMIN_SEC_PERM_MAP.get(sec)
    if req_perm and not pctx.permissions.has_permission(uid, req_perm):
        await send_or_edit_admin(pctx, update, "⛔ আপনার এই সেকশন ব্যবহারের অনুমতি নেই।", InlineKeyboardMarkup([admin_back_row(pctx)]))
        return
    if sec == "lock":
        pctx.permissions.lock_admin_session(uid)
        pctx.runtime.clear_state(uid)
        await send_or_edit_admin(pctx, update, "🔒 এডমিন প্যানেল লক করা হয়েছে।", InlineKeyboardMarkup([[pctx.kb.ibtn("🔓 পুনরায় খুলুন", callback_data="adm:home", action_kind="primary")], [pctx.kb.ibtn("🏠 User Home", callback_data="um:home", action_kind="default")]]))
        return
    if sec == "home":
        pctx.runtime.clear_state(uid)
        await show_admin_dashboard(pctx, update, uid)
        return
    if sec == "s02":
        if len(parts) > 2 and parts[2] == "test":
            await run_adm_s02_self_test(pctx, update)
        else:
            await show_adm_s02_diagnostics(pctx, update)
    elif sec == "s03":
        act = parts[2] if len(parts) > 2 else ""
        if act == "chtog" and len(parts) > 3:
            cid = int(parts[3])
            r = pctx.db.query_one("SELECT is_active FROM channels WHERE id=?", (cid,))
            if r:
                pctx.db.execute_write("UPDATE channels SET is_active=? WHERE id=?", (0 if r["is_active"] else 1, cid))
            await show_adm_s03_channels(pctx, update)
        elif act == "chtest" and len(parts) > 3:
            r = pctx.db.query_one("SELECT * FROM channels WHERE id=?", (int(parts[3]),))
            if r:
                m, err = await safe_send_message_to_chat(context.bot, str(r["chat_id"]), f"🧪 Test Post OK ({now_dhaka_iso()})")
                await send_or_edit_admin(pctx, update, "✅ Test Post sent!" if m else f"❌ Failed: {escape_html(err)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s03")]))
        elif act == "chdel" and len(parts) > 3:
            pctx.db.execute_write("DELETE FROM channels WHERE id=?", (int(parts[3]),))
            await show_adm_s03_channels(pctx, update)
        elif act == "sptog" and len(parts) > 3:
            sid = int(parts[3])
            r = pctx.db.query_one("SELECT is_active FROM support_contacts WHERE id=?", (sid,))
            if r:
                pctx.db.execute_write("UPDATE support_contacts SET is_active=? WHERE id=?", (0 if r["is_active"] else 1, sid))
            await show_adm_s03_channels(pctx, update)
        elif act == "spdel" and len(parts) > 3:
            pctx.db.execute_write("DELETE FROM support_contacts WHERE id=?", (int(parts[3]),))
            await show_adm_s03_channels(pctx, update)
        elif act == "chadd":
            pctx.runtime.set_state(uid, flow="admin", step="s03_chadd", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>purpose | chat_id | title | join_link</code>\n(purposes: force_join, task_fs_review, finance_review, payout_order, leaderboard, otp_notify, otp_relay, auto_backup)", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s03")]))
        elif act == "spadd":
            pctx.runtime.set_state(uid, flow="admin", step="s03_spadd", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Name | @username | Description</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s03")]))
        else:
            await show_adm_s03_channels(pctx, update)
    elif sec == "s04":
        if len(parts) > 3 and parts[2] == "tog":
            pctx.config.toggle_bool(parts[3], admin_id=uid)
            await show_adm_s04_force_join(pctx, update)
        elif len(parts) > 2 and parts[2] == "add":
            pctx.runtime.set_state(uid, flow="admin", step="s04_fjadd", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>@channel_or_id | Title | https://t.me/link</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s04")]))
        else:
            await show_adm_s04_force_join(pctx, update)
    elif sec == "s05":
        act = parts[2] if len(parts) > 2 else ""
        if act == "cat" and len(parts) > 3:
            await show_adm_s05_category(pctx, update, parts[3])
        elif act == "key" and len(parts) > 3:
            await show_adm_s05_key_detail(pctx, update, parts[3])
        elif act in ("ebn", "een") and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s05_edit_text", data={"key": parts[3], "lang": "bn" if act == "ebn" else "en"})
            await send_or_edit_admin(pctx, update, f"Send new {'BN' if act == 'ebn' else 'EN'} text for <code>{parts[3]}</code>:", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s05:key:{parts[3]}")]))
        elif act in ("tact", "thid") and len(parts) > 3:
            pctx.text.toggle_text_flag(parts[3], "is_active" if act == "tact" else "is_hidden", uid)
            await show_adm_s05_key_detail(pctx, update, parts[3])
        elif act == "prev" and len(parts) > 3:
            bn_p = pctx.text.get_text(parts[3], "bn", name="Demo", user_id="123", balance="৳100")
            await send_or_edit_admin(pctx, update, f"👁️ <b>Preview:</b>\n\n{bn_p}", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s05:key:{parts[3]}")]))
        elif act == "rst" and len(parts) > 3:
            pctx.text.reset_text_to_default(parts[3], uid)
            await show_adm_s05_key_detail(pctx, update, parts[3])
        elif act == "sz" and len(parts) > 4 and parts[4] in ("global", "short", "medium", "current"):
            pctx.config.set_setting(f"msg_size_txt_{parts[3]}", parts[4], uid)
            await show_adm_s05_key_detail(pctx, update, parts[3])
        elif act == "search":
            pctx.runtime.set_state(uid, flow="admin", step="s05_search", data={})
            await send_or_edit_admin(pctx, update, "🔍 Send keyword to search across all bot texts:", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s05")]))
        elif act == "botname":
            pctx.runtime.set_state(uid, flow="admin", step="s05_botname", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Bot Name BN | Bot Name EN</code> (or <code>AUTO | AUTO</code>):", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s05")]))
        elif act == "togsw":
            pctx.config.toggle_bool("language_switcher_enabled", admin_id=uid)
            await show_adm_s05_texts(pctx, update)
        else:
            await show_adm_s05_texts(pctx, update)
    elif sec == "s06":
        act = parts[2] if len(parts) > 2 else ""
        if act == "kb" and len(parts) > 3:
            ok_k, msg_k, _ = pctx.kb.toggle_keyboard_switch(parts[3], uid)
            if not ok_k:
                await send_or_edit_admin(pctx, update, f"⚠️ {escape_html(msg_k)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s06")]))
            else:
                await show_adm_s06_buttons(pctx, update)
        elif act == "coltog":
            pctx.config.toggle_bool("button_colors_enabled", admin_id=uid)
            await show_adm_s06_buttons(pctx, update)
        elif act == "colrst":
            pctx.kb.reset_all_button_colors(uid)
            await show_adm_s06_buttons(pctx, update)
        elif act == "btn" and len(parts) > 3:
            await show_adm_s06_btn_detail(pctx, update, int(parts[3]))
        elif act == "cyc" and len(parts) > 3:
            bid = int(parts[3])
            b = pctx.kb.get_button_by_id(bid)
            if b:
                idx = OFFICIAL_BUTTON_STYLES.index(str(b["button_style"])) if str(b["button_style"]) in OFFICIAL_BUTTON_STYLES else 0
                nxt = OFFICIAL_BUTTON_STYLES[(idx + 1) % len(OFFICIAL_BUTTON_STYLES)]
                pctx.kb.set_button_style(bid, nxt, uid)
            await show_adm_s06_buttons(pctx, update)
        elif act == "sc" and len(parts) > 4:
            pctx.kb.set_button_style(int(parts[3]), parts[4], uid)
            await show_adm_s06_btn_detail(pctx, update, int(parts[3]))
        elif act in ("ben", "bhid") and len(parts) > 3:
            bid = int(parts[3])
            b = pctx.kb.get_button_by_id(bid)
            if b:
                col = "is_enabled" if act == "ben" else "is_hidden"
                pctx.db.execute_write(f"UPDATE dynamic_buttons SET {col}=? WHERE id=?", (0 if b[col] else 1, bid))
            await show_adm_s06_btn_detail(pctx, update, bid)
        elif act == "bed" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s06_bed", data={"bid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "Send: <code>Label BN | Label EN | Emoji</code>", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s06:btn:{parts[3]}")]))
        elif act == "add":
            pctx.runtime.set_state(uid, flow="admin", step="s06_add", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Label BN | Label EN | Emoji | info/url/task/store_cat/fs | target | primary/success/danger/default</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s06")]))
        elif act == "theme":
            pctx.runtime.set_state(uid, flow="admin", step="s06_theme", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Header Icon | Divider Line</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s06")]))
        else:
            await show_adm_s06_buttons(pctx, update)
    elif sec == "s07":
        act = parts[2] if len(parts) > 2 else ""
        if act == "p" and len(parts) > 3:
            await show_adm_s07_studio(pctx, update, int(parts[3]))
        elif act == "ev" and len(parts) > 3:
            await show_adm_s07_event(pctx, update, parts[3], 0)
        elif act == "evp" and len(parts) > 4:
            await show_adm_s07_event(pctx, update, parts[3], int(parts[4]))
        elif act == "ef" and len(parts) > 4:
            pctx.studio.toggle_event_flag(parts[3], parts[4], uid)
            await show_adm_s07_event(pctx, update, parts[3])
        elif act == "md" and len(parts) > 4:
            pctx.studio.set_event_delivery_mode(parts[3], parts[4], uid)
            await show_adm_s07_event(pctx, update, parts[3])
        elif act == "v" and len(parts) > 3:
            await show_adm_s07_variant(pctx, update, int(parts[3]))
        elif act == "vf" and len(parts) > 4:
            pctx.studio.toggle_variant_flag(int(parts[3]), parts[4], uid)
            await show_adm_s07_variant(pctx, update, int(parts[3]))
        elif act == "ve" and len(parts) > 4:
            pctx.runtime.set_state(uid, flow="admin", step="s07_ve", data={"vid": int(parts[3]), "lang": parts[4]})
            await send_or_edit_admin(pctx, update, f"Send: <code>Title | Body HTML</code> ({parts[4].upper()})", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s07:v:{parts[3]}")]))
        elif act == "addv" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s07_addv", data={"ev": parts[3]})
            await send_or_edit_admin(pctx, update, "Send: <code>Title BN | Title EN | Body BN | Body EN</code>", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s07:ev:{parts[3]}")]))
        elif act == "addev":
            pctx.runtime.set_state(uid, flow="admin", step="s07_addev", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>event_key | Title BN | Title EN | Body BN | Body EN</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s07")]))
        elif act == "sz" and len(parts) > 3 and parts[3] in ("short", "medium", "current"):
            pctx.config.set_setting("message_size_mode", parts[3], uid)
            await show_adm_s07_studio(pctx, update)
        elif act == "evsz" and len(parts) > 4 and parts[4] in ("global", "short", "medium", "current"):
            pctx.config.set_setting(f"msg_size_ev_{parts[3]}", parts[4], uid)
            await show_adm_s07_event(pctx, update, parts[3])
        else:
            await show_adm_s07_studio(pctx, update)
    elif sec == "s08":
        act = parts[2] if len(parts) > 2 else ""
        if act == "sec" and len(parts) > 3:
            await show_adm_s08_sector_rules(pctx, update, int(parts[3]))
        elif act == "r" and len(parts) > 3:
            await show_adm_s08_rule_detail(pctx, update, parts[3])
        elif act == "rtog" and len(parts) > 4:
            ok_r, msg_r, _ = pctx.rules.toggle_rule(parts[3], parts[4], uid)
            if not ok_r:
                await send_or_edit_admin(pctx, update, f"🔒 {escape_html(msg_r)}", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s08:r:{parts[3]}")]))
            else:
                await show_adm_s08_rule_detail(pctx, update, parts[3])
        elif act == "red" and len(parts) > 4:
            pctx.runtime.set_state(uid, flow="admin", step="s08_red", data={"rk": parts[3], "lang": parts[4]})
            await send_or_edit_admin(pctx, update, f"Send: <code>Title | Description</code> ({parts[4].upper()})", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s08:r:{parts[3]}")]))
        elif act == "rrst" and len(parts) > 3:
            pctx.rules.reset_rule(parts[3], uid)
            await show_adm_s08_rule_detail(pctx, update, parts[3])
        else:
            await show_adm_s08_sectors(pctx, update)
    elif sec == "s09":
        act = parts[2] if len(parts) > 2 else ""
        if act == "gtog" and len(parts) > 3:
            pctx.config.toggle_bool(parts[3], admin_id=uid)
            await show_adm_s09_tasks(pctx, update)
        elif act == "gkeys":
            pctx.runtime.set_state(uid, flow="admin", step="s09_gkeys", data={})
            await send_or_edit_admin(pctx, update, "⚙️ Send Global Required Cookie Keys (e.g. <code>c_user,xs</code> or <code>none</code>):", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s09")]))
        elif act == "add":
            pctx.runtime.set_state(uid, flow="admin", step="s09_add", data={})
            await send_or_edit_admin(pctx, update, "➕ Send: <code>Title BN | Title EN | Reward | Instruction BN | TOTP(1/0) | Cookie(1/0)</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s09")]))
        elif act == "t" and len(parts) > 3:
            await show_adm_s09_task_detail(pctx, update, int(parts[3]))
        elif act == "ttog" and len(parts) > 4:
            pctx.tasks.toggle_task_bool(int(parts[3]), parts[4], uid)
            await show_adm_s09_task_detail(pctx, update, int(parts[3]))
        elif act == "tkeys" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s09_tkeys", data={"tid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "⚙️ Send Task Cookie Keys (e.g. <code>c_user,xs</code> or <code>none</code>):", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s09:t:{parts[3]}")]))
        elif act == "wiz" and len(parts) > 3:
            await show_adm_s09_wizard(pctx, update, int(parts[3]))
        elif act == "scmb" and len(parts) > 4:
            pctx.tasks.update_task_fields(int(parts[3]), {"field_combo_mode": parts[4]}, uid)
            await show_adm_s09_wizard(pctx, update, int(parts[3]))
        elif act == "spwm" and len(parts) > 4:
            pctx.tasks.update_task_fields(int(parts[3]), {"password_mode": parts[4]}, uid)
            await show_adm_s09_wizard(pctx, update, int(parts[3]))
        elif act == "setpw" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s09_setpw", data={"tid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "🔑 Send Static Password or Pattern (e.g. <code>Work@{4DIGIT}{2ALPHA}</code>):", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s09:wiz:{parts[3]}")]))
        elif act == "setcmb" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s09_setcmb", data={"tid": int(parts[3])})
            await send_or_edit_admin(
                pctx,
                update,
                "📋 কমা দিয়ে কাস্টম ফিল্ডগুলো লিখুন (যেমন: <code>Full Name, Password</code>):",
                InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s09:wiz:{parts[3]}")]),
            )
        elif act == "upsrc" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s09_upsrc", data={"tid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "📤 Upload Source File (.txt, .csv, .xls, .xlsx) now:", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s09:t:{parts[3]}")]))
        elif act == "steps" and len(parts) > 3:
            await show_adm_s09_steps(pctx, update, int(parts[3]))
        elif act == "addst" and len(parts) > 4:
            pctx.runtime.set_state(uid, flow="admin", step="s09_addst", data={"tid": int(parts[3]), "phase": parts[4]})
            await send_or_edit_admin(pctx, update, f"🪜 Send ({parts[4]}): <code>Title BN | Title EN | text/number/photo/file/select | Instruction</code>", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s09:steps:{parts[3]}")]))
        elif act == "sttog" and len(parts) > 4:
            pctx.tasks.toggle_step_flag(int(parts[3]), "is_enabled")
            await show_adm_s09_steps(pctx, update, int(parts[4]))
        elif act == "stup" and len(parts) > 4:
            pctx.tasks.reorder_step(int(parts[3]), "up")
            await show_adm_s09_steps(pctx, update, int(parts[4]))
        elif act == "stdn" and len(parts) > 4:
            pctx.tasks.reorder_step(int(parts[3]), "down")
            await show_adm_s09_steps(pctx, update, int(parts[4]))
        elif act == "stdel" and len(parts) > 4:
            pctx.tasks.delete_step(int(parts[3]))
            await show_adm_s09_steps(pctx, update, int(parts[4]))
        elif act == "testu" and len(parts) > 3:
            u_row = pctx.users.get_user(uid)
            if u_row:
                prev = pctx.tasks.test_as_user_preview(int(parts[3]), u_row, "bn")
                await send_or_edit_admin(pctx, update, prev, InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s09:t:{parts[3]}")]))
        elif act == "clone" and len(parts) > 3:
            _, msg_cl, new_id = pctx.tasks.clone_task(int(parts[3]), uid)
            await send_or_edit_admin(pctx, update, f"📋 {escape_html(msg_cl)}", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s09:t:{new_id or parts[3]}")]))
        elif act in ("expa", "expn") and len(parts) > 3:
            tid = int(parts[3])
            ok_e, msg_e, fpath, sub_ids = pctx.task_subs.export_task_master_file(tid, "xlsx", incremental_only=(act == "expn"), admin_id=uid, bypass_cooldown=True)
            if not ok_e or fpath is None:
                await send_or_edit_admin(pctx, update, f"⚠️ {escape_html(msg_e)}", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s09:t:{tid}")]))
            else:
                with open(fpath, "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=fpath.name, caption=f"📥 Task #{tid} Export ({len(sub_ids)} rows)")
                pctx.task_subs.mark_submissions_exported(tid, sub_ids, fpath, "xlsx", uid)
        elif act == "stog" and len(parts) > 3:
            tid = int(parts[3])
            t = pctx.tasks.get_task(tid)
            if t:
                nxt_s = "paused" if str(t["status"]) == "active" else "active"
                pctx.tasks.update_task_fields(tid, {"status": nxt_s}, uid)
            await show_adm_s09_task_detail(pctx, update, tid)
        elif act == "arch" and len(parts) > 3:
            pctx.tasks.update_task_fields(int(parts[3]), {"is_archived": 1, "status": "archived"}, uid)
            await show_adm_s09_tasks(pctx, update)
        else:
            await show_adm_s09_tasks(pctx, update)
    elif sec == "s10":
        act = parts[2] if len(parts) > 2 else ""
        if act == "tog" and len(parts) > 3:
            pctx.config.toggle_bool(parts[3], admin_id=uid)
            await show_adm_s10_auto_review(pctx, update)
        elif act == "set" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s10_set", data={"key": parts[3]})
            await send_or_edit_admin(pctx, update, f"⏱️ Send value for <code>{parts[3]}</code> (e.g. <code>30s</code>, <code>2m</code>, or number):", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s10")]))
        elif act == "sumnow":
            txt = pctx.reports.build_daily_summary_text("bn")
            await safe_send_message_to_chat(context.bot, uid, txt)
        else:
            await show_adm_s10_auto_review(pctx, update)
    elif sec == "s11":
        act = parts[2] if len(parts) > 2 else ""
        if act == "queue":
            await show_adm_s11_queue(pctx, update)
        elif act == "rev" and len(parts) > 3:
            await show_adm_s11_review_sub(pctx, update, int(parts[3]))
        elif act in ("ba", "br") and len(parts) > 4:
            fs_sid, batch_n = int(parts[3]), int(parts[4])
            recs = pctx.fs.list_submission_records(fs_sid, status_filter="pending", limit=batch_n)
            rids = [int(r["id"]) for r in recs]
            reason = pctx.text.get_text("default_reject_reason", "bn") if act == "br" else ""
            ok_rv, msg_rv, res_rv = pctx.fs.review_fs_records(fs_sid, rids, "approve" if act == "ba" else "reject", uid, reason)
            if ok_rv and res_rv:
                target_u = pctx.users.get_user(res_rv["user_id"])
                u_lang = str(target_u["language"] or "bn") if target_u else "bn"
                ev_k = "fs_approved_final_msg" if res_rv["approved"] > 0 else "fs_rejected_final_msg"
                card, _, en = pctx.studio.render_event_message(
                    ev_k, lang=u_lang, name=str(target_u["full_name"]) if target_u else "",
                    sub_uid=res_rv["sub_uid"], approved=res_rv["approved"], rejected=res_rv["rejected"],
                    total=res_rv["total"], earned_reward=format_money(res_rv["total_reward"]),
                    new_balance=format_money(res_rv["new_balance"]), version=res_rv["version"],
                    rejected_lines_summary=res_rv["rejected_summary"] or "-",
                )
                pctx.notifications.enqueue(res_rv["user_id"], card if (en and card) else f"📊 FS {res_rv['sub_uid']} v{res_rv['version']}: ✅{res_rv['approved']} ❌{res_rv['rejected']}")
            await send_or_edit_admin(pctx, update, f"{'✅' if ok_rv else '❌'} {escape_html(msg_rv)}", InlineKeyboardMarkup([[pctx.kb.ibtn("🔍 Back to Submission", callback_data=f"adm:s11:rev:{fs_sid}", action_kind="primary")], admin_back_row(pctx, "adm:s11:queue")]))
        elif act == "add":
            pctx.runtime.set_state(uid, flow="admin", step="s11_add", data={})
            await send_or_edit_admin(pctx, update, "➕ Send: <code>Title BN | Title EN | Reward Per Record | Min Columns | any/email/phone</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s11")]))
        elif act == "tpls":
            tpls = pctx.fs.list_reject_templates(active_only=False)
            txt = "🚫 <b>Reject Templates:</b>\n" + "\n".join(f"• #{t['id']} [{t['scope']}] {escape_html(t['reason_bn'])}" for t in tpls)
            await send_or_edit_admin(pctx, update, txt, InlineKeyboardMarkup([[pctx.kb.ibtn("➕ Add Template", callback_data="adm:s11:addtpl", action_kind="confirm")], admin_back_row(pctx, "adm:s11")]))
        elif act == "addtpl":
            pctx.runtime.set_state(uid, flow="admin", step="s11_addtpl", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>scope(all/fs/deposit) | Title BN | Reason BN | Reason EN</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s11:tpls")]))
        elif act == "expall":
            ok_e, msg_e, fpath, rids = pctx.excel.export_fs_master(None, False, "xlsx", uid)
            if ok_e and fpath:
                with open(fpath, "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=fpath.name)
                pctx.excel.mark_fs_records_exported(rids)
            else:
                await send_or_edit_admin(pctx, update, f"⚠️ {escape_html(msg_e)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s11")]))
        else:
            await show_adm_s11_fs(pctx, update)
    elif sec == "s12":
        act = parts[2] if len(parts) > 2 else ""
        if act == "addcat":
            pctx.runtime.set_state(uid, flow="admin", step="s12_addcat", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Name BN | Name EN | Emoji</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s12")]))
        elif act == "addprod":
            pctx.runtime.set_state(uid, flow="admin", step="s12_addprod", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>CategoryID | Name BN | Name EN | Price | WarrantyHours | deposit_only/any</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s12")]))
        elif act == "p" and len(parts) > 3:
            await show_adm_s12_prod_detail(pctx, update, int(parts[3]))
        elif act == "upstk" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s12_upstk", data={"pid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "📤 Upload Stock File (.txt, .csv, .xls, .xlsx):", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s12:p:{parts[3]}")]))
        elif act == "addst" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s12_addst", data={"pid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "Send: <code>Step Title BN | Step Title EN | Instruction</code>", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s12:p:{parts[3]}")]))
        elif act == "addtr" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s12_addtr", data={"pid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "Send: <code>MinQty | UnitPrice</code>", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s12:p:{parts[3]}")]))
        elif act == "ptog" and len(parts) > 4:
            pid = int(parts[3])
            p = pctx.store.get_product(pid)
            if p:
                pctx.store.update_product(pid, {parts[4]: 0 if p[parts[4]] else 1}, uid)
            await show_adm_s12_prod_detail(pctx, update, pid)
        elif act == "wal" and len(parts) > 3:
            pid = int(parts[3])
            p = pctx.store.get_product(pid)
            if p:
                nxt_w = "deposit_only" if str(p["wallet_mode"]) == "any" else "any"
                pctx.store.update_product(pid, {"wallet_mode": nxt_w}, uid)
            await show_adm_s12_prod_detail(pctx, update, pid)
        elif act == "clone" and len(parts) > 3:
            _, m_c, npid = pctx.store.clone_product(int(parts[3]), uid)
            await send_or_edit_admin(pctx, update, f"📋 {escape_html(m_c)}", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s12:p:{npid or parts[3]}")]))
        elif act == "coupons":
            cps = pctx.store.list_coupons()
            txt = "🎟️ <b>Coupons:</b>\n" + ("\n".join(f"• <code>{c['code']}</code> ({c['discount_value']} {c['discount_type']}) Used:{c['used_count']}/{c['max_uses']}" for c in cps[:15]) or "None")
            await send_or_edit_admin(pctx, update, txt, InlineKeyboardMarkup([[pctx.kb.ibtn("➕ Add Coupon", callback_data="adm:s12:addcp", action_kind="confirm")], admin_back_row(pctx, "adm:s12")]))
        elif act == "addcp":
            pctx.runtime.set_state(uid, flow="admin", step="s12_addcp", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>CODE | percent/fixed | Value | MaxUses</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s12:coupons")]))
        elif act == "warr":
            wars = pctx.db.query_all("SELECT * FROM store_warranty_requests WHERE status='pending' ORDER BY id ASC LIMIT 10")
            rows_w: List[List[InlineKeyboardButton]] = []
            for w in wars:
                rows_w.append([
                    pctx.kb.ibtn(f"🔁 Replace {w['warranty_uid']}", callback_data=f"adm:s12:wres:{w['id']}:replace", action_kind="confirm"),
                    pctx.kb.ibtn("💰 Refund", callback_data=f"adm:s12:wres:{w['id']}:refund", action_kind="primary"),
                    pctx.kb.ibtn("❌", callback_data=f"adm:s12:wres:{w['id']}:reject", action_kind="reject"),
                ])
            rows_w.append(admin_back_row(pctx, "adm:s12"))
            await send_or_edit_admin(pctx, update, f"🛡️ <b>Pending Warranty Claims ({len(wars)}):</b>", InlineKeyboardMarkup(rows_w))
        elif act == "wres" and len(parts) > 4:
            ok_w, msg_w, _ = pctx.store.resolve_warranty_request(int(parts[3]), parts[4], uid, "Resolved by Admin")
            await send_or_edit_admin(pctx, update, f"{'✅' if ok_w else '❌'} {escape_html(msg_w)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s12:warr")]))
        elif act == "expord":
            ok_o, msg_o, fp_o = pctx.store.export_completed_orders("xlsx", uid)
            if ok_o and fp_o:
                with open(fp_o, "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=fp_o.name)
            else:
                await send_or_edit_admin(pctx, update, f"⚠️ {escape_html(msg_o)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s12")]))
        else:
            await show_adm_s12_store(pctx, update)
    elif sec == "s13":
        act = parts[2] if len(parts) > 2 else ""
        if act == "tog" and len(parts) > 3:
            pctx.config.toggle_bool(parts[3], admin_id=uid)
            await show_adm_s13_otp(pctx, update)
        elif act == "qpush":
            pctx.runtime.set_state(uid, flow="admin", step="s13_qpush", data={})
            await send_or_edit_admin(pctx, update, "⚡ Send: <code>phone_number | sms_or_code</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s13")]))
        elif act == "addc":
            pctx.runtime.set_state(uid, flow="admin", step="s13_addc", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Name BN | Name EN | Flag | +Code | NumbersPerClick | Fee | WaitSec</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s13")]))
        elif act == "c" and len(parts) > 3:
            await show_adm_s13_country_detail(pctx, update, int(parts[3]))
        elif act == "upn" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s13_upn", data={"cid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "📤 Upload Numbers File (.txt, .csv, .xls, .xlsx):", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s13:c:{parts[3]}")]))
        elif act == "setn" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s13_setn", data={"cid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "🔢 Send how many numbers per click (1, 2, 3, ...):", InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s13:c:{parts[3]}")]))
        elif act == "ctog" and len(parts) > 4:
            cid = int(parts[3])
            c = pctx.otp.get_country(cid)
            if c:
                pctx.otp.update_country(cid, {parts[4]: 0 if c[parts[4]] else 1}, uid)
            await show_adm_s13_country_detail(pctx, update, cid)
        elif act == "exp":
            ok_e, msg_e, fp_e = pctx.otp.export_otp_logs("xlsx", uid)
            if ok_e and fp_e:
                with open(fp_e, "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=fp_e.name)
            else:
                await send_or_edit_admin(pctx, update, f"⚠️ {escape_html(msg_e)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s13")]))
        else:
            await show_adm_s13_otp(pctx, update)
    elif sec == "s14":
        act = parts[2] if len(parts) > 2 else ""
        if act == "tog" and len(parts) > 3:
            pctx.config.toggle_bool(parts[3], admin_id=uid)
            await show_adm_s14_deposit(pctx, update)
        elif act == "ocrapi":
            pctx.runtime.set_state(uid, flow="admin", step="s14_ocrapi", data={})
            await send_or_edit_admin(pctx, update, "🔑 Send: <code>OCR_API_URL | OCR_API_KEY</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s14")]))
        elif act == "addm":
            pctx.runtime.set_state(uid, flow="admin", step="s14_addm", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Name BN | Name EN | Number/PayID | Min | Max | Bonus%</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s14")]))
        elif act == "m" and len(parts) > 3:
            await show_adm_s14_method_detail(pctx, update, int(parts[3]))
        elif act == "mtog" and len(parts) > 4:
            mid, fld = int(parts[3]), parts[4]
            m = pctx.deposits.get_method(mid)
            if m and fld in ("is_active", "is_hidden", "require_txid", "require_screenshot", "require_sender"):
                pctx.deposits.update_method(mid, {fld: 0 if int(m[fld]) == 1 else 1}, uid)
            await show_adm_s14_method_detail(pctx, update, mid)
        elif act == "med" and len(parts) > 4:
            mid, what = int(parts[3]), parts[4]
            hints = {
                "name": "✏️ Send: <code>Name BN | Name EN</code>",
                "acc": "📲 Send: <code>Account Number/PayID | Holder Type (Personal/Agent/Merchant) | Network (optional)</code>",
                "limits": "💰 Send: <code>Min Amount | Max Amount | Bonus% | Charge%</code>",
                "instr": "📝 Send: <code>Instruction BN | Instruction EN</code>",
            }
            pctx.runtime.set_state(uid, flow="admin", step=f"s14_med_{what}", data={"mid": mid})
            await send_or_edit_admin(pctx, update, hints.get(what, "Send value:"), InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s14:m:{mid}")]))
        elif act == "march" and len(parts) > 3:
            pctx.deposits.update_method(int(parts[3]), {"is_archived": 1, "is_active": 0}, uid)
            await show_adm_s14_deposit(pctx, update)
        elif act == "app" and len(parts) > 3:
            ok_d, msg_d, res_d = pctx.deposits.approve_deposit(int(parts[3]), uid)
            if ok_d and res_d:
                dep = res_d["dep"]
                if dep.get("channel_id") and dep.get("channel_message_id"):
                    await safe_edit_channel_message(context.bot, dep["channel_id"], int(dep["channel_message_id"]), f"💳 Deposit <code>{dep['deposit_uid']}</code> ✅ APPROVED", None, bool(dep["is_media_msg"]))
                pctx.notifications.enqueue(int(dep["user_id"]), f"🟢 Deposit <code>{dep['deposit_uid']}</code> Approved (+{format_money(dep['net_credit'])})!")
            await show_adm_s14_deposit(pctx, update)
        elif act == "rej" and len(parts) > 3:
            ok_d, msg_d, res_d = pctx.deposits.reject_deposit(int(parts[3]), uid, "Rejected by admin")
            if ok_d and res_d:
                dep = res_d["dep"]
                pctx.notifications.enqueue(int(dep["user_id"]), f"🔴 Deposit <code>{dep['deposit_uid']}</code> Rejected.")
            await show_adm_s14_deposit(pctx, update)
        else:
            await show_adm_s14_deposit(pctx, update)
    elif sec == "s15":
        act = parts[2] if len(parts) > 2 else ""
        if act == "addm":
            pctx.runtime.set_state(uid, flow="admin", step="s15_addm", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Name BN | Name EN | bd_mobile/crypto | fixed/percent | FeeVal | Min | Max</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s15")]))
        elif act == "m" and len(parts) > 3:
            await show_adm_s15_method_detail(pctx, update, int(parts[3]))
        elif act == "mtog" and len(parts) > 4:
            mid, fld = int(parts[3]), parts[4]
            m = pctx.withdrawals.get_method(mid)
            if m and fld in ("is_active", "is_hidden"):
                pctx.withdrawals.update_method(mid, {fld: 0 if int(m[fld]) == 1 else 1}, uid)
            await show_adm_s15_method_detail(pctx, update, mid)
        elif act == "med" and len(parts) > 4:
            mid, what = int(parts[3]), parts[4]
            hints = {
                "name": "✏️ Send: <code>Name BN | Name EN</code>",
                "fee": "💸 Send: <code>fixed/percent | Fee Value</code>",
                "limits": "💰 Send: <code>Min Amount | Max Amount</code>",
                "regex": "🔐 Send: <code>bd_mobile/crypto/custom | Wallet Regex</code>",
                "instr": "📝 Send: <code>Instruction BN | Instruction EN</code>",
            }
            pctx.runtime.set_state(uid, flow="admin", step=f"s15_med_{what}", data={"mid": mid})
            await send_or_edit_admin(pctx, update, hints.get(what, "Send value:"), InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s15:m:{mid}")]))
        elif act == "march" and len(parts) > 3:
            pctx.withdrawals.update_method(int(parts[3]), {"is_archived": 1, "is_active": 0}, uid)
            await show_adm_s15_withdraw(pctx, update)
        elif act == "paid" and len(parts) > 3:
            ok_w, msg_w, res_w = pctx.withdrawals.mark_paid_withdrawal(int(parts[3]), uid)
            if ok_w and res_w:
                wd = res_w["wd"]
                pctx.notifications.enqueue(int(wd["user_id"]), f"💸 Withdrawal <code>{wd['withdraw_uid']}</code> Paid ({format_money(wd['net_amount'])})!")
            await show_adm_s15_withdraw(pctx, update)
        elif act == "rej" and len(parts) > 3:
            ok_w, msg_w, res_w = pctx.withdrawals.reject_withdrawal(int(parts[3]), uid, "Rejected by admin")
            if ok_w and res_w:
                wd = res_w["wd"]
                pctx.notifications.enqueue(int(wd["user_id"]), f"❌ Withdrawal <code>{wd['withdraw_uid']}</code> Rejected & Refunded.")
            await show_adm_s15_withdraw(pctx, update)
        else:
            await show_adm_s15_withdraw(pctx, update)
    elif sec == "sys":
        act = parts[2] if len(parts) > 2 else ""
        if act == "tog":
            pctx.config.toggle_bool("auto_backup_enabled", admin_id=uid)
            await show_adm_sys_hub(pctx, update)
        elif act == "files":
            pctx.config.toggle_bool("auto_backup_send_individual_files", admin_id=uid)
            await show_adm_sys_hub(pctx, update)
        elif act == "tgt":
            cur_t = pctx.config.get_str("auto_backup_target", "channel")
            nxt_t = {"channel": "both", "both": "main_admin", "main_admin": "channel"}.get(cur_t, "channel")
            pctx.config.set_setting("auto_backup_target", nxt_t, uid)
            await show_adm_sys_hub(pctx, update)
        elif act == "int" and len(parts) > 3 and parts[3].isdigit():
            pctx.config.set_setting("auto_backup_interval_hours", max(1, int(parts[3])), uid)
            await show_adm_sys_hub(pctx, update)
        elif act == "intc":
            pctx.runtime.set_state(uid, flow="admin", step="sys_intc", data={})
            await send_or_edit_admin(pctx, update, "⏱️ কত ঘণ্টা পরপর অটো-ব্যাকআপ হবে তা লিখুন (যেমন: 1, 2, 3, 6, 12):", InlineKeyboardMarkup([admin_back_row(pctx, "adm:sys")]))
        elif act == "bkfj":
            ch = pctx.db.query_one("SELECT * FROM channels WHERE purpose='auto_backup' ORDER BY id ASC LIMIT 1")
            if ch:
                new_jr = 0 if int(ch["join_required"]) == 1 else 1
                new_pm = "public" if new_jr == 1 else "admin_only"
                pctx.db.execute_write(
                    "UPDATE channels SET join_required=?, privacy_mode=?, is_active=1, is_hidden=0 WHERE id=?",
                    (new_jr, new_pm, int(ch["id"])),
                )
            await show_adm_sys_hub(pctx, update)
        elif act == "ch":
            pctx.runtime.set_state(uid, flow="admin", step="sys_ch", data={})
            await send_or_edit_admin(pctx, update, "📢 Send: <code>Channel_ID | Join_Link(optional)</code>\nউদাহরণ: <code>-1004498787785 | https://t.me/+xxxx</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:sys")]))
        elif act == "bklink":
            pctx.runtime.set_state(uid, flow="admin", step="sys_bklink", data={})
            await send_or_edit_admin(pctx, update, "🔗 ব্যাকআপ চ্যানেলের Join Link পাঠান (যেমন: <code>https://t.me/+xxxx</code>):", InlineKeyboardMarkup([admin_back_row(pctx, "adm:sys")]))
        elif act == "chtest":
            bk_ch = pctx.get_primary_channel_id("auto_backup")
            if not bk_ch:
                await send_or_edit_admin(pctx, update, "⚠️ কোনো Auto-Backup চ্যানেল সেট করা নেই।", InlineKeyboardMarkup([admin_back_row(pctx, "adm:sys")]))
            else:
                m, err = await safe_send_message_to_chat(context.bot, bk_ch, f"🧪 Auto-Backup Channel Test OK ({now_dhaka_iso()})")
                await send_or_edit_admin(pctx, update, "✅ Test Post sent!" if m else f"❌ Failed: {escape_html(err)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:sys")]))
        elif act == "msg" and len(parts) > 3 and parts[3] in ("short", "medium", "current"):
            pctx.config.set_setting("message_size_mode", parts[3], uid)
            await show_adm_sys_hub(pctx, update)
        elif act == "runnow":
            res_bk = await execute_full_auto_backup_delivery(pctx, context.bot, admin_id=uid)
            err_txt = ("\nErrors: " + "; ".join(res_bk["errors"][:3])) if res_bk["errors"] else ""
            await send_or_edit_admin(
                pctx, update,
                f"📤 <b>Auto-Backup সম্পন্ন!</b>\n• ID: <code>{res_bk['backup_uid']}</code>\n• মোট ফাইল: <b>{res_bk['total_files']}</b> | পাঠানো হয়েছে: <b>{res_bk['sent_count']}</b>{escape_html(err_txt)}",
                InlineKeyboardMarkup([admin_back_row(pctx, "adm:sys")]),
            )
        else:
            await show_adm_sys_hub(pctx, update)
    elif sec == "s16":
        act = parts[2] if len(parts) > 2 else ""
        if act == "tog" and len(parts) > 3:
            pctx.config.toggle_bool(parts[3], admin_id=uid)
            await show_adm_s16_growth(pctx, update)
        elif act == "set" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s16_set", data={"key": parts[3]})
            await send_or_edit_admin(pctx, update, f"Send numeric value for <code>{parts[3]}</code>:", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s16")]))
        elif act == "addbon":
            pctx.runtime.set_state(uid, flow="admin", step="s16_addbon", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>Title BN | Title EN | Reward | MaxClaims | MinTasks</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s16")]))
        elif act == "expbon":
            ok_b, msg_b, fp_b = pctx.bonuses.export_bonus_claims("xlsx", uid)
            if ok_b and fp_b:
                with open(fp_b, "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=fp_b.name)
            else:
                await send_or_edit_admin(pctx, update, f"⚠️ {escape_html(msg_b)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s16")]))
        elif act == "lbadj":
            pctx.runtime.set_state(uid, flow="admin", step="s16_lbadj", data={})
            await send_or_edit_admin(pctx, update, "➕ Send: <code>task/fs | user_id | +N or -N | Reason</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s16")]))
        elif act == "lbpub":
            lb_ch = pctx.get_primary_channel_id("leaderboard")
            if lb_ch:
                t_txt = pctx.leaderboard.format_leaderboard_text("task", "bn")
                f_txt = pctx.leaderboard.format_leaderboard_text("fs", "bn")
                await safe_send_message_to_chat(context.bot, lb_ch, t_txt + "\n\n" + f_txt)
                await send_or_edit_admin(pctx, update, "📢 Published to Leaderboard Channel!", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s16")]))
        elif act == "lbrst" and len(parts) > 3:
            ok_r, msg_r, winners = pctx.leaderboard.reset_cycle_and_award(parts[3], uid)
            for w in winners:
                pctx.notifications.enqueue(w["user_id"], f"🏆 Congratulations! You won {format_money(w['prize'])} in {parts[3].upper()} Leaderboard (Rank #{w['rank']})!")
            await send_or_edit_admin(pctx, update, f"🔄 {escape_html(msg_r)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s16")]))
        else:
            await show_adm_s16_growth(pctx, update)
    elif sec == "s17":
        act = parts[2] if len(parts) > 2 else ""
        if act == "search":
            pctx.runtime.set_state(uid, flow="admin", step="s17_search", data={})
            await send_or_edit_admin(pctx, update, "🔍 Send User ID, @username, Name, or Order/Sub/TxID:", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s17")]))
        elif act == "expall":
            rows_u = pctx.users.list_all_for_export()
            if rows_u:
                hdrs = list(rows_u[0].keys())
                data_r = [[r[h] for h in hdrs] for r in rows_u]
                fp_u, _ = pctx.excel.export_rows(hdrs, data_r, "All_Users", "all", "xlsx", "Users", uid)
                with open(fp_u, "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=fp_u.name, caption=f"👥 All Users ({len(rows_u)})")
        elif act == "warnall":
            pctx.runtime.set_state(uid, flow="admin", step="s17_warnall", data={})
            await send_or_edit_admin(pctx, update, "⚠️ Send warning notice text to send to ALL active users:", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s17")]))
        elif act == "u" and len(parts) > 3:
            await show_adm_s17_user_detail(pctx, update, int(parts[3]))
        elif act in ("cred", "ded", "warn") and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step=f"s17_{act}", data={"tuid": int(parts[3])})
            hint = "Send: <code>Amount | earned/deposit | Reason</code>" if act in ("cred", "ded") else "Send warning reason:"
            await send_or_edit_admin(pctx, update, hint, InlineKeyboardMarkup([admin_back_row(pctx, f"adm:s17:u:{parts[3]}")]))
        elif act == "blk" and len(parts) > 3:
            tuid = int(parts[3])
            u_r = pctx.users.get_user(tuid)
            if u_r:
                pctx.users.set_block_status(tuid, str(u_r["status"]) != "blocked", "Admin panel action", uid)
            await show_adm_s17_user_detail(pctx, update, tuid)
        else:
            await show_adm_s17_users(pctx, update)
    elif sec == "s18":
        act = parts[2] if len(parts) > 2 else ""
        if act == "bc":
            pctx.runtime.set_state(uid, flow="admin", step="s18_bc", data={})
            await send_or_edit_admin(pctx, update, "📢 Send broadcast message (Text or Photo with caption):", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s18")]))
        elif act == "qretry":
            n = pctx.notifications.retry_failed()
            await send_or_edit_admin(pctx, update, f"🔁 Re-queued {n} notification(s).", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s18")]))
        elif act == "qclr":
            n = pctx.notifications.clear_failed()
            await send_or_edit_admin(pctx, update, f"🧹 Cleared {n} queue entries.", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s18")]))
        elif act == "tkt" and len(parts) > 3:
            pctx.runtime.set_state(uid, flow="admin", step="s18_tkt", data={"tid": int(parts[3])})
            await send_or_edit_admin(pctx, update, "💬 Send reply text for this ticket:", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s18")]))
        elif act == "apl" and len(parts) > 4:
            ok_a, arow = pctx.appeals.resolve_appeal(int(parts[3]), parts[4], uid, f"{parts[4]} by admin")
            if ok_a and arow:
                pctx.notifications.enqueue(int(arow["user_id"]), f"⚖️ Your Appeal <code>{arow['appeal_uid']}</code> was <b>{parts[4].upper()}</b>.")
            await show_adm_s18_support(pctx, update)
        else:
            await show_adm_s18_support(pctx, update)
    elif sec == "s19":
        act = parts[2] if len(parts) > 2 else ""
        if act == "panic":
            ok_p, msg_p = pctx.security.toggle_panic_freeze(uid, not pctx.security.is_panic_frozen())
            await send_or_edit_admin(pctx, update, f"🚨 {escape_html(msg_p)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s19")]))
        elif act == "tog" and len(parts) > 3:
            pctx.config.toggle_bool(parts[3], admin_id=uid)
            await show_adm_s19_security(pctx, update, uid)
        else:
            await show_adm_s19_security(pctx, update, uid)
    elif sec == "s20":
        act = parts[2] if len(parts) > 2 else ""
        if act == "recon":
            rec = pctx.leaderboard  # run ledger reconciliation
            r_res = pctx.ledger.run_reconciliation(uid)
            txt = (
                f"⚖️ <b>Reconciliation {r_res['run_uid']}</b>\n"
                f"• Users Checked: <b>{r_res['total_users']}</b> | Mismatches: <b>{r_res['mismatches_found']}</b>\n"
                f"• Earned Liability: <code>{format_money(r_res['total_earned_liability'])}</code>\n"
                f"• Deposit Liability: <code>{format_money(r_res['total_deposit_liability'])}</code>\n"
                f"• Held Liability: <code>{format_money(r_res['total_held_liability'])}</code>"
            )
            await send_or_edit_admin(pctx, update, txt, InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
        elif act == "expledg":
            ok_l, msg_l, fp_l = pctx.reports.export_financial_ledger("all", "xlsx", uid)
            if ok_l and fp_l:
                with open(fp_l, "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=fp_l.name)
            else:
                await send_or_edit_admin(pctx, update, f"⚠️ {escape_html(msg_l)}", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
        elif act == "bkp":
            ok_b, msg_b, zpath, buid = pctx.backup.create_zip_backup("manual", uid)
            if ok_b and zpath:
                with open(zpath, "rb") as fp:
                    await context.bot.send_document(chat_id=uid, document=fp, filename=zpath.name, caption=f"💾 {buid}")
                pctx.backup.mark_backup_sent_to_telegram(buid)
        elif act == "autobk":
            pctx.config.toggle_bool("auto_backup_enabled", admin_id=uid)
            await show_adm_s20_admin_backup(pctx, update, uid)
        elif act == "audit":
            logs = pctx.audit.list_recent(12)
            txt = "📜 <b>Recent Audit Logs:</b>\n" + "\n".join(f"• [{l['actor_id']}] {l['action']} ({l['target_type']}:{l['target_id']})" for l in logs)
            await send_or_edit_admin(pctx, update, txt, InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
        elif act == "rtrst":
            res_rt = pctx.backup.runtime_only_reset(uid)
            await send_or_edit_admin(pctx, update, f"🧹 Runtime-Only Reset complete! Cleared {res_rt['runtime_states']} states.", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
        elif act == "addasst":
            pctx.runtime.set_state(uid, flow="admin", step="s20_addasst", data={})
            await send_or_edit_admin(pctx, update, "Send: <code>telegram_user_id | Full Name</code>", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
        elif act == "asst" and len(parts) > 3:
            await show_adm_s20_assistant_perms(pctx, update, int(parts[3]))
        elif act == "atog" and len(parts) > 3:
            pctx.permissions.toggle_assistant_active(uid, int(parts[3]))
            await show_adm_s20_assistant_perms(pctx, update, int(parts[3]))
        elif act == "arem" and len(parts) > 3:
            pctx.permissions.remove_assistant(uid, int(parts[3]))
            await show_adm_s20_admin_backup(pctx, update, uid)
        elif act == "passtog":
            if not pctx.permissions.is_main_admin(uid):
                await send_or_edit_admin(pctx, update, "⛔ শুধুমাত্র মূল এডমিন পাসওয়ার্ড পরিবর্তন করতে পারবেন।", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
            else:
                cur_on = pctx.config.get_bool("admin_panel_password_enabled", False)
                if not cur_on and not pctx.config.get_str("admin_panel_password", "").strip():
                    pctx.runtime.set_state(uid, flow="admin", step="s20_passset", data={})
                    await send_or_edit_admin(pctx, update, "🔐 পাসওয়ার্ড চালু করার আগে নতুন পাসওয়ার্ড লিখুন (কমপক্ষে ৪ অক্ষর):", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
                else:
                    pctx.config.set_setting("admin_panel_password_enabled", not cur_on, admin_id=uid, reason="toggle_admin_pass")
                    pctx.permissions.revoke_all_admin_sessions()
                    await show_adm_s20_admin_backup(pctx, update, uid)
        elif act == "passset":
            if not pctx.permissions.is_main_admin(uid):
                await send_or_edit_admin(pctx, update, "⛔ শুধুমাত্র মূল এডমিন পাসওয়ার্ড পরিবর্তন করতে পারবেন।", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
            else:
                pctx.runtime.set_state(uid, flow="admin", step="s20_passset", data={})
                await send_or_edit_admin(pctx, update, "✏️ এডমিন প্যানেলের নতুন পাসওয়ার্ড লিখুন (কমপক্ষে ৪ অক্ষর):", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
        elif act == "passview":
            if not pctx.permissions.is_main_admin(uid):
                await send_or_edit_admin(pctx, update, "⛔ শুধুমাত্র মূল এডমিন পাসওয়ার্ড দেখতে পারবেন।", InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
            else:
                cur_pw = pctx.config.get_str("admin_panel_password", "").strip()
                msg_pw = f"🔑 বর্তমান পাসওয়ার্ড: <code>{escape_html(cur_pw)}</code>" if cur_pw else "⚠️ এখনো কোনো পাসওয়ার্ড সেট করা হয়নি।"
                await send_or_edit_admin(pctx, update, msg_pw, InlineKeyboardMarkup([admin_back_row(pctx, "adm:s20")]))
        elif act == "passmain":
            if pctx.permissions.is_main_admin(uid):
                pctx.config.toggle_bool("admin_panel_password_main", admin_id=uid)
                pctx.permissions.revoke_all_admin_sessions()
            await show_adm_s20_admin_backup(pctx, update, uid)
        elif act == "aapp" and len(parts) > 3:
            ok_ap, _ = pctx.permissions.approve_assistant(uid, int(parts[3]))
            if ok_ap:
                pass_req = pctx.permissions.is_password_required_for(int(parts[3]), pctx.config)
                extra = "\n🔐 এডমিন প্যানেলে ঢুকতে /admin লিখে পাসওয়ার্ড দিন।" if pass_req else "\n⚙️ এডমিন প্যানেলে ঢুকতে /admin চাপুন।"
                pctx.notifications.enqueue(int(parts[3]), f"🎉 আপনার এডমিন অ্যাক্সেস মূল এডমিন <b>Approve</b> করেছেন!{extra}")
            await show_adm_s20_assistant_perms(pctx, update, int(parts[3]))
        elif act == "arej" and len(parts) > 3:
            ok_rj, _ = pctx.permissions.reject_assistant(uid, int(parts[3]))
            if ok_rj:
                pctx.notifications.enqueue(int(parts[3]), "⛔ আপনার এডমিন অ্যাক্সেস মূল এডমিন কর্তৃক <b>Reject</b> করা হয়েছে।")
            await show_adm_s20_assistant_perms(pctx, update, int(parts[3]))
        elif act == "ap" and len(parts) > 4:
            pctx.permissions.toggle_assistant_perm(uid, int(parts[3]), parts[4])
            await show_adm_s20_assistant_perms(pctx, update, int(parts[3]))
        else:
            await show_adm_s20_admin_backup(pctx, update, uid)


async def handle_admin_runtime_input(
    pctx: PlatformContext,
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    uid: int,
    st: Dict[str, Any],
) -> None:
    msg = update.message
    if msg is None:
        return
    step = st["step"]
    req_perm = ADMIN_SEC_PERM_MAP.get(step.split("_")[0])
    if req_perm and not pctx.permissions.has_permission(uid, req_perm):
        pctx.runtime.clear_state(uid)
        await msg.reply_text("⛔ আপনার এই সেকশন ব্যবহারের অনুমতি নেই।")
        return
    d = st["data"]
    txt = (msg.text or msg.caption or "").strip()

    # Document uploads inside Admin Panel (Task source, Store stock, OTP numbers, Zip restore)
    if msg.document and step in ("s09_upsrc", "s12_upstk", "s13_upn"):
        tg_f = await context.bot.get_file(msg.document.file_id)
        buf = io.BytesIO()
        await tg_f.download_to_memory(buf)
        fb = buf.getvalue()
        fn = msg.document.file_name or "file.txt"
        pctx.runtime.clear_state(uid)
        if step == "s09_upsrc":
            ok, res_m, info = pctx.tasks.upload_source_file(int(d["tid"]), fb, fn, uid)
            await msg.reply_text(f"{'✅' if ok else '❌'} {res_m}\nSample: {info.get('sample', [])[:1]}")
        elif step == "s12_upstk":
            ok, res_m, info = pctx.store.upload_product_stock(int(d["pid"]), fb, fn, uid)
            for wuid in info.get("notify_user_ids", []):
                pctx.notifications.enqueue(wuid, f"🔔 Stock Restocked for Product #{d['pid']}! Check Product Store now.")
            await msg.reply_text(f"{'✅' if ok else '❌'} {res_m}")
        elif step == "s13_upn":
            ok, res_m, _ = pctx.otp.upload_country_numbers(int(d["cid"]), fb, fn, uid)
            await msg.reply_text(f"{'✅' if ok else '❌'} {res_m}")
        return

    if step == "s18_bc":
        pctx.runtime.clear_state(uid)
        mtype = "photo" if msg.photo else ("video" if msg.video else ("document" if msg.document else "text"))
        fid = msg.photo[-1].file_id if msg.photo else (msg.video.file_id if msg.video else (msg.document.file_id if msg.document else ""))
        res = await pctx.broadcast.send_broadcast(context.bot, uid, "all", "all", mtype, txt, fid)
        await msg.reply_text(f"📢 Broadcast {res['broadcast_uid']} Done! Sent: {res['sent']}/{res['target']}, Failed: {res['failed']}")
        return

    pctx.runtime.clear_state(uid)
    parts = [p.strip() for p in txt.split("|")]

    if step == "s03_chadd" and len(parts) >= 2:
        is_fj = (parts[0] == "force_join")
        priv_mode = "public" if is_fj else "admin_only"
        join_req = 1 if is_fj else 0
        pctx.db.execute_write(
            "INSERT INTO channels (purpose, chat_id, title, join_link, is_active, is_hidden, sort_order, privacy_mode, join_required, created_at) VALUES (?, ?, ?, ?, 1, 0, 1, ?, ?, ?)",
            (parts[0], parts[1], parts[2] if len(parts) > 2 else parts[1], parts[3] if len(parts) > 3 else "", priv_mode, join_req, now_utc_iso()),
        )
        await msg.reply_text("✅ Channel added.")
    elif step == "s03_spadd" and len(parts) >= 2:
        pctx.db.execute_write(
            "INSERT INTO support_contacts (name, username_or_link, description_bn, description_en, is_active, is_hidden, sort_order, created_at) VALUES (?, ?, ?, ?, 1, 0, 1, ?)",
            (parts[0], parts[1], parts[2] if len(parts) > 2 else "", parts[2] if len(parts) > 2 else "", now_utc_iso()),
        )
        await msg.reply_text("✅ Support contact added.")
    elif step == "s04_fjadd" and len(parts) >= 1:
        pctx.db.execute_write(
            "INSERT INTO channels (purpose, chat_id, title, join_link, is_active, is_hidden, sort_order, privacy_mode, join_required, created_at) VALUES ('force_join', ?, ?, ?, 1, 0, 1, 'public', 1, ?)",
            (parts[0], parts[1] if len(parts) > 1 else parts[0], parts[2] if len(parts) > 2 else "", now_utc_iso()),
        )
        await msg.reply_text("✅ Force Join channel added.")
    elif step == "s05_edit_text":
        ok, m_t = pctx.text.update_text(d["key"], d["lang"], txt, uid)
        await msg.reply_text(("✅ " if ok else "❌ ") + m_t)
    elif step == "s05_search":
        hits = pctx.text.search_texts(txt, 15)
        rows_s = [[pctx.kb.ibtn(f"{h['text_key']} ({h['label_bn'][:16]})", callback_data=f"adm:s05:key:{h['text_key']}", action_kind="primary")] for h in hits]
        await msg.reply_text(f"🔍 Found {len(hits)} match(es):", reply_markup=InlineKeyboardMarkup(rows_s) if rows_s else None)
    elif step == "s05_botname" and len(parts) >= 2:
        pctx.config.set_setting("bot_name_bn", parts[0], uid)
        pctx.config.set_setting("bot_name_en", parts[1], uid)
        await msg.reply_text("✅ Bot names updated.")
    elif step == "s06_bed" and len(parts) >= 2:
        pctx.db.execute_write("UPDATE dynamic_buttons SET label_bn=?, label_en=?, emoji=?, updated_at=? WHERE id=?", (parts[0], parts[1], parts[2] if len(parts) > 2 else "", now_utc_iso(), int(d["bid"])))
        await msg.reply_text("✅ Button labels updated.")
    elif step == "s06_add" and len(parts) >= 5:
        ok_b, m_b, _ = pctx.kb.create_custom_button(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5] if len(parts) > 5 else "primary", "both", uid)
        await msg.reply_text(("✅ " if ok_b else "❌ ") + m_b)
    elif step == "s06_theme" and len(parts) >= 2:
        pctx.config.set_setting("theme_header_icon", parts[0], uid)
        pctx.config.set_setting("theme_divider", parts[1], uid)
        await msg.reply_text("✅ Theme updated.")
    elif step == "s07_ve" and len(parts) >= 2:
        ok_v, m_v = pctx.studio.edit_variant(int(d["vid"]), d["lang"], parts[0], parts[1], uid)
        await msg.reply_text(("✅ " if ok_v else "❌ ") + m_v)
    elif step == "s07_addv" and len(parts) >= 4:
        ok_v, m_v, _ = pctx.studio.add_custom_variant(d["ev"], parts[0], parts[1], parts[2], parts[3], uid)
        await msg.reply_text(("✅ " if ok_v else "❌ ") + m_v)
    elif step == "s07_addev" and len(parts) >= 5:
        ok_e, m_e = pctx.studio.add_custom_event(parts[0], parts[1], parts[2], parts[3], parts[4], uid)
        await msg.reply_text(("✅ " if ok_e else "❌ ") + m_e)
    elif step == "s08_red" and len(parts) >= 2:
        ok_r, m_r = pctx.rules.update_rule_texts(d["rk"], d["lang"], parts[0], parts[1], uid)
        await msg.reply_text(("✅ " if ok_r else "❌ ") + m_r)
    elif step == "s09_gkeys":
        pctx.config.set_setting("global_cookie_required_keys", txt or "none", uid)
        await msg.reply_text(f"✅ Global Cookie Keys set to: {txt or 'none'}")
    elif step == "s09_tkeys":
        pctx.tasks.update_task_fields(int(d["tid"]), {"cookie_required_keys": txt or "none"}, uid)
        await msg.reply_text(f"✅ Task #{d['tid']} Cookie Keys updated.")
    elif step == "s09_add" and len(parts) >= 3:
        tid = pctx.tasks.create_task(
            title_bn=parts[0], title_en=parts[1], reward_amount=float(parts[2] or 0),
            instruction_bn=parts[3] if len(parts) > 3 else "",
            require_totp=(parts[4] == "1") if len(parts) > 4 else False,
            require_cookie=(parts[5] == "1") if len(parts) > 5 else False,
            admin_id=uid,
        )
        await msg.reply_text(f"✅ Task #{tid} created!")
    elif step == "s09_setpw":
        tid = int(d["tid"])
        t = pctx.tasks.get_task(tid)
        col = "password_pattern" if (t and str(t["password_mode"]) == "pattern") else "static_password"
        pctx.tasks.update_task_fields(tid, {col: txt}, uid)
        await msg.reply_text(f"✅ Updated {col} for Task #{tid}.")
    elif step == "s09_setcmb":
        tid = int(d["tid"])
        fields = [f.strip() for f in txt.split(",") if f.strip()]
        if not fields:
            await msg.reply_text("❌ অন্তত একটি ফিল্ডের নাম লিখুন।")
        else:
            pctx.tasks.update_task_fields(
                tid,
                {"field_combo_mode": "custom", "custom_fields_json": safe_json_dumps(fields)},
                uid,
            )
            await msg.reply_text(f"✅ Task #{tid} Custom Combo set to: {', '.join(fields)}")
    elif step == "s09_addst" and len(parts) >= 2:
        sid = pctx.tasks.add_task_step(int(d["tid"]), d["phase"], parts[0], parts[1], parts[3] if len(parts) > 3 else "", parts[3] if len(parts) > 3 else "", parts[2] if len(parts) > 2 else "text")
        await msg.reply_text(f"✅ Task Step #{sid} added.")
    elif step == "s10_set":
        val = parse_duration_input(txt) if "sec" in d["key"] else parse_positive_float(txt)
        if val is not None:
            pctx.config.set_setting(d["key"], val, uid)
            await msg.reply_text(f"✅ {d['key']} updated to {val}.")
        else:
            await msg.reply_text("❌ Invalid value.")
    elif step == "s11_add" and len(parts) >= 3:
        fid = pctx.fs.create_fs_task(parts[0], parts[1], float(parts[2] or 0), min_columns=int(parts[3] or 1) if len(parts) > 3 else 1, pattern_type=parts[4] if len(parts) > 4 else "any", admin_id=uid)
        await msg.reply_text(f"✅ FS Task #{fid} created!")
    elif step == "s11_addtpl" and len(parts) >= 4:
        pctx.fs.add_reject_template(parts[0], parts[1], parts[1], parts[2], parts[3])
        await msg.reply_text("✅ Reject template added.")
    elif step == "s12_addcat" and len(parts) >= 2:
        cid = pctx.store.create_category(parts[0], parts[1], parts[2] if len(parts) > 2 else "🛍️", admin_id=uid)
        await msg.reply_text(f"✅ Category #{cid} created.")
    elif step == "s12_addprod" and len(parts) >= 4:
        pid = pctx.store.create_product(int(parts[0] or 0), parts[1], parts[2], float(parts[3] or 0), warranty_hours=int(parts[4] or 0) if len(parts) > 4 else 0, wallet_mode=parts[5] if len(parts) > 5 else "any", admin_id=uid)
        await msg.reply_text(f"✅ Product #{pid} created.")
    elif step == "s12_addst" and len(parts) >= 2:
        pctx.store.add_product_step(int(d["pid"]), parts[0], parts[1], parts[2] if len(parts) > 2 else "")
        await msg.reply_text("✅ Product step added.")
    elif step == "s12_addtr" and len(parts) >= 2:
        pctx.store.add_price_tier(int(d["pid"]), int(parts[0]), float(parts[1]))
        await msg.reply_text("✅ Price tier added.")
    elif step == "s12_addcp" and len(parts) >= 4:
        ok_c, m_c = pctx.store.create_coupon(parts[0], parts[1], float(parts[2]), int(parts[3]))
        await msg.reply_text(("✅ " if ok_c else "❌ ") + m_c)
    elif step == "s13_qpush" and len(parts) >= 2:
        ok_q, msg_q, matched = pctx.otp.ingest_sms(parts[0], parts[1], bridge_source="admin_quick_push")
        if ok_q:
            await deliver_otp_match_to_user_and_channel(pctx, context.bot, matched)
        await msg.reply_text(("✅ " if ok_q else "❌ ") + msg_q)
    elif step == "s13_addc" and len(parts) >= 4:
        cid = pctx.otp.create_country(parts[0], parts[1], parts[2], parts[3], int(parts[4] or 1) if len(parts) > 4 else 1, float(parts[5] or 0) if len(parts) > 5 else 0.0, int(parts[6] or 300) if len(parts) > 6 else 300, uid)
        await msg.reply_text(f"✅ OTP Country #{cid} created.")
    elif step == "s13_setn" and txt.isdigit():
        pctx.otp.update_country(int(d["cid"]), {"numbers_per_click": max(1, int(txt))}, uid)
        await msg.reply_text("✅ Numbers per click updated.")
    elif step == "s14_ocrapi" and len(parts) >= 1:
        pctx.config.set_setting("ocr_cloud_api_url", parts[0], uid)
        if len(parts) > 1:
            pctx.config.set_setting("ocr_cloud_api_key", parts[1], uid)
        await msg.reply_text("✅ Cloud OCR settings updated.")
    elif step == "s14_addm" and len(parts) >= 5:
        mid = pctx.deposits.create_method(parts[0], parts[1], parts[2], min_amount=float(parts[3]), max_amount=float(parts[4]), bonus_percent=float(parts[5]) if len(parts) > 5 else 0.0, admin_id=uid)
        await msg.reply_text(f"✅ Deposit method #{mid} added.")
    elif step == "s15_addm" and len(parts) >= 7:
        mid = pctx.withdrawals.create_method(parts[0], parts[1], parts[2], parts[3], float(parts[4]), float(parts[5]), float(parts[6]), admin_id=uid)
        await msg.reply_text(f"✅ Withdraw method #{mid} added.")
    elif step == "s16_set":
        val = parse_positive_float(txt)
        if val is not None:
            pctx.config.set_setting(d["key"], val, uid)
            await msg.reply_text("✅ Updated.")
    elif step == "s16_addbon" and len(parts) >= 5:
        bid = pctx.bonuses.create_bonus(parts[0], parts[1], parts[0], parts[1], float(parts[2]), int(parts[3]), int(parts[4]), admin_id=uid)
        await msg.reply_text(f"✅ Bonus #{bid} created.")
    elif step == "s16_lbadj" and len(parts) >= 4:
        ok_a, m_a = pctx.leaderboard.adjust_user_score(parts[0].lower(), int(parts[1]), int(parts[2]), parts[3], uid)
        await msg.reply_text(("✅ " if ok_a else "❌ ") + m_a)
    elif step == "s17_search":
        hits = pctx.users.search_users(txt, 10)
        rows_u = [[pctx.kb.ibtn(f"{u['full_name'][:18]} ({u['user_id']})", callback_data=f"adm:s17:u:{u['user_id']}", action_kind="primary")] for u in hits]
        await msg.reply_text(f"🔍 Found {len(hits)} user(s):", reply_markup=InlineKeyboardMarkup(rows_u) if rows_u else None)
    elif step in ("s17_cred", "s17_ded") and len(parts) >= 3:
        amt = parse_positive_float(parts[0])
        bucket = parts[1] if parts[1] in ("earned", "deposit") else "earned"
        if amt and amt > 0:
            is_cred = step == "s17_cred"
            ok_l, msg_l, txid, _ = pctx.ledger.apply_transaction(
                int(d["tuid"]), "manual_credit" if is_cred else "admin_deduct", amt,
                "credit" if is_cred else "debit", bucket, None, "admin_panel", "", uid, parts[2]
            )
            if ok_l:
                pctx.notifications.enqueue(int(d["tuid"]), f"💳 Admin {'credited' if is_cred else 'deducted'} <code>{format_money(amt)}</code> ({bucket}). Reason: {escape_html(parts[2])}")
            await msg.reply_text(("✅ " if ok_l else "❌ ") + f"{msg_l} {txid}")
    elif step == "s17_warn":
        ok_w, cnt_w, auto_b = pctx.users.issue_warning(int(d["tuid"]), uid, txt, txt)
        pctx.notifications.enqueue(int(d["tuid"]), f"⚠️ <b>Warning Strike ({cnt_w}):</b> {escape_html(txt)}")
        await msg.reply_text(f"⚠️ Warning issued (Strikes: {cnt_w}, Auto-Blocked: {auto_b})")
    elif step == "s17_warnall":
        all_u = pctx.db.query_all("SELECT user_id FROM users WHERE status='active'")
        for u in all_u:
            pctx.users.issue_warning(int(u["user_id"]), uid, txt, txt, strike_delta=0, is_broadcast=True)
            pctx.notifications.enqueue(int(u["user_id"]), f"⚠️ <b>Notice:</b> {escape_html(txt)}")
        await msg.reply_text(f"⚠️ Warning notice queued for {len(all_u)} active users.")
    elif step == "s18_tkt":
        ok_t, msg_t, t_row = pctx.tickets.reply_ticket(int(d["tid"]), uid, txt)
        if ok_t and t_row:
            pctx.notifications.enqueue(int(t_row["user_id"]), f"🎫 <b>Support Reply ({t_row['ticket_uid']}):</b>\n{escape_html(txt)}")
        await msg.reply_text(("✅ " if ok_t else "❌ ") + msg_t)
    elif step == "s20_addasst" and len(parts) >= 1 and parts[0].isdigit():
        target_aid = int(parts[0])
        full_nm = parts[1] if len(parts) > 1 else ""
        ok_a, m_a = pctx.permissions.add_or_update_assistant(uid, target_aid, full_nm)
        if ok_a:
            await send_assistant_approval_request(pctx, context.bot, target_aid, full_nm, uid)
        await msg.reply_text(("⏳ " if ok_a else "❌ ") + m_a + ("\n📢 Auto-Backup চ্যানেলে এবং মূল এডমিনের কাছে অনুমোদন রিকোয়েস্ট পাঠানো হয়েছে।" if ok_a else ""))
    elif step == "s20_passset":
        if not pctx.permissions.is_main_admin(uid):
            await msg.reply_text("⛔ শুধুমাত্র মূল এডমিন পাসওয়ার্ড পরিবর্তন করতে পারবেন।")
        elif len(txt) < 4:
            await msg.reply_text("❌ পাসওয়ার্ড কমপক্ষে ৪ অক্ষরের হতে হবে।")
        else:
            pctx.config.set_setting("admin_panel_password", txt, admin_id=uid, reason="set_admin_password")
            pctx.config.set_setting("admin_panel_password_enabled", True, admin_id=uid, reason="enable_admin_password")
            pctx.permissions.revoke_all_admin_sessions()
            await msg.reply_text(f"✅ এডমিন প্যানেল পাসওয়ার্ড সেট ও চালু করা হয়েছে!\n🔑 পাসওয়ার্ড: <code>{escape_html(txt)}</code>", parse_mode=ParseMode.HTML)
    elif step == "s14_med_name" and len(parts) >= 2:
        pctx.deposits.update_method(int(d["mid"]), {"name_bn": parts[0], "name_en": parts[1]}, uid)
        await msg.reply_text("✅ Deposit method name updated.")
    elif step == "s14_med_acc" and len(parts) >= 1:
        upd: Dict[str, Any] = {"account_number": parts[0]}
        if len(parts) > 1 and parts[1]:
            upd["account_holder_type"] = parts[1]
        if len(parts) > 2:
            upd["network_info"] = parts[2]
        pctx.deposits.update_method(int(d["mid"]), upd, uid)
        await msg.reply_text("✅ Deposit account/PayID updated.")
    elif step == "s14_med_limits" and len(parts) >= 2:
        mn, mx = parse_positive_float(parts[0]), parse_positive_float(parts[1])
        if mn is None or mx is None:
            await msg.reply_text("❌ Invalid min/max amounts.")
        else:
            upd_l: Dict[str, Any] = {"min_amount": mn, "max_amount": mx}
            if len(parts) > 2 and parse_positive_float(parts[2]) is not None:
                upd_l["bonus_percent"] = float(parse_positive_float(parts[2]) or 0.0)
            if len(parts) > 3 and parse_positive_float(parts[3]) is not None:
                upd_l["charge_percent"] = float(parse_positive_float(parts[3]) or 0.0)
            pctx.deposits.update_method(int(d["mid"]), upd_l, uid)
            await msg.reply_text("✅ Deposit limits & bonus updated.")
    elif step == "s14_med_instr" and len(parts) >= 1:
        pctx.deposits.update_method(int(d["mid"]), {"instruction_bn": parts[0], "instruction_en": parts[1] if len(parts) > 1 else parts[0]}, uid)
        await msg.reply_text("✅ Deposit instructions updated.")
    elif step == "s15_med_name" and len(parts) >= 2:
        pctx.withdrawals.update_method(int(d["mid"]), {"name_bn": parts[0], "name_en": parts[1]}, uid)
        await msg.reply_text("✅ Withdraw method name updated.")
    elif step == "s15_med_fee" and len(parts) >= 2:
        ftype = parts[0].lower() if parts[0].lower() in ("fixed", "percent") else "fixed"
        fval = parse_positive_float(parts[1])
        if fval is None:
            await msg.reply_text("❌ Invalid fee value.")
        else:
            pctx.withdrawals.update_method(int(d["mid"]), {"fee_type": ftype, "fee_value": fval}, uid)
            await msg.reply_text(f"✅ Withdraw fee updated ({ftype}: {fval}).")
    elif step == "s15_med_limits" and len(parts) >= 2:
        mn, mx = parse_positive_float(parts[0]), parse_positive_float(parts[1])
        if mn is None or mx is None:
            await msg.reply_text("❌ Invalid min/max amounts.")
        else:
            pctx.withdrawals.update_method(int(d["mid"]), {"min_amount": mn, "max_amount": mx}, uid)
            await msg.reply_text("✅ Withdraw limits updated.")
    elif step == "s15_med_regex" and len(parts) >= 1:
        upd_r: Dict[str, Any] = {"method_type": parts[0]}
        if len(parts) > 1:
            upd_r["wallet_regex"] = parts[1]
        pctx.withdrawals.update_method(int(d["mid"]), upd_r, uid)
        await msg.reply_text("✅ Withdraw wallet type & regex updated.")
    elif step == "s15_med_instr" and len(parts) >= 1:
        pctx.withdrawals.update_method(int(d["mid"]), {"instruction_bn": parts[0], "instruction_en": parts[1] if len(parts) > 1 else parts[0]}, uid)
        await msg.reply_text("✅ Withdraw instructions updated.")
    elif step == "sys_intc":
        hrs = parse_positive_int(txt)
        if hrs and hrs >= 1:
            pctx.config.set_setting("auto_backup_interval_hours", hrs, uid)
            await msg.reply_text(f"✅ Auto-Backup interval set to {hrs} hour(s).")
        else:
            await msg.reply_text("❌ দয়া করে ১ বা তার বেশি পূর্ণসংখ্যা লিখুন।")
    elif step == "sys_ch" and len(parts) >= 1 and parts[0]:
        chat_id_new = parts[0]
        join_lnk = parts[1] if len(parts) > 1 else ""
        ch = pctx.db.query_one("SELECT id FROM channels WHERE purpose='auto_backup' ORDER BY id ASC LIMIT 1")
        if ch:
            pctx.db.execute_write(
                "UPDATE channels SET chat_id=?, join_link=COALESCE(NULLIF(?,''), join_link), is_active=1, is_hidden=0 WHERE id=?",
                (chat_id_new, join_lnk, int(ch["id"])),
            )
        else:
            pctx.db.execute_write(
                "INSERT INTO channels (purpose, chat_id, title, join_link, is_active, is_hidden, sort_order, privacy_mode, join_required, created_at) VALUES ('auto_backup', ?, 'Auto-Backup Channel', ?, 1, 0, 1, 'admin_only', 0, ?)",
                (chat_id_new, join_lnk, now_utc_iso()),
            )
        await msg.reply_text(f"✅ Auto-Backup channel updated: {chat_id_new}")
    elif step == "sys_bklink":
        ch = pctx.db.query_one("SELECT id FROM channels WHERE purpose='auto_backup' ORDER BY id ASC LIMIT 1")
        if ch:
            pctx.db.execute_write("UPDATE channels SET join_link=? WHERE id=?", (txt, int(ch["id"])))
            await msg.reply_text("✅ Auto-Backup channel join link updated.")
        else:
            await msg.reply_text("⚠️ প্রথমে চ্যানেল ID সেট করুন।")


async def handle_all_messages(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pctx: PlatformContext = context.application.bot_data["pctx"]

    # Bridge 1: Private OTP Relay Channel/Group Messages
    if update.channel_post or (update.effective_chat and update.effective_chat.type in ("channel", "group", "supergroup")):
        post = update.channel_post or update.message
        if post and (post.text or post.caption) and pctx.config.get_bool("otp_relay_bridge_enabled", True):
            relay_chs = {str(r["chat_id"]).strip() for r in pctx.get_channels("otp_relay")}
            chat_id_str = str(post.chat_id)
            chat_un = f"@{post.chat.username}" if post.chat and post.chat.username else ""
            if chat_id_str in relay_chs or (chat_un and chat_un in relay_chs):
                ok_m, _, matched = pctx.otp.parse_relay_message_and_ingest(post.text or post.caption or "")
                if ok_m:
                    await deliver_otp_match_to_user_and_channel(pctx, context.bot, matched)
        return

    if update.effective_user is None or update.message is None:
        return
    uid = int(update.effective_user.id)
    text_in = (update.message.text or "").strip()

    # Check Reply Keyboard Admin button
    if pctx.permissions.is_any_admin(uid) and text_in in ("⚙️ এডমিন প্যানেল", "⚙️ Admin Panel"):
        await cmd_admin(update, context)
        return

    # Check active runtime_state flow
    st = pctx.runtime.get_state(uid)
    if st:
        if st["flow"] == "admin_auth" and st["step"] == "await_password":
            try:
                await update.message.delete()
            except Exception:
                pass
            expected_pw = pctx.config.get_str("admin_panel_password", "").strip()
            if expected_pw and hmac.compare_digest(text_in, expected_pw):
                pctx.permissions.unlock_admin_session(uid)
                pctx.runtime.clear_state(uid)
                await show_admin_dashboard(pctx, update, uid)
            else:
                tries = int(st["data"].get("tries", 0)) + 1
                if tries >= 5:
                    pctx.runtime.clear_state(uid)
                    await safe_send_message_to_chat(context.bot, uid, "❌ ৫ বার ভুল পাসওয়ার্ড দেওয়ায় বাতিল করা হয়েছে। পুনরায় চেষ্টা করতে /admin লিখুন।")
                else:
                    pctx.runtime.update_data(uid, {"tries": tries})
                    await safe_send_message_to_chat(context.bot, uid, f"❌ ভুল পাসওয়ার্ড! ({tries}/5) সঠিক পাসওয়ার্ড লিখুন অথবা /start দিয়ে বের হন।")
            return
        if st["flow"] == "admin" and pctx.permissions.is_any_admin(uid):
            if not await ensure_admin_panel_ready(pctx, update, uid):
                return
            await handle_admin_runtime_input(pctx, update, context, uid, st)
            return

        user_row = await pctx.gatekeep_user(update, context, module_key="general")
        if user_row is None:
            return
        if st["flow"] == "task":
            await handle_task_runtime_input(pctx, update, context, user_row, st)
            return
        if st["flow"] == "fs":
            await handle_fs_runtime_input(pctx, update, context, user_row, st)
            return
        if st["flow"] == "store":
            await handle_store_runtime_input(pctx, update, user_row, st)
            return
        if st["flow"] == "deposit":
            await handle_deposit_runtime_input(pctx, update, context, user_row, st)
            return
        if st["flow"] == "withdraw":
            await handle_withdraw_runtime_input(pctx, update, user_row, st)
            return
        if st["flow"] in ("ticket", "appeal", "warranty", "points_exchange"):
            await handle_misc_user_runtime_input(pctx, update, user_row, st)
            return

    # Reply Keyboard Menu Button Matcher (RULE 89)
    btn_row = pctx.kb.match_reply_button(text_in)
    if btn_row is not None:
        bkey = str(btn_row["button_key"])
        mod_map = {"u_tasks": "task", "u_file_submit": "fs", "u_store": "store", "u_otp": "otp", "u_deposit": "deposit", "u_withdraw": "withdraw", "u_bonus": "reward", "u_checkin": "reward"}
        user_row = await pctx.gatekeep_user(update, context, module_key=mod_map.get(bkey, "general"))
        if user_row is None:
            return
        if str(btn_row["action_type"]) == "custom" or int(btn_row["is_builtin"]) == 0:
            await handle_custom_dynamic_button(pctx, update, user_row, int(btn_row["id"]))
            return
        dispatch = {
            "u_tasks": lambda: show_tasks_list(pctx, update, user_row),
            "u_file_submit": lambda: show_fs_tasks_list(pctx, update, user_row),
            "u_store": lambda: show_store_categories(pctx, update, user_row),
            "u_otp": lambda: show_otp_countries(pctx, update, user_row),
            "u_deposit": lambda: show_deposit_methods(pctx, update, user_row),
            "u_withdraw": lambda: show_withdraw_methods(pctx, update, user_row),
            "u_profile": lambda: show_user_profile(pctx, update, user_row),
            "u_balance": lambda: show_user_balance(pctx, update, user_row, 0),
            "u_orders": lambda: show_my_orders_activity(pctx, update, user_row, "orders", 0),
            "u_referral": lambda: show_referral_dashboard(pctx, update, user_row),
            "u_task_lb": lambda: show_leaderboard_screen(pctx, update, user_row, "task"),
            "u_fs_lb": lambda: show_leaderboard_screen(pctx, update, user_row, "fs"),
            "u_bonus": lambda: show_bonuses_menu(pctx, update, user_row),
            "u_checkin": lambda: show_daily_checkin(pctx, update, user_row),
            "u_support": lambda: show_support_and_tickets(pctx, update, user_row),
            "u_rules": lambda: show_user_rules(pctx, update, user_row),
            "u_language": lambda: show_language_selector(pctx, update, user_row),
        }
        fn = dispatch.get(bkey)
        if fn:
            await fn()
# ==============================================================================
# AUTOMATION SCHEDULER (AUTO-REVIEW, TIMEOUTS, QUEUE, MIDNIGHT REPORT & BACKUP)
# ==============================================================================

class AutomationScheduler:
    """
    Runs background asyncio loops without blocking Telegram handlers:
    - Every 8s: Task & Deposit Auto-Approve / Auto-Reject + Notification Queue
    - Every 12s: OTP Provider API Polling & OTP Expiry Auto-Refund / Recycle
    - Every 60s: Task Allocation Timeout Auto-Release, Runtime Cleanup, Midnight Summary & Auto-Backup
    """

    def __init__(self, pctx: PlatformContext, bot: Bot) -> None:
        self.pctx = pctx
        self.bot = bot
        self._running = False
        self._tasks: List[asyncio.Task[Any]] = []
        self._last_auto_backup_ts: float = time.time()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._tasks = [
            asyncio.create_task(self._fast_loop(), name="sched_fast"),
            asyncio.create_task(self._otp_loop(), name="sched_otp"),
            asyncio.create_task(self._maintenance_loop(), name="sched_maint"),
        ]
        LOGGER.info("AutomationScheduler started (3 workers).")

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        LOGGER.info("AutomationScheduler stopped cleanly.")

    async def _fast_loop(self) -> None:
        while self._running:
            try:
                await self._process_due_task_auto_reviews()
                await self._process_due_deposit_auto_reviews()
                await self.pctx.notifications.process_queue(self.bot, batch_size=25)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                LOGGER.error("Scheduler fast loop error: %s", exc, exc_info=True)
            await asyncio.sleep(8.0)

    async def _otp_loop(self) -> None:
        while self._running:
            try:
                matched_list = await self.pctx.otp.poll_provider_api()
                for m in matched_list:
                    await deliver_otp_match_to_user_and_channel(self.pctx, self.bot, m)

                expired_refunds = self.pctx.otp.process_expired_sessions_and_recycles()
                for exp in expired_refunds:
                    u = self.pctx.users.get_user(exp["user_id"])
                    lang = str(u["language"] or "bn") if u else "bn"
                    card, _, en = self.pctx.studio.render_event_message(
                        "otp_timeout_refund",
                        lang=lang,
                        otp_uid=exp["otp_uid"],
                        refund_amount=format_money(exp["refund_amount"]),
                    )
                    txt = card if (en and card) else f"⏳ OTP {exp['otp_uid']} expired. Refunded {format_money(exp['refund_amount'])}."
                    self.pctx.notifications.enqueue(exp["user_id"], txt)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                LOGGER.error("Scheduler OTP loop error: %s", exc, exc_info=True)
            await asyncio.sleep(12.0)

    async def _maintenance_loop(self) -> None:
        while self._running:
            try:
                self.pctx.tasks.release_expired_allocations()
                self.pctx.runtime.cleanup_expired()
                await self._check_midnight_daily_summary()
                await self._check_scheduled_auto_backup()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                LOGGER.error("Scheduler maintenance loop error: %s", exc, exc_info=True)
            await asyncio.sleep(60.0)

    async def _process_due_task_auto_reviews(self) -> None:
        now_s = now_utc_iso()
        due_rows = self.pctx.db.query_all(
            """
            SELECT * FROM task_submissions
            WHERE status='pending' AND auto_action_at != '' AND auto_action_at <= ?
            ORDER BY id ASC LIMIT 20
            """,
            (now_s,),
        )
        for sub in due_rows:
            sid = int(sub["id"])
            mode = str(sub["auto_review_mode"])
            if mode == "auto_approve":
                if self.pctx.security.is_panic_frozen() or int(sub["is_suspicious"]) == 1:
                    continue
                ok, _, res = self.pctx.task_subs.approve_submission(sid, admin_id=0, is_auto=True)
                if ok:
                    if sub["review_channel_id"] and int(sub["review_message_id"]) > 0:
                        await safe_edit_channel_message(
                            self.bot,
                            sub["review_channel_id"],
                            int(sub["review_message_id"]),
                            f"📋 Task <code>{sub['sub_uid']}</code>\n\n✅ <b>AUTO-APPROVED</b>",
                            InlineKeyboardMarkup([[self.pctx.kb.ibtn("✅ Auto-Approved", callback_data="noop", action_kind="approve")]]),
                            is_media=False,
                        )
                    u = self.pctx.users.get_user(int(sub["user_id"]))
                    lang = str(u["language"] or "bn") if u else "bn"
                    card, _, en = self.pctx.studio.render_event_message(
                        "task_approved_msg",
                        lang=lang,
                        name=str(u["full_name"]) if u else "",
                        sub_uid=sub["sub_uid"],
                        reward=format_money(sub["reward_snapshot"]),
                        new_balance=format_money(res["new_balance"]),
                    )
                    self.pctx.notifications.enqueue(int(sub["user_id"]), card if (en and card) else f"✅ Task <code>{sub['sub_uid']}</code> Auto-Approved!")
            elif mode == "auto_reject":
                t_row = self.pctx.tasks.get_task(int(sub["task_id"]))
                reason = str(t_row["auto_reject_reason"]) if t_row else "Auto rejected after timeout"
                ok, _, _ = self.pctx.task_subs.reject_submission(sid, admin_id=0, reason=reason, is_auto=True)
                if ok:
                    if sub["review_channel_id"] and int(sub["review_message_id"]) > 0:
                        await safe_edit_channel_message(
                            self.bot,
                            sub["review_channel_id"],
                            int(sub["review_message_id"]),
                            f"📋 Task <code>{sub['sub_uid']}</code>\n\n❌ <b>AUTO-REJECTED</b>",
                            InlineKeyboardMarkup([[self.pctx.kb.ibtn("❌ Auto-Rejected", callback_data="noop", action_kind="reject")]]),
                            is_media=False,
                        )
                    u = self.pctx.users.get_user(int(sub["user_id"]))
                    lang = str(u["language"] or "bn") if u else "bn"
                    card, _, en = self.pctx.studio.render_event_message(
                        "task_rejected_msg",
                        lang=lang,
                        name=str(u["full_name"]) if u else "",
                        sub_uid=sub["sub_uid"],
                        reject_reason=reason,
                    )
                    self.pctx.notifications.enqueue(int(sub["user_id"]), card if (en and card) else f"❌ Task <code>{sub['sub_uid']}</code> Auto-Rejected.")

    async def _process_due_deposit_auto_reviews(self) -> None:
        now_s = now_utc_iso()
        due_rows = self.pctx.db.query_all(
            """
            SELECT * FROM deposits
            WHERE status='pending' AND auto_action_at != '' AND auto_action_at <= ?
            ORDER BY id ASC LIMIT 20
            """,
            (now_s,),
        )
        for dep in due_rows:
            did = int(dep["id"])
            mode = str(dep["auto_review_mode"])
            if mode == "auto_approve":
                if self.pctx.security.is_panic_frozen():
                    continue
                ok, _, res = self.pctx.deposits.approve_deposit(did, admin_id=0, is_auto=True)
                if ok:
                    if dep["channel_id"] and int(dep["channel_message_id"]) > 0:
                        await safe_edit_channel_message(
                            self.bot,
                            dep["channel_id"],
                            int(dep["channel_message_id"]),
                            f"💳 Deposit <code>{dep['deposit_uid']}</code>\n\n✅ <b>AUTO-APPROVED</b>",
                            InlineKeyboardMarkup([[self.pctx.kb.ibtn("✅ Auto-Approved", callback_data="noop", action_kind="approve")]]),
                            is_media=bool(dep["is_media_msg"]),
                        )
                    u = self.pctx.users.get_user(int(dep["user_id"]))
                    lang = str(u["language"] or "bn") if u else "bn"
                    card, _, en = self.pctx.studio.render_event_message(
                        "deposit_approved_success",
                        lang=lang,
                        name=str(u["full_name"]) if u else "",
                        deposit_uid=dep["deposit_uid"],
                        net_credit=format_money(dep["net_credit"]),
                        new_deposit_balance=format_money(res["new_deposit_balance"]),
                    )
                    self.pctx.notifications.enqueue(int(dep["user_id"]), card if (en and card) else f"✅ Deposit <code>{dep['deposit_uid']}</code> Auto-Approved!")
            elif mode == "auto_reject":
                reason = "Auto rejected after review timeout"
                ok, _, _ = self.pctx.deposits.reject_deposit(did, admin_id=0, reason=reason, is_auto=True)
                if ok:
                    if dep["channel_id"] and int(dep["channel_message_id"]) > 0:
                        await safe_edit_channel_message(
                            self.bot,
                            dep["channel_id"],
                            int(dep["channel_message_id"]),
                            f"💳 Deposit <code>{dep['deposit_uid']}</code>\n\n❌ <b>AUTO-REJECTED</b>",
                            InlineKeyboardMarkup([[self.pctx.kb.ibtn("❌ Auto-Rejected", callback_data="noop", action_kind="reject")]]),
                            is_media=bool(dep["is_media_msg"]),
                        )
                    self.pctx.notifications.enqueue(int(dep["user_id"]), f"🔴 Deposit <code>{dep['deposit_uid']}</code> Auto-Rejected.")

    async def _check_midnight_daily_summary(self) -> None:
        if not self.pctx.config.get_bool("daily_summary_enabled", True):
            return
        dhaka_now = now_dhaka()
        if dhaka_now.hour != 0:
            return
        today_s = dhaka_now.strftime("%Y-%m-%d")
        done = self.pctx.db.query_one(
            "SELECT id FROM scheduled_jobs_log WHERE job_name='daily_summary' AND run_date_dhaka=?",
            (today_s,),
        )
        if done is not None:
            return
        summary_txt = self.pctx.reports.build_daily_summary_text("bn")
        msg, err = await safe_send_message_to_chat(self.bot, DEFAULT_MAIN_ADMIN_ID, summary_txt)
        with self.pctx.db.atomic(immediate=True) as conn:
            conn.execute(
                "INSERT INTO scheduled_jobs_log (job_name, run_date_dhaka, status, details, created_at) VALUES ('daily_summary', ?, ?, ?, ?)",
                (today_s, "sent" if msg else "failed", err[:200], now_utc_iso()),
            )

    async def _check_scheduled_auto_backup(self) -> None:
        if not self.pctx.config.get_bool("auto_backup_enabled", True):
            return
        interval_hrs = max(1, self.pctx.config.get_int("auto_backup_interval_hours", 24))
        last_ts = self.pctx.config.get_float("last_auto_backup_ts", 0.0)
        now_ts = time.time()
        if last_ts <= 0:
            self.pctx.config.set_setting("last_auto_backup_ts", str(int(now_ts)), admin_id=0, reason="init_backup_timer")
            return
        if (now_ts - last_ts) < interval_hrs * 3600:
            return
        await execute_full_auto_backup_delivery(self.pctx, self.bot, admin_id=0)


# ==============================================================================
# TELEGRAM APPLICATION BUILDER, ERROR HANDLER & GRACEFUL SHUTDOWN
# ==============================================================================

async def global_error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err_msg = SECRET_FILTER.mask_text(str(context.error or "Unknown error"))
    LOGGER.error("Unhandled Telegram update error: %s", err_msg, exc_info=context.error)


def build_application(token: str, pctx: PlatformContext) -> Application:
    async def _post_init(app: Application) -> None:
        pctx._bot_ref = app.bot  # type: ignore[attr-defined]
        try:
            me = await app.bot.get_me()
            BOT_IDENTITY.set_identity(me.id, me.username, me.first_name)
            LOGGER.info("Bot connected as @%s (%s)", me.username, me.first_name)
        except Exception as exc:
            LOGGER.warning("get_me failed during post_init: %s", exc)

        try:
            await app.bot.set_my_commands([
                BotCommand("start", "Start / মেইন মেনু"),
                BotCommand("menu", "Main Menu / মেনু"),
                BotCommand("admin", "Admin Panel (Admins Only)"),
            ])
        except Exception as exc:
            LOGGER.warning("set_my_commands warning: %s", exc)

        if pctx.config.get_bool("otp_webhook_bridge_enabled", False):
            ok_wh, msg_wh = pctx.webhook.start()
            LOGGER.info("OTP Webhook bridge: %s (%s)", ok_wh, msg_wh)

        sched = AutomationScheduler(pctx, app.bot)
        app.bot_data["scheduler"] = sched
        sched.start()

    async def _post_shutdown(app: Application) -> None:
        sched: Optional[AutomationScheduler] = app.bot_data.get("scheduler")
        if sched is not None:
            await sched.stop()
        pctx.webhook.stop()
        pctx.db.close_thread_conn()
        LOGGER.info("Graceful shutdown completed.")

    app = (
        ApplicationBuilder()
        .token(token)
        .connect_timeout(30.0)
        .read_timeout(30.0)
        .write_timeout(30.0)
        .pool_timeout(30.0)
        .get_updates_connect_timeout(30.0)
        .get_updates_read_timeout(30.0)
        .post_init(_post_init)
        .post_shutdown(_post_shutdown)
        .build()
    )
    app.bot_data["pctx"] = pctx
    pctx._bot_ref = app.bot  # type: ignore[attr-defined]

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("menu", cmd_menu))
    app.add_handler(CommandHandler("admin", cmd_admin))
    app.add_handler(CallbackQueryHandler(handle_all_callbacks))
    app.add_handler(MessageHandler(filters.ALL & (~filters.COMMAND), handle_all_messages))
    app.add_error_handler(global_error_handler)
    return app


# ==============================================================================
# COMPREHENSIVE CLI SELF-TEST SUITE (--self-test)
# ==============================================================================

async def run_comprehensive_self_test() -> int:
    print("Running comprehensive platform self-test...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_db = Path(tmp_dir) / "selftest.db"
        pctx = PlatformContext(db_path=test_db)
        passed = 0
        failed = 0

        def _check(name: str, cond: bool, detail: str = "") -> None:
            nonlocal passed, failed
            if cond:
                passed += 1
                print(f"  [PASS] {name}")
            else:
                failed += 1
                print(f"  [FAIL] {name} -> {detail}")

        # 1. Schema, Migration, Seeding & Dynamic Bot Name
        _check("DB WAL & Schema", pctx.migration_info["current_version"] == DB_SCHEMA_VERSION)
        _check("Dynamic Bot Name (no hardcoded brand)", pctx.config.get_bot_name("en") == "Bot")

        # 2. Message Studio 25x30 = 750 rows (1,500 BN+EN variants)
        ms_cnt = pctx.db.query_one("SELECT COUNT(*) AS c FROM message_studio_variants")
        _check("Message Studio 750 variants (1500 BN/EN)", bool(ms_cnt and int(ms_cnt["c"]) >= 750))
        rendered, _, en = pctx.studio.render_event_message("start_welcome", "bn", name="<Test>", user_id="1", balance="৳0")
        _check("Message Studio HTML Escaping", en and "&lt;Test&gt;" in rendered and "<blockquote>" in rendered)

        # 3. Dual Keyboard & Anti-Lockout + Button Colors
        pctx.kb.toggle_keyboard_switch("reply_keyboard_enabled", 1)
        ok_lock, _, _ = pctx.kb.toggle_keyboard_switch("inline_keyboard_enabled", 1)
        _check("Dual Keyboard Anti-Lockout Guard", not ok_lock)
        pctx.kb.toggle_keyboard_switch("reply_keyboard_enabled", 1)
        btn = BUTTON_ADAPTER.make_inline_button("Test", callback_data="t:1", style="primary")
        _check("PTB Button Color Adapter", btn.text == "Test")

        # 4. User Registration, Atomic Ledger, Hold/Release & Reconciliation
        u1, is_n1 = pctx.users.ensure_user_registered(10001, "Tester One", "tester1")
        u1_dup, is_n2 = pctx.users.ensure_user_registered(10001, "Tester One", "tester1")
        _check("User Unique Registration", is_n1 and not is_n2)
        ok1, _, tx1, _ = pctx.ledger.apply_transaction(10001, "manual_credit", 100.0, "credit", "earned", "idem_test_1")
        ok2, _, tx2, _ = pctx.ledger.apply_transaction(10001, "manual_credit", 100.0, "credit", "earned", "idem_test_1")
        _check("Ledger Idempotency Guard", ok1 and ok2 and tx1 == tx2 and float(pctx.users.get_user(10001)["earned_balance"]) == 100.0)

        # 5. Task + TOTP Dup Block + Cookie Verification (Reorder-Proof) + Export
        tid = pctx.tasks.create_task("Test Task", "Test Task", 10.0, source_enabled=True, field_combo_mode="user_pass_full", require_totp=True, totp_dup_block=True, require_cookie=True, cookie_dup_block=True, cookie_required_keys="c_user,xs", admin_id=1)
        csv_src = b"Username,Full Name,Password\nuser_a,Alpha Name,pass123\n"
        ok_src, _, _ = pctx.tasks.upload_source_file(tid, csv_src, "src.csv", 1)
        _check("Case-Insensitive Task Source Upload", ok_src)
        ok_al, _, alloc = pctx.tasks.allocate_source_for_user(tid, pctx.users.get_user(10001))  # type: ignore[arg-type]
        _check("Task Atomic Single Allocation + Full Name/User", ok_al and alloc is not None and alloc["fields"].get("Full Name") == "Alpha Name")

        ok_t1, _, t_info = pctx.task_subs.validate_totp_submission(pctx.tasks.get_task(tid), "JBSWY3DPEHPK3PXP")  # type: ignore[arg-type]
        ok_c1, _, c_info = pctx.task_subs.validate_cookie_submission(pctx.tasks.get_task(tid), "c_user=111; xs=secret_val;")  # type: ignore[arg-type]
        _check("TOTP & Cookie Validation", ok_t1 and ok_c1 and len(t_info["totp_6digit_code"]) == 6)

        ok_sub, _, sub_res = pctx.task_subs.submit_task(tid, pctx.users.get_user(10001), alloc["allocation_id"], alloc["source_record_id"], alloc["fields"], [{"label": "Note", "value": "Done"}], t_info, c_info)  # type: ignore[index,arg-type]
        _check("Task Submission Commit", ok_sub)

        ok_t_dup, _, _ = pctx.task_subs.validate_totp_submission(pctx.tasks.get_task(tid), "JBSWY3DPEHPK3PXP")  # type: ignore[arg-type]
        ok_c_dup, _, _ = pctx.task_subs.validate_cookie_submission(pctx.tasks.get_task(tid), '[{"name":"xs","value":"secret_val"},{"name":"c_user","value":"111"}]')  # type: ignore[arg-type]
        _check("TOTP Dup Block & Reorder-Proof Cookie Dup Block", (not ok_t_dup) and (not ok_c_dup))

        ok_exp, _, exp_path, exp_ids = pctx.task_subs.export_task_master_file(tid, "xlsx", False, 1, True)
        _check("Task Master XLSX Export (TOTP+Cookie cols)", ok_exp and exp_path is not None and exp_path.exists() and len(exp_ids) == 1)

        # 6. File Submit + Batch Review + Leaderboard Approved-Only + Manual Score
        fs_id = pctx.fs.create_fs_task("FS Test", "FS Test", 5.0, min_columns=2, smart_skip_invalid=True, admin_id=1)
        fs_bytes = b"a1@mail.com|p1\ninvalid_1col\na2@mail.com|p2\na3@mail.com|p3\n"
        ok_fp, _, fs_prev = pctx.fs.parse_and_preview_fs_submission(fs_id, 10001, fs_bytes, "test.txt")
        _check("FS Multi-Column & Smart Skip", ok_fp and fs_prev["valid_count"] == 3 and fs_prev["skipped_invalid"] == 1)
        _, _, fs_sub = pctx.fs.commit_fs_submission(pctx.users.get_user(10001), fs_prev, fs_bytes)  # type: ignore[arg-type]
        recs = pctx.fs.list_submission_records(fs_sub["id"], "pending", 10)
        ok_rev, _, rev_res = pctx.fs.review_fs_records(fs_sub["id"], [int(recs[0]["id"]), int(recs[1]["id"])], "approve", 1)
        _check("FS Batch Review & Atomic Reward", ok_rev and rev_res["approved"] == 2 and rev_res["total_reward"] == 10.0)
        pctx.leaderboard.adjust_user_score("fs", 10001, 5, "Bonus work", 1)
        _, lb_rows = pctx.leaderboard.get_rankings("fs")
        _check("FS Approved-Only LB + Manual Score", len(lb_rows) == 1 and lb_rows[0]["total_score"] == 7)

        # 7. Store, OTP & Deposit/Withdraw
        cat_id = pctx.store.create_category("Test Cat", "Test Cat")
        prod_id = pctx.store.create_product(cat_id, "Item", "Item", 10.0, warranty_hours=24)
        pctx.store.upload_product_stock(prod_id, b"line1\nline2\n", "stk.txt", 1)
        ok_ord, _, ord_res = pctx.store.checkout_order(prod_id, pctx.users.get_user(10001), 1)  # type: ignore[arg-type]
        _check("Store Concurrent Checkout & Stock", ok_ord and ord_res["remaining_stock"] == 1)

        cid = pctx.otp.create_country("USA", "USA", "🇺🇸", "+1", 1, 2.0, 300)
        pctx.otp.upload_country_numbers(cid, b"+15551234567\n", "nums.txt", 1)
        ok_oa, _, o_res = pctx.otp.allocate_numbers_for_user(cid, 10001)
        ok_om, _, matched = pctx.otp.ingest_sms("+15551234567", "Your verification code is 482910", "relay_channel")
        _check("OTP Allocation & Smart Regex Ingestion", ok_oa and ok_om and matched["otp_code"] == "482910")

        ok_w, _, wd_res = pctx.withdrawals.request_withdrawal(1, pctx.users.get_user(10001), "01712345678", 50.0)  # type: ignore[arg-type]
        _check("Withdrawal Wallet Validation & Hold", ok_w)
        pctx.withdrawals.mark_paid_withdrawal(wd_res["id"], 1)

        # 8. Reconciliation & Backup
        recon = pctx.ledger.run_reconciliation(1)
        _check("Ledger Reconciliation (0 mismatches)", recon["mismatches_found"] == 0)
        ok_bk, _, zpath, _ = pctx.backup.create_zip_backup("selftest", 1)
        _check("Zip Backup Creation", ok_bk and zpath is not None and zpath.exists())

        pctx.db.close_thread_conn()
        print(f"\nSelf-Test Completed: {passed} Passed, {failed} Failed.")
        return 0 if failed == 0 else 1


def main() -> None:
    if "--self-test" in sys.argv:
        code = asyncio.run(run_comprehensive_self_test())
        sys.exit(code)

    token = load_bot_token()
    pctx = PlatformContext(db_path=DB_PATH)
    app = build_application(token, pctx)

    def _sig_handler(signum: int, frame: Any) -> None:
        LOGGER.info("Received signal %s, initiating shutdown...", signum)
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _sig_handler)
        except Exception:
            pass

    LOGGER.info("Starting Bot Engine v%s...", BOT_ENGINE_VERSION)
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=False)


if __name__ == "__main__":
    main()


























































