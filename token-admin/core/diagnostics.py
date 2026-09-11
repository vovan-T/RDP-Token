import logging
import os
import platform
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


LOGGER_NAME = "rdp_token"


def log_path() -> Path:
    base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
    if base:
        return Path(base) / "RDP-Token" / "logs" / "manager.log"
    return Path.home() / ".rdp-token" / "logs" / "manager.log"


def configure_logging() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        return logger
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(threadName)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False
    logger.info(
        "Application start python=%s os=%s release=%s",
        platform.python_version(), platform.system(), platform.release(),
    )
    return logger


def logger() -> logging.Logger:
    return configure_logging()


def log_unhandled_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger().critical("Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))
