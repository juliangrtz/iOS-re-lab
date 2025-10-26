import logging
import time
from typing import Optional

from PySide6.QtCore import QMetaObject, Qt, Q_ARG
from PySide6.QtWidgets import QTextEdit
from ansi2html import Ansi2HTMLConverter
from colorama import Fore, Style

LOGGING_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_FILENAME = f"logs/iOS-re-lab_{time.strftime('%Y_%m_%d.log')}"

logging.basicConfig(
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S',
    format=LOGGING_FORMAT,
    filename=LOG_FILENAME,
)

COLOR_MAPPINGS = {
    logging.DEBUG: Fore.CYAN,
    logging.INFO: Fore.GREEN,
    logging.WARNING: Fore.YELLOW,
    logging.ERROR: Fore.RED,
}


class ColorFormatter(logging.Formatter):
    def format(self, record):
        color = COLOR_MAPPINGS.get(record.levelno, "")
        base = super().format(record)
        return f"{color}{base}{Style.RESET_ALL}"


class _GuiLogger:

    def __init__(self):
        self.logger = logging.getLogger("iOS-re-lab")
        self.logger.setLevel(logging.DEBUG)
        self._text_widget: Optional[QTextEdit] = None
        self._ansi_converter = Ansi2HTMLConverter(inline=True)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(ColorFormatter(LOGGING_FORMAT))
        self.logger.addHandler(console_handler)

        if not any(isinstance(h, logging.FileHandler) for h in self.logger.handlers):
            file_handler = logging.FileHandler(LOG_FILENAME, encoding="utf-8", mode="a")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
            self.logger.addHandler(file_handler)

    def set_text_widget(self, widget: QTextEdit):
        self._text_widget = widget

    def _append_to_text_widget(self, text: str, level: int):
        if not self._text_widget or not text.strip():
            return

        color = COLOR_MAPPINGS.get(level, "")
        html_text = self._ansi_converter.convert(f"{color}{text}{Style.RESET_ALL}", full=False)

        # todo smelly

        QMetaObject.invokeMethod(
            self._text_widget,
            "append",
            Qt.QueuedConnection,
            Q_ARG(str, html_text)
        )

        QMetaObject.invokeMethod(
            self._text_widget,
            "ensureCursorVisible",
            Qt.QueuedConnection
        )

    def debug(self, msg: str, *args):
        self.logger.debug(msg, *args)
        self._append_to_text_widget(msg.format(*args), logging.DEBUG)

    def info(self, msg: str, *args):
        self.logger.info(msg, *args)
        self._append_to_text_widget(msg.format(*args), logging.INFO)

    def warning(self, msg: str, *args):
        self.logger.warning(msg, *args)
        self._append_to_text_widget(msg.format(*args), logging.WARNING)

    def error(self, msg: str, *args):
        self.logger.error(msg, *args)
        self._append_to_text_widget(msg.format(*args), logging.ERROR)


_gui_logger_instance: Optional[_GuiLogger] = None


def init(widget: Optional[QTextEdit] = None) -> _GuiLogger:
    global _gui_logger_instance
    if _gui_logger_instance is None:
        _gui_logger_instance = _GuiLogger()
    if widget:
        _gui_logger_instance.set_text_widget(widget)
    return _gui_logger_instance


def debug(msg: str, *args): init().debug(msg, *args)


def info(msg: str, *args): init().info(msg, *args)


def warn(msg: str, *args): init().warning(msg, *args)


def error(msg: str, *args): init().error(msg, *args)
