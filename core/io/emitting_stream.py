import time

from PyQt5.QtWidgets import QTextEdit
from PySide6.QtGui import QTextCursor
from ansi2html import Ansi2HTMLConverter

from core.utils import create_path_if_not_exists


class EmittingStream:
    ansiConverter = Ansi2HTMLConverter(inline=True)

    def __init__(self, text_widget: QTextEdit, err=False):
        self.text_widget = text_widget
        self.err = err

        create_path_if_not_exists("logs")
        today = time.strftime("%Y-%m-%d")
        self.log = open(f"logs/iOS-re-lab_{today}.log", mode="a", encoding="utf-8")

    def write(self, text):
        if text.strip():
            html_text = self.ansiConverter.convert(text, full=False)
            if self.err:
                html_text = f"<span style='color: #ff0000'>{html_text}</span><br>"
            self.text_widget.append(html_text)

            cursor = self.text_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.text_widget.setTextCursor(cursor)
            self.text_widget.ensureCursorVisible()
            #self.log.write(text)

    def flush(self):
        pass
