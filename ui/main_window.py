import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QAction, QGuiApplication, QTextCursor
from PySide6.QtWidgets import (
    QMainWindow, QDockWidget, QMessageBox, QWidget
)
from PySide6.QtWidgets import QTextEdit
from ansi2html import Ansi2HTMLConverter

from core.constants import VERSION
from ui.tabs.frida_tab import FridaTab
from ui.tabs.scanner_tab import ScannerTab


class EmittingStream:
    ansiConverter = Ansi2HTMLConverter(inline=True)

    def __init__(self, text_widget: QTextEdit):
        self.text_widget = text_widget

    def write(self, text):
        if text.strip():
            html_text = self.ansiConverter.convert(text, full=False)
            self.text_widget.append(html_text)

            cursor = self.text_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.text_widget.setTextCursor(cursor)
            self.text_widget.ensureCursorVisible()

    def flush(self):
        pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"iOS reverse engineering laboratory v{VERSION}")
        self.setWindowIcon(QIcon("img/apple.ico"))

        screen = QGuiApplication.primaryScreen().availableGeometry()
        self.resize(screen.width() - 50, screen.height() - 50)
        self.move(screen.topLeft())

        central = QWidget()
        self.setCentralWidget(central)

        self._init_menubar()
        self.docks = {}
        self._load_dock_tabs()

    def _init_menubar(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        about_action = menubar.addAction("About")
        about_action.triggered.connect(self._show_about)

    def _show_about(self):
        qMessageBox = QMessageBox()
        qMessageBox.setTextFormat(Qt.TextFormat.RichText)
        qMessageBox.setWindowTitle("About iOS-re-lab")
        qMessageBox.setText(
            (
                f"iOS Reverse Engineering Laboratory v{VERSION}<br>"
                "<a href=\"https://github.com/juliangrtz/ios-re-lab\">https://github.com/juliangrtz/ios-re-lab</a><br>"
                "A toolkit for instrumenting iOS apps and analyzing decrypted Mach-O binaries. Work in progress.<br>"
            )
        )
        qMessageBox.setStandardButtons(QMessageBox.StandardButton.Close)
        qMessageBox.exec()

    def _load_dock_tabs(self):
        self.docks["Frida"] = self._add_dock_tab(
            "Frida",
            FridaTab(),
            width=int(self.width() / 2),
            area=Qt.DockWidgetArea.LeftDockWidgetArea
        )
        self.docks["Scanner"] = self._add_dock_tab(
            "Scanner",
            ScannerTab(),
            width=int(self.width() / 2),
            area=Qt.DockWidgetArea.RightDockWidgetArea
        )
        self.docks["Log"] = self._add_dock_tab(
            "Log",
            self._create_output_widget(),
            height=400,
            area=Qt.DockWidgetArea.BottomDockWidgetArea
        )

    def _add_dock_tab(
            self,
            name: str,
            widget: QWidget,
            width: int = 0,
            height: int = 0,
            area=Qt.DockWidgetArea.RightDockWidgetArea
    ) -> QDockWidget:
        dock = QDockWidget(name, self)
        dock.setWidget(widget)
        dock.setMinimumWidth(width)
        dock.setMinimumHeight(height)
        dock.setFloating(False)
        dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetClosable |
            QDockWidget.DockWidgetFeature.DockWidgetMovable |
            QDockWidget.DockWidgetFeature.DockWidgetFloatable
        )
        self.addDockWidget(area, dock)
        return dock

    def _create_output_widget(self) -> QTextEdit:
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.acceptRichText()
        text_edit.setStyleSheet(
            "background-color: black; font-family: monospace;"
        )

        sys.stdout = EmittingStream(text_edit)
        sys.stderr = EmittingStream(text_edit)

        return text_edit

    def write_output(self, text: str):
        if "Log" in self.docks:
            self.docks["Log"].widget().append(text)
