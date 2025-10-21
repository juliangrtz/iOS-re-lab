import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QAction, QGuiApplication
from PySide6.QtWidgets import (
    QMainWindow, QDockWidget, QMessageBox, QWidget
)
from PySide6.QtWidgets import QTextEdit

from core.constants import VERSION
from core.io.emitting_stream import EmittingStream
from ui.tabs.frida_tab import FridaTab
from ui.tabs.scanner_tab import ScannerTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"iOS reverse engineering laboratory v{VERSION}")
        self.setWindowIcon(QIcon("img/apple.ico"))

        screen_geom = QGuiApplication.primaryScreen().availableGeometry()
        width = screen_geom.width()
        height = screen_geom.height()
        self.resize(width, height)
        self.setWindowState(Qt.WindowState.WindowMaximized)

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
            area=Qt.DockWidgetArea.LeftDockWidgetArea,
            width=int(self.width() / 2),
        )
        self.docks["Scanner"] = self._add_dock_tab(
            "Scanner",
            ScannerTab(),
            area=Qt.DockWidgetArea.RightDockWidgetArea,
            width=int(self.width() / 2),
        )
        self.docks["Log"] = self._add_dock_tab(
            "Log",
            self._create_output_widget(),
            area=Qt.DockWidgetArea.BottomDockWidgetArea,
            height=400,
        )

    def _add_dock_tab(
            self,
            name: str,
            widget: QWidget,
            area: Qt.DockWidgetArea,
            width: int = 0,
            height: int = 0
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
        sys.stderr = EmittingStream(text_edit, err=True)

        return text_edit

    def write_output(self, text: str):
        if "Log" in self.docks:
            self.docks["Log"].widget().append(text)
