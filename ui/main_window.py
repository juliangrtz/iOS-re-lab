from PySide6.QtWidgets import (
    QMainWindow, QDockWidget, QMessageBox, QWidget
)
from PySide6.QtGui import QIcon, QAction, QGuiApplication
from PySide6.QtCore import Qt

from core.constants import VERSION
from ui.tabs.scanner_tab import ScannerTab
from ui.tabs.frida_tab import FridaTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("iOS reverse engineering laboratory")
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
            "Frida", FridaTab(), int(self.width() / 2), area=Qt.DockWidgetArea.LeftDockWidgetArea)
        self.docks["Scanner"] = self._add_dock_tab(
            "Scanner", ScannerTab(), int(self.width() / 2), area=Qt.DockWidgetArea.RightDockWidgetArea)

    def _add_dock_tab(self, name: str, widget: QWidget, width: int, area=Qt.DockWidgetArea.RightDockWidgetArea) -> QDockWidget:
        dock = QDockWidget(name, self)
        dock.setWidget(widget)
        dock.setMinimumWidth(width)
        dock.setFloating(False)
        dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetClosable |
            QDockWidget.DockWidgetFeature.DockWidgetMovable |
            QDockWidget.DockWidgetFeature.DockWidgetFloatable
        )
        self.addDockWidget(area, dock)
        return dock
