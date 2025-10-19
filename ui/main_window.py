from PySide6.QtWidgets import (
    QMainWindow, QDockWidget, QToolBar, QFileDialog, QMessageBox, QWidget
)
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import Qt

from ui.tabs.scanner_tab import ScannerTab
from ui.tabs.frida_tab import FridaTab
# from ui.tabs.patcher_tab import PatcherTab  # future dockable tab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("iOS reverse engineering laboratory")
        self.resize(1200, 800)
        self.setWindowIcon(QIcon("img/apple.ico"))

        # Central widget (optional, empty placeholder)
        central = QWidget()
        self.setCentralWidget(central)

        # Initialize toolbar
        self._init_toolbar()

        # Initialize dockable tabs
        self.docks = {}
        self._load_dock_tabs()

    def _init_toolbar(self):
        toolbar = QToolBar("Main")
        self.addToolBar(toolbar)

        # Open Mach-O binary
        open_action = QAction(QIcon.fromTheme(
            "document-open"), "Open Decrypted Binary", self)
        open_action.triggered.connect(self._open_file)
        toolbar.addAction(open_action)

        # Future toolbar actions can be added here
        # e.g., refresh Frida devices, patch syscalls, etc.

    def _load_dock_tabs(self):
        self.docks["Frida"] = self._add_dock_tab(
            "Frida", FridaTab(), int(self.width() / 2), area=Qt.LeftDockWidgetArea)
        self.docks["Scanner"] = self._add_dock_tab(
            "Scanner", ScannerTab(), int(self.width() / 2), area=Qt.RightDockWidgetArea)

    def _add_dock_tab(self, name: str, widget: QWidget, width: int, area=Qt.RightDockWidgetArea) -> QDockWidget:
        dock = QDockWidget(name, self)
        dock.setWidget(widget)
        dock.setMinimumWidth(width)
        dock.setFloating(False)
        dock.setFeatures(
            QDockWidget.DockWidgetClosable |
            QDockWidget.DockWidgetMovable |
            QDockWidget.DockWidgetFloatable
        )
        self.addDockWidget(area, dock)
        return dock

    def _open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open decrypted Mach-O File", "", "Mach-O Files (*)"
        )
        if path:
            # send the file to whichever dock currently has focus
            focused_widget = self.focusWidget()
            for dock_name, dock in self.docks.items():
                tab_widget = dock.widget()
                if hasattr(tab_widget, "load_file") and (focused_widget is None or tab_widget.isAncestorOf(focused_widget)):
                    tab_widget.load_file(path)
                    return

            # fallback: just send to Scanner tab
            if "Scanner" in self.docks:
                self.docks["Scanner"].widget().load_file(path)
            else:
                QMessageBox.information(
                    self, "No handler", "No tab can handle files yet.")
