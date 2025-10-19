from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QToolBar, QFileDialog, QMessageBox
)
from PySide6.QtGui import QIcon, QAction
from ui.tabs.scanner_tab import ScannerTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("iOS reverse engineering laboratory")
        self.resize(1200, 800)
        self.setWindowIcon(QIcon("img/apple.ico"))
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._init_toolbar()
        self._load_tabs()

    def _init_toolbar(self):
        toolbar = QToolBar("Main")
        self.addToolBar(toolbar)

        open_action = QAction(QIcon.fromTheme(
            "document-open"), "Open Decrypted Binary", self)
        open_action.triggered.connect(self._open_file)
        toolbar.addAction(open_action)

    def _open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open decrypted Mach-O File", "", "Mach-O Files (*)")
        if path:
            current_tab = self.tabs.currentWidget()
            if hasattr(current_tab, "load_file"):
                current_tab.load_file(path)
            else:
                QMessageBox.information(
                    self, "No handler", "This tab cannot open files yet.")

    def _load_tabs(self):
        # currently hard-coded; later we can make this dynamic/plugin-based
        self.tabs.addTab(ScannerTab(), "Scanner")
        # self.tabs.addTab(DebuggerTab(), "Debugger")
        # self.tabs.addTab(PatcherTab(), "Syscall Patcher")
        # ...
