from PySide6.QtWidgets import QMainWindow, QTabWidget, QApplication, QMenu
from PySide6.QtCore import Qt, QPoint


class DetachableTabWidget(QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMovable(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_tab_menu)

    def _show_tab_menu(self, pos):
        index = self.tabBar().tabAt(pos)
        if index < 0:
            return
        menu = QMenu()
        detach_action = menu.addAction("Detach Tab")
        action = menu.exec(self.mapToGlobal(pos))
        if action == detach_action:
            self._detach_tab(index)

    def _detach_tab(self, index):
        widget = self.widget(index)
        text = self.tabText(index)
        icon = self.tabIcon(index)

        # Remove from current tab widget
        self.removeTab(index)

        # Create new window for the tab
        window = QMainWindow()
        window.setWindowTitle(text)
        window.setWindowIcon(icon)
        window.setCentralWidget(widget)
        window.resize(800, 600)
        window.show()
