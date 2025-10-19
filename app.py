import sys
import os
import ctypes
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)

    icon_path = os.path.join("img", "apple.ico")
    app.setWindowIcon(QIcon(icon_path))

    if sys.platform.startswith("win"):
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "com.juliangrtz.ios-re-lab")
            ctypes.windll.user32.LoadImageW(0, icon_path, 1, 0, 0, 0x10)
        except Exception as e:
            print(f"Warning: Could not set taskbar icon: {e}")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
