from PySide6.QtCore import QThreadPool
from PySide6.QtGui import QShortcut, QKeySequence, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel,
    QFileDialog, QHBoxLayout, QMessageBox, QLineEdit, QPlainTextEdit
)

from core.concurrency.worker import Worker
from core.disasm.capstone_disasm import CapstoneDisassembler
from core.macho.macho import is_macho_file
from ui.syntax_highlighters.arm64_highlighter import Arm64Highlighter


class DisassemblyTab(QWidget):
    def __init__(self):
        super().__init__()
        self.qvBoxLayout = QVBoxLayout(self)

        header_layout = QHBoxLayout()
        self.label = QLabel("Disassembly")
        self.open_button = QPushButton("📂 Open Binary")
        self.open_button.clicked.connect(self._open_file)
        header_layout.addWidget(self.label)
        header_layout.addStretch()
        header_layout.addWidget(self.open_button)

        search_layout = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 Search (Ctrl+F)")
        self.search_box.returnPressed.connect(self._on_search)

        self.jump_box = QLineEdit()
        self.jump_box.setPlaceholderText("🏷 Jump to address (G)")
        self.jump_box.returnPressed.connect(self._on_jump)

        search_layout.addWidget(self.search_box)
        search_layout.addWidget(self.jump_box)

        self.disasm_view = QPlainTextEdit()
        self.disasm_view.setReadOnly(True)
        self.disasm_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.disasm_view.setUndoRedoEnabled(False)

        font = QFont("Consolas")
        font.setStyleHint(QFont.Monospace)
        self.disasm_view.setFont(font)

        self.highlighter = Arm64Highlighter(self.disasm_view.document())

        self.disasm_button = QPushButton("Disassemble")
        self.disasm_button.setMinimumHeight(30)
        self.disasm_button.setStyleSheet("font-weight: bold")
        self.disasm_button.clicked.connect(self._on_scan_clicked)
        self.disasm_button.setEnabled(False)

        self.qvBoxLayout.addLayout(header_layout)
        self.qvBoxLayout.addLayout(search_layout)
        self.qvBoxLayout.addWidget(self.disasm_button)
        self.qvBoxLayout.addWidget(self.disasm_view)

        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._focus_search)
        QShortcut(QKeySequence("Ctrl+G"), self, activated=self._focus_jump)
        QShortcut(QKeySequence("G"), self, activated=self._focus_jump)

        self.setAcceptDrops(True)
        self.file_path = None

    def _focus_search(self):
        self.search_box.setFocus()
        self.search_box.selectAll()

    def _focus_jump(self):
        self.jump_box.setFocus()
        self.jump_box.selectAll()

    def _toggle_button_states(self, on):
        self.disasm_button.setEnabled(on)
        self.open_button.setEnabled(on)

    # todo remove code duplicate -> unify file loading
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if any(url.toLocalFile().endswith((".macho", "")) for url in urls):
                event.acceptProposedAction()
            else:
                event.ignore()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            file_path = event.mimeData().urls()[0].toLocalFile()
            if file_path and is_macho_file(file_path):
                self._handle_dropped_file(file_path)
                event.acceptProposedAction()

    def _handle_dropped_file(self, file_path: str):
        self.file_path = file_path
        self._start_disassembly()

    def _open_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Select Mach-O File", "", "Mach-O Files (*)"
        )
        if file and is_macho_file(file):
            self.file_path = file
            self.disasm_button.setEnabled(True)
            self.label.setText(f"Disassembly — {file.split('/')[-1]}")

    def _on_scan_clicked(self):
        if not self.file_path:
            return
        self._start_disassembly()

    def _start_disassembly(self):
        if not self.file_path:
            return

        self._toggle_button_states(False)
        self.disasm_view.clear()

        disassembler = CapstoneDisassembler(self.file_path)
        worker = Worker(disassembler.disassemble)
        worker.signals.result.connect(self._on_disassembly_finished)
        worker.signals.error.connect(self._on_disassembly_error)
        worker.signals.finished.connect(lambda: self._toggle_button_states(True))
        QThreadPool.globalInstance().start(worker)

    def _on_disassembly_finished(self, text: str):
        self.disasm_view.setPlainText(text)

    def _on_disassembly_error(self, err_tuple):
        exctype, value, tb_str = err_tuple
        self.disasm_view.setPlainText(f"[ERROR]\n{value}\n\n{tb_str}")

    def _on_search(self):
        term = self.search_box.text().strip()
        if not term:
            return
        cursor = self.disasm_view.textCursor()
        found = self.disasm_view.find(term)
        if not found:
            cursor.movePosition(cursor.MoveOperation.Start)
            if not self.disasm_view.find(term):
                QMessageBox.information(self, "Search", f"'{term}' not found.")

    def _on_jump(self):
        addr_text = self.jump_box.text().strip()
        cursor = self.disasm_view.document().find(addr_text)
        if cursor.isNull():
            QMessageBox.information(self, "Jump", f"Address {addr_text} not found!")
            return

        self.disasm_view.setTextCursor(cursor)
        self.disasm_view.ensureCursorVisible()
