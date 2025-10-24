from PySide6.QtCore import QThreadPool
from PySide6.QtGui import QShortcut, QKeySequence, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel,
    QHBoxLayout, QMessageBox, QLineEdit, QPlainTextEdit
)

from core.concurrency.worker import Worker
from core.disasm.capstone_disasm import CapstoneDisassembler
from ui.syntax_highlighters.arm64_highlighter import Arm64Highlighter


class DisassemblyTab(QWidget):
    def __init__(self):
        super().__init__()
        self.qvBoxLayout = QVBoxLayout(self)

        header_layout = QHBoxLayout()
        self.label = QLabel("🧩 Disassembly\nPowered by Capstone.")
        header_layout.addWidget(self.label)
        header_layout.addStretch()

        search_layout = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 Search (Ctrl+F)")
        self.search_box.returnPressed.connect(self._on_search)

        self.jump_box = QLineEdit()
        self.jump_box.setPlaceholderText("🏷 Jump to address (G)")
        self.jump_box.returnPressed.connect(self._on_jump)

        search_layout.addWidget(self.search_box)
        search_layout.addWidget(self.jump_box)

        # QPlainTextEdit is utterly horrible for large amounts of disassembly.
        # TODO Look into alternatives.
        self.disasm_view = QPlainTextEdit()
        self.disasm_view.setReadOnly(True)
        self.disasm_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.disasm_view.setUndoRedoEnabled(False)

        font = QFont("Consolas")
        font.setStyleHint(QFont.Monospace)
        self.disasm_view.setFont(font)

        self.highlighter = Arm64Highlighter(self.disasm_view.document())

        self.qvBoxLayout.addLayout(header_layout)
        self.qvBoxLayout.addLayout(search_layout)
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

    def start_disassembly(self, file_path):
        if not file_path:
            return

        self.disasm_view.clear()

        disassembler = CapstoneDisassembler(file_path)
        worker = Worker(disassembler.disassemble)
        worker.signals.result.connect(self._on_disassembly_finished)
        worker.signals.error.connect(self._on_disassembly_error)
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
