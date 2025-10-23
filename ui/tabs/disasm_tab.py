from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel,
    QFileDialog, QHBoxLayout, QTextEdit
)

from core.concurrency.worker import Worker
from core.disasm.capstone_disasm import CapstoneDisassembler
from core.macho.macho import is_macho_file


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

        self.disasm_view = QTextEdit()
        self.disasm_view.setReadOnly(True)
        # TODO add basic disassembler features: syntax highlighting, jump, search etc.

        self.disasm_button = QPushButton("Disassemble")
        self.disasm_button.setMinimumHeight(30)
        self.disasm_button.setStyleSheet("font-weight: bold")
        self.disasm_button.clicked.connect(self._on_scan_clicked)
        self.disasm_button.setEnabled(False)

        self.qvBoxLayout.addLayout(header_layout)
        self.qvBoxLayout.addWidget(self.disasm_button)
        self.qvBoxLayout.addWidget(self.disasm_view)

        self.setAcceptDrops(True)

        self.file_path = None

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
