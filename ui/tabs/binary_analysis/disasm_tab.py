import os
import tempfile

from PySide6.QtCore import QThreadPool, QTimer, Qt
from PySide6.QtGui import QShortcut, QKeySequence, QFont, QAction, QCursor, QColor, QTextFormat, QTextCursor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout,
    QMessageBox, QLineEdit, QPlainTextEdit, QMenu, QStyle, QFileDialog, QTextEdit
)

from core import logger
from core.concurrency.worker import Worker
from core.disasm.capstone_disasm import CapstoneDisassembler
from ui.syntax_highlighters.arm64_highlighter import Arm64Highlighter
from ui.tabs.binary_analysis.macho_info import MachOInfoTab


class DisassemblyTab(QWidget):
    def __init__(self, info_tab: MachOInfoTab):
        super().__init__()
        self.info_tab = info_tab
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

        self.disasm_view = QPlainTextEdit()
        self.disasm_view.setReadOnly(True)
        self.disasm_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.disasm_view.setUndoRedoEnabled(False)
        self.disasm_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.disasm_view.customContextMenuRequested.connect(self.context_menu)

        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
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
        self.tmp_disasm_path = None
        self.loaded_lines = 0
        self.lines_per_chunk = 2000

        self.disasm_view.verticalScrollBar().valueChanged.connect(self._on_scroll)
        self.marked_lines = set()

    def context_menu(self):
        if self.disasm_view.document().isEmpty():
            return

        menu = QMenu(self)
        export_action = QAction("Export to file")
        export_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        export_action.triggered.connect(self._export_to_file)

        mark_action = QAction("Mark")
        mark_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TitleBarCloseButton))
        mark_action.triggered.connect(self._mark_location)

        menu.addAction(export_action)
        menu.addAction(mark_action)

        menu.exec_(QCursor.pos())

    def _export_to_file(self):
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Export disassembly")
        file_dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        file_dialog.setViewMode(QFileDialog.ViewMode.Detail)
        file_dialog.setNameFilter("Assembly files (*.asm);;All files (*)")

        if file_dialog.exec():
            selected_file = file_dialog.selectedFiles()[0]
            try:
                with open(selected_file, "w") as f:
                    f.writelines(self.disasm_view.toPlainText())
                    logger.info(f"Disassembly saved to {selected_file}.")
            except Exception as e:
                logger.error(f"Failed to save to {selected_file}: {e}")

    def _mark_location(self):
        cursor = self.disasm_view.textCursor()
        current_line = cursor.blockNumber()

        if current_line in self.marked_lines:
            self.marked_lines.remove(current_line)
        else:
            self.marked_lines.add(current_line)

        self._update_marked_lines()

    def _update_marked_lines(self):
        extra_selections = []

        for line_num in self.marked_lines:
            selection = QTextEdit.ExtraSelection()
            line_color = QColor(255, 255, 150, 100)
            selection.format.setBackground(line_color)
            selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)

            cursor = self.disasm_view.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.MoveAnchor, line_num)
            selection.cursor = cursor

            extra_selections.append(selection)

        self.disasm_view.setExtraSelections(extra_selections)

    def _focus_search(self):
        self.search_box.setFocus()
        self.search_box.selectAll()

    def _focus_jump(self):
        self.jump_box.setFocus()
        self.jump_box.selectAll()

    def start_disassembly(
            self,
            file_path,
            only_text_section,
            start_addr=None,
            end_addr=None,
            chunk_size=0x2000
    ):
        if not file_path:
            return

        fd, tmp_path = tempfile.mkstemp(prefix="disasm_", suffix=".txt")
        os.close(fd)
        self.tmp_disasm_path = tmp_path
        self.disasm_view.setPlainText("[INFO] Disassembling, please wait...")
        self.loaded_lines = 0

        disassembler = CapstoneDisassembler(
            file_path,
            only_text_section,
            self.info_tab.get_macho(),
            chunk_size=chunk_size
        )
        disassembler.set_range(start_addr, end_addr)

        worker = Worker(self._run_disassembly_to_file, disassembler)
        worker.signals.result.connect(self._on_disassembly_finished)
        worker.signals.error.connect(self._on_disassembly_error)
        QThreadPool.globalInstance().start(worker)

    def _run_disassembly_to_file(self, disassembler: CapstoneDisassembler):
        text = disassembler.disassemble()
        with open(self.tmp_disasm_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(text)
        return self.tmp_disasm_path

    def _on_disassembly_finished(self, tmp_path: str):
        self.disasm_view.clear()
        self._load_next_chunk()

    def _load_next_chunk(self):
        if not self.tmp_disasm_path or not os.path.exists(self.tmp_disasm_path):
            return

        with open(self.tmp_disasm_path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(self.loaded_lines):
                f.readline()

            lines = []
            for _ in range(self.lines_per_chunk):
                line = f.readline()
                if not line:
                    break
                lines.append(line.rstrip())

        if lines:
            self.disasm_view.appendPlainText("\n".join(lines))
            self.loaded_lines += len(lines)

    def _on_scroll(self, value):
        scroll_bar = self.disasm_view.verticalScrollBar()
        if scroll_bar.maximum() - value < 50:
            QTimer.singleShot(0, self._load_next_chunk)

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
