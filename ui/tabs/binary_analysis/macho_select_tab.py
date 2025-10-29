from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QCheckBox, QFrame, QGroupBox, QPushButton,
    QFileDialog, QHBoxLayout, QLineEdit, QSpinBox, QFormLayout
)

from core import logger
from core.analysis_config import ANALYSIS_CONFIG
from core.macho.macho import is_macho_file


class MachOSelectTab(QWidget):
    def __init__(self, scanner_tab=None, disasm_tab=None, info_tab=None):
        super().__init__()
        self.setAcceptDrops(True)
        self.disasm_tab = disasm_tab
        self.scanner_tab = scanner_tab
        self.info_tab = info_tab

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)

        self.drag_drop_frame = QFrame()
        self.drag_drop_frame.setFrameShape(QFrame.StyledPanel)
        self.drag_drop_frame.setStyleSheet(
            "QFrame {border: 2px dashed gray; border-radius: 8px;}"
            "QFrame:hover {border-color: #0078d7;}"
        )
        drag_layout = QVBoxLayout(self.drag_drop_frame)
        drag_layout.setContentsMargins(10, 20, 10, 20)

        self.file_label = QLabel("No file selected")
        self.file_label.setAlignment(Qt.AlignCenter)
        self.file_label.setStyleSheet("font-weight: bold; font-size: 15px; color: #555;")
        drag_layout.addWidget(self.file_label)

        main_layout.addWidget(self.drag_drop_frame)

        scan_group = QGroupBox("🔍 Scan Settings")
        scan_layout = QVBoxLayout(scan_group)

        self.scan_checkbox = QCheckBox("Enable binary scan for suspicious artifacts")
        self.scan_checkbox.setChecked(True)
        scan_layout.addWidget(self.scan_checkbox)

        self.yara_checkbox = QCheckBox("Run YARA rules during scan to detect protectors")
        self.yara_checkbox.setChecked(True)
        scan_layout.addWidget(self.yara_checkbox)

        self.verbose_checkbox = QCheckBox("Verbose logging")
        self.verbose_checkbox.setChecked(False)
        scan_layout.addWidget(self.verbose_checkbox)

        syscall_layout = QHBoxLayout()
        syscall_label = QLabel("Syscall map path:")
        self.syscall_path_edit = QLineEdit("data/syscalls.json")
        syscall_layout.addWidget(syscall_label)
        syscall_layout.addWidget(self.syscall_path_edit)
        scan_layout.addLayout(syscall_layout)

        main_layout.addWidget(scan_group)

        disasm_group = QGroupBox("🧩 Disassembly Settings")
        disasm_layout = QFormLayout(disasm_group)

        self.disasm_checkbox = QCheckBox("Enable disassembly")
        self.disasm_checkbox.setChecked(True)
        disasm_layout.addRow(self.disasm_checkbox)

        self.disas_only_text_checkbox = QCheckBox("Only disassemble __TEXT section")
        self.disas_only_text_checkbox.setChecked(True)
        disasm_layout.addRow(self.disas_only_text_checkbox)

        self.start_addr_edit = QLineEdit()
        self.start_addr_edit.setPlaceholderText("Optional, defaults to 0x0. Must be hexadecimal.")
        disasm_layout.addRow("Start address:", self.start_addr_edit)

        self.end_addr_edit = QLineEdit()
        self.end_addr_edit.setPlaceholderText("Optional, defaults to file size. Must be hexadecimal.")
        disasm_layout.addRow("End address:", self.end_addr_edit)

        self.chunk_size_spin = QSpinBox()
        self.chunk_size_spin.setRange(0x100, 0x10000)
        self.chunk_size_spin.setSingleStep(0x100)
        self.chunk_size_spin.setValue(0x2000)
        disasm_layout.addRow("Chunk size (bytes):", self.chunk_size_spin)

        main_layout.addWidget(disasm_group)

        self.start_btn = QPushButton("Start Analysis")
        self.start_btn.setMinimumHeight(40)
        self.start_btn.setStyleSheet("font-weight: bold; font-size: 20px;")
        self.start_btn.setEnabled(False)
        self.start_btn.clicked.connect(self._on_start)
        main_layout.addWidget(self.start_btn)

        for cb in [
            self.scan_checkbox, self.yara_checkbox, self.verbose_checkbox,
            self.disasm_checkbox, self.disas_only_text_checkbox
        ]:
            cb.stateChanged.connect(self._update_config)
        self.syscall_path_edit.textChanged.connect(self._update_config)
        self.start_addr_edit.textChanged.connect(self._update_config)
        self.end_addr_edit.textChanged.connect(self._update_config)
        self.chunk_size_spin.valueChanged.connect(self._update_config)
        self.disas_only_text_checkbox.stateChanged.connect(self._toggle_range_inputs)
        self._toggle_range_inputs()

    def _toggle_range_inputs(self):
        only_text = self.disas_only_text_checkbox.isChecked()
        self.start_addr_edit.setDisabled(only_text)
        self.end_addr_edit.setDisabled(only_text)

    def mousePressEvent(self, event):
        if self.drag_drop_frame.geometry().contains(event.position().toPoint()):
            self._open_file()
        super().mousePressEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            file_path = event.mimeData().urls()[0].toLocalFile()
            if file_path and is_macho_file(file_path):
                self.set_file(file_path)
                event.acceptProposedAction()

    def _open_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Select Mach-O File", "", "Mach-O Files (*)"
        )
        if file and is_macho_file(file):
            self.set_file(file)

    def set_file(self, file_path: str):
        ANALYSIS_CONFIG.file_path = file_path
        self.file_label.setText(f"Selected File: {file_path.split('/')[-1]}")
        self._update_config()
        self.start_btn.setEnabled(True)

    def _update_config(self):
        opts = ANALYSIS_CONFIG.options
        opts.scan = self.scan_checkbox.isChecked()
        opts.yara = self.yara_checkbox.isChecked()
        opts.verbose = self.verbose_checkbox.isChecked()
        opts.syscall_map = self.syscall_path_edit.text()
        opts.disasm = self.disasm_checkbox.isChecked()
        opts.disasm_only_text = self.disas_only_text_checkbox.isChecked()
        opts.start_addr = self.start_addr_edit.text() or None
        opts.end_addr = self.end_addr_edit.text() or None
        opts.chunk_size = self.chunk_size_spin.value()

    def reset_config(self):
        self.__init__()

    def _on_start(self):
        file_path = ANALYSIS_CONFIG.file_path
        if not file_path:
            logger.warn("No Mach-O file selected!")
            return

        self.info_tab.load_macho(file_path)

        opts = ANALYSIS_CONFIG.options

        if opts.get("disasm") and self.disasm_tab:
            self.disasm_tab.start_disassembly(
                file_path,
                opts.get("disasm_only_text"),
                start_addr=opts.get("start_addr"),
                end_addr=opts.get("end_addr"),
                chunk_size=opts.get("chunk_size")
            )

        if opts.get("scan") and self.scanner_tab:
            self.scanner_tab.run_scan(
                file_path,
                syscall_map_path=opts.get("syscall_map"),
                verbose=opts.get("verbose"),
                run_yara=opts.get("yara")
            )
