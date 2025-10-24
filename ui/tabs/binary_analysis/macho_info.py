import lief
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel, QTreeWidget, QVBoxLayout, QTreeWidgetItem

from core import logger


class MachOInfoTab(QWidget):
    def __init__(self):
        super().__init__()
        self.qvBoxLayout = QVBoxLayout(self)

        header_layout = QHBoxLayout()
        self.label = QLabel("ℹ️ Mach-O Information\nPowered by LIEF.")
        header_layout.addWidget(self.label)
        header_layout.addStretch()

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Value"])
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(0, 220)
        self.tree.setAlternatingRowColors(True)

        self.qvBoxLayout.addLayout(header_layout)
        self.qvBoxLayout.addWidget(self.tree)

    def load_macho(self, file_path: str):
        try:
            binary = lief.parse(file_path)
        except Exception as e:
            self._display_error(f"Error parsing file: {e}")
            return

        if not isinstance(binary, lief.MachO.Binary):
            self._display_error("Not a valid Mach-O binary.")
            return

        logger.debug(f"File analysis for {file_path} started.")
        self.tree.clear()
        self._fill_tree(binary)

    def _fill_tree(self, binary: lief.MachO.Binary):
        ### HEADER ###
        header = binary.header

        header_entries = [
            ("Bitness", "64-bit" if header.is_64bit else "32-bit"),
            ("CPU type", header.cpu_type.name),
            ("CPU subtype", hex(header.cpu_subtype)),
            ("File type", header.file_type.name),
        ]

        for key, value in header_entries:
            self.tree.addTopLevelItem(QTreeWidgetItem([key, value]))

        flags_item = QTreeWidgetItem(["Flags", ""])  # ["Flags", hex(header.flags)]
        self.tree.addTopLevelItem(flags_item)

        flag_enum = lief.MachO.Header.FLAGS
        set_flags = [flag for flag in flag_enum if header.has(flag)]
        if set_flags:
            for flag in set_flags:
                child = QTreeWidgetItem([flag.name, hex(flag.__int__())])
                flags_item.addChild(child)

        else:
            flags_item.addChild(QTreeWidgetItem(["None set", ""]))

        flags_item.setExpanded(True)
        logger.debug(
            f"Mach-O header parsed successfully. {binary.header}"
        )

        ### SECTIONS ###
        sections_item = QTreeWidgetItem(["Sections", ""])
        self.tree.addTopLevelItem(sections_item)

        sections = binary.sections
        logger.debug(f"LIEF detected {len(sections)} sections:")
        for section in binary.sections:
            logger.debug(f"{section}")
            section_item = QTreeWidgetItem([section.name, ""])

            properties = [
                ("Address", hex(section.virtual_address)),
                ("Offset", hex(section.offset)),
                ("Align", str(section.alignment)),
                ("Type", section.type.name),
                ("Reloc Offset", str(section.relocation_offset)),
                ("Reloc Count", str(section.numberof_relocations)),
                ("Reserved1", str(section.reserved1)),
                ("Reserved2", str(section.reserved2)),
                ("Reserved3", str(section.reserved3)),
            ]

            for key, val in properties:
                section_item.addChild(QTreeWidgetItem([key, val]))
            sections_item.addChild(section_item)

            flags_parent = QTreeWidgetItem(["Flags", ""])
            section_item.addChild(flags_parent)
            set_flags = [
                flag for flag in lief.MachO.Section.FLAGS if section.has(flag)
            ]
            if set_flags:
                for flag in set_flags:
                    if flag == lief.MachO.Section.FLAGS.PURE_INSTRUCTIONS:
                        section_item.setForeground(0, QBrush(QColor.fromRgb(255, 0, 0)))
                        section_item.setText(0, section_item.text(0) + " (executable)")

                    flags_parent.addChild(QTreeWidgetItem([flag.name, hex(flag.__int__())]))
            else:
                flags_parent.addChild(QTreeWidgetItem(["None", ""]))
            sections_item.setExpanded(True)

    def _display_error(self, error: str):
        self.tree.clear()
        self.tree.addTopLevelItem(QTreeWidgetItem(["Error", str(error)]))
        logger.error(f"Couldn't obtain Mach-O info: {error}")
