from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QTextCharFormat, QColor, QFont, QSyntaxHighlighter


class Arm64Highlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#c678dd"))  # purple
        keyword_format.setFontWeight(QFont.Weight.Bold)
        # https://github.com/compnerd/arm64asm-vim/blob/main/syntax/arm64asm.vim
        keywords = open("ui/syntax_highlighters/arm64.txt", "r").read().splitlines()
        for kw in keywords:
            self.rules.append((QRegularExpression(rf"\b{kw}\b"), keyword_format))

        reg_format = QTextCharFormat()
        reg_format.setForeground(QColor("#61afef"))  # blue
        self.rules.append((QRegularExpression(r"\b(w|x)\d{1,2}\b"), reg_format))

        imm_format = QTextCharFormat()
        imm_format.setForeground(QColor("#d19a66"))  # orange
        self.rules.append((QRegularExpression(r"#-?\d+"), imm_format))

        addr_format = QTextCharFormat()
        addr_format.setForeground(QColor("#98c379"))  # green
        self.rules.append((QRegularExpression(r"0x[0-9a-fA-F]+"), addr_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#5c6370"))  # gray
        self.rules.append((QRegularExpression(r";.*$"), comment_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                match = it.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), fmt)
