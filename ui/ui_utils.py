from PySide6.QtWidgets import QTreeWidgetItem
from PySide6.QtGui import Qt, QIcon, QPixmap, QImage, QPainter, QColor, QFont
import base64


def _pixmap_from_bytes(data: bytes) -> QPixmap | None:
    if not data:
        return None
    pix = QPixmap()
    ok = pix.loadFromData(data)
    return pix if ok else None


def _placeholder_icon(text: str = "", size: int = 64) -> QIcon:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(QColor("#2f3542"))
    p = QPainter(img)
    p.setPen(QColor("white"))
    f = QFont("Sans", int(size / 3))
    f.setBold(True)
    p.setFont(f)
    rect = img.rect()
    p.drawText(rect, int(Qt.AlignCenter | Qt.TextWordWrap),
               text[:2].upper() if text else "?")
    p.end()
    return QIcon(QPixmap.fromImage(img))
