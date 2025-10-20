import json
import os
from typing import Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QTreeWidget, QTreeWidgetItem,
    QHBoxLayout, QMessageBox, QInputDialog, QLineEdit, QFileDialog
)
from frida.core import Session

from core import terminal
from core.frida.frida_integration import FridaManager, FridaError

COMPILED_SVC_TRACER = False


class FridaTab(QWidget):
    def __init__(self):
        super().__init__()
        self.frida = FridaManager()
        self.current_device_id = None
        self.selected_app_identifier = None
        self.compiled_svc_tracer = False

        self.qvBoxLayout = QVBoxLayout(self)
        self.label = QLabel(
            f"🧪 Frida (v{self.frida.get_frida_version()})\nClick on a device to enumerate its applications.")
        header_layout = QHBoxLayout()
        header_layout.addWidget(self.label)
        header_layout.addStretch()

        self.refresh_devices_btn = QPushButton("Refresh Devices")
        self.refresh_devices_btn.clicked.connect(self.refresh_devices)
        header_layout.addWidget(self.refresh_devices_btn)

        self.qvBoxLayout.addLayout(header_layout)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Type", "Info"])
        self.tree.setColumnCount(2)
        self.tree.header().setStretchLastSection(True)
        self.tree.itemClicked.connect(self._on_item_clicked)

        btn_layout = QHBoxLayout()
        self.spawn_btn = QPushButton("Spawn and inject script")
        self.spawn_btn.setEnabled(False)
        self.spawn_btn.clicked.connect(self._on_spawn_clicked)

        self.attach_btn = QPushButton("Attach and inject script")
        self.attach_btn.setEnabled(False)
        self.attach_btn.clicked.connect(self._on_attach_clicked)

        self.trace_svc_btn = QPushButton("Spawn and trace system calls")
        self.trace_svc_btn.setEnabled(False)
        self.trace_svc_btn.clicked.connect(self._on_trace_svc_clicked)

        btn_layout.addWidget(self.spawn_btn)
        btn_layout.addWidget(self.attach_btn)
        btn_layout.addWidget(self.trace_svc_btn)

        self.qvBoxLayout.addWidget(self.tree)
        self.qvBoxLayout.addLayout(btn_layout)

        self.refresh_devices()

    def clear(self):
        self.tree.clear()
        self.current_device_id = None
        self.selected_app_identifier = None
        self.spawn_btn.setEnabled(False)
        self.attach_btn.setEnabled(False)
        self.trace_svc_btn.setEnabled(False)

    def refresh_devices(self):
        self.clear()
        try:
            devices = self.frida.list_ios_devices()
            if not devices:
                terminal.error(
                    "No Frida devices found (ensure frida-server is running on device).")
                return

            for d in devices:
                id_ = d.get("id") or d.get("name")
                name = d.get("name") or id_
                type_ = d.get("type")
                dev_item = QTreeWidgetItem([f"{type_}", f"{name} (id={id_})"])
                dev_item.setData(0, Qt.ItemDataRole.UserRole, {
                    "type": "device", "device_id": id_})

                self.tree.addTopLevelItem(dev_item)

        except FridaError as e:
            QMessageBox.critical(self, "Frida error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Unexpected error", str(e))

    def _on_item_clicked(self, item, _):
        meta = item.data(0, Qt.ItemDataRole.UserRole)
        if meta and meta.get("type") == "device":
            device_id = meta.get("device_id")
            self._populate_apps_for_device(item, device_id)
            return

        if meta and meta.get("type") == "app":
            self.selected_app_identifier = meta.get("identifier")
            self.spawn_btn.setEnabled(True)
            self.attach_btn.setEnabled(True)
            self.trace_svc_btn.setEnabled(True)
            terminal.info(f"Selected app: {self.selected_app_identifier}")
            return

        self.selected_app_identifier = None
        self.spawn_btn.setEnabled(False)
        self.attach_btn.setEnabled(False)

    def _populate_apps_for_device(self, device_item: QTreeWidgetItem, device_id: str):
        for i in reversed(range(device_item.childCount())):
            device_item.removeChild(device_item.child(i))

        try:
            apps = self.frida.list_applications(device_id)
            if not apps:
                child = QTreeWidgetItem(["(no apps found)"])
                device_item.addChild(child)
                return

            for a in apps:
                identifier = a.get("identifier") or a.get("name") or str(a)
                name = a.get("name") or identifier
                pid = a.get("pid")
                info = f"{name}"
                if pid:
                    info += f" (pid={pid})"
                app_item = QTreeWidgetItem([identifier, info])
                app_item.setData(0, Qt.ItemDataRole.UserRole, {
                    "type": "app", "device_id": device_id, "identifier": identifier, "pid": pid})
                device_item.addChild(app_item)

            device_item.setExpanded(True)
            self.tree.setColumnWidth(0, 250)
            self.current_device_id = device_id

        except FridaError as e:
            QMessageBox.critical(self, "Frida error", str(e))

    def _spawn_selected_app(self) -> Tuple[Session, int]:
        if not self.selected_app_identifier or not self.current_device_id:
            QMessageBox.information(
                self, "Select app", "Please select an app to spawn.")
            raise

        res = self.frida.spawn_app(
            self.current_device_id, self.selected_app_identifier)
        pid = res.get("pid") if isinstance(res, dict) else None
        terminal.info(
            f"Spawned {self.selected_app_identifier} -> pid={pid}")
        if not pid:
            raise FridaError(
                f"Could not get pid for {self.selected_app_identifier}")
        try:
            session = self.frida.attach(self.current_device_id, pid)
            terminal.info(f"Attached to spawned pid {pid}: {session}")
            return session, pid
        except Exception as e:
            terminal.warn(f"Failed to attach to spawned pid {pid}: {e}")
            try:
                self.frida.resume(self.current_device_id, pid)
                terminal.info(f"Resumed pid {pid} (after failed attach)")
            except Exception as e2:
                terminal.warn(f"Could not resume pid {pid}: {e2}")
            raise

    def _on_spawn_clicked(self):
        try:
            session, pid = self._spawn_selected_app()
            try:
                self._inject_script(session, self._read_script_file())
            except Exception as e:
                terminal.warn(f"Script injection failed for pid {pid}: {e}")

            try:
                self.frida.resume(self.current_device_id, pid)  # type: ignore
                terminal.info(f"Resumed pid {pid}")
            except Exception as e:
                terminal.warn(f"Could not resume pid {pid}: {e}")

        except Exception as e:
            QMessageBox.critical(self, "Spawn error", str(e))

    def _on_attach_clicked(self):
        pid_text, ok = QInputDialog.getText(
            self, "Attach", "Enter PID to attach (or leave blank to attach to selected app pid):",
            QLineEdit.EchoMode.Normal, "")
        if not ok:
            return
        pid = None
        if pid_text and pid_text.strip():
            try:
                pid = int(pid_text.strip())
            except ValueError:
                QMessageBox.warning(self, "Invalid PID", "PID must be numeric")
                return

        sel = self.tree.currentItem()
        meta = sel.data(0, Qt.ItemDataRole.UserRole) if sel else None
        if pid is None and meta and meta.get("type") == "app":
            pid = meta.get("pid")
        if pid is None:
            QMessageBox.information(
                self, "PID required", "No PID provided and selected app has no pid.")
            return

        try:
            if not self.current_device_id:
                raise FridaError("Current device ID not set")
            session = self.frida.attach(self.current_device_id, pid)
            try:
                self._inject_script(session, self._read_script_file())
            except Exception as e:
                terminal.warn(f"Script injection failed after attach: {e}")
        except Exception as e:
            QMessageBox.critical(self, "Attach error", str(e))

    def _read_script_file(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select script", "", "JavaScript file (*.js)")
            if not file_path:
                raise
            with open(file_path, mode="r", encoding="utf-8") as script:
                with open("core/frida/common.js", mode="r", encoding="utf-8") as common:
                    return script.read() + "\n" + common.read()
        except Exception as e:
            QMessageBox.critical(self, "File error",
                                 f"Could not read file: {e}")
            raise

    def _inject_script(self, session, script):
        if session is None:
            QMessageBox.warning(self, "No session",
                                "No Frida session available to inject the script.")
            return

        try:
            script = session.create_script(script)

            def on_message(message, _):
                try:
                    if isinstance(message, dict):
                        mtype = message.get("type")
                        payload = message.get("payload")
                        if mtype == "send":
                            if isinstance(payload, (dict, list)):
                                terminal.info(f"[frida] {json.dumps(payload)}")
                            else:
                                terminal.info(f"[frida] {payload}")
                        elif mtype == "error":
                            terminal.error(f"[frida error] {payload}")
                        else:
                            terminal.info(f"[frida msg] {message}")
                    else:
                        terminal.info(f"[frida] {message}")
                except Exception as ex:
                    terminal.warn(f"Error in on_message handler: {ex}")

            script.on("message", on_message)

            script.load()
            terminal.info(f"Injected script")

        except Exception as e:
            QMessageBox.critical(self, "Injection failed",
                                 f"Could not inject script: {e}")
            raise

    def _on_trace_svc_clicked(self):
        if not self.compiled_svc_tracer:
            retval = os.system(
                "cd core/frida/frida-iOS-syscall-tracer && git pull && npm install"
            )

            if retval != 0:
                QMessageBox.critical(self, "Error",
                                     f"Could not compile syscall tracer: npm returned {retval}\nIs npm installed?")
                return
            self.compiled_svc_tracer = True

        try:
            with open("core/frida/frida-iOS-syscall-tracer/_tracer.js", mode="r", encoding="utf-8") as tracer:
                with open("core/frida/common.js", mode="r", encoding="utf-8") as common:
                    session, pid = self._spawn_selected_app()
                    self._inject_script(
                        session, tracer.read() + "\n" + common.read()
                    )
                    self.frida.resume(
                        self.current_device_id, pid  # type: ignore
                    )
        except Exception as e:
            QMessageBox.critical(self, "File error",
                                 f"Could not read tracer: {e}")
