import traceback
from typing import List, Dict

import frida

from core import logger


class FridaError(Exception):
    pass


class FridaManager:
    def __init__(self):
        pass

    def get_frida_version(self) -> str:
        """
        Returns the currently installed Frida version.
        """
        return frida.__version__

    def list_ios_devices(self) -> List[Dict]:
        """
        Returns list of iOS devices as dicts: {'id': id, 'name': name, 'type': 'usb'|'remote'|'local', 'usb': bool}
        """
        results = []
        for dev in frida.enumerate_devices():
            results.append({
                "id": getattr(dev, "id", getattr(dev, "name", str(dev))),
                "name": getattr(dev, "name", getattr(dev, "id", str(dev))),
                "type": getattr(dev, "type", "unknown"),
            })

        return results

    def _get_device_obj(self, device_id: str):
        """
        Returns the frida device object corresponding to device_id.
        """
        for d in frida.enumerate_devices():
            did = getattr(d, "id", None) or getattr(
                d, "name", None) or str(d)
            if str(did) == str(device_id):
                return d

        raise FridaError(f"Device '{device_id}' not found")

    def list_applications(self, device_id: str) -> List[Dict]:
        """
        Lists installed applications on device. Returns list of dicts with keys: identifier, name, pid (if running / optional).
        """
        try:
            d = self._get_device_obj(device_id)
            apps = []
            for a in d.enumerate_applications():
                apps.append({
                    "identifier": getattr(a, "identifier", getattr(a, "bundle_id", None) or str(a)),
                    "name": getattr(a, "name", getattr(a, "display_name", None) or str(a)),
                    "pid": getattr(a, "pid", None),
                    "icon": getattr(a, "icon", None)
                })
            return apps

        except Exception as e:
            logger.error(
                f"list_applications error: {e}\n{traceback.format_exc()}")
            raise FridaError(str(e))

    def spawn_app(self, device_id: str, app_identifier: str) -> Dict:
        """
        Spawns the app on the device. Returns dict with 'pid' and optional 'success' flag.
        """
        try:
            d = self._get_device_obj(device_id)
            if not hasattr(d, "spawn"):
                raise FridaError("Device does not support spawn()")

            pid = d.spawn([app_identifier]) if isinstance(
                app_identifier, str) else d.spawn(app_identifier)
            return {"pid": int(pid) if pid is not None else None, "identifier": app_identifier}
        except Exception as e:
            logger.error(f"spawn_app error: {e}\n{traceback.format_exc()}")
            raise FridaError(str(e))

    def resume(self, device_id: str, pid: int):
        """
        Resumes a previously spawned pid.
        """
        try:
            d = self._get_device_obj(device_id)
            if not hasattr(d, "resume"):
                raise FridaError("Device does not support resume()")
            d.resume(pid)
            return True
        except Exception as e:
            logger.error(
                f"resume error: {e}\n{traceback.format_exc()}")
            raise FridaError(str(e))

    def attach(self, device_id: str, pid: int):
        """
        Attaches to a running pid. Returns session object (or a light dict if not possible).
        """
        try:
            d = self._get_device_obj(device_id)
            sess = d.attach(pid)
            return sess
        except Exception as e:
            logger.error(f"attach error: {e}\n{traceback.format_exc()}")
            raise FridaError(str(e))
