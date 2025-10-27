from pathlib import Path

from core import logger


def generate_native_hook(context, module, offset):
    with open("core/frida/templates/native_hook.js", "r") as template:
        script = template.read()
        script = script.replace("%CONTEXT%", context)
        script = script.replace("%OFFSET%", offset)
        script = script.replace("%MODULE%", module)

        out_dir = Path("hooks")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{module}_{offset}.js"
        suffix = 1
        while out_path.exists():
            out_path = out_dir / f"{module}_{offset}_{suffix}.js"
            suffix += 1

        out_path.write_text(script, encoding="utf-8")
        logger.debug(f"Hook generated: {out_path}")
