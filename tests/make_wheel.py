#!/usr/bin/env python3
"""Build a tiny offline wheel standing in for a Python tool, for the venv tests.

    make_wheel.py <dist-name> <version> <stub-script> <out-dir>

The wheel installs a console script named <dist-name>. `--version` prints
"<dist-name> v<version>-venv" so a test can tell the venv copy from the stub
on PATH; anything else is handed to the stub script, so the tool behaves the
same in a real run. Built by hand (a wheel is a zip) because the test sandbox
has no network and no build backend.
"""
import base64
import hashlib
import sys
import zipfile
from pathlib import Path

name, version, stub, out = sys.argv[1:5]
mod = f"fake_{name.replace('-', '_')}"
dist = f"{name.replace('-', '_')}-{version}.dist-info"

files = {
    f"{mod}/__init__.py": f'''import runpy, sys
STUB = {str(Path(stub).resolve())!r}
def main():
    if "--version" in sys.argv[1:] or "-V" in sys.argv[1:]:
        print("{name} v{version}-venv"); return
    sys.argv[0] = STUB
    runpy.run_path(STUB, run_name="__main__")
''',
    f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
    f"{dist}/WHEEL": "Wheel-Version: 1.0\nGenerator: make_wheel.py\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    f"{dist}/entry_points.txt": f"[console_scripts]\n{name} = {mod}:main\n",
}


def digest(data):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


record = [f"{p},{digest(c.encode())},{len(c.encode())}" for p, c in files.items()]
record.append(f"{dist}/RECORD,,")
files[f"{dist}/RECORD"] = "\n".join(record) + "\n"

Path(out).mkdir(parents=True, exist_ok=True)
whl = Path(out) / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
with zipfile.ZipFile(whl, "w") as z:
    for p, c in files.items():
        z.writestr(p, c)
print(whl)
