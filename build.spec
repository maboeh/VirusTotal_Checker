# -*- mode: python ; coding: utf-8 -*-

import os
import re
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Version aus config.py parsen (Import schlägt im spec-Kontext fehl,
# da das Projektverzeichnis nicht auf sys.path steht)
_spec_dir = os.getcwd()
with open(os.path.join(_spec_dir, 'config.py'), encoding='utf-8') as _f:
    _config_src = _f.read()
_match = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', _config_src, re.MULTILINE)
APP_VERSION = _match.group(1) if _match else '0.0.0'

block_cipher = None

a = Analysis(['main.py'],
             pathex=['.'],
             binaries=[],
             datas=collect_data_files('customtkinter'),
             hiddenimports=['customtkinter'] + collect_submodules('customtkinter'),
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='virustotal_scanner',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=False)
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='virustotal_scanner')

# macOS: .app Bundle erzeugen
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='VirusTotal Scanner.app',
        bundle_identifier='com.maboeh.virustotalscanner',
        info_plist={
            'CFBundleName': 'VirusTotal Scanner',
            'CFBundleShortVersionString': APP_VERSION,
            'CFBundleVersion': APP_VERSION,
            'NSHighResolutionCapable': True,
            'LSMinimumSystemVersion': '10.13',
        },
    )
