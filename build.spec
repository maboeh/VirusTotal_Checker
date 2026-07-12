# -*- mode: python ; coding: utf-8 -*-

import sys

from PyInstaller.utils.hooks import collect_data_files

# Version aus config.py auslesen, um DRY zu wahren
from config import VERSION as APP_VERSION

block_cipher = None

a = Analysis(['main.py'],
             pathex=['.'],
             binaries=[],
             datas=collect_data_files('customtkinter'),
             hiddenimports=['customtkinter'],
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
