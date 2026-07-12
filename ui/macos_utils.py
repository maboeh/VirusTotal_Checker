"""macOS-spezifische Helfer fuer Fenster-Fokus und App-Aktivierung.

Auf macOS erscheinen ``CTkToplevel``-Dialoge hinter dem Hauptfenster und
PyInstaller-gebuildete ``.app``-Bundles werden oft nicht als aktive App
aktiviert. Die Funktionen hier heben Fenster zuverlaessig nach vorne und
aktivieren die App, sodass Button-Klicks auch im gebauten Bundle
verarbeitet werden.
"""
from __future__ import annotations

import sys


def is_macos() -> bool:
    return sys.platform == "darwin"


def activate_app() -> None:
    """Aktiviert die App nativ unter macOS, sonst kein-op.

    Wird benoetigt, damit ein PyInstaller-``.app``-Bundle den echten
    App-Fokus erhaelt und Klicks auf Buttons verarbeitet werden.
    """
    if not is_macos():
        return
    try:
        from AppKit import NSApplicationActivateIgnoringOtherApps, NSApp  # type: ignore
    except Exception:
        try:
            # Fallback fuer aeltere pyobjc-Versionen (deprecated, aber funktionsfaehig)
            from AppKit import NSApp  # type: ignore
            NSApp.activateIgnoringOtherApps_(True)
        except Exception:
            return
        return
    try:
        NSApp.activateWithOptions_(NSApplicationActivateIgnoringOtherApps)
    except Exception:
        try:
            NSApp.activateIgnoringOtherApps_(True)
        except Exception:
            pass


def bring_to_front(window) -> None:
    """Hebt ein Tkinter/CTk-Fenster zuverlaessig nach vorne.

    Auf macOS wird zusaetzlich kurz ``-topmost`` eingeschaltet, um das
    Fenster ueber allen anderen zu platzieren, danach wieder
    ausgeschaltet, damit es sich normal verhaelt.
    """
    try:
        window.lift()
    except Exception:
        pass
    try:
        window.attributes("-topmost", True)
    except Exception:
        pass
    try:
        window.focus_force()
    except Exception:
        pass
    # macOS: App erneut aktivieren, damit das Fenster auch wirklich
    # den Key-Window-Status erhaelt. Reihenfolge ist kritisch.
    if is_macos():
        activate_app()
    try:
        window.lift()
    except Exception:
        pass
    try:
        window.focus_set()
    except Exception:
        pass
    # topmost erst nach einer kurzen Pause entfernen, damit das
    # Window-Manager das Fenster wirklich nach vorne gehoben hat.
    try:
        window.after(200, lambda: _reset_topmost(window))
    except Exception:
        pass


def _reset_topmost(window) -> None:
    try:
        window.attributes("-topmost", False)
    except Exception:
        pass
