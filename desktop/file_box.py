#!/usr/bin/env python3
"""Simple desktop file box application using Tkinter.

Each user has a directory inside ``boxes/`` named after their username.
Files dropped onto the window will be copied to the recipient's box.
The window lists files in the current user's box and refreshes periodically.

This is a demonstration implementation and does not include any
authentication or network communication. It is intended for local use
where multiple users share the same filesystem.
"""

import argparse
import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:  # pragma: no cover - handled at runtime
    TkinterDnD = tk.Tk  # type: ignore
    DND_FILES = "DND_Files"

BOXES_ROOT = os.path.join(os.path.dirname(__file__), "boxes")
REFRESH_MS = 1000  # refresh interval for file list


def ensure_user_dir(username: str) -> str:
    """Ensure that the directory for ``username`` exists and return its path."""
    path = os.path.join(BOXES_ROOT, username)
    os.makedirs(path, exist_ok=True)
    return path


def copy_file_to_user(src: str, username: str) -> None:
    """Copy ``src`` file to ``username``'s box."""
    dest_dir = ensure_user_dir(username)
    shutil.copy2(src, dest_dir)


class FileBoxApp(TkinterDnD.Tk):
    """Main application window."""

    def __init__(self, username: str) -> None:
        super().__init__()
        self.username = username
        self.title(f"File Box - {username}")
        self.geometry("400x300")

        self.box_dir = ensure_user_dir(username)

        self.listbox = tk.Listbox(self)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Enable drag and drop
        self.drop_target_register(DND_FILES)
        self.dnd_bind("<Drop>", self.on_drop)

        refresh_button = tk.Button(self, text="Refresh", command=self.refresh)
        refresh_button.pack(pady=(0, 10))

        self.refresh()

    def refresh(self) -> None:
        """Refresh the list of files in the user's box."""
        self.listbox.delete(0, tk.END)
        try:
            files = sorted(os.listdir(self.box_dir))
        except FileNotFoundError:
            files = []
        for name in files:
            self.listbox.insert(tk.END, name)
        self.after(REFRESH_MS, self.refresh)

    def on_drop(self, event) -> None:
        """Handle files dropped onto the window."""
        # event.data may contain a space separated list of filenames
        files = self.tk.splitlist(event.data)
        for path in files:
            if os.path.isdir(path):
                messagebox.showwarning("Directories not allowed", path)
                continue
            recipient = simpledialog.askstring(
                "Send to", f"Send '{os.path.basename(path)}' to which user?"
            )
            if recipient:
                try:
                    copy_file_to_user(path, recipient)
                except Exception as exc:  # pragma: no cover
                    messagebox.showerror("Error", str(exc))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Desktop file box application")
    parser.add_argument("--user", required=False, help="Current username")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    username = args.user
    if not username:
        username = simpledialog.askstring("User", "Enter your username")
    if not username:
        messagebox.showerror("Error", "Username is required")
        return
    app = FileBoxApp(username)
    app.mainloop()


if __name__ == "__main__":
    main()
