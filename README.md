# 📦 CBZ Cover Manager

A powerful and modern GUI tool for managing, adding, removing, and previewing **cover images in CBZ files** (Comic Book Zip). Built with **Python + Tkinter**, it supports drag-and-drop, dark mode, manual and automated assignments, and many advanced features for batch processing comic archives.

---

## 🚀 Features

- ✅ Load `.cbz` or `.zip` files (with optional auto-rename)
- ✅ Drag & Drop folder or files into UI
- ✅ Navigate and preview pages from within CBZs
- ✅ Mark pages for deletion, with undo support
- ✅ Auto/Manual/Global Front & Back cover assignment
- ✅ CBZ-level and Global cover removal options
- ✅ Preview assigned covers before applying
- ✅ Reorder covers via drag-and-drop
- ✅ Apply or Clear changes selectively or globally
- ✅ Fully responsive **Dark Mode** with AMOLED black support
- ✅ Help & About with GitHub link

---

## 🖼️ Cover Assignment Logic

- **Auto Assignment**: based on filename patterns like `v02 Front.webp`
- **Manual Assignment**: choose image files or CBZ pages manually
- **Global Assignment**: assign same image to all CBZs (optionally filter by name)
- **Set as Cover from CBZ**: mark currently previewed page as front/back
- **Priority**: Manual > Auto > Global

---

## 📦 Installation

### Option 1: Run with Python

```bash
pip install -r requirements.txt
python cbzgui.py
```

### Option 2: Run with [UV](https://github.com/astral-sh/uv)

Add this to the top of `cbzgui.py`:

```python
# uv: entrypoint=cbzgui.py
```

Then run:

```bash
uv run cbzgui.py
```

### Option 3: Compile to EXE (Windows)

```bash
pyinstaller --noconsole --onefile --name "CBZCoverManager" cbzgui.py
```

---

## 🧪 Dependencies

- `Pillow`
- `tkinter` (built-in)
- `tkinterDnD2` (optional but recommended for drag-and-drop)

To install:

```bash
pip install Pillow tkinterdnd2
```

---

## 📖 Usage Guide

See the **Help** section within the app or check the in-app `?` menu for a detailed walkthrough. A quick summary:

- Load your files or folder
- Assign covers manually, automatically, or globally
- Preview and reorder assignments
- Apply or Clear changes
- Toggle dark mode and more

---

## 🔗 GitHub

[GitHub Repo](https://github.com/your-repo)

---

## 🧑‍💻 Author

Built with ❤️ using Python, GUI tooling, and AI-assisted development.
