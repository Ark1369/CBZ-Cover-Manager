# 📦 CBZ Cover Manager

A powerful and modern GUI tool for managing, adding, removing, and previewing **cover images in CBZ files** (Comic Book Zip). Built with **Python + Tkinter**, it supports drag-and-drop, dark mode, manual and automated assignments.

---

## 🚀 Features

- ✅ Load `.cbz` or `.zip` files (with optional auto-rename).
- ✅ Drag & Drop folder or files into UI.
- ✅ Navigate and preview pages from within CBZs.
- ✅ Mark pages for deletion, with undo support.
- ✅ Auto/Manual/Global Front & Back cover assignment.
- ✅ CBZ-level and Global cover removal options.
- ✅ Preview assigned covers before applying.
- ✅ Reorder covers via drag-and-drop.
- ✅ Apply or Clear changes selectively or globally.
- ✅ Fully responsive **Dark Mode** with AMOLED black support.
- ✅ Help & About with GitHub link.

---

## 🖼️ Cover Assignment Logic

- **Auto Assignment**: based on filename patterns like `v02 Front.webp/v02 Front Alt.webp/v02 Front 2.webp and so on`
- **Manual Assignment**: choose image files or CBZ pages manually
- **Global Assignment**: assign same image to all CBZs (optionally filter by name to apply selectively)
- **Set as Cover from CBZ**: mark currently previewed page as Front/Back COver instead.
- **Priority**: Manual > Auto > Global

---
![image](https://github.com/user-attachments/assets/1ace9cb9-5436-4c15-a0df-7e2a852d020c)
_Example Preview of GUI showing Manual Assign, Auto Assign, Set as Front/Back Cover and Delete in Play._

## 📦 Installation

### 🧪 Dependencies

- `Pillow`
- `tkinter` (built-in)
- `tkinterDnD2` (optional but recommended for drag-and-drop)

### Option 1: Run with Python

```bash
pip install Pillow tkinterdnd2
python cbzgui.py
```

### Option 2: Run with [UV](https://github.com/astral-sh/uv)

```bash
pip install uv
uv run cbzgui.py
```
### Option 3: Grab the .exe from Release Page.
---

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

[GitHub Repo](https://github.com/Ark1369/CBZ-Cover-Manager)

---

## 🧑‍💻 Author

Built using Python and AI-assisted development.
