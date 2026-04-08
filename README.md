# CBZ Cover Manager

**CBZ Cover Manager** is a lightweight, fast, and feature-rich desktop GUI application built with Python and Tkinter for managing, assigning, and modifying front and back covers of CBZ (Comic Book Archive) files. 

It provides an intuitive interface with drag-and-drop support, auto-matching capabilities, and safe asynchronous zip operations to ensure your comic archives are updated efficiently without corrupting data.

## 🚀 Features

- **Drag and Drop Support:** Seamlessly drag and drop CBZ files, folders, or images directly into the application.
- **Fast ZIP Operations:** Uses intelligent, cache-backed ZIP operations (`fastappendcovers`) to append covers without requiring full extraction and recompression when possible.
- **Responsive UI & Dark Mode:** Virtual scrolling for high performance even with hundreds of loaded files, plus a built-in Dark Mode toggle.
- **Real-Time Filtering:** Search and filter your loaded CBZ files instantly to apply targeted changes.
- **Smart Auto-Assignment:** Automatically matches loose image files to corresponding CBZ files by extracting volume numbers (e.g., `v01`, `vol.7`, `volume 12`).
- **Global Cover Assignment:** Apply a specific front or back cover to all loaded CBZ files or a filtered subset with one click.
- **Manual Assignment:** Drag and drop images onto individual CBZ preview panels to assign them manually.
- **Cover Deletion:** Easily mark the first or last images inside a CBZ for deletion to clean up unwanted metadata or ad pages to all loaded CBZ files or a filtered subset with one click.
- **Set as Cover from CBZ**: Mark currently previewed page from Navigation as Front/Back Cover.
- **Priority**: Manual > Auto > Global.
- **Remove Covers**: One click removal of everything this program has added without touching your original files.

---
![image](https://github.com/user-attachments/assets/1ace9cb9-5436-4c15-a0df-7e2a852d020c)
_Example Preview of GUI showing Manual Assign, Auto Assign, Set as Front/Back Cover and Delete in Play._


## 🛠️ Prerequisites

- **Python 3.7+**
- Required Python packages: `Pillow` and `tkinterdnd2`.

## 📦 Installation & Usage

You can run the application using standard Python `pip` or using `uv` for modern, isolated package management.

### Method 1: Standard Pip (Recommended)

1. Clone or download this repository.
2. Install the required dependencies:
   ```bash
   pip install Pillow tkinterdnd2
   ```
3. Run the application:
   ```bash
   python cbz-cover-manager.py
   ```

### Method 2: Using UV

1. Install `uv` if you haven't already:
   ```bash
   pip install uv
   ```
2. Run the application directly (dependencies will be handled):
   ```bash
   uv run cbz-cover-manager.py
   ```

## 📖 How to Use

1. **Loading Files:** 
   - Drag and drop `.cbz` files or entire folders containing `.cbz` files directly into the main window.
   - Alternatively, use the **Load** dropdown menu in the toolbar.
   - *Tip:* You can enable the "Load ZIP as CBZ" toggle in the top right to automatically convert dropped `.zip` archives.

2. **Assigning Covers:**
   - **Auto Assign:** Click `Auto Assign All` to have the app look for volume patterns in your loaded image files and assign them automatically to the correct CBZ.
   - **Global Front / Back:** Use the `Global Front` or `Global Back` buttons (or drag images onto them) to assign an image to *all currently displayed/filtered* CBZ files.
   - **Manual:** Drag an image directly over the Front/Back preview areas of a specific CBZ card to assign it.

3. **Managing Existing Covers:**
   - Use `Delete First Image` or `Delete Last Image` to queue up the removal of pages inside the archives.
   - You can clear assignments at any time using the `Remove Covers` menu or the `Clear All` button.

4. **Applying Changes:**
   - Once your covers are assigned and previewed in the UI, click **Apply All**. 
   - The app will safely rewrite your archives in the background using thread-safe operations. Check the log window at the bottom for real-time progress.

## ⚠️ Safety & Backups

While CBZ Cover Manager employs safe rewriting techniques (writing to a temporary UUID file before replacing the original), it is always highly recommended to **backup your comic files** before running bulk operations. 

## 📝 License

This project is open-source and free to use.

## 🧑‍💻 Author

Built using Python and AI-assisted development.
