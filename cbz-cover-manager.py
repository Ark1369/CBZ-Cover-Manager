#To Run - pip install Pillow tkinterdnd2 and then python cbz-cover-manager.py 
#To Run via UV - pip install uv and then uv run cbz-cover-manager.py 

# Requires-Python: >=3.9
# Requires-Dist: pillow
# Requires-Dist: tkinterdnd2

import os
import re
import zipfile
import threading
import hashlib
import traceback
import concurrent.futures
import queue as std_queue
import tkinter as tk
import time
import uuid
from tkinter import filedialog, ttk
try:
    from tkinterdnd2 import TkinterDnD
    from tkinterdnd2 import DND_FILES
except ImportError:
    TkinterDnD = None
    DND_FILES = None
from PIL import Image, ImageTk, ImageEnhance
from io import BytesIO


# === Utility Functions ===
def extract_vol_number(filename):
    match = re.search(r"\d+", filename)
    return int(match.group()) if match else None

def file_hash(path, algo='sha256'):
    hash_func = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def zip_image_hashes(zip_path, algo="sha256"):
    hashes = {}
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if name.lower().endswith((".jpg", ".jpeg", ".png", ".webp")):
                try:
                    data = zf.read(name)
                    h = hashlib.new(algo)
                    h.update(data)
                    hashes[name] = h.hexdigest()
                except KeyError:
                    continue
    return hashes

def rewrite_cbz(cbz_path, add_images=None, delete_files=None, zip_hash_cache=None, global_hash_cache=None, compress=True):
    """
    Safely rewrites a CBZ by applying all deletions and additions in one pass.
    """
    add_images = add_images or []
    delete_files = set(delete_files or [])

    compression = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED

    if zip_hash_cache is None:
        zip_hash_cache = zip_image_hashes(cbz_path)

    tmp_cbz = cbz_path + f".{uuid.uuid4().hex}.tmp"

    try:
        with zipfile.ZipFile(cbz_path, "r") as zin:
            items_to_keep = [
                item for item in zin.infolist()
                if item.filename not in delete_files
            ]

            with zipfile.ZipFile(tmp_cbz, "w", compression=compression) as zout:
                for item in items_to_keep:
                    with zin.open(item.filename) as source:
                        zout.writestr(item, source.read())

                existing = set(item.filename for item in items_to_keep)
                to_add = build_cover_filenames(add_images)

                for path, arcname in to_add:
                    file_hash_val = (
                        global_hash_cache.get(path)
                        if global_hash_cache and path in global_hash_cache
                        else file_hash(path)
                    )
                    if arcname in existing:
                        if file_hash_val == zip_hash_cache.get(arcname):
                            continue  # skip identical
                    zout.write(path, arcname)

        os.replace(tmp_cbz, cbz_path)
        return True  # change applied
    except Exception as e:
        if os.path.exists(tmp_cbz):
            os.remove(tmp_cbz)
        raise e

def fast_append_covers(cbz_path, image_paths, zip_hash_cache=None, global_hash_cache=None):
    if zip_hash_cache is None:
        zip_hash_cache = zip_image_hashes(cbz_path)

    with zipfile.ZipFile(cbz_path, "a") as cbz:
        existing = set(cbz.namelist())
        to_add = build_cover_filenames(image_paths)

        for path, arc in to_add:
            file_hash_val = (
                global_hash_cache.get(path)
                if global_hash_cache and path in global_hash_cache
                else file_hash(path)
            )
            if arc in existing:
                if file_hash_val == zip_hash_cache.get(arc):
                    continue  # skip identical
            cbz.write(path, arcname=arc)

def build_cover_filenames(cover_image_paths):
    """
    Constructs unique filenames for cover images added to CBZ.
    Applies offset ranges based on tag:
        - manual front: !0000+
        - auto front:   !0100+
        - global front: !0200+
        - manual back:  zzzzzz_9900+
        - auto back:    zzzzzz_9800+
        - global back:  zzzzzz_9700+
    """
    all_images = []
    counters = {
        ("manual", False): 0,
        ("auto", False): 0,
        ("global", False): 0,
        ("manual", True): 0,
        ("auto", True): 0,
        ("global", True): 0,
    }

    base_offsets = {
        ("manual", False): 0,
        ("auto", False): 100,
        ("global", False): 200,
        ("manual", True): 9900,
        ("auto", True): 9800,
        ("global", True): 9700,
    }

    for entry in cover_image_paths:
        if len(entry) == 3:
            path, is_back, tag = entry
        else:
            path, is_back = entry
            tag = "manual"  # fallback

        key = (tag, is_back)
        base = base_offsets.get(key, 0)
        count = counters[key]

        filename, ext = os.path.splitext(os.path.basename(path))
        if is_back:
            arcname = f"zzzzzz_{base + count:04}_backcover_{tag}{ext}"
        else:
            arcname = f"!{base + count:04}_cover_{tag}{ext}"

        counters[key] += 1
        all_images.append((path, arcname))

    return all_images

def safe_basename(path):
    try:
        return os.path.basename(path)
    except Exception:
        return path.encode("utf-8", errors="replace").decode("utf-8")
    
def get_tk_image(data, size=(120, 180), dimmed=False):
    img = Image.open(BytesIO(data))
    if dimmed:
        img = ImageEnhance.Brightness(img).enhance(0.4)
    img.thumbnail(size)
    return ImageTk.PhotoImage(img)

def log_exception(log_func, msg, exc=None):
    log_func(f"{msg}\n{traceback.format_exc()}" if exc else msg)

class GuiSafeExecutor:
    def __init__(self, root, max_workers=5):
        self.root = root
        self.task_queue = std_queue.Queue()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.root.after(100, self._process_queue)

    def run_async(self, func, *args, **kwargs):
        def wrapped():
            try:
                result = func(*args, **kwargs)
                return result
            except Exception:
                traceback.print_exc()
        self.executor.submit(wrapped)

    def call_in_main_thread(self, func):
        self.task_queue.put(func)

    def _process_queue(self):
        while not self.task_queue.empty():
            func = self.task_queue.get()
            try:
                func()
            except Exception:
                traceback.print_exc()
        self.root.after(100, self._process_queue)

class DragGhostWindow:
    def __init__(self, image, x, y):
        self.window = tk.Toplevel()
        self.window.overrideredirect(True)
        self.window.geometry(f"+{x}+{y}")
        tk.Label(self.window, image=image).pack()

    def move(self, x, y):
        if self.window:
            self.window.geometry(f"+{x}+{y}")

    def destroy(self):
        if self.window:
            self.window.destroy()
            self.window = None

class CBZCoverManager:
    def __init__(self, root):
        self.use_compression = True  # set to False to store uncompressed CBZs
        self.root = root
        self.root.title("CBZ Cover Manager")
        screen_height = root.winfo_screenheight()
        self.root.geometry(f"1700x{screen_height-80}+80+0")
        
        style = ttk.Style()
        style.theme_use("clam")  # You’re already using this
        style.configure("TFrame", background="#f4f4f4")
        style.configure("TButton", padding=4)
        style.configure("TLabel", background="#f4f4f4")

        self.executor = GuiSafeExecutor(self.root)
        self.cbz_entries = []
        self.image_files = []
        self._auto = {}
        self._manual_front = {}
        self._manual_back = {}
        self._delete_queue = {}
        self.preview_state = {}
        self.preview_widgets = {}
        self.assignment_widgets = {}
        self.progress = tk.StringVar()
        self.task_queue = std_queue.Queue()
        self._last_active_preview_side = "front"

        self._global_front = []
        self._global_back = []
        self._global_hashes = {}  # Cache hashes once for global covers
        self._global_cbz_filter = ""

        self._dark_mode = tk.BooleanVar(value=False)
        self._menus = []
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Base theme
        self._load_zip_as_cbz = tk.BooleanVar(value=False)
        
        def apply_dark_mode(enabled, target=None):
            bg = "#000000" if enabled else "#f4f4f4"   # ← AMOLED Black
            fg = "#eeeeee" if enabled else "#000000"
            active_bg = "#222222" if enabled else "#e0e0e0"
            active_fg = "#ffffff" if enabled else "#000000"
        
            widgets = [self.root] if target is None else [target]
            for w in widgets:
                w.configure(bg=bg)
        
            self.canvas.configure(bg=bg)
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabelframe", background=bg, foreground=fg)
            self.style.configure("TLabelframe.Label", background=bg, foreground=fg)
            self.style.configure("TLabel", background=bg, foreground=fg)
            self.style.configure("TMenubutton", background=bg, foreground=fg)
            self.style.map("TMenubutton",
                           background=[("active", active_bg), ("pressed", active_bg)],
                           foreground=[("active", active_fg), ("pressed", active_fg)])
            self.style.configure("TButton", background=bg, foreground=fg)
            self.style.map("TButton",
                           background=[("active", active_bg), ("pressed", active_bg)],
                           foreground=[("active", active_fg), ("pressed", active_fg)])
            self.style.configure("TCheckbutton", background=bg, foreground=fg)
            self.style.map("TCheckbutton",
                           background=[("active", active_bg), ("pressed", active_bg)],
                           foreground=[("active", active_fg), ("pressed", active_fg)])
        
            # Menus
            for menu in getattr(self, "_menus", []):
                menu.configure(
                    bg=bg,
                    fg=fg,
                    activebackground=active_bg,
                    activeforeground=active_fg
                )
        self._apply_dark_style = apply_dark_mode

        self.init_ui()
        self.root.after(100, self.process_queue)

        if TkinterDnD:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self._on_drop)        
        
    def init_ui(self):
        # === Log box ===
        log_frame = ttk.Panedwindow(self.root, orient=tk.VERTICAL)
        log_frame.pack(side=tk.BOTTOM, fill=tk.X)
        log_scroll = ttk.Scrollbar(log_frame)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
        self.log_box = tk.Text(
            log_frame,
            height=18,
            wrap=tk.WORD,
            yscrollcommand=log_scroll.set,
            bg="#222",
            fg="#eee",
            insertbackground="#eee",
            font=("Courier New", 9)
        )
        self.log_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.config(command=self.log_box.yview)
    
        # === Global Progress Bar ===
        self.global_progress = ttk.Progressbar(self.root, mode="determinate")
        self.global_progress.pack(fill=tk.X, side=tk.BOTTOM, padx=4, pady=2)
    
        # === Toolbar ===
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=5, pady=4)
    
        load_btn = ttk.Menubutton(top, text="Load")
        load_menu = tk.Menu(load_btn, tearoff=0)
        load_btn["menu"] = load_menu
        load_menu.add_command(label="Load Folder", command=self.load_folder)
        load_menu.add_command(label="Load CBZ File(s)", command=self.load_cbz_files)
        self._menus.append(load_menu)
        load_btn.pack(side=tk.LEFT, padx=5)
        self.add_tooltip(load_btn, "Load CBZs from a folder or selected files")
    
        def add_btn(text, cmd, tip):
            btn = ttk.Button(top, text=text, command=cmd)
            btn.pack(side=tk.LEFT, padx=3)
            self.add_tooltip(btn, tip)
    
        add_btn("Auto Assign All", self.auto_assign_all, "Automatically match images to CBZs by volume number")
        add_btn("Global Front", lambda: self.assign_global_cover("front"), "Assign a front cover to all matching CBZs")
        add_btn("Global Back", lambda: self.assign_global_cover("back"), "Assign a back cover to all matching CBZs")
        add_btn("Clear Global Covers", self.clear_global_covers, "Clear all global front/back assignments")
        add_btn("Delete First Image", self.mark_first_image_all, "Mark the first image in each CBZ for deletion")
        add_btn("Delete Last Image", self.mark_last_image_all, "Mark the last image in each CBZ for deletion")
    
        # === Dropdown Menu for Remove Covers ===
        remove_btn = ttk.Menubutton(top, text="Remove Covers")
        remove_menu = tk.Menu(remove_btn, tearoff=0)
        remove_btn["menu"] = remove_menu
        remove_menu.add_command(label="Remove Auto Assigned Covers", command=self.remove_auto_covers)
        remove_menu.add_command(label="Remove Manually Assigned Covers", command=self.remove_manual_covers)
        remove_menu.add_command(label="Remove Globally Assigned Covers", command=self.remove_global_covers)
        remove_menu.add_command(label="Remove All Covers", command=self.mark_all_covers_for_deletion)
        self._menus.append(remove_menu)
        remove_btn.pack(side=tk.LEFT, padx=5)
        self.add_tooltip(remove_btn, "Remove various types of assigned covers")
    
        add_btn("Apply All", self.apply_all, "Apply all cover assignments and deletions")
        add_btn("Clear All", self.clear_all, "Clear all assignments and previews")
    
        # === Right-end toggles ===
        help_btn = ttk.Menubutton(top, text="Help")
        help_menu = tk.Menu(help_btn, tearoff=0, bg="#2e2e2e", fg="#eeeeee", activebackground="#444", activeforeground="#fff")
        help_btn["menu"] = help_menu
        help_menu.add_command(label="About", command=self.show_about_window)
        help_menu.add_command(label="Usage Help", command=self.show_help_window)
        self._menus.append(help_menu)
        help_btn.pack(side=tk.RIGHT, padx=5)
        self.add_tooltip(help_btn, "Help, usage guide and about info")
        
        dark_toggle = ttk.Checkbutton(top, text="Dark Mode", variable=self._dark_mode, command=self.toggle_theme)
        dark_toggle.pack(side=tk.RIGHT, padx=5)
        self.add_tooltip(dark_toggle, "Toggle dark/light theme")
        
        zip_toggle = ttk.Checkbutton(top, text="Load ZIP as CBZ", variable=self._load_zip_as_cbz)
        zip_toggle.pack(side=tk.RIGHT, padx=6)
        self.add_tooltip(zip_toggle, "Treat dropped or loaded .zip files as .cbz")

        
        # === Global Filter alignment fix ===
        filter_entry = ttk.Entry(top, width=25)
        filter_entry.insert(0, "")
        filter_entry.pack(side=tk.RIGHT, padx=(2, 4))
        filter_entry.bind("<KeyRelease>", lambda e: setattr(self, '_global_cbz_filter', filter_entry.get().strip()))
        self.add_tooltip(filter_entry, "Only apply global covers to CBZs containing this name")
        
        ttk.Label(top, text="Global Filter:").pack(side=tk.RIGHT, padx=(4, 2))
    
        # === Scrollable Canvas ===
        self.canvas = tk.Canvas(self.root, bg="#f4f4f4")
        self.scrollbar = ttk.Scrollbar(self.root, command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
    
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
    
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
        def bind_canvas_mousewheel(widget, canvas):
            def _on_enter(_): canvas.bind_all("<MouseWheel>", on_mousewheel)
            def _on_leave(_): canvas.unbind_all("<MouseWheel>")
            def on_mousewheel(event): canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
            widget.bind("<Enter>", _on_enter)
            widget.bind("<Leave>", _on_leave)
        
        bind_canvas_mousewheel(self.canvas, self.canvas)
    
        if hasattr(self, '_apply_dark_style'):
            self._apply_dark_style(self._dark_mode.get())


    def _cbz_matches_global_filter(self, cbz_path):
        return (
            not self._global_cbz_filter or
            self._global_cbz_filter.lower() in os.path.basename(cbz_path).lower()
        )
        
    def add_tooltip(self, widget, text):
        def on_enter(event):
            self.tooltip = tk.Toplevel(widget)
            self.tooltip.overrideredirect(True)
            self.tooltip.configure(bg="#ffffe0", padx=2, pady=2)
            x, y = event.x_root + 10, event.y_root + 10
            self.tooltip.geometry(f"+{x}+{y}")
            label = tk.Label(self.tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1, font=("Arial", 9))
            label.pack()
    
        def on_leave(event):
            if hasattr(self, "tooltip"):
                self.tooltip.destroy()
    
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def toggle_theme(self):
        enabled = self._dark_mode.get()
        self._apply_dark_style(enabled)
        self.log_box.configure(
            bg="#111" if enabled else "#222",
            fg="#eee" if enabled else "#000",
            insertbackground="#eee" if enabled else "#000"
        )

    def process_queue(self):
        while not self.task_queue.empty():
            func = self.task_queue.get()
            func()
        self.root.after(100, self.process_queue)

    def _on_drop(self, event):
        paths = self.root.tk.splitlist(event.data)
        cbz_files = []
        for path in paths:
            path = path.strip('"')
            if os.path.isdir(path):
                self.log(f"🗂️ Dropped folder: {path}")
                self.load_folder(path)
                return  # stop here, folders should be exclusive
            elif path.lower().endswith(".cbz"):
                cbz_files.append(path)
            elif self._load_zip_as_cbz.get() and path.lower().endswith(".zip"):
                cbz_equiv = os.path.splitext(path)[0] + ".cbz"
                try:
                    os.rename(path, cbz_equiv)
                    self.log(f"🔄 Renamed ZIP to CBZ: {cbz_equiv}")
                    cbz_files.append(cbz_equiv)
                except Exception as e:
                    self.log(f"❌ Failed to rename {path}: {e}")
                    
        if cbz_files:
            self.log(f"📘 Dropped {len(cbz_files)} CBZ file(s)")
            self.load_cbz_files(cbz_files)
 
    def _center_window(self, win):
        win.update_idletasks()
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
    
        w = win.winfo_width()
        h = win.winfo_height()
    
        x = root_x + (root_w - w) // 2
        y = root_y + (root_h - h) // 2
        win.geometry(f"+{x}+{y}")

               
    def show_about_window(self):
        win = tk.Toplevel(self.root)
        win.title("About")
        win.geometry("400x180")
        self._center_window(win)
    
        ttk.Label(win, text="📦 CBZ Cover Manager", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(win, text="A powerful GUI for Managing Covers & Images in CBZ files.\n Created using Python with help of AI.", justify="center").pack()
        
        link = ttk.Label(win, text="GitHub: https://github.com/Ark1369/CBZ-Cover-Manager", foreground="blue", cursor="hand2")
        link.pack(pady=5)
        link.bind("<Button-1>", lambda e: self._open_github())
    
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)
        self._apply_dark_style(self._dark_mode.get(), win)
    
    def show_help_window(self):
        win = tk.Toplevel(self.root)
        win.title("Help & Usage")
        win.geometry("750x850")
        self._center_window(win)
    
        is_dark = self._dark_mode.get()
        bg = "#2e2e2e" if is_dark else "#ffffff"
        fg = "#eeeeee" if is_dark else "#000000"
    
        text = tk.Text(
            win, wrap=tk.WORD, font=("Arial", 10),
            bg=bg, fg=fg, insertbackground=fg,
            state="normal", relief=tk.FLAT
        )
    
        text.insert("1.0", """\
    📦 CBZ Cover Manager – Usage Guide
    
    🗂️ 1. Loading:
    - Use "Load Folder" to select a folder.
    - Use "Load CBZ File(s)" to select one or more CBZ files.
    - You can also drag and drop CBZs or folders into the window.
    - If "Load ZIP as CBZ" is checked, ZIP files will auto-rename to CBZ when loaded.
    
    🖼️ 2. CBZ Preview:
    - Each CBZ shows a preview window.
    - Use "<" and ">" buttons to navigate pages.
    - Click "Delete" to mark an image for deletion. Click "Undelete" to cancel.
    - Marked images are dimmed for visual clarity.
    
    🎯 3. Assigning Covers:
    - "Auto Assign" matches images to CBZs using volume numbers.
      • e.g. "v02 Front.webp" → assigned to v02 as front cover.
    - "Manual Front/Back" lets you assign images freely from file system.
    - "Set as Front/Back Cover" assigns the current preview image from within CBZ.
    - "Global Front/Back" assigns images to all CBZs (filtered by Global Filter if used).
    - Global Filter: restrict Global Covers to matching file names (e.g., "2022").
    
    
    🧩 4. Cover Previews:
    - Assigned covers appear below each CBZ card.
    - Covers are grouped by Auto / Manual / Global.
    - Click ❌ to unassign a specific cover.
    - "Clear Global Covers" removes global front/back images from pending list.
    
    ⚙️ 5. Actions:
    - "Apply" saves changes (adds/removes covers) for a single CBZ.
    - "Apply All" processes all CBZs with pending changes.
    - "Clear" resets changes for a single CBZ.
    - "Clear All" resets all edits across the session.
    - "Remove Covers" (per CBZ) removes all covers added by this tool.
    - "Remove Covers" (dropdown menu) offers options to remove Auto, Manual, Global, or All covers across CBZs.
    
    🎨 6. Other Features:
    - "Dark Mode" toggle for a darker UI experience.
    - "About" window provides GitHub link and credits.
    
    📘 Tip:
    - Manual > Auto > Global priority determines order when multiple covers exist.
    - All cover images added are renamed uniquely, originals are untouched.
    
    Visit the README on GitHub for full documentation and updates.
    """)
    
        text.configure(state="disabled")
        text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=5)
        self._apply_dark_style(self._dark_mode.get(), win)

    def log(self, msg):
        def insert():
            tag = (
                'green' if 'Applied' in msg or 'assigned' in msg
                else ('red' if 'Deleted' in msg or 'Marked' in msg or 'Failed' in msg else 'white')
            )
            self.log_box.insert(tk.END, msg + "\n", tag)
            self.log_box.tag_config('green', foreground='lightgreen')
            self.log_box.tag_config('red', foreground='tomato')
            self.log_box.tag_config('white', foreground='white')
            self.log_box.see(tk.END)
        self.task_queue.put(insert)


    def load_folder(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
    
        def worker():
            self.executor.call_in_main_thread(lambda: self.log("Loading files..."))
            cbz_entries, image_files = [], []
    
            for root, _, files in os.walk(folder):
                for file in files:
                    full = os.path.join(root, file)
                    ext = file.lower()
                    if ext.endswith(".cbz"):
                        cbz_entries.append(full)
                    elif self._load_zip_as_cbz.get() and ext.endswith(".zip"):
                        new_cbz = os.path.splitext(full)[0] + ".cbz"
                        try:
                            os.rename(full, new_cbz)
                            self.log(f"🔄 Renamed ZIP to CBZ: {new_cbz}")
                            cbz_entries.append(new_cbz)
                        except Exception as e:
                            self.log(f"❌ Failed to rename ZIP: {e}")
                    elif ext.endswith((".jpg", ".jpeg", ".png", ".webp")):
                        image_files.append(full)
    
            def finalize():
                self.cbz_entries = cbz_entries
                self.image_files = image_files
                self._auto.clear()
                self._manual_front.clear()
                self._manual_back.clear()
                self._delete_queue.clear()
                self.preview_state.clear()
                self.preview_widgets.clear()
                self.assignment_widgets.clear()
                self.refresh_list()
                self.log(f"Loaded {len(cbz_entries)} CBZs and {len(image_files)} images.")
    
            self.executor.call_in_main_thread(finalize)
    
        self.executor.run_async(worker)


    def load_cbz_files(self, files=None):
        if files is None:
            files = filedialog.askopenfilenames(filetypes=[("CBZ Files", "*.cbz"), ("ZIP Files", "*.zip")])
        if not files:
            return
    
        cbz_entries = []
        for path in files:
            ext = path.lower()
            if ext.endswith(".cbz"):
                cbz_entries.append(path)
            elif self._load_zip_as_cbz.get() and ext.endswith(".zip"):
                new_cbz = os.path.splitext(path)[0] + ".cbz"
                try:
                    os.rename(path, new_cbz)
                    self.log(f"🔄 Renamed ZIP to CBZ: {new_cbz}")
                    cbz_entries.append(new_cbz)
                except Exception as e:
                    self.log(f"❌ Failed to rename ZIP: {e}")
    
        self.cbz_entries = cbz_entries
        self.image_files.clear()
    
        # Scan folders of selected CBZs for image files
        scanned_dirs = set(os.path.dirname(f) for f in self.cbz_entries)
        image_exts = (".jpg", ".jpeg", ".png", ".webp")
        for folder in scanned_dirs:
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.lower().endswith(image_exts):
                        full = os.path.join(root, file)
                        self.image_files.append(full)
    
        self._auto.clear()
        self._manual_front.clear()
        self._manual_back.clear()
        self._delete_queue.clear()
        self.preview_state.clear()
        self.preview_widgets.clear()
        self.assignment_widgets.clear()
    
        self.refresh_list()
        self.log(f"Loaded {len(self.cbz_entries)} CBZ(s) and {len(self.image_files)} image(s).")


    def mark_first_image_all(self):
        for cbz_path in self.cbz_entries:
            try:
                with zipfile.ZipFile(cbz_path, "r") as zf:
                    images = sorted([f for f in zf.namelist() if f.lower().endswith(("jpg", "jpeg", "png", "webp"))])
                    if images:
                        self._delete_queue.setdefault(cbz_path, set()).add(images[0])
                        self.preview_state.pop(cbz_path, None)
                        self.preview_widgets.pop(cbz_path, None)
                        self.assignment_widgets.pop(cbz_path, None)
                        self.collapse_cbz_tile(cbz_path)
                        self.log(f"Marked first image for deletion in {os.path.basename(cbz_path)}")
            except Exception as e:
                self.log(f"Error marking first image in {cbz_path}: {e}")
    
    def mark_last_image_all(self):
        for cbz_path in self.cbz_entries:
            try:
                with zipfile.ZipFile(cbz_path, "r") as zf:
                    images = sorted([f for f in zf.namelist() if f.lower().endswith(("jpg", "jpeg", "png", "webp"))])
                    if images:
                        self._delete_queue.setdefault(cbz_path, set()).add(images[-1])
                        self.preview_state.pop(cbz_path, None)
                        self.preview_widgets.pop(cbz_path, None)
                        self.assignment_widgets.pop(cbz_path, None)
                        self.collapse_cbz_tile(cbz_path)
                        self.log(f"Marked last image for deletion in {os.path.basename(cbz_path)}")
            except Exception as e:
                self.log(f"Error marking last image in {cbz_path}: {e}")

    def refresh_list(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        for cbz in self.cbz_entries:
            self.make_cbz_card(cbz)

    def make_cbz_card(self, cbz_path):
        f = ttk.LabelFrame(self.scrollable_frame, text="", width=535, height=360)
        f.grid_propagate(False)
        f.grid_columnconfigure(0, weight=1)
    
        row = self.cbz_entries.index(cbz_path) // 3
        col = self.cbz_entries.index(cbz_path) % 3
        f.grid(row=row, column=col, padx=5, pady=5, sticky="nw")
    
        # Title
        title_frame = ttk.Frame(f)
        title_frame.pack(fill=tk.X)
    
        ttk.Label(
            title_frame,
            text=safe_basename(cbz_path),
            anchor="center",
            justify="center",
            wraplength=520,
            font=("Arial", 10, "bold")
        ).pack(pady=(4, 2), padx=5)
    
        # Button row
        btn_frame = ttk.Frame(f)
        btn_frame.pack(pady=2)
    
        def add_btn(text, cmd, tooltip):
            btn = ttk.Button(btn_frame, text=text, command=cmd)
            btn.pack(side=tk.LEFT, padx=3)
            self.add_tooltip(btn, tooltip)
    
        add_btn("Auto Assign", lambda: self.auto_assign(cbz_path), "Auto-assign images by volume number")
        add_btn("Manual Front", lambda: self.manual_assign(cbz_path, "front"), "Manually assign a front cover")
        add_btn("Manual Back", lambda: self.manual_assign(cbz_path, "back"), "Manually assign a back cover")
        add_btn("Remove Covers", lambda: self.remove_cbz_covers(cbz_path), "Remove auto/manual covers from this CBZ")
        add_btn("Clear", lambda: self.clear_cbz(cbz_path), "Clear all assignments for this CBZ")
        add_btn("Apply", lambda: self.executor.run_async(self.apply_cbz, cbz_path), "Apply changes to this CBZ")
    
        # Preview container
        preview_container = ttk.Frame(f)
        preview_container.pack(pady=4)
    
        preview_row = ttk.Frame(preview_container)
        preview_row.pack(anchor="center")
        self.preview_widgets[cbz_path] = preview_row
    
        # Assignment container
        assignment = ttk.Frame(f)
        assignment.pack(fill=tk.X, padx=4, pady=(2, 4))
        self.assignment_widgets[cbz_path] = assignment
    
        self.render_cbz_preview(cbz_path)
        self.render_assignment_preview(cbz_path)

    def render_cbz_preview(self, cbz_path):
        preview = self.preview_widgets.get(cbz_path)
        if not preview:
            return
    
        for widget in preview.winfo_children():
            widget.destroy()
    
        try:
            with zipfile.ZipFile(cbz_path, "r") as cbz:
                images = sorted([
                    f for f in cbz.namelist()
                    if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))
                ])
                if not images:
                    ttk.Label(preview, text="No images in CBZ").pack()
                    return
    
                state = self.preview_state.setdefault(cbz_path, {"images": images, "front": 0, "back": len(images) - 1})
                state["images"] = images
                state["front"] = min(state["front"], len(images) - 1)
                state["back"] = min(state["back"], len(images) - 1)
                to_delete = self._delete_queue.get(cbz_path, set())
    
                manual_fronts = {entry[0] for entry in self._manual_front.get(cbz_path, [])}
                manual_backs = {entry[0] for entry in self._manual_back.get(cbz_path, [])}
    
                # Container for previews
                preview_row = ttk.Frame(preview)
                preview_row.pack(anchor="center")
    
                side_frames = {}
    
                for side in ["front", "back"]:
                    idx = state[side]
                    if idx >= len(images):
                        continue
    
                    img_name = images[idx]
                    try:
                        img_data = cbz.read(img_name)
                        dimmed = img_name in to_delete
                        tkimg = get_tk_image(img_data, dimmed=dimmed)
                    except Exception as e:
                        self.log(f"Failed to load image {img_name}: {e}")
                        continue
    
                    frame = ttk.Frame(preview_row, width=260, height=260)
                    frame.pack(side=tk.LEFT, padx=8, pady=6)
                    frame.pack_propagate(False)
    
                    img_holder = ttk.Frame(frame, height=160)
                    img_holder.pack(fill=tk.BOTH, expand=True)
                    img_holder.pack_propagate(False)
    
                    label = tk.Label(
                        img_holder,
                        image=tkimg,
                        bg="#222" if dimmed or self._dark_mode.get() else "#fff",
                        bd=2,
                        relief="solid"
                    )
                    label.image = tkimg
                    label.pack(anchor="center", pady=2)

                    label.config(highlightthickness=0)
    
                    # Navigation & Delete
                    btns = ttk.Frame(frame)
                    btns.pack(anchor="center", pady=(2, 0))
    
                    def make_nav(step, s=side):
                        def _move():
                            self._last_active_preview_side = s
                            self._navigate_image(cbz_path, s, step)
                        return _move
    
                    ttk.Button(btns, text="←", command=make_nav(-1)).pack(side=tk.LEFT, padx=2)
                    ttk.Button(btns, text="→", command=make_nav(1)).pack(side=tk.LEFT, padx=2)
    
                    def make_toggle(img=img_name):
                        def toggle():
                            dq = self._delete_queue.setdefault(cbz_path, set())
                            if img in dq:
                                dq.remove(img)
                                self.log(f"Unmarked {img} for deletion")
                            else:
                                dq.add(img)
                                self.log(f"Marked {img} for deletion")
                            self.render_cbz_preview(cbz_path)
                        return toggle
    
                    btn_text = "Undelete" if img_name in to_delete else "Delete"
                    ttk.Button(btns, text=btn_text, command=make_toggle()).pack(side=tk.LEFT, padx=2)
    
                    side_frames[side] = (frame, img_name)
    
                # Set as Cover Buttons - Positioned BELOW both previews
                cover_btns = ttk.Frame(preview)
                cover_btns.pack(anchor="center", pady=(6, 2))
    
                def make_set_cover(assign_to):  # assign_to = "front" or "back"
                    def set_cover():
                        active = self._last_active_preview_side
                        state = self.preview_state.get(cbz_path)
                        if not state:
                            return
                        idx = state[active]
                        img_name = state["images"][idx]
                
                        is_back = assign_to == "back"
                        entry = (img_name, is_back, "manual")
                        target = self._manual_back if is_back else self._manual_front
                        if cbz_path not in target:
                            target[cbz_path] = []
                        if entry not in target[cbz_path]:
                            target[cbz_path].append(entry)
                            self.log(f"Set {img_name} as manual {assign_to} cover for {safe_basename(cbz_path)}")
                        self.render_assignment_preview(cbz_path)
                        self.render_cbz_preview(cbz_path)
                    return set_cover
    
                ttk.Button(cover_btns, text="Set as Front Cover", command=make_set_cover("front")).pack(side=tk.LEFT, padx=6)
                ttk.Button(cover_btns, text="Set as Back Cover", command=make_set_cover("back")).pack(side=tk.LEFT, padx=6)
    
        except Exception as e:
            self.log(f"Error reading CBZ: {e}")


    def clear_global_covers(self):
        self._global_front.clear()
        self._global_back.clear()
        self._global_hashes.clear()
        self.log("Cleared all global cover assignments")
        
    def remove_auto_covers(self):
        pattern = re.compile(r"!010\d+_cover_auto|zzzzzz_980\d+_backcover_auto", re.IGNORECASE)
        affected = 0
        for cbz_path in self.cbz_entries:
            try:
                with zipfile.ZipFile(cbz_path, "r") as zf:
                    auto_files = {name for name in zf.namelist() if pattern.search(name)}
                    if auto_files:
                        self._delete_queue.setdefault(cbz_path, set()).update(auto_files)
                        self.preview_state.pop(cbz_path, None)
                        self.preview_widgets.pop(cbz_path, None)
                        self.assignment_widgets.pop(cbz_path, None)
                        self.collapse_cbz_tile(cbz_path)
                        affected += len(auto_files)
            except Exception as e:
                self.log(f"Error removing auto covers in {cbz_path}: {e}")
        self.log(f"Marked {affected} auto-assigned cover(s) for deletion")
    
    def remove_manual_covers(self):
        pattern = re.compile(r"!000\d+_cover_manual|zzzzzz_990\d+_backcover_manual", re.IGNORECASE)
        affected = 0
        for cbz_path in self.cbz_entries:
            try:
                with zipfile.ZipFile(cbz_path, "r") as zf:
                    manual_files = {name for name in zf.namelist() if pattern.search(name)}
                    if manual_files:
                        self._delete_queue.setdefault(cbz_path, set()).update(manual_files)
                        self.preview_state.pop(cbz_path, None)
                        self.preview_widgets.pop(cbz_path, None)
                        self.assignment_widgets.pop(cbz_path, None)
                        self.collapse_cbz_tile(cbz_path)
                        affected += len(manual_files)
            except Exception as e:
                self.log(f"Error removing manual covers in {cbz_path}: {e}")
        self.log(f"Marked {affected} manually-assigned cover(s) for deletion")
    
    def remove_global_covers(self):
        pattern = re.compile(r"!020\d+_cover_global|zzzzzz_970\d+_backcover_global", re.IGNORECASE)
        affected = 0
        for cbz_path in self.cbz_entries:
            try:
                with zipfile.ZipFile(cbz_path, "r") as zf:
                    global_files = {name for name in zf.namelist() if pattern.search(name)}
                    if global_files:
                        self._delete_queue.setdefault(cbz_path, set()).update(global_files)
                        self.preview_state.pop(cbz_path, None)
                        self.preview_widgets.pop(cbz_path, None)
                        self.assignment_widgets.pop(cbz_path, None)
                        self.collapse_cbz_tile(cbz_path)
                        affected += len(global_files)
            except Exception as e:
                self.log(f"Error removing global covers in {cbz_path}: {e}")
        self.log(f"Marked {affected} global cover(s) for deletion")

    
    def remove_cbz_covers(self, cbz_path):
        pattern = re.compile(r"^(!0\d{3}_cover_|zzzzzz_\d{4}_backcover_)", re.IGNORECASE)
        try:
            with zipfile.ZipFile(cbz_path, "r") as zf:
                to_delete = {f for f in zf.namelist() if pattern.match(f)}
                if to_delete:
                    self._delete_queue.setdefault(cbz_path, set()).update(to_delete)
                    self.preview_state.pop(cbz_path, None)
                    self.preview_widgets.pop(cbz_path, None)
                    self.assignment_widgets.pop(cbz_path, None)
                    self.collapse_cbz_tile(cbz_path)
                    self.log(f"Marked {len(to_delete)} assigned cover(s) for deletion in {safe_basename(cbz_path)}")
                else:
                    self.log(f"No assigned covers found to delete in {safe_basename(cbz_path)}")
        except Exception as e:
            self.log(f"Error scanning {cbz_path}: {e}")


    def mark_all_covers_for_deletion(self):
        pattern = re.compile(r"^(!\d+_cover|zzzzzz_\d+_backcover)", re.IGNORECASE)
        for cbz_path in self.cbz_entries:
            try:
                with zipfile.ZipFile(cbz_path, "r") as zf:
                    to_delete = {
                        name for name in zf.namelist()
                        if pattern.match(name)
                    }
                    if to_delete:
                        self._delete_queue[cbz_path] = to_delete
                        self.preview_state.pop(cbz_path, None)
                        self.preview_widgets.pop(cbz_path, None)
                        self.assignment_widgets.pop(cbz_path, None)
                        self.collapse_cbz_tile(cbz_path)
                        self.log(f"Marked {len(to_delete)} covers in {safe_basename(cbz_path)} for deletion")
            except Exception as e:
                self.log(f"Error while marking covers in {cbz_path}: {e}")
                
    def _make_nav_callback(self, cbz_path, side, delta):
        return lambda: self.navigate_image(cbz_path, side, delta)

    def _navigate_image(self, cbz_path, side, step):
        state = self.preview_state.get(cbz_path)
        if not state:
            return
        current = state.get(side, 0)
        images = state["images"]
        new_index = max(0, min(len(images) - 1, current + step))
        state[side] = new_index
        self.render_cbz_preview(cbz_path)

    def render_assignment_preview(self, cbz_path):
        frame = self.assignment_widgets.get(cbz_path)
        if not frame:
            return
    
        for w in frame.winfo_children():
            w.destroy()
    
        all_sources = [
            (self._manual_front.get(cbz_path, []), '_manual_front'),
            (self._manual_back.get(cbz_path, []), '_manual_back'),
            (self._auto.get(cbz_path, []), '_auto'),
        ]
    
        combined = []
        src_map = []
        for items, label in all_sources:
            combined.extend(items)
            src_map.extend([(label, i) for i in range(len(items))])
    
        def save_reordered(updated):
            fronts, backs, autos = [], [], []
            for (path, is_back, tag), (src, _) in zip(updated, src_map):
                entry = (path, is_back, tag)
                if src == '_manual_front':
                    fronts.append(entry)
                elif src == '_manual_back':
                    backs.append(entry)
                elif src == '_auto':
                    autos.append(entry)
            self._manual_front[cbz_path] = fronts
            self._manual_back[cbz_path] = backs
            self._auto[cbz_path] = autos
    
        thumbnails = []
        max_per_row = 3
        rows = []
        for i in range(0, len(combined), max_per_row):
            row = ttk.Frame(frame)
            row.pack(fill=tk.X, padx=4, pady=(4 if i == 0 else 2))
            rows.append(row)
    
        ghost_label = None  # for drag preview
    
        def on_drag_start(event, label, idx):
            nonlocal ghost_label
            if ghost_label:
                try:
                    ghost_label.destroy()
                except:
                    pass
            label._drag_data = {'x': event.x, 'y': event.y, 'index': idx}
            label.config(highlightbackground="#FFA500", highlightthickness=2)
            ghost_label = tk.Toplevel()
            ghost_label.overrideredirect(True)
            ghost_label.geometry(f"+{event.x_root}+{event.y_root}")
            ghost = tk.Label(ghost_label, image=label.image)
            ghost.pack()
    
        def on_drag_motion(event, label):
            if ghost_label:
                ghost_label.geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
    
        def on_drag_release(event, label):
            nonlocal ghost_label
            idx = label._drag_data['index']
            drop_x, drop_y = event.x_root, event.y_root
            if ghost_label:
                ghost_label.destroy()
                ghost_label = None
    
            for insert_idx, target in enumerate(thumbnails):
                try:
                    tx1, ty1 = target.winfo_rootx(), target.winfo_rooty()
                    tx2, ty2 = tx1 + target.winfo_width(), ty1 + target.winfo_height()
                    if tx1 <= drop_x <= tx2 and ty1 <= drop_y <= ty2:
                        if idx != insert_idx:
                            item = combined.pop(idx)
                            src = src_map.pop(idx)
                            combined.insert(insert_idx, item)
                            src_map.insert(insert_idx, src)
                            save_reordered(combined)
                            self.render_assignment_preview(cbz_path)
                        break
                except:
                    continue
            try:
                label.config(highlightthickness=0)
            except:
                pass
    
        def remove_image(index):
            removed = combined.pop(index)
            src_map.pop(index)
            save_reordered(combined)
            self.preview_state.pop(cbz_path, None)
            self.preview_widgets.pop(cbz_path, None)
            self.assignment_widgets.pop(cbz_path, None)
            self.collapse_cbz_tile(cbz_path)
            self.log(f"Unassigned image: {os.path.basename(removed[0])}")

    
        for idx, (path, is_back, tag) in enumerate(combined):
            try:
                if os.path.isfile(path):
                    with open(path, "rb") as f:
                        img_data = f.read()
                else:
                    with zipfile.ZipFile(cbz_path, "r") as zf:
                        img_data = zf.read(path)
    
                is_dimmed = (path in self._delete_queue.get(cbz_path, set()))
                tkimg = get_tk_image(img_data, dimmed=is_dimmed)
                
            except Exception as e:
                self.log(f"Preview error: {e}")
                continue
    
            row = rows[idx // max_per_row]
            lbl_frame = ttk.LabelFrame(row, text=f"{'Back' if is_back else 'Front'} [{tag}]")
            lbl_frame.pack(side=tk.LEFT, padx=4, pady=2)
    
            lbl = tk.Label(
                lbl_frame,
                image=tkimg,
                bd=2,
                relief="flat",
                background="#111" if self._dark_mode.get() else "#f4f4f4"
            )
            lbl.image = tkimg
            lbl.pack()
    
            # Drag & drop bindings
            lbl._drag_data = {}
            lbl.bind("<Button-1>", lambda e, l=lbl, i=idx: on_drag_start(e, l, i))
            lbl.bind("<B1-Motion>", lambda e, l=lbl: on_drag_motion(e, l))
            lbl.bind("<ButtonRelease-1>", lambda e, l=lbl: on_drag_release(e, l))
    
            # Remove/unassign
            btn = ttk.Button(lbl_frame, text="❌", command=lambda i=idx: remove_image(i))
            btn.pack(pady=(2, 0))
    
            thumbnails.append(lbl)

    def manual_assign(self, cbz_path, which):
        files = filedialog.askopenfilenames(filetypes=[("Image Files", "*.jpg *.jpeg *.png *.webp")])
        if not files:
            return
    
        entries = []
        assigned = 0
        for f in files:
            try:
                with open(f, "rb"):
                    pass
                entries.append((f, which == "back", "manual"))
                assigned += 1
            except Exception as e:
                self.log(f"Failed to read file '{f}': {e}")
    
        if which == "front":
            self._manual_front.setdefault(cbz_path, []).extend(entries)
        else:
            self._manual_back.setdefault(cbz_path, []).extend(entries)
    
        self.log(f"Manually assigned {assigned} {which} image(s) to {safe_basename(cbz_path)}")
        self.render_assignment_preview(cbz_path)


    def auto_assign(self, cbz_path):
        vol = extract_vol_number(safe_basename(cbz_path))
        if vol is None:
            self._auto[cbz_path] = []
            return
        vol_pattern = re.compile(rf"v(?:ol)?\.?0*{vol}\b", re.IGNORECASE)
        matches = [
            img for img in self.image_files
            if vol_pattern.search(os.path.basename(img))
        ]
        self._auto[cbz_path] = [(img, "back" in img.lower(), "auto") for img in matches]  # Tag as auto
        self.log(f"Auto-assigned {len(matches)} images to {safe_basename(cbz_path)}")
        self.render_assignment_preview(cbz_path)

    def apply_cbz(self, cbz_path):
        self.executor.call_in_main_thread(lambda: self.log(f"Applying changes to {os.path.basename(cbz_path)}..."))
    
        apply_global = self._cbz_matches_global_filter(cbz_path)
    
        images = (
            (self._global_front if apply_global else []) +
            self._auto.get(cbz_path, []) +
            self._manual_front.get(cbz_path, []) +
            self._manual_back.get(cbz_path, []) +
            (self._global_back if apply_global else [])
        )
        deletions = list(self._delete_queue.get(cbz_path, set()))
        has_changes = False
    
        try:
            zip_hashes = zip_image_hashes(cbz_path)
    
            # Prepare temp extracted images if needed
            temp_files = []
            final_images = []
    
            with zipfile.ZipFile(cbz_path, "r") as zf:
                for path, is_back, tag in images:
                    if os.path.isfile(path):
                        final_images.append((path, is_back, tag))
                    else:
                        try:
                            data = zf.read(path)
                            ext = os.path.splitext(path)[1].lower() or ".jpg"
                            tmp = os.path.join(os.path.dirname(cbz_path), f"__extracted_{uuid.uuid4().hex}{ext}")
                            with open(tmp, "wb") as out:
                                out.write(data)
                            temp_files.append(tmp)
                            final_images.append((tmp, is_back, tag))
                        except Exception as e:
                            self.executor.call_in_main_thread(lambda err=e: self.log(f"Failed to extract {path}: {err}"))
    
            if deletions:
                changed = rewrite_cbz(
                    cbz_path,
                    add_images=final_images,
                    delete_files=deletions,
                    zip_hash_cache=zip_hashes,
                    global_hash_cache=self._global_hashes,
                    compress=self.use_compression
                )
            else:
                fast_append_covers(
                    cbz_path,
                    image_paths=final_images,
                    zip_hash_cache=zip_hashes,
                    global_hash_cache=self._global_hashes
                )
                changed = bool(final_images)
    
            has_changes = changed
    
            if changed:
                self._auto.pop(cbz_path, None)
                self._manual_front.pop(cbz_path, None)
                self._manual_back.pop(cbz_path, None)
                self._delete_queue.pop(cbz_path, None)
                self.preview_state.pop(cbz_path, None)
                self.preview_widgets.pop(cbz_path, None)
                self.assignment_widgets.pop(cbz_path, None)
    
            self.executor.call_in_main_thread(lambda: self.collapse_cbz_tile(cbz_path))
    
            if changed:
                self.executor.call_in_main_thread(
                    lambda: self.log(f"Applied covers to {os.path.basename(cbz_path)}")
                )
            elif not apply_global and (self._global_front or self._global_back):
                self.executor.call_in_main_thread(
                    lambda: self.log(f"Skipped global covers for {os.path.basename(cbz_path)} due to filter")
                )
    
        except Exception as e:
            self.executor.call_in_main_thread(
                lambda err=e: self.log(f"Failed to apply changes to {os.path.basename(cbz_path)}: {err}")
            )
    
        finally:
            for tmp in temp_files:
                try:
                    os.remove(tmp)
                except:
                    pass

    def apply_all(self):
        filter_str = self._global_cbz_filter.strip().lower()
    
        def _cbz_has_work(cbz):
            return (
                self._auto.get(cbz)
                or self._manual_front.get(cbz)
                or self._manual_back.get(cbz)
                or self._delete_queue.get(cbz)
                or (self._cbz_matches_global_filter(cbz) and (self._global_front or self._global_back))
            )
    
        to_process = [cbz for cbz in self.cbz_entries if _cbz_has_work(cbz)]
    
        self.global_progress["maximum"] = len(to_process)
        self.global_progress["value"] = 0
    
        # Highlight filtered CBZs in UI
        for cbz_path in self.cbz_entries:
            frame = self.assignment_widgets.get(cbz_path, None)
            if frame:
                color = "#d0f0ff" if self._cbz_matches_global_filter(cbz_path) else "#f0f0f0"
                parent = frame.master.master
                try:
                    parent.config(bg=color)
                except:
                    pass
    
        def worker_apply(cbz_path):
            try:
                self.apply_cbz(cbz_path)
            except Exception as e:
                self.task_queue.put(lambda: self.log(f"Failed to apply changes to {os.path.basename(cbz_path)}: {e}"))
            self.task_queue.put(lambda: self.global_progress.step(1))
    
        def run_all():
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                for cbz in to_process:
                    executor.submit(worker_apply, cbz)
    
            def clear_globals():
                self._global_front.clear()
                self._global_back.clear()
                self._global_hashes.clear()
                self.log("Global covers auto-cleared after apply")
            self.task_queue.put(clear_globals)
    
        threading.Thread(target=run_all, daemon=True).start()

    def assign_global_cover(self, which):
        files = filedialog.askopenfilenames(filetypes=[("Image Files", "*.jpg *.jpeg *.png *.webp")])
        if not files:
            return
    
        cache = {f: file_hash(f) for f in files}
        entries = [(f, which == "back", "global") for f in files]
    
        if which == "front":
            existing = set(f for f, _, _ in self._global_front)
            for f, is_back, tag in entries:
                if f not in existing:
                    self._global_front.append((f, is_back, tag))
                    existing.add(f)
        else:
            existing = set(f for f, _, _ in self._global_back)
            for f, is_back, tag in entries:
                if f not in existing:
                    self._global_back.append((f, is_back, tag))
                    existing.add(f)
    
        self._global_hashes.update(cache)
        self.log(f"Assigned {len(files)} global {which} cover image(s)")



    def auto_assign_all(self):
        for cbz in self.cbz_entries:
            self.auto_assign(cbz)

    def clear_cbz(self, cbz_path):
        self._auto.pop(cbz_path, None)
        self._manual_front.pop(cbz_path, None)
        self._manual_back.pop(cbz_path, None)
        self._delete_queue.pop(cbz_path, None)
        self.preview_state.pop(cbz_path, None)
        self.preview_widgets.pop(cbz_path, None)
        self.assignment_widgets.pop(cbz_path, None)
        self.collapse_cbz_tile(cbz_path)
        self.log(f"Cleared assignments for {safe_basename(cbz_path)}")

    def clear_all(self):
        self._auto.clear()
        self._manual_front.clear()
        self._manual_back.clear()
        self._delete_queue.clear()
        self.preview_state.clear()
        self.refresh_list()
        self._global_front.clear()
        self._global_back.clear()
        self.log("Cleared all assignments and deletions")

    def collapse_cbz_tile(self, cbz_path):
        idx = self.cbz_entries.index(cbz_path)
        row = idx // 3
        col = idx % 3
        for widget in self.scrollable_frame.grid_slaves(row=row, column=col):
            widget.destroy()
        self.make_cbz_card(cbz_path)

if __name__ == "__main__":
    if TkinterDnD:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    app = CBZCoverManager(root)
    root.mainloop()
