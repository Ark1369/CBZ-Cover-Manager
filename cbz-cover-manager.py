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
from tkinter import messagebox
import time
import uuid
from tkinter import filedialog, ttk
from collections import OrderedDict

try:
    from tkinterdnd2 import TkinterDnD
    from tkinterdnd2 import DND_FILES
except ImportError:
    TkinterDnD = None
    DND_FILES = None

from PIL import Image, ImageTk, ImageEnhance
from io import BytesIO

# Logging configuration
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LRUZipCache:
    """LRU cache for open ZipFile handles to reduce file I/O"""
    def __init__(self, max_size=15):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.lock = threading.Lock()

    def get(self, path):
        with self.lock:
            if path in self.cache:
                self.cache.move_to_end(path)
                return self.cache[path]
            try:
                zf = zipfile.ZipFile(path, 'r')
                self.cache[path] = zf
                if len(self.cache) > self.max_size:
                    oldest_path, oldest_zf = self.cache.popitem(last=False)
                    try:
                        oldest_zf.close()
                    except:
                        pass
                return zf
            except Exception as e:
                logger.error(f"Failed to open ZIP: {e}")
                return None

    def invalidate(self, path):
        with self.lock:
            if path in self.cache:
                try:
                    self.cache[path].close()
                except:
                    pass
                del self.cache[path]

    def clear(self):
        with self.lock:
            for zf in self.cache.values():
                try:
                    zf.close()
                except:
                    pass
            self.cache.clear()

# === Utility Functions ===
def thread_safe_callback(func, *args, **kwargs):
    """Ensure GUI updates happen on main thread"""
    try:
        func(*args, **kwargs)
    except Exception as e:
        logger.error(f"Error in thread-safe callback: {e}")

def validate_cbz_path(path):
    """Validate CBZ file path for safety"""
    if not path:
        return False
    try:
        normalized = os.path.normpath(os.path.abspath(path))
        if not os.path.exists(normalized):
            logger.warning(f"File does not exist: {normalized}")
            return False
        if not normalized.lower().endswith('.cbz'):
            logger.warning(f"Invalid file extension: {normalized}")
            return False
        return True
    except Exception as e:
        logger.error(f"Path validation error: {e}")
        return False

def extract_vol_number(filename):
    # Look for volume patterns like v01, vol.7, volume 12, etc.
    match = re.search(
        r'\bv(?:ol(?:ume)?)?\.?\s*0*(\d+)\b',
        filename,
        re.IGNORECASE
    )
    return int(match.group(1)) if match else None


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
    logger.info(f"Executing rewrite_cbz")
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
                            continue

                    zout.write(path, arcname)

        os.replace(tmp_cbz, cbz_path)
        return True

    except Exception as e:
        if os.path.exists(tmp_cbz):
            os.remove(tmp_cbz)
        raise e

def fast_append_covers(cbz_path, image_paths, zip_hash_cache=None, global_hash_cache=None):
    logger.info(f"Executing fast_append_covers")
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
                    continue

            cbz.write(path, arcname=arc)

def build_cover_filenames(cover_image_paths):
    """
    FIX #7: Constructs unique filenames with overflow protection
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
            tag = "manual"

        key = (tag, is_back)
        base = base_offsets.get(key, 0)
        count = counters[key]
        filename, ext = os.path.splitext(os.path.basename(path))

        # FIX #7: Handle overflow (>100 covers of same type)
        if count >= 100:
            logger.warning(f"⚠️ Cover overflow for {key}: {count} covers")
            unique_id = uuid.uuid4().hex[:8]
            if is_back:
                arcname = f"zzzzzz_{base}XX_backcover_{tag}_{unique_id}{ext}"
            else:
                arcname = f"!{base}XX_cover_{tag}_{unique_id}{ext}"
        else:
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

class CBZCoverManager:
    def __init__(self, root):
        self.use_compression = True
        self.root = root
        self.root.title("CBZ Cover Manager")
        screen_height = root.winfo_screenheight()
        self.root.geometry(f"1700x{screen_height-80}+80+0")

        style = ttk.Style()
        style.theme_use("clam")
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

        # FIX #2: Changed structure to track which files each global cover applies to
        # OLD: self._global_front = [(path, is_back, tag), ...]
        # NEW: self._global_front = [{'images': [...], 'apply_to': [cbz1, cbz2, ...]}, ...]
        self._global_front = []  # List of dicts with 'images' and 'apply_to' keys
        self._global_back = []   # List of dicts with 'images' and 'apply_to' keys
        self._global_hashes = {}
        # FIX #2: Replace global_cbz_filter with general_filter
        self._general_filter = tk.StringVar()
        self._filtered_cbz_entries = []
        self._dark_mode = tk.BooleanVar(value=False)
        self._menus = []
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._load_zip_as_cbz = tk.BooleanVar(value=False)

        # FIX #3: Thumbnail cache
        self._thumbnail_cache = {}

        # FIX #6: ZIP file handle cache
        self._zip_cache = LRUZipCache(max_size=15)

        # FIXED: Simpler virtual scrolling with placeholder frames
        self._card_frames = {}  # idx -> frame widget (always exists in grid)
        self._card_loaded = {}  # idx -> bool (whether content is loaded)
        self._cards_per_row = 3  # FIX #1: Will be dynamic
        self._min_card_width = 545  # FIX #1: For responsive layout calculation
        self._card_height = 380
        self._last_scroll_pos = 0
        self._scroll_update_pending = False

        def apply_dark_mode(enabled, target=None):
            bg = "#000000" if enabled else "#f4f4f4"
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

        # FIX: Delay drag & drop registration until window is ready
        if TkinterDnD:
            def register_drops():
                try:
                    self.root.drop_target_register(DND_FILES)
                    self.root.dnd_bind('<<Drop>>', self._on_drop)
                    self.log("✅ Drag & drop ready")
                except Exception as e:
                    self.log(f"⚠️ Drag & drop failed: {e}")
            
            # Schedule registration after window is fully ready (300ms delay)
            self.root.after(300, register_drops)


    # FIX #2 & #3: New helper methods for filtering
    def _get_operation_context(self):
        """Returns (display_list, total_count, shown_count, is_filtered)"""
        is_filtered = bool(self._general_filter.get().strip())
        display_list = self._filtered_cbz_entries if is_filtered else self.cbz_entries
        total = len(self.cbz_entries)
        shown = len(display_list)
        return display_list, total, shown, is_filtered

    def _apply_filter(self):
        """FIX #2: Apply filter to visible CBZ entries in real-time"""
        filter_text = self._general_filter.get().strip().lower()

        if not filter_text:
            self._filtered_cbz_entries = self.cbz_entries.copy()
        else:
            self._filtered_cbz_entries = [
                cbz for cbz in self.cbz_entries
                if filter_text in os.path.basename(cbz).lower()
            ]
            total = len(self.cbz_entries)
            shown = len(self._filtered_cbz_entries)
            self.log(f"🔍 Filter active: Displaying {shown} out of {total} files")

        self.refresh_list()
        self.canvas.yview_moveto(0)

    def _calculate_cards_per_row(self):
        """FIX #1: Calculate optimal cards per row based on canvas width"""
        canvas_width = self.canvas.winfo_width()
        if canvas_width < self._min_card_width:
            return 1
        return max(1, canvas_width // self._min_card_width)
        
    def _get_applicable_global_covers(self, cbz_path, side):
        """
        Get global covers that should apply to this specific CBZ file.
        
        Returns list of (path, is_back, tag) tuples that apply to cbz_path.
        
        This fixes the issue where global covers added with different filters
        were being applied to all files instead of just the filtered files.
        """
        covers = self._global_front if side == "front" else self._global_back
        applicable = []
        
        for entry in covers:
            if isinstance(entry, dict):
                # New format: check if this CBZ is in the apply_to list
                if cbz_path in entry.get('apply_to', []):
                    applicable.extend(entry.get('images', []))
            else:
                # Old format compatibility (single tuple): apply to all
                applicable.append(entry)
        
        return applicable

    def ondrop(self, event):
        """Enhanced drag and drop handler"""
        self.log(f"🔍 Drop detected! Event data: {event.data[:100]}...")  # Debug log
        
        try:
            paths = self.root.tk.splitlist(event.data)
            self.log(f"📂 Parsed {len(paths)} path(s)")  # Debug log
        except Exception as e:
            self.log(f"❌ Failed to parse paths: {e}")
            return
        
        cbz_files = []
        folders = []
        
        for path in paths:
            original_path = path
            path = path.strip('{}').strip('"').strip("'")
            self.log(f"🔎 Processing: {path}")  # Debug log
            
            if not os.path.exists(path):
                self.log(f"⚠️ Path does not exist: {path} (original: {original_path})")
                continue        

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
            return btn

        add_btn("Auto Assign All", self.auto_assign_all, "Automatically match images to CBZs by volume number")

        # FIX #5: Make Global Front/Back buttons accept drag & drop
        def create_global_btn(text, side, tooltip):
            btn = ttk.Button(top, text=text, command=lambda: self.assign_global_cover(side))
            btn.pack(side=tk.LEFT, padx=3)

            # Enable drag & drop
            if TkinterDnD and DND_FILES:
                btn.drop_target_register(DND_FILES)
                btn.dnd_bind('<<Drop>>', lambda e, s=side: self._on_global_button_drop(e, s))

            self.add_tooltip(btn, tooltip + " (or drag images here)")
            return btn

        create_global_btn("Global Front", "front", "Assign front cover to filtered files")
        create_global_btn("Global Back", "back", "Assign back cover to filtered files")

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

        # === FIX #2: General Filter (real-time filtering) ===
        self._general_filter.set("")
        filter_entry = ttk.Entry(top, textvariable=self._general_filter, width=25)
        filter_entry.pack(side=tk.RIGHT, padx=(2, 4))
        self._general_filter.trace_add('write', lambda *args: self._apply_filter())
        self.add_tooltip(filter_entry, "Filter displayed files by name (updates in real-time)")
        ttk.Label(top, text="Filter:").pack(side=tk.RIGHT, padx=(4, 2))

        # === Scrollable Canvas ===
        self.canvas = tk.Canvas(self.root, bg="#f4f4f4")
        self.scrollbar = ttk.Scrollbar(self.root, command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self._on_frame_configure()
        )

        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # FIXED: Bind scroll events properly
        self.canvas.bind('<Configure>', self._on_canvas_resize)
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)

        if hasattr(self, '_apply_dark_style'):
            self._apply_dark_style(self._dark_mode.get())

    def _on_frame_configure(self):
        """Update scroll region when frame changes"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._schedule_load_visible_cards()

    def _on_canvas_resize(self, event=None):
        """FIX #1: Handle canvas resize and recalculate layout"""
        new_cards_per_row = self._calculate_cards_per_row()
        if new_cards_per_row != self._cards_per_row:
            self._cards_per_row = new_cards_per_row
            if self.cbz_entries:  # Only refresh if files are loaded
                self.refresh_list()
        else:
            self._schedule_load_visible_cards()

    def _on_mousewheel(self, event):
        """Handle mousewheel scroll"""
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        self._schedule_load_visible_cards()

    def _schedule_load_visible_cards(self):
        """Debounced card loading"""
        if not self._scroll_update_pending:
            self._scroll_update_pending = True
            self.root.after(150, self._load_visible_cards)

    def _load_visible_cards(self):
        """Load content for visible cards only"""
        self._scroll_update_pending = False
        if not self.cbz_entries:
            return

        try:
            # Get canvas viewport
            canvas_height = self.canvas.winfo_height()
            if canvas_height <= 1:
                return

            bbox = self.canvas.bbox("all")
            if not bbox:
                return

            y_view = self.canvas.yview()
            total_height = bbox[3] - bbox[1]

            if total_height <= 0:
                return

            viewport_top = y_view[0] * total_height
            viewport_bottom = y_view[1] * total_height

            # Add buffer
            buffer = self._card_height * 1
            viewport_top = max(0, viewport_top - buffer)
            viewport_bottom = viewport_bottom + buffer

            # Check each card
            display_list = self._filtered_cbz_entries if self._filtered_cbz_entries else self.cbz_entries
            for idx, cbz_path in enumerate(display_list):
                if idx not in self._card_frames:
                    continue

                frame = self._card_frames[idx]

                try:
                    # Get frame position
                    frame_y = frame.winfo_y()
                    frame_height = self._card_height

                    is_visible = (frame_y + frame_height >= viewport_top and frame_y <= viewport_bottom)
                    is_loaded = self._card_loaded.get(idx, False)

                    if is_visible and not is_loaded:
                        # Load this card
                        self._populate_card_content(idx, cbz_path, frame)
                        self._card_loaded[idx] = True

                except tk.TclError:
                    pass

        except Exception as e:
            logger.error(f"Error loading visible cards: {e}")

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
        self._thumbnail_cache.clear()

    def process_queue(self):
        while not self.task_queue.empty():
            func = self.task_queue.get()
            func()
        self.root.after(100, self.process_queue)

    # FIX #5: Handler for drag & drop on Global Front/Back buttons
    def _on_global_button_drop(self, event, side):
        """FIX #2 & #5: Handle images dropped on Global Front/Back buttons"""
        try:
            paths = self.root.tk.splitlist(event.data)
            image_files = []

            for path in paths:
                path = path.strip('{}').strip('"').strip("'")
                if os.path.exists(path) and path.lower().endswith(('.jpg', '.jpeg', '.png', '.webp')):
                    image_files.append(path)

            if not image_files:
                self.log("⚠️ No valid images dropped")
                return

            # Calculate hashes
            cache = {f: file_hash(f) for f in image_files}
            entries = [(f, side == "back", "global") for f in image_files]
            
            # FIX #2: Track which files this applies to
            display_list, total, shown, is_filtered = self._get_operation_context()
            
            # FIX #2: Create new entry with filter context
            new_entry = {
                'images': entries,
                'apply_to': display_list.copy()
            }
            
            if side == "front":
                self._global_front.append(new_entry)
            else:
                self._global_back.append(new_entry)
            
            self._global_hashes.update(cache)
            
            # FIX #6: Enhanced logging
            if is_filtered:
                self.log(f"✅ Added {len(image_files)} image(s) as global {side} to {shown} filtered files [Total: {total}]")
            else:
                self.log(f"✅ Added {len(image_files)} image(s) as global {side} to {shown} file(s)")
                
        except Exception as e:
            self.log(f"❌ Error dropping images: {e}")

    def _on_drop(self, event):
        """Enhanced drag and drop handler"""
        paths = self.root.tk.splitlist(event.data)
        cbz_files = []
        folders = []

        for path in paths:
            path = path.strip('{}').strip('"').strip("'")
            if not os.path.exists(path):
                self.log(f"⚠️ Path does not exist: {path}")
                continue

            if os.path.isdir(path):
                folders.append(path)
            elif path.lower().endswith(".cbz"):
                cbz_files.append(path)
            elif self._load_zip_as_cbz.get() and path.lower().endswith(".zip"):
                cbz_equiv = os.path.splitext(path)[0] + ".cbz"
                try:
                    os.rename(path, cbz_equiv)
                    self.log(f"🔄 Renamed ZIP to CBZ: {os.path.basename(cbz_equiv)}")
                    cbz_files.append(cbz_equiv)
                except Exception as e:
                    self.log(f"❌ Failed to rename {os.path.basename(path)}: {e}")

        if folders:
            if len(folders) == 1:
                self.log(f"🗂️ Processing dropped folder: {os.path.basename(folders[0])}")
                self.load_folder_path(folders[0])
            else:
                self.log(f"🗂️ Processing {len(folders)} dropped folders")
                self.load_multiple_folders(folders)
            return

        if cbz_files:
            self.log(f"📘 Dropped {len(cbz_files)} CBZ file(s)")
            self.load_cbz_files(cbz_files)

    def load_folder_path(self, folder_path):
        """Load CBZ files from a specific folder path"""
        def worker():
            self.executor.call_in_main_thread(lambda: self.log(f"Loading files from {os.path.basename(folder_path)}..."))
            cbz_entries, image_files = [], []

            for root, _, files in os.walk(folder_path):
                for file in files:
                    full = os.path.join(root, file)
                    ext = file.lower()

                    if ext.endswith(".cbz"):
                        cbz_entries.append(full)
                    elif self._load_zip_as_cbz.get() and ext.endswith(".zip"):
                        new_cbz = os.path.splitext(full)[0] + ".cbz"
                        try:
                            os.rename(full, new_cbz)
                            self.executor.call_in_main_thread(
                                lambda p=new_cbz: self.log(f"🔄 Renamed ZIP to CBZ: {os.path.basename(p)}")
                            )
                            cbz_entries.append(new_cbz)
                        except Exception as e:
                            self.executor.call_in_main_thread(
                                lambda err=e: self.log(f"❌ Failed to rename ZIP: {err}")
                            )
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
                self._thumbnail_cache.clear()
                self._zip_cache.clear()

                # FIX #4: Auto-clear global covers
                self._global_front.clear()
                self._global_back.clear()
                self._global_hashes.clear()

                # Reset filter
                self._general_filter.set("")
                self._filtered_cbz_entries = self.cbz_entries.copy()

                self.refresh_list()
                # FIX #2: Reset scroll position
                self.canvas.yview_moveto(0)
                self.log(f"✅ Loaded {len(cbz_entries)} CBZ(s) and {len(image_files)} image(s) from {os.path.basename(folder_path)}")
                self.log("🧹 Auto-cleared global covers")

            self.executor.call_in_main_thread(finalize)

        self.executor.run_async(worker)

    def load_multiple_folders(self, folders):
        """Load CBZ files from multiple folders"""
        def worker():
            self.executor.call_in_main_thread(lambda: self.log(f"Loading files from {len(folders)} folders..."))
            all_cbz_entries, all_image_files = [], []

            for folder_path in folders:
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        full = os.path.join(root, file)
                        ext = file.lower()

                        if ext.endswith(".cbz"):
                            all_cbz_entries.append(full)
                        elif self._load_zip_as_cbz.get() and ext.endswith(".zip"):
                            new_cbz = os.path.splitext(full)[0] + ".cbz"
                            try:
                                os.rename(full, new_cbz)
                                self.executor.call_in_main_thread(
                                    lambda p=new_cbz: self.log(f"🔄 Renamed ZIP to CBZ: {os.path.basename(p)}")
                                )
                                all_cbz_entries.append(new_cbz)
                            except Exception as e:
                                self.executor.call_in_main_thread(
                                    lambda err=e: self.log(f"❌ Failed to rename ZIP: {err}")
                                )
                        elif ext.endswith((".jpg", ".jpeg", ".png", ".webp")):
                            all_image_files.append(full)

            def finalize():
                self.cbz_entries = all_cbz_entries
                self.image_files = all_image_files
                self._auto.clear()
                self._manual_front.clear()
                self._manual_back.clear()
                self._delete_queue.clear()
                self.preview_state.clear()
                self.preview_widgets.clear()
                self.assignment_widgets.clear()
                self._thumbnail_cache.clear()
                self._zip_cache.clear()

                # FIX #4: Auto-clear global covers
                self._global_front.clear()
                self._global_back.clear()
                self._global_hashes.clear()

                # Reset filter
                self._general_filter.set("")
                self._filtered_cbz_entries = self.cbz_entries.copy()

                self.refresh_list()
                # FIX #2: Reset scroll position
                self.canvas.yview_moveto(0)
                self.log(f"✅ Loaded {len(all_cbz_entries)} CBZ(s) and {len(all_image_files)} image(s) from {len(folders)} folders")
                self.log("🧹 Auto-cleared global covers")

            self.executor.call_in_main_thread(finalize)

        self.executor.run_async(worker)

    def load_folder(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self.load_folder_path(folder)

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
        self._thumbnail_cache.clear()
        self._zip_cache.clear()

        # FIX #4: Auto-clear global covers
        self._global_front.clear()
        self._global_back.clear()
        self._global_hashes.clear()

        # Reset filter
        self._general_filter.set("")
        self._filtered_cbz_entries = self.cbz_entries.copy()

        self.refresh_list()
        # FIX #2: Reset scroll position
        self.canvas.yview_moveto(0)
        self.log(f"Loaded {len(self.cbz_entries)} CBZ(s) and {len(self.image_files)} image(s).")
        self.log("🧹 Auto-cleared global covers")

    # FIXED: refresh_list creates all placeholder frames immediately
    def refresh_list(self):
        """FIX #2: Create placeholder frames for filtered CBZ entries"""
        # Clear existing frames
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self._card_frames.clear()
        self._card_loaded.clear()

        # FIX #2: Use filtered list for display
        display_list = self._filtered_cbz_entries if self._filtered_cbz_entries else self.cbz_entries

        # Create placeholder frame for each CBZ
        for idx, cbz_path in enumerate(display_list):
            row = idx // self._cards_per_row
            col = idx % self._cards_per_row

            # Create empty frame placeholder
            frame = ttk.LabelFrame(self.scrollable_frame, text="", width=535, height=self._card_height)
            frame.grid_propagate(False)
            frame.grid_columnconfigure(0, weight=1)
            frame.grid(row=row, column=col, padx=5, pady=5, sticky="nw")

            # Add loading label
            ttk.Label(frame, text=f"Loading...\\n{safe_basename(cbz_path)}",
                     anchor="center", font=("Arial", 9)).pack(expand=True)

            self._card_frames[idx] = frame
            self._card_loaded[idx] = False

        # Force update to establish scroll region
        self.scrollable_frame.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        # FIX #5: Load first batch incrementally
        self.root.after(100, self._load_visible_cards)

    def _populate_card_content(self, idx, cbz_path, frame):
        """Populate a placeholder frame with actual content"""
        # Clear loading label
        for widget in frame.winfo_children():
            widget.destroy()

        # Title
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X)

        ttk.Label(
            title_frame,
            text=safe_basename(cbz_path),
            anchor="center",
            justify="center",
            wraplength=520,
            font=("Arial", 10, "bold")
        ).pack(pady=(4, 2), padx=5)

        # Buttons
        btn_frame = ttk.Frame(frame)
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
        preview_container = ttk.Frame(frame)
        preview_container.pack(pady=4)

        preview_row = ttk.Frame(preview_container)
        preview_row.pack(anchor="center")
        self.preview_widgets[cbz_path] = preview_row

        # Assignment container
        assignment = ttk.Frame(frame)
        assignment.pack(fill=tk.X, padx=4, pady=(2, 4))
        self.assignment_widgets[cbz_path] = assignment

        # FIX #4: Load preview asynchronously
        self.executor.run_async(self._async_render_cbz_preview, cbz_path)
        self.render_assignment_preview(cbz_path)

    # FIX #4: Async preview rendering with caching
    def _async_render_cbz_preview(self, cbz_path):
        """Load preview images asynchronously in background thread"""
        try:
            zf = self._zip_cache.get(cbz_path)
            if not zf:
                return

            images = sorted([
                f for f in zf.namelist()
                if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))
            ])

            if not images:
                self.executor.call_in_main_thread(
                    lambda: self._display_no_images(cbz_path)
                )
                return

            state = self.preview_state.setdefault(cbz_path, {
                "images": images,
                "front": 0,
                "back": len(images) - 1
            })

            state["images"] = images
            state["front"] = min(state["front"], len(images) - 1)
            state["back"] = min(state["back"], len(images) - 1)

            to_delete = self._delete_queue.get(cbz_path, set())

            preview_data = []
            for side in ["front", "back"]:
                idx = state[side]
                if idx >= len(images):
                    continue

                img_name = images[idx]

                # FIX #3: Check thumbnail cache
                cache_key = (cbz_path, img_name, img_name in to_delete)
                if cache_key in self._thumbnail_cache:
                    tkimg = self._thumbnail_cache[cache_key]
                    preview_data.append((side, img_name, tkimg, img_name in to_delete))
                    continue

                try:
                    img_data = zf.read(img_name)
                    dimmed = img_name in to_delete
                    tkimg = get_tk_image(img_data, dimmed=dimmed)

                    # FIX #3: Cache the thumbnail
                    self._thumbnail_cache[cache_key] = tkimg
                    preview_data.append((side, img_name, tkimg, dimmed))

                except Exception as e:
                    logger.error(f"Failed to load image {img_name}: {e}")

            self.executor.call_in_main_thread(
                lambda: self._display_preview_data(cbz_path, preview_data, state)
            )

        except Exception as e:
            logger.error(f"Error in async preview: {e}")
            self.executor.call_in_main_thread(
                lambda: self.log(f"Error reading CBZ: {e}")
            )

    def _display_no_images(self, cbz_path):
        """Display message when CBZ has no images"""
        preview = self.preview_widgets.get(cbz_path)
        if preview:
            for widget in preview.winfo_children():
                widget.destroy()
            ttk.Label(preview, text="No images in CBZ").pack()

    def _display_preview_data(self, cbz_path, preview_data, state):
        """Display loaded preview data in UI"""
        preview = self.preview_widgets.get(cbz_path)
        if not preview:
            return

        for widget in preview.winfo_children():
            widget.destroy()

        preview_row = ttk.Frame(preview)
        preview_row.pack(anchor="center")

        for side, img_name, tkimg, dimmed in preview_data:
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

            # ⭐ Enable drag & drop for this preview label
            if TkinterDnD and DND_FILES:
                label.drop_target_register(DND_FILES)
                label.dnd_bind('<<Drop>>', lambda e, cbz=cbz_path, s=side: self._on_preview_drop(e, cbz, s))

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

                    # FIX #3: Invalidate cached thumbnails
                    for key in list(self._thumbnail_cache.keys()):
                        if key[0] == cbz_path and key[1] == img:
                            del self._thumbnail_cache[key]

                    self.executor.run_async(self._async_render_cbz_preview, cbz_path)

                return toggle

            to_delete = self._delete_queue.get(cbz_path, set())
            btn_text = "Undelete" if img_name in to_delete else "Delete"
            ttk.Button(btns, text=btn_text, command=make_toggle()).pack(side=tk.LEFT, padx=2)

        # Set as Cover Buttons
        cover_btns = ttk.Frame(preview)
        cover_btns.pack(anchor="center", pady=(6, 2))

        def make_set_cover(assign_to):
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
                self.executor.run_async(self._async_render_cbz_preview, cbz_path)

            return set_cover

        ttk.Button(cover_btns, text="Set as Front Cover", command=make_set_cover("front")).pack(side=tk.LEFT, padx=6)
        ttk.Button(cover_btns, text="Set as Back Cover", command=make_set_cover("back")).pack(side=tk.LEFT, padx=6)

    def render_cbz_preview(self, cbz_path):
        """Wrapper that triggers async preview rendering"""
        self.executor.run_async(self._async_render_cbz_preview, cbz_path)

    def _on_preview_drop(self, event, cbz_path, side):
        """Handle dropping images onto front/back preview areas"""
        try:
            paths = self.root.tk.splitlist(event.data)
            image_files = []

            for path in paths:
                path = path.strip('{}').strip('"').strip("'")
                if not os.path.exists(path):
                    self.log(f"⚠️ File does not exist: {path}")
                    continue

                if path.lower().endswith(('.jpg', '.jpeg', '.png', '.webp')):
                    image_files.append(path)
                else:
                    self.log(f"⚠️ Skipping non-image file: {os.path.basename(path)}")

            if not image_files:
                return

            # Add as manual covers
            is_back = (side == "back")
            entries = [(f, is_back, "manual") for f in image_files]

            if is_back:
                self._manual_back.setdefault(cbz_path, []).extend(entries)
            else:
                self._manual_front.setdefault(cbz_path, []).extend(entries)

            self.log(f"✅ Added {len(image_files)} image(s) as manual {side} cover(s) for {safe_basename(cbz_path)}")

            # Update the preview
            self.render_assignment_preview(cbz_path)
            self.executor.run_async(self._async_render_cbz_preview, cbz_path)

        except Exception as e:
            self.log(f"❌ Error dropping images: {e}")

    def _navigate_image(self, cbz_path, side, step):
        state = self.preview_state.get(cbz_path)
        if not state:
            return

        current = state.get(side, 0)
        images = state["images"]
        new_index = max(0, min(len(images) - 1, current + step))
        state[side] = new_index

        # FIX #3: Invalidate cache for old position
        if current != new_index:
            for key in list(self._thumbnail_cache.keys()):
                if key[0] == cbz_path:
                    del self._thumbnail_cache[key]

        self.executor.run_async(self._async_render_cbz_preview, cbz_path)

    def mark_first_image_all(self):
        logger.info(f"Executing mark_first_image_all")
        # FIX #3: Use filtered list
        display_list, total, shown, is_filtered = self._get_operation_context()
        affected = 0

        for cbz_path in display_list:
            try:
                zf = self._zip_cache.get(cbz_path)
                if not zf:
                    continue

                images = sorted([f for f in zf.namelist() if f.lower().endswith(("jpg", "jpeg", "png", "webp"))])
                if images:
                    self._delete_queue.setdefault(cbz_path, set()).add(images[0])
                    self.preview_state.pop(cbz_path, None)
                    idx = self.cbz_entries.index(cbz_path)
                    if idx in self._card_loaded:
                        self._card_loaded[idx] = False
                    affected += 1
            except Exception as e:
                self.log(f"Error marking first image in {cbz_path}: {e}")

        # FIX #6: Enhanced logging
        if is_filtered:
            self.log(f"✅ Marked first image in {affected} filtered file(s) [Showing {shown}/{total}]")
        else:
            self.log(f"✅ Marked first image in {affected} file(s)")
        self._schedule_load_visible_cards()

    def mark_last_image_all(self):
        logger.info(f"Executing mark_last_image_all")
        # FIX #3: Use filtered list
        display_list, total, shown, is_filtered = self._get_operation_context()
        affected = 0

        for cbz_path in display_list:
            try:
                zf = self._zip_cache.get(cbz_path)
                if not zf:
                    continue

                images = sorted([f for f in zf.namelist() if f.lower().endswith(("jpg", "jpeg", "png", "webp"))])
                if images:
                    self._delete_queue.setdefault(cbz_path, set()).add(images[-1])
                    self.preview_state.pop(cbz_path, None)
                    idx = self.cbz_entries.index(cbz_path)
                    if idx in self._card_loaded:
                        self._card_loaded[idx] = False
                    affected += 1
            except Exception as e:
                self.log(f"Error marking last image in {cbz_path}: {e}")

        # FIX #6: Enhanced logging
        if is_filtered:
            self.log(f"✅ Marked last image in {affected} filtered file(s) [Showing {shown}/{total}]")
        else:
            self.log(f"✅ Marked last image in {affected} file(s)")
        self._schedule_load_visible_cards()

    def render_assignment_preview(self, cbzpath):
        frame = self.assignment_widgets.get(cbzpath)
        if not frame:
            return

        for w in frame.winfo_children():
            w.destroy()

        all_sources = [
            (self._manual_front.get(cbzpath, []), '_manual_front'),
            (self._manual_back.get(cbzpath, []), '_manual_back'),
            (self._auto.get(cbzpath, []), '_auto'),
        ]

        combined = []
        src_map = []

        for items, label in all_sources:
            combined.extend(items)
            src_map.extend([(label, i) for i in range(len(items))])

        if not combined:
            return

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

            self._manual_front[cbzpath] = fronts
            self._manual_back[cbzpath] = backs
            self._auto[cbzpath] = autos

        thumbnails = []
        max_per_row = 3
        rows = []

        for i in range(0, len(combined), max_per_row):
            row = ttk.Frame(frame)
            row.pack(fill=tk.X, padx=4, pady=(4 if i == 0 else 2))
            rows.append(row)

        ghost_label = None  # For drag preview

        def on_drag_start(event, label, idx):
            nonlocal ghost_label
            if ghost_label:
                try:
                    ghost_label.destroy()
                except (AttributeError, tk.TclError):
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
                            self.render_assignment_preview(cbzpath)
                        break
                except (AttributeError, ValueError, IndexError):
                    continue

            try:
                label.config(highlightthickness=0)
            except (AttributeError, tk.TclError):
                pass

        def remove_image(index):
            removed = combined.pop(index)
            src_map.pop(index)
            save_reordered(combined)

            idx = self.cbz_entries.index(cbzpath)
            if idx in self._card_loaded:
                self._card_loaded[idx] = False

            self._schedule_load_visible_cards()
            self.log(f"Unassigned image: {os.path.basename(removed[0])}")

        for idx, (path, is_back, tag) in enumerate(combined):
            try:
                if os.path.isfile(path):
                    with open(path, "rb") as f:
                        img_data = f.read()
                else:
                    zf = self._zip_cache.get(cbzpath)
                    if not zf:
                        continue
                    img_data = zf.read(path)

                is_dimmed = (path in self._delete_queue.get(cbzpath, set()))
                cache_key = (path, "assignment", is_dimmed)

                if cache_key in self._thumbnail_cache:
                    tkimg = self._thumbnail_cache[cache_key]
                else:
                    tkimg = get_tk_image(img_data, dimmed=is_dimmed)
                    self._thumbnail_cache[cache_key] = tkimg

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

            # ⭐ DRAG & DROP BINDINGS
            lbl._drag_data = {}
            lbl.bind("<Button-1>", lambda e, l=lbl, i=idx: on_drag_start(e, l, i))
            lbl.bind("<B1-Motion>", lambda e, l=lbl: on_drag_motion(e, l))
            lbl.bind("<ButtonRelease-1>", lambda e, l=lbl: on_drag_release(e, l))

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

        vol_pattern = re.compile(
            rf'v(?:ol(?:ume)?)?\.?\s*0*{vol}(?:\b|$)|'
            rf'\bv\.?\s*0*{vol}(?:\b|$)|'
            rf'\bvol.\.?\s*0*{vol}(?:\b|$)|'
            rf'\bvol\.?\s*0*{vol}(?:\b|$)|'
            rf'\bvolume\s+0*{vol}(?:\b|$)',
            re.IGNORECASE
        )

        matches = [img for img in self.image_files
                   if vol_pattern.search(os.path.basename(img))]

        self._auto[cbz_path] = [(img, img.lower().endswith(('back', 'backcover')), "auto")
                                for img in matches]

        self.log(f"Auto-assigned {len(matches)} image(s) to {safe_basename(cbz_path)}")
        self.render_assignment_preview(cbz_path)

    def auto_assign_all(self):
        for cbz_path in self.cbz_entries:
            self.auto_assign(cbz_path)
        self.log("✅ Auto-assignment completed for all files")

    def assign_global_cover(self, which):
        """FIX #2: Assign global covers with filter context tracking"""
        files = filedialog.askopenfilenames(filetypes=[("Image Files", "*.jpg *.jpeg *.png *.webp")])
        if not files:
            return

        cache = {f: file_hash(f) for f in files}
        entries = [(f, which == "back", "global") for f in files]
        
        # FIX #2: Get current filtered list to track which files this applies to
        display_list, total, shown, is_filtered = self._get_operation_context()
        
        # FIX #2: Create new entry with filter context
        new_entry = {
            'images': entries,
            'apply_to': display_list.copy()  # Save snapshot of which files to apply to
        }
        
        if which == "front":
            self._global_front.append(new_entry)
        else:
            self._global_back.append(new_entry)
        
        self._global_hashes.update(cache)
        
        # FIX #6: Enhanced logging
        if is_filtered:
            self.log(f"📎 Assigned {len(files)} global {which} cover(s) to {shown} filtered file(s) [Total: {total}]")
        else:
            self.log(f"📎 Assigned {len(files)} global {which} cover(s) to {shown} file(s)")



    def clear_global_covers(self):
        self._global_front.clear()
        self._global_back.clear()
        self._global_hashes.clear()
        self.log("🧹 Cleared all global covers")

    def remove_auto_covers(self):
        self._auto.clear()
        self.log("🧹 Removed all auto-assigned covers")
        self.refresh_list()

    def remove_manual_covers(self):
        self._manual_front.clear()
        self._manual_back.clear()
        self.log("🧹 Removed all manually assigned covers")
        self.refresh_list()

    def remove_global_covers(self):
        # Remove global covers from all CBZ files
        display_list, total, shown, is_filtered = self._get_operation_context()
        
        for cbz_path in display_list:
            try:
                zf = self._zip_cache.get(cbz_path)
                if not zf:
                    continue
                
                # Find and mark global covers for deletion
                for img_name in zf.namelist():
                    if img_name.lower().startswith("!") and "_cover_global" in img_name.lower():
                        self._delete_queue.setdefault(cbz_path, set()).add(img_name)
                    elif img_name.lower().startswith("zzzzzz_") and "_backcover_global" in img_name.lower():
                        self._delete_queue.setdefault(cbz_path, set()).add(img_name)
            except Exception as e:
                self.log(f"Error processing {cbz_path}: {e}")
        
        self.clear_global_covers()
        if is_filtered:
            self.log(f"🧹 Removed globally assigned covers from {shown} filtered file(s) [Total: {total}]")
        else:
            self.log(f"🧹 Removed globally assigned covers from {shown} file(s)")
        self.refresh_list()

    def mark_all_covers_for_deletion(self):
        """Mark all added covers (auto, manual, global) for deletion"""
        display_list, total, shown, is_filtered = self._get_operation_context()
        affected = 0
        
        for cbz_path in display_list:
            try:
                zf = self._zip_cache.get(cbz_path)
                if not zf:
                    continue
                
                # Find all cover files
                for img_name in zf.namelist():
                    if (img_name.lower().startswith("!") or 
                        img_name.lower().startswith("zzzzzz_")):
                        if ("_cover_" in img_name.lower() or 
                            "_backcover_" in img_name.lower()):
                            self._delete_queue.setdefault(cbz_path, set()).add(img_name)
                            affected += 1
            except Exception as e:
                self.log(f"Error processing {cbz_path}: {e}")
        
        if is_filtered:
            self.log(f"🧹 Marked {affected} covers for deletion in {shown} filtered file(s) [Total: {total}]")
        else:
            self.log(f"🧹 Marked {affected} covers for deletion in {shown} file(s)")
        self.refresh_list()

    def remove_cbz_covers(self, cbz_path):
        """Remove auto and manual covers from specific CBZ"""
        self._auto.pop(cbz_path, None)
        self._manual_front.pop(cbz_path, None)
        self._manual_back.pop(cbz_path, None)
        self.log(f"🧹 Removed covers from {safe_basename(cbz_path)}")
        self.render_assignment_preview(cbz_path)

    def clear_cbz(self, cbz_path):
        """Clear all assignments for a specific CBZ"""
        self._auto.pop(cbz_path, None)
        self._manual_front.pop(cbz_path, None)
        self._manual_back.pop(cbz_path, None)
        self._delete_queue.pop(cbz_path, None)
        self.preview_state.pop(cbz_path, None)
        
        # Invalidate cache
        for key in list(self._thumbnail_cache.keys()):
            if key[0] == cbz_path:
                del self._thumbnail_cache[key]
        
        self.log(f"🧹 Cleared all assignments for {safe_basename(cbz_path)}")
        
        # Refresh this card
        idx = self.cbz_entries.index(cbz_path)
        if idx in self._card_loaded:
            self._card_loaded[idx] = False
        self._schedule_load_visible_cards()

    def clear_all(self):
        """FIX #4: Clear all assignments and reset filter"""
        self._auto.clear()
        self._manual_front.clear()
        self._manual_back.clear()
        self._delete_queue.clear()
        self.preview_state.clear()
        self._thumbnail_cache.clear()
        
        # FIX #4: Clear global covers
        self._global_front.clear()
        self._global_back.clear()
        self._global_hashes.clear()
        
        # Reset filter
        self._general_filter.set("")
        self._filtered_cbz_entries = self.cbz_entries.copy()
        
        self.refresh_list()
        self.log("🧹 Cleared all assignments, filters, and global covers")

    def apply_cbz(self, cbz_path):
        self.executor.call_in_main_thread(lambda: self.log(f"Applying changes to {os.path.basename(cbz_path)}..."))

        # FIX #2: Get only applicable global covers for this specific CBZ
        global_front = self._get_applicable_global_covers(cbz_path, "front")
        global_back = self._get_applicable_global_covers(cbz_path, "back")

        images = (
            global_front +
            self._auto.get(cbz_path, []) +
            self._manual_front.get(cbz_path, []) +
            self._manual_back.get(cbz_path, []) +
            global_back
        )

        to_delete = self._delete_queue.get(cbz_path, set())

        if not images and not to_delete:
            self.executor.call_in_main_thread(
                lambda: self.log(f"⚠️ No changes to apply for {os.path.basename(cbz_path)}")
            )
            return

        try:
            # ✅ FIX: Force close any open handles (previews) BEFORE touching the file
            self._zip_cache.invalidate(cbz_path)
            # Optional: Short sleep to let the OS release the lock fully
            time.sleep(0.05) 

            # [Existing code continues below...]
            zip_hash_cache = zip_image_hashes(cbz_path)

            if images and not to_delete:
                fast_append_covers(cbz_path, images, zip_hash_cache, self._global_hashes)
            else:
                rewrite_cbz(
                    cbz_path,
                    add_images=images,
                    delete_files=to_delete,
                    zip_hash_cache=zip_hash_cache,
                    global_hash_cache=self._global_hashes,
                    compress=self.use_compression
                )

            # Clear applied assignments
            self._auto.pop(cbz_path, None)
            self._manual_front.pop(cbz_path, None)
            self._manual_back.pop(cbz_path, None)
            self._delete_queue.pop(cbz_path, None)
            self.preview_state.pop(cbz_path, None)

            # Invalidate caches
            self._zip_cache.invalidate(cbz_path)
            for key in list(self._thumbnail_cache.keys()):
                if key[0] == cbz_path:
                    del self._thumbnail_cache[key]

            self.executor.call_in_main_thread(
                lambda: self.log(f"✅ Applied changes to {os.path.basename(cbz_path)}")
            )

            # Refresh this card
            idx = self.cbz_entries.index(cbz_path)
            if idx in self._card_loaded:
                self._card_loaded[idx] = False
            self.executor.call_in_main_thread(self._schedule_load_visible_cards)

        except Exception as e:
            base = os.path.basename(cbz_path)
            err = traceback.format_exc()  # best: keeps the real root cause
            self.executor.call_in_main_thread(
                lambda base=base, err=err: self.log(f"❌ Error applying to {base}:\n{err}")
            )

    def apply_all(self):
        display_list, total, shown, is_filtered = self._get_operation_context()

        def _cbz_has_work(cbz):
            return (self._auto.get(cbz) or self._manual_front.get(cbz) or
                    self._manual_back.get(cbz) or self._delete_queue.get(cbz) or
                    (cbz in display_list and (self._global_front or self._global_back)))

        to_process = [cbz for cbz in display_list if _cbz_has_work(cbz)]

        if not to_process:
            self.log("⚠️ No changes to apply")
            return

        if is_filtered:
            self.log(f"🚀 Applying changes to {len(to_process)} file(s) [Filter: showing {shown}/{total}]")
        else:
            self.log(f"🚀 Applying changes to {len(to_process)} file(s)")

        def worker():
            self.global_progress["maximum"] = len(to_process)
            self.global_progress["value"] = 0
            
            for i, cbz_path in enumerate(to_process):
                try:
                    self.apply_cbz(cbz_path)
                except Exception as e:
                    self.executor.call_in_main_thread(
                        lambda err=e, path=cbz_path: self.log(f"❌ Error: {path}: {err}")
                    )
                
                self.executor.call_in_main_thread(
                    lambda val=i+1: self.global_progress.configure(value=val)
                )
            
            # FIX #4: Auto-clear global covers after Apply All completes
            self.executor.call_in_main_thread(
                lambda: self.clear_global_covers()
            )
            
            self.executor.call_in_main_thread(
                lambda: self.log(f"✅ Apply All completed for {len(to_process)} file(s)")
            )
            self.executor.call_in_main_thread(
                lambda: self.global_progress.configure(value=0)
            )
        
        self.executor.run_async(worker)

    def log(self, msg):
        """Add message to log box"""
        self.log_box.insert(tk.END, f"{msg}\n")
        self.log_box.see(tk.END)
        logger.info(msg)

    def show_about_window(self):
        """Show about dialog"""
        about_text = """CBZ Cover Manager
        
A tool for managing covers in CBZ comic book archives.

Features:
- Auto-assign covers by volume number
- Manually assign front/back covers
- Global covers for multiple files
- Real-time filtering
- Drag & drop support
- Delete first/last images

Version: 2.0 (Fully Fixed)
"""
        messagebox.showinfo("About", about_text)

    def show_help_window(self):
        """Show help dialog"""
        help_text = """Usage Guide:

1. Load CBZ files or folders using the Load button
2. Use Filter to show only specific files
3. Auto Assign All matches covers by volume number
4. Global Front/Back assigns covers to filtered files
5. Click Apply All to save all changes

Tips:
- Drag images onto preview areas to assign
- Drag images onto Global Front/Back buttons
- Use filter to apply changes to specific files only
- Global covers auto-clear when loading new files
"""
        messagebox.showinfo("Help", help_text)


if __name__ == "__main__":
    if TkinterDnD:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
        print("⚠️ tkinterdnd2 not installed - drag & drop disabled")

    app = CBZCoverManager(root)
    root.mainloop()
