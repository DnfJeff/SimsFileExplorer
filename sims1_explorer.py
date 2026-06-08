"""
Sims 1 File Explorer
====================
A Windows-Explorer-style file browser with seamless drill-down into:
  • Filesystem folders
  • ZIP archives
  • FAR1 archives (The Sims 1)
  • IFF files (resources indexed via rsmp or sequential scan)

All parsing is self-contained — no external dependencies beyond stdlib + tkinter.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import zipfile
import struct
import io
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any
import threading


# ─────────────────────────────────────────────────────────────────────────────
#  BINARY READER  (no external deps)
# ─────────────────────────────────────────────────────────────────────────────

class BinReader:
    """Minimal binary reader — little-endian by default, switchable per-call."""

    def __init__(self, data: bytes, big_endian: bool = False):
        self._data = data
        self._pos = 0
        self._be = big_endian

    @property
    def pos(self): return self._pos
    @property
    def remaining(self): return len(self._data) - self._pos
    def has(self, n): return self._pos + n <= len(self._data)
    def seek(self, p): self._pos = p
    def skip(self, n): self._pos += n

    def read_bytes(self, n: int) -> bytes:
        b = self._data[self._pos:self._pos + n]
        self._pos += n
        return b

    def read_u8(self) -> int:
        v = self._data[self._pos]
        self._pos += 1
        return v

    def read_u16(self, big=None) -> int:
        be = self._be if big is None else big
        fmt = '>H' if be else '<H'
        v, = struct.unpack_from(fmt, self._data, self._pos)
        self._pos += 2
        return v

    def read_u32(self, big=None) -> int:
        be = self._be if big is None else big
        fmt = '>I' if be else '<I'
        v, = struct.unpack_from(fmt, self._data, self._pos)
        self._pos += 4
        return v

    def read_i32(self, big=None) -> int:
        be = self._be if big is None else big
        fmt = '>i' if be else '<i'
        v, = struct.unpack_from(fmt, self._data, self._pos)
        self._pos += 4
        return v

    def read_cstr_fixed(self, n: int) -> str:
        """Read n bytes, strip null padding, decode latin-1."""
        raw = self._data[self._pos:self._pos + n]
        self._pos += n
        null = raw.find(b'\x00')
        if null >= 0:
            raw = raw[:null]
        return raw.decode('latin-1', errors='replace')

    def read_cstr_null(self) -> str:
        """Read until null byte."""
        end = self._data.index(b'\x00', self._pos)
        s = self._data[self._pos:end].decode('latin-1', errors='replace')
        self._pos = end + 1
        return s

    def read_cstr_n(self, n: int) -> str:
        """Read exactly n bytes as string (no null stripping)."""
        raw = self._data[self._pos:self._pos + n]
        self._pos += n
        return raw.decode('latin-1', errors='replace')


# ─────────────────────────────────────────────────────────────────────────────
#  FAR1 PARSER
# ─────────────────────────────────────────────────────────────────────────────

FAR_MAGIC = b"FAR!byAZ"

@dataclass
class FarEntry:
    filename: str
    data_offset: int
    data_length: int

def parse_far1(data: bytes) -> List[FarEntry]:
    """Parse a FAR1 archive and return all entries."""
    if len(data) < 16 or data[:8] != FAR_MAGIC:
        raise ValueError("Not a FAR1 archive")
    r = BinReader(data, big_endian=False)
    r.skip(8)               # magic
    version = r.read_u32()  # version
    if version not in (1, 3):
        raise ValueError(f"Unsupported FAR version: {version}")
    manifest_offset = r.read_u32()
    r.seek(manifest_offset)
    num_files = r.read_u32()
    entries = []
    for _ in range(num_files):
        length1 = r.read_i32()
        _length2 = r.read_i32()   # duplicate
        offset   = r.read_i32()
        fname_len = r.read_i32()  # v1a uses 4-byte length
        filename = r.read_cstr_n(fname_len)
        entries.append(FarEntry(filename=filename,
                                data_offset=offset,
                                data_length=length1))
    return entries

def far1_read_entry(data: bytes, entry: FarEntry) -> bytes:
    return data[entry.data_offset: entry.data_offset + entry.data_length]


# ─────────────────────────────────────────────────────────────────────────────
#  IFF PARSER  (resource-level, no chunk-specific parsing)
# ─────────────────────────────────────────────────────────────────────────────

IFF_MAGIC = b"IFF FILE 2.5:TYPE FOLLOWED BY SIZE\x00 JAMIE DOORNBOS & MAXIS 1"

@dataclass
class IffResource:
    type_code: str      # 4-char type tag
    chunk_id: int
    flags: int
    label: str
    data_offset: int    # offset of the data portion inside IFF bytes
    data_size: int
    raw_data: bytes     # raw payload

def parse_iff(data: bytes) -> List[IffResource]:
    """Parse an IFF file and return all resource chunks."""
    if len(data) < 64:
        raise ValueError("File too short to be IFF")

    # Header is 60-byte signature string + 4-byte rsmp offset = 64 bytes total
    sig = data[:60]
    if not sig.startswith(b"IFF FILE"):
        raise ValueError("Not a valid IFF file")

    r = BinReader(data, big_endian=True)   # IFF container = big-endian
    r.seek(64)   # skip header

    resources = []
    while r.has(76):
        chunk_start = r.pos
        type_code = r.read_cstr_fixed(4)
        chunk_size = r.read_u32()    # includes 76-byte header
        chunk_id   = r.read_u16()
        flags      = r.read_u16()
        label      = r.read_cstr_fixed(64)

        header_size = 76
        data_size = chunk_size - header_size
        if data_size < 0 or not r.has(max(data_size, 0)):
            break

        raw = r.read_bytes(data_size) if data_size > 0 else b''

        resources.append(IffResource(
            type_code=type_code,
            chunk_id=chunk_id,
            flags=flags,
            label=label,
            data_offset=chunk_start + header_size,
            data_size=data_size,
            raw_data=raw,
        ))

    return resources


# ─────────────────────────────────────────────────────────────────────────────
#  RSMP PARSER  (used when available to annotate resources)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RsmpEntry:
    file_offset: int
    resource_id: int
    flags: int
    name: str = ""

def parse_rsmp(raw: bytes) -> Dict[Tuple[str, int], RsmpEntry]:
    """Parse an rsmp chunk payload and return a (type_code, res_id) → RsmpEntry map."""
    if len(raw) < 20:
        return {}
    r = BinReader(raw, big_endian=False)  # rsmp internals = little-endian
    try:
        _reserved = r.read_u32()
        version   = r.read_u32()
        _ident    = r.read_bytes(4)   # 'rsmp'
        _size     = r.read_u32()
        type_count = r.read_u32()

        result: Dict[Tuple[str, int], RsmpEntry] = {}
        for _ in range(type_count):
            type_code = r.read_cstr_n(4)
            num_entries = r.read_u32()
            for _ in range(num_entries):
                offset = r.read_u32()
                res_id = r.read_u16()
                if version == 1:
                    res_id_high = r.read_u16()
                    res_id = (res_id_high << 16) | res_id
                flags = r.read_u16()
                name = ""
                if version == 0:
                    name = r.read_cstr_null()
                elif version == 1:
                    name_len = r.read_u8()
                    if name_len > 0:
                        name = r.read_cstr_n(name_len)
                entry = RsmpEntry(file_offset=offset, resource_id=res_id,
                                  flags=flags, name=name)
                result[(type_code, res_id)] = entry
        return result
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
#  RESOURCE TYPE DESCRIPTIONS
# ─────────────────────────────────────────────────────────────────────────────

RESOURCE_DESCRIPTIONS = {
    "OBJD": ("Object Definition",    "🧩"),
    "BHAV": ("Behavior/Script",      "⚙️"),
    "STR#": ("String Table",         "💬"),
    "TTAs": ("Pie Menu Strings",     "💬"),
    "TTAB": ("Pie Menu Table",       "📋"),
    "SPR#": ("Sprite (8-dir)",       "🖼️"),
    "SPR2": ("Sprite (Z-buf)",       "🖼️"),
    "DGRP": ("Draw Group",           "🎨"),
    "PALT": ("Palette",              "🎨"),
    "BCON": ("Behavior Constants",   "🔢"),
    "SLOT": ("Slot Definitions",     "📐"),
    "GLOB": ("Semiglobal Ref",       "🌐"),
    "OBJf": ("Object Functions",     "🔧"),
    "TPRP": ("Tree Properties",      "🌲"),
    "TRCN": ("Tree Constraints",     "🌲"),
    "FWAV": ("Audio Reference",      "🔊"),
    "CATS": ("Catalog Sort",         "📂"),
    "CARR": ("Career Data",          "💼"),
    "CTSS": ("Catalog Strings",      "💬"),
    "FCNS": ("Constants",            "🔢"),
    "NREF": ("Name Reference",       "🔗"),
    "NBRS": ("Neighbor Strings",     "👥"),
    "PDAT": ("Person Data",          "👤"),
    "NGBH": ("Neighborhood Data",    "🏘️"),
    "FAMI": ("Family Data",          "👨‍👩‍👧"),
    "FAMT": ("Family Ties",           "👨‍👩‍👧"),
    "FPOS": ("Floor Position",       "📐"),
    "HOUS": ("House Data",           "🏠"),
    "MOBI": ("Motive Data",          "❤️"),
    "MOTV": ("Motive Vector",        "❤️"),
    "SIMI": ("Sim Info",             "🧑"),
    "VERS": ("Version Info",         "ℹ️"),
    "rsmp": ("Resource Index",       "🗂️"),
    "XMTO": ("Xtra Motives",         "❤️"),
    "MTOP": ("Motive Override",      "❤️"),
}

def resource_icon_label(type_code: str) -> Tuple[str, str]:
    """Return (icon, description) for a resource type code."""
    if type_code in RESOURCE_DESCRIPTIONS:
        desc, icon = RESOURCE_DESCRIPTIONS[type_code]
        return icon, desc
    return "📄", f"Resource ({type_code})"


# ─────────────────────────────────────────────────────────────────────────────
#  VIRTUAL TREE NODE  (represents any item in the explorer)
# ─────────────────────────────────────────────────────────────────────────────

class NodeKind:
    FS_DIR    = "fs_dir"
    FS_FILE   = "fs_file"
    ZIP       = "zip"
    ZIP_DIR   = "zip_dir"
    ZIP_FILE  = "zip_file"
    FAR       = "far"
    FAR_ENTRY = "far_entry"
    IFF       = "iff"
    IFF_RES   = "iff_res"

@dataclass
class Node:
    kind: str
    label: str          # display text
    icon: str           # emoji
    # Payload varies by kind
    path: Optional[str] = None          # filesystem path
    parent_data: Optional[bytes] = None # bytes of parent container
    entry: Any = None                   # FarEntry / IffResource
    is_expandable: bool = False
    metadata: str = ""                  # right-column info


def _fmt_size(n: int) -> str:
    if n < 1024: return f"{n} B"
    if n < 1048576: return f"{n/1024:.1f} KB"
    return f"{n/1048576:.1f} MB"


# ─────────────────────────────────────────────────────────────────────────────
#  EXPLORER BACKEND  (builds child node lists)
# ─────────────────────────────────────────────────────────────────────────────

IFF_EXTENSIONS = {'.iff', '.flr', '.wll', '.spf', '.stx'}
FAR_EXTENSIONS = {'.far', '.far2', '.far3'}
IFF_LIKE_EXTENSIONS = IFF_EXTENSIONS | {'.cmx', '.bcf'}  # VitaBoy too

def _is_iff(filename: str) -> bool:
    return Path(filename).suffix.lower() in IFF_EXTENSIONS | {'.cmx', '.bcf'}

def _is_far(filename: str) -> bool:
    return Path(filename).suffix.lower() in FAR_EXTENSIONS

def children_of(node: Node) -> List[Node]:
    """Return child nodes for any given node."""
    kind = node.kind

    # ── Filesystem directory ──────────────────────────────────────────────
    if kind == NodeKind.FS_DIR:
        children = []
        try:
            entries = sorted(os.scandir(node.path), key=lambda e: (not e.is_dir(), e.name.lower()))
            for e in entries:
                if e.is_dir():
                    children.append(Node(
                        kind=NodeKind.FS_DIR,
                        label=e.name,
                        icon="📁",
                        path=e.path,
                        is_expandable=True,
                    ))
                else:
                    size = e.stat().st_size
                    suffix = Path(e.name).suffix.lower()
                    if suffix == '.zip':
                        children.append(Node(kind=NodeKind.ZIP, label=e.name, icon="🗜️",
                                             path=e.path, is_expandable=True,
                                             metadata=_fmt_size(size)))
                    elif _is_far(e.name):
                        children.append(Node(kind=NodeKind.FAR, label=e.name, icon="📦",
                                             path=e.path, is_expandable=True,
                                             metadata=_fmt_size(size)))
                    elif _is_iff(e.name):
                        children.append(Node(kind=NodeKind.IFF, label=e.name, icon="🗃️",
                                             path=e.path, is_expandable=True,
                                             metadata=_fmt_size(size)))
                    else:
                        children.append(Node(kind=NodeKind.FS_FILE, label=e.name, icon="📄",
                                             path=e.path, is_expandable=False,
                                             metadata=_fmt_size(size)))
        except PermissionError:
            pass
        return children

    # ── ZIP archive (from filesystem) ────────────────────────────────────
    if kind == NodeKind.ZIP:
        return _zip_root_children(node.path)

    # ── ZIP virtual directory ─────────────────────────────────────────────
    if kind == NodeKind.ZIP_DIR:
        return _zip_dir_children(node.path, node.entry)  # entry = prefix str

    # ── FAR archive (from filesystem) ────────────────────────────────────
    if kind in (NodeKind.FAR,):
        try:
            data = Path(node.path).read_bytes()
            entries = parse_far1(data)
            children = []
            for e in sorted(entries, key=lambda x: x.filename.lower()):
                fname = e.filename
                size = e.data_length
                if _is_iff(fname):
                    children.append(Node(kind=NodeKind.IFF, label=fname, icon="🗃️",
                                         path=node.path,
                                         parent_data=data, entry=e,
                                         is_expandable=True,
                                         metadata=_fmt_size(size)))
                elif _is_far(fname):
                    children.append(Node(kind=NodeKind.FAR, label=fname, icon="📦",
                                         path=node.path,
                                         parent_data=data, entry=e,
                                         is_expandable=True,
                                         metadata=_fmt_size(size)))
                else:
                    children.append(Node(kind=NodeKind.FAR_ENTRY, label=fname, icon="📄",
                                         path=node.path,
                                         parent_data=data, entry=e,
                                         is_expandable=False,
                                         metadata=_fmt_size(size)))
            return children
        except Exception as ex:
            return [Node(kind=NodeKind.FS_FILE, label=f"[Error: {ex}]", icon="⚠️",
                         is_expandable=False)]

    # ── IFF file (from filesystem OR from FAR entry) ──────────────────────
    if kind == NodeKind.IFF:
        return _iff_children(node)

    # ── IFF resource (leaf) ───────────────────────────────────────────────
    if kind == NodeKind.IFF_RES:
        return []  # Leaves — no further expansion yet

    return []


def _get_iff_bytes(node: Node) -> bytes:
    """Retrieve raw IFF bytes whether it's a direct file or a FAR entry."""
    if node.parent_data is not None and node.entry is not None:
        # Nested inside FAR
        e = node.entry
        return node.parent_data[e.data_offset: e.data_offset + e.data_length]
    else:
        return Path(node.path).read_bytes()


def _iff_children(node: Node) -> List[Node]:
    try:
        data = _get_iff_bytes(node)
        resources = parse_iff(data)
        if not resources:
            return [Node(kind=NodeKind.FS_FILE, label="(no resources found)", icon="ℹ️",
                         is_expandable=False)]

        # Build rsmp lookup if available
        rsmp_map: Dict[Tuple[str, int], RsmpEntry] = {}
        for res in resources:
            if res.type_code == 'rsmp':
                rsmp_map = parse_rsmp(res.raw_data)
                break

        # Group by type for cleaner display
        type_groups: Dict[str, List[IffResource]] = {}
        for res in resources:
            type_groups.setdefault(res.type_code, []).append(res)

        children = []
        for type_code in sorted(type_groups.keys()):
            group = type_groups[type_code]
            icon, desc = resource_icon_label(type_code)
            for res in sorted(group, key=lambda r: r.chunk_id):
                rsmp_name = ""
                if (type_code, res.chunk_id) in rsmp_map:
                    rsmp_name = rsmp_map[(type_code, res.chunk_id)].name

                label_parts = [f"{type_code} #{res.chunk_id}"]
                # Prefer rsmp name, then chunk label
                display_name = rsmp_name or res.label
                if display_name:
                    label_parts.append(f'"{display_name}"')
                label = "  ".join(label_parts)

                meta = f"{desc} · {_fmt_size(res.data_size)}"

                children.append(Node(
                    kind=NodeKind.IFF_RES,
                    label=label,
                    icon=icon,
                    path=node.path,
                    parent_data=data,
                    entry=res,
                    is_expandable=False,
                    metadata=meta,
                ))
        return children
    except Exception as ex:
        return [Node(kind=NodeKind.FS_FILE, label=f"[Parse error: {ex}]", icon="⚠️",
                     is_expandable=False)]


def _zip_root_children(path: str) -> List[Node]:
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            names = zf.namelist()
        # Gather top-level items
        top: Dict[str, bool] = {}  # name → is_dir
        for name in names:
            parts = name.split('/')
            top_part = parts[0]
            if not top_part:
                continue
            is_dir = len(parts) > 2 or (len(parts) == 2 and parts[1] == '')
            if top_part not in top:
                top[top_part] = is_dir
            elif is_dir:
                top[top_part] = True

        children = []
        for name in sorted(top.keys(), key=lambda x: (not top[x], x.lower())):
            if top[name]:
                children.append(Node(kind=NodeKind.ZIP_DIR, label=name, icon="📁",
                                     path=path, entry=name + "/",
                                     is_expandable=True))
            else:
                children.append(Node(kind=NodeKind.ZIP_FILE, label=name, icon="📄",
                                     path=path, entry=name,
                                     is_expandable=False))
        return children
    except Exception as ex:
        return [Node(kind=NodeKind.FS_FILE, label=f"[ZIP error: {ex}]", icon="⚠️",
                     is_expandable=False)]


def _zip_dir_children(zip_path: str, prefix: str) -> List[Node]:
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()
        # Items at this prefix level
        seen: Dict[str, bool] = {}
        for name in names:
            if not name.startswith(prefix):
                continue
            rest = name[len(prefix):]
            if not rest:
                continue
            parts = rest.split('/')
            top_part = parts[0]
            if not top_part:
                continue
            is_dir = len(parts) > 2 or (len(parts) == 2 and parts[1] == '')
            if top_part not in seen:
                seen[top_part] = is_dir
            elif is_dir:
                seen[top_part] = True

        children = []
        for name in sorted(seen.keys(), key=lambda x: (not seen[x], x.lower())):
            full = prefix + name
            if seen[name]:
                children.append(Node(kind=NodeKind.ZIP_DIR, label=name, icon="📁",
                                     path=zip_path, entry=full + "/",
                                     is_expandable=True))
            else:
                children.append(Node(kind=NodeKind.ZIP_FILE, label=name, icon="📄",
                                     path=zip_path, entry=full,
                                     is_expandable=False))
        return children
    except Exception as ex:
        return [Node(kind=NodeKind.FS_FILE, label=f"[Error: {ex}]", icon="⚠️",
                     is_expandable=False)]


# ─────────────────────────────────────────────────────────────────────────────
#  DETAIL PANEL  — what to show in the right pane
# ─────────────────────────────────────────────────────────────────────────────

def get_detail_lines(node: Node) -> List[Tuple[str, str]]:
    """Return [(label, value)] pairs for the detail pane."""
    lines = []

    if node.kind == NodeKind.FS_DIR:
        lines.append(("Type", "Folder"))
        lines.append(("Path", node.path))
        try:
            items = os.listdir(node.path)
            lines.append(("Items", str(len(items))))
        except:
            pass

    elif node.kind in (NodeKind.FS_FILE, NodeKind.FAR_ENTRY, NodeKind.ZIP_FILE):
        lines.append(("Name", node.label))
        if node.path:
            lines.append(("In", node.path))
        if node.entry and hasattr(node.entry, 'data_length'):
            lines.append(("Size", _fmt_size(node.entry.data_length)))

    elif node.kind in (NodeKind.FAR, NodeKind.ZIP):
        lines.append(("Type", "FAR Archive" if node.kind == NodeKind.FAR else "ZIP Archive"))
        lines.append(("Path", node.path))
        try:
            size = Path(node.path).stat().st_size
            lines.append(("File size", _fmt_size(size)))
        except:
            pass

    elif node.kind == NodeKind.IFF:
        lines.append(("Type", "IFF Resource Container"))
        lines.append(("Name", node.label))
        if node.path:
            lines.append(("Archive / Path", node.path))
        if node.entry and hasattr(node.entry, 'data_length'):
            lines.append(("Size (in FAR)", _fmt_size(node.entry.data_length)))

    elif node.kind == NodeKind.IFF_RES:
        res: IffResource = node.entry
        icon, desc = resource_icon_label(res.type_code)
        lines.append(("Type", f"{icon}  {res.type_code}  —  {desc}"))
        lines.append(("Chunk ID", str(res.chunk_id)))
        lines.append(("Flags", f"0x{res.flags:04X}"))
        if res.label:
            lines.append(("Label", res.label))
        lines.append(("Data size", _fmt_size(res.data_size)))
        lines.append(("Data offset", f"0x{res.data_offset:08X}"))
        # Hex preview
        preview = res.raw_data[:64]
        if preview:
            hex_str = ' '.join(f'{b:02X}' for b in preview)
            lines.append(("Hex preview", hex_str + ("…" if len(res.raw_data) > 64 else "")))

    return lines


# ─────────────────────────────────────────────────────────────────────────────
#  BREADCRUMB BAR
# ─────────────────────────────────────────────────────────────────────────────

class BreadcrumbBar(tk.Frame):
    def __init__(self, parent, on_click, **kwargs):
        super().__init__(parent, **kwargs)
        self._on_click = on_click
        self._crumbs: List[Tuple[str, Any]] = []  # (label, node)
        self.configure(bg="#2b2b2b")

    def set_path(self, crumbs: List[Tuple[str, Any]]):
        for w in self.winfo_children():
            w.destroy()
        self._crumbs = crumbs
        for i, (label, node) in enumerate(crumbs):
            if i > 0:
                sep = tk.Label(self, text=" › ", fg="#888888", bg="#2b2b2b",
                               font=("Segoe UI", 9))
                sep.pack(side=tk.LEFT)
            btn = tk.Button(self, text=label, fg="#4fc3f7", bg="#2b2b2b",
                            relief=tk.FLAT, cursor="hand2",
                            font=("Segoe UI", 9),
                            activeforeground="#ffffff", activebackground="#3a3a3a",
                            padx=2, pady=0,
                            command=lambda n=node: self._on_click(n))
            btn.pack(side=tk.LEFT)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────

DARK_BG   = "#1e1e1e"
PANEL_BG  = "#252526"
TREE_BG   = "#1e1e1e"
TREE_FG   = "#d4d4d4"
SEL_BG    = "#094771"
SEL_FG    = "#ffffff"
DETAIL_BG = "#252526"
HEADER_BG = "#2d2d2d"
ACCENT    = "#4fc3f7"
MUTED     = "#858585"
BORDER    = "#3c3c3c"


class SimsExplorer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sims 1 File Explorer")
        self.geometry("1200x750")
        self.configure(bg=DARK_BG)
        self.minsize(800, 500)

        # State
        self._node_map: Dict[str, Node] = {}        # iid → Node
        self._crumb_stack: List[Tuple[str, Any]] = []  # (label, node)
        self._loading: bool = False

        self._build_ui()
        self._populate_drives()

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self):
        self._style_ttk()

        # Top toolbar
        toolbar = tk.Frame(self, bg=HEADER_BG, height=36)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        toolbar.pack_propagate(False)

        tk.Button(toolbar, text="⬆  Up", command=self._go_up,
                  fg=TREE_FG, bg=HEADER_BG, relief=tk.FLAT,
                  activeforeground="#ffffff", activebackground="#3c3c3c",
                  font=("Segoe UI", 9), padx=10, pady=4).pack(side=tk.LEFT, padx=4, pady=4)

        tk.Button(toolbar, text="📂  Open Folder…", command=self._open_folder,
                  fg=TREE_FG, bg=HEADER_BG, relief=tk.FLAT,
                  activeforeground="#ffffff", activebackground="#3c3c3c",
                  font=("Segoe UI", 9), padx=10, pady=4).pack(side=tk.LEFT, padx=2, pady=4)

        tk.Button(toolbar, text="📦  Open FAR…", command=self._open_far,
                  fg=ACCENT, bg=HEADER_BG, relief=tk.FLAT,
                  activeforeground="#ffffff", activebackground="#3c3c3c",
                  font=("Segoe UI", 9), padx=10, pady=4).pack(side=tk.LEFT, padx=2, pady=4)

        tk.Button(toolbar, text="🗃️  Open IFF…", command=self._open_iff,
                  fg=ACCENT, bg=HEADER_BG, relief=tk.FLAT,
                  activeforeground="#ffffff", activebackground="#3c3c3c",
                  font=("Segoe UI", 9), padx=10, pady=4).pack(side=tk.LEFT, padx=2, pady=4)

        # Status bar
        self._status_var = tk.StringVar(value="Ready")
        status = tk.Label(self, textvariable=self._status_var,
                          fg=MUTED, bg=DARK_BG, anchor=tk.W,
                          font=("Segoe UI", 8), padx=8)
        status.pack(fill=tk.X, side=tk.BOTTOM)

        # Breadcrumb bar
        self._breadcrumb = BreadcrumbBar(self, on_click=self._jump_to_node, bg=DARK_BG)
        self._breadcrumb.pack(fill=tk.X, side=tk.TOP, padx=4, pady=2)

        # Main splitter
        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=BORDER,
                               sashwidth=4, sashrelief=tk.FLAT)
        paned.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        # Left: tree
        left_frame = tk.Frame(paned, bg=PANEL_BG)
        paned.add(left_frame, minsize=300, width=500)

        tree_scroll_y = ttk.Scrollbar(left_frame, orient=tk.VERTICAL)
        tree_scroll_x = ttk.Scrollbar(left_frame, orient=tk.HORIZONTAL)

        self._tree = ttk.Treeview(left_frame,
                                  columns=("meta",),
                                  show="tree headings",
                                  selectmode="browse",
                                  yscrollcommand=tree_scroll_y.set,
                                  xscrollcommand=tree_scroll_x.set)
        self._tree.heading("#0", text="Name", anchor=tk.W)
        self._tree.heading("meta", text="Size / Info", anchor=tk.W)
        self._tree.column("#0", width=360, stretch=True)
        self._tree.column("meta", width=110, stretch=False)

        tree_scroll_y.config(command=self._tree.yview)
        tree_scroll_x.config(command=self._tree.xview)

        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self._tree.pack(fill=tk.BOTH, expand=True)

        self._tree.bind("<<TreeviewOpen>>", self._on_expand)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>", self._on_double_click)
        self._tree.bind("<Return>", self._on_double_click)

        # Right: detail panel
        right_frame = tk.Frame(paned, bg=DETAIL_BG)
        paned.add(right_frame, minsize=250, width=340)

        tk.Label(right_frame, text="Properties", fg=ACCENT, bg=DETAIL_BG,
                 font=("Segoe UI", 10, "bold"), padx=12, pady=8,
                 anchor=tk.W).pack(fill=tk.X)

        sep = tk.Frame(right_frame, height=1, bg=BORDER)
        sep.pack(fill=tk.X)

        self._detail_frame = tk.Frame(right_frame, bg=DETAIL_BG)
        self._detail_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

    def _style_ttk(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Treeview",
                         background=TREE_BG,
                         foreground=TREE_FG,
                         fieldbackground=TREE_BG,
                         borderwidth=0,
                         font=("Segoe UI", 9),
                         rowheight=22)
        style.configure("Treeview.Heading",
                         background=HEADER_BG,
                         foreground=MUTED,
                         font=("Segoe UI", 8),
                         relief=tk.FLAT)
        style.map("Treeview",
                  background=[("selected", SEL_BG)],
                  foreground=[("selected", SEL_FG)])
        style.configure("Vertical.TScrollbar",
                         background=PANEL_BG, troughcolor=DARK_BG,
                         arrowcolor=MUTED, borderwidth=0)
        style.configure("Horizontal.TScrollbar",
                         background=PANEL_BG, troughcolor=DARK_BG,
                         arrowcolor=MUTED, borderwidth=0)

    # ── Initial population ─────────────────────────────────────────────────

    def _populate_drives(self):
        """Populate the tree with filesystem roots."""
        self._tree.delete(*self._tree.get_children())
        self._node_map.clear()

        if sys.platform == "win32":
            import string
            drives = [f"{d}:\\" for d in string.ascii_uppercase
                      if os.path.exists(f"{d}:\\")]
        else:
            drives = ["/"]

        for drive in drives:
            node = Node(kind=NodeKind.FS_DIR, label=drive, icon="💻",
                        path=drive, is_expandable=True)
            iid = self._add_node("", node)
            self._tree.insert(iid, "end", text="loading…")  # lazy expand sentinel

        self._breadcrumb.set_path([("Computer", None)])

    # ── Tree helpers ───────────────────────────────────────────────────────

    def _add_node(self, parent_iid: str, node: Node) -> str:
        text = f"{node.icon}  {node.label}"
        iid = self._tree.insert(parent_iid, "end",
                                text=text,
                                values=(node.metadata,),
                                open=False)
        self._node_map[iid] = node
        return iid

    def _clear_children(self, iid: str):
        for child in self._tree.get_children(iid):
            self._clear_children(child)
            del self._node_map[child]
        self._tree.delete(*self._tree.get_children(iid))

    # ── Events ────────────────────────────────────────────────────────────

    def _on_expand(self, event):
        iid = self._tree.focus()
        if not iid or iid not in self._node_map:
            return
        node = self._node_map[iid]
        if not node.is_expandable:
            return

        children = self._tree.get_children(iid)
        # If only a sentinel "loading…" child, expand for real
        if len(children) == 1 and self._tree.item(children[0])["text"] == "loading…":
            self._tree.delete(children[0])
            self._load_children(iid, node)

    def _load_children(self, parent_iid: str, node: Node):
        self._status_var.set(f"Loading {node.label}…")
        self.update_idletasks()

        child_nodes = children_of(node)
        for cn in child_nodes:
            ciid = self._add_node(parent_iid, cn)
            if cn.is_expandable:
                self._tree.insert(ciid, "end", text="loading…")

        count = len(child_nodes)
        self._status_var.set(f"{count} item{'s' if count != 1 else ''}")

    def _on_select(self, event):
        iid = self._tree.focus()
        if iid and iid in self._node_map:
            self._show_detail(self._node_map[iid])

    def _on_double_click(self, event):
        iid = self._tree.focus()
        if not iid or iid not in self._node_map:
            return
        node = self._node_map[iid]
        if node.is_expandable:
            # Toggle open/closed
            if self._tree.item(iid, "open"):
                self._tree.item(iid, open=False)
            else:
                self._tree.item(iid, open=True)
                self._on_expand(event)

    # ── Navigation ────────────────────────────────────────────────────────

    def _jump_to_node(self, node):
        """Jump back to a breadcrumb node — simplified: just open a new root."""
        if node is None:
            self._populate_drives()

    def _go_up(self):
        iid = self._tree.focus()
        if iid:
            parent = self._tree.parent(iid)
            if parent:
                self._tree.focus(parent)
                self._tree.selection_set(parent)
                self._tree.see(parent)

    def _open_folder(self):
        path = filedialog.askdirectory(title="Open Folder")
        if path:
            self._add_root_node(Node(kind=NodeKind.FS_DIR, label=Path(path).name or path,
                                     icon="📁", path=path, is_expandable=True))

    def _open_far(self):
        path = filedialog.askopenfilename(
            title="Open FAR Archive",
            filetypes=[("FAR Archives", "*.far *.far2 *.far3"), ("All files", "*.*")])
        if path:
            self._add_root_node(Node(kind=NodeKind.FAR, label=Path(path).name,
                                     icon="📦", path=path, is_expandable=True))

    def _open_iff(self):
        path = filedialog.askopenfilename(
            title="Open IFF File",
            filetypes=[("IFF Files", "*.iff *.flr *.wll *.spf *.stx"),
                       ("All files", "*.*")])
        if path:
            self._add_root_node(Node(kind=NodeKind.IFF, label=Path(path).name,
                                     icon="🗃️", path=path, is_expandable=True))

    def _add_root_node(self, node: Node):
        iid = self._add_node("", node)
        self._tree.item(iid, open=True)
        self._tree.insert(iid, "end", text="loading…")
        self._on_expand(None)
        self._tree.focus(iid)
        self._tree.selection_set(iid)
        self._tree.see(iid)

    # ── Detail panel ──────────────────────────────────────────────────────

    def _show_detail(self, node: Node):
        for w in self._detail_frame.winfo_children():
            w.destroy()

        lines = get_detail_lines(node)
        for label, value in lines:
            row = tk.Frame(self._detail_frame, bg=DETAIL_BG)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label + ":", fg=MUTED, bg=DETAIL_BG,
                     font=("Segoe UI", 8), width=14, anchor=tk.NE,
                     justify=tk.RIGHT).pack(side=tk.LEFT, padx=(0, 6))
            # Wrap long values
            val_label = tk.Label(row, text=value, fg=TREE_FG, bg=DETAIL_BG,
                                 font=("Consolas" if "hex" in label.lower() or "offset" in label.lower()
                                       else "Segoe UI", 8),
                                 anchor=tk.NW, justify=tk.LEFT,
                                 wraplength=230)
            val_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Spacer
        tk.Frame(self._detail_frame, bg=DETAIL_BG, height=12).pack()

        # Show kind badge
        kind_colors = {
            NodeKind.FS_DIR:    ("#ffd54f", "Folder"),
            NodeKind.FS_FILE:   (MUTED,     "File"),
            NodeKind.FAR:       ("#ff8a65", "FAR Archive"),
            NodeKind.FAR_ENTRY: ("#ffb74d", "FAR Entry"),
            NodeKind.ZIP:       ("#ce93d8", "ZIP Archive"),
            NodeKind.ZIP_DIR:   ("#ffd54f", "ZIP Folder"),
            NodeKind.ZIP_FILE:  (MUTED,     "ZIP Entry"),
            NodeKind.IFF:       ("#80cbc4", "IFF Container"),
            NodeKind.IFF_RES:   (ACCENT,    "IFF Resource"),
        }
        color, badge = kind_colors.get(node.kind, (MUTED, node.kind))
        tk.Label(self._detail_frame, text=f"  {badge}  ",
                 fg=DARK_BG, bg=color,
                 font=("Segoe UI", 8, "bold"),
                 padx=6, pady=3, relief=tk.FLAT).pack(anchor=tk.W, pady=4)


# ─────────────────────────────────────────────────────────────────────────────

def main():
    app = SimsExplorer()
    app.mainloop()

if __name__ == "__main__":
    main()
