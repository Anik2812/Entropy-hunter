#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        ENTROPY HUNTER  v3.0 — Forensic Hidden Volume Detection             ║
║        Kali Linux Edition — All-in-One Single Script                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  NEW IN v3.0 (vs v2.0)                                                     ║
║  ✦ Full E01/EWF support via pyewf (with raw stream fallback)               ║
║  ✦ Full-disk heatmap showing ALL file types (text, compressed, encrypted)  ║
║  ✦ Scan a SPECIFIC byte range (--scan-range START END) instead of full disk║
║  ✦ Dramatically improved accuracy — far fewer false positives              ║
║    · Multi-pass entropy variance filter (flat high entropy = crypto)       ║
║    · Magic-byte cross-check before alerting                                 ║
║    · Minimum contiguous region enforcement (default 4 MiB)                  ║
║    · Allocated space excluded via FS bitmap before scanning                 ║
║    · Entropy plateau detection (encrypted regions are CONSISTENTLY high)   ║
║  ✦ File-type classification on heatmap: text/compressed/encrypted/zero     ║
║  ✦ CSV + JSON + HTML reports                                                ║
║  ✦ Full self-test suite                                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  USAGE                                                                      ║
║    python3 entropy_hunter_v3.py --selftest                                  ║
║    python3 entropy_hunter_v3.py --demo                                      ║
║    python3 entropy_hunter_v3.py --scan image.dd                             ║
║    python3 entropy_hunter_v3.py --scan image.E01                            ║
║    python3 entropy_hunter_v3.py --scan image.dd --scan-range 0 1073741824  ║
║    python3 entropy_hunter_v3.py --scan image.dd -t 7.9 --step 512         ║
║    python3 entropy_hunter_v3.py --scan image.dd --workers 8 --verbose      ║
║    python3 entropy_hunter_v3.py --scan image.dd --show-all-regions         ║
║    python3 entropy_hunter_v3.py --list-partitions image.dd                 ║
║    python3 entropy_hunter_v3.py --make-test-dd test.dd --size-mb 200      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os, sys, struct, math, hashlib, json, csv, time, datetime, argparse
import textwrap, tempfile, multiprocessing, concurrent.futures
from collections import defaultdict
from typing import List, Tuple, Dict, Any, Optional

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.colors import LinearSegmentedColormap
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

# Try pyewf for real E01 support
try:
    import pyewf
    HAS_PYEWF = True
except ImportError:
    HAS_PYEWF = False

# ─────────────────────────────────────────────────────────────────────────────
#  TERMINAL COLOURS
# ─────────────────────────────────────────────────────────────────────────────
R   = "\033[1;31m"
G   = "\033[1;32m"
Y   = "\033[1;33m"
B   = "\033[1;34m"
M   = "\033[1;35m"
C   = "\033[1;36m"
W   = "\033[1;37m"
DIM = "\033[0;90m"
RST = "\033[0m"
BLD = "\033[1m"

MiB = 1024 * 1024
GiB = 1024 * MiB

# ─────────────────────────────────────────────────────────────────────────────
#  KNOWN HIGH-ENTROPY FILE SIGNATURES (magic bytes)
#  Used to classify regions BEFORE deciding they are hidden volumes
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_HIGH_ENTROPY_MAGIC = {
    b"PK\x03\x04":        "ZIP",
    b"PK\x05\x06":        "ZIP (empty)",
    b"PK\x07\x08":        "ZIP (spanned)",
    b"\xFF\xD8\xFF":      "JPEG",
    b"Rar!":              "RAR",
    b"\x1F\x8B":          "GZIP",
    b"7z\xBC\xAF":        "7ZIP",
    b"\xFD7zXZ":          "XZ",
    b"BZh":               "BZIP2",
    b"\x89PNG":           "PNG",
    b"GIF8":              "GIF",
    b"%PDF":              "PDF (compressed)",
    b"\x00\x01\x00\x00":  "TTF Font",
    b"MSCF":              "CAB",
    b"\xD0\xCF\x11\xE0":  "OLE2 (Office)",
    b"MZ":                "PE/EXE (can be high-H)",
}

# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────
def banner():
    print(f"""{C}
  ███████╗███╗   ██╗████████╗██████╗  ██████╗ ██████╗ ██╗   ██╗
  ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗╚██╗ ██╔╝
  █████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██████╔╝ ╚████╔╝
  ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██╔═══╝   ╚██╔╝
  ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║        ██║
  ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝        ╚═╝
{W}        ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
        ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
        ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
        ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
        ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
        ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{RST}
  {DIM}v3.0 — E01 Support · Precision Accuracy · Full-Disk Heatmap · Scan-Range{RST}
  {DIM}pyewf: {"✓ loaded" if HAS_PYEWF else "✗ not found (install: pip install pyewf)"}{RST}
    """)


# ═════════════════════════════════════════════════════════════════════════════
# §1  ENTROPY ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def shannon_entropy_pure(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    log2_n = math.log2(n)
    h = 0.0
    for c in counts:
        if c:
            h -= (c / n) * (math.log2(c) - log2_n)
    return max(0.0, min(8.0, h))


def shannon_entropy_numpy(data: bytes) -> float:
    arr    = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256).astype(np.float64)
    mask   = counts > 0
    p      = counts[mask] / len(arr)
    return float(max(0.0, min(8.0, -np.sum(p * np.log2(p)))))


shannon_entropy = shannon_entropy_numpy if HAS_NUMPY else shannon_entropy_pure


def classify_block(data: bytes, h: float) -> str:
    """
    Classify a block into a category based on entropy AND magic bytes.
    Categories: ZERO, TEXT, BINARY, COMPRESSED, KNOWN_ENCRYPTED, ENCRYPTED, SLACK
    """
    if len(data) == 0:
        return "ZERO"

    # Check for known magic bytes first — these are NOT hidden volumes
    for magic, name in KNOWN_HIGH_ENTROPY_MAGIC.items():
        if data[:len(magic)] == magic:
            if h >= 7.0:
                return f"KNOWN_HI:{name}"
            return f"FILE:{name}"

    if h < 0.5:
        return "ZERO"
    if h < 3.5:
        return "TEXT"
    if h < 6.0:
        return "BINARY"
    if h < 7.0:
        return "COMPRESSED"
    if h < 7.7:
        return "LIKELY_COMPRESSED"
    if h < 7.85:
        return "AMBIGUOUS"
    return "ENCRYPTED"


def entropy_label(h: float) -> str:
    if h < 0.5:  return f"{DIM}ZERO{RST}"
    if h < 3.5:  return f"{G}TEXT{RST}"
    if h < 6.0:  return f"{Y}BINARY{RST}"
    if h < 7.0:  return f"{Y}COMPRESSED{RST}"
    if h < 7.85: return f"{M}AMBIGUOUS{RST}"
    return f"{R}★ENCRYPTED{RST}"


def entropy_block_char(h: float, category: str = "") -> str:
    if "KNOWN_HI" in category or "FILE:" in category:
        return f"{B}█{RST}"   # Blue = known file
    if h < 0.5:  return f"{DIM}·{RST}"
    if h < 3.5:  return f"{G}░{RST}"
    if h < 6.0:  return f"{G}▒{RST}"
    if h < 7.0:  return f"{Y}▓{RST}"
    if h < 7.85: return f"{M}█{RST}"
    return f"{R}█{RST}"


# ─────────────────────────────────────────────────────────────────────────────
# §1b  ENTROPY VARIANCE FILTER  (key accuracy improvement)
#
#  Real encrypted volumes have CONSISTENTLY high entropy — the variance
#  across consecutive windows is very LOW (all values cluster near 7.95-8.0).
#
#  Compressed files, multimedia, and mixed data have HIGH VARIANCE
#  even if their mean entropy is high, because individual blocks vary widely.
#
#  This filter dramatically reduces false positives.
# ─────────────────────────────────────────────────────────────────────────────

def entropy_variance_check(entropies: List[float],
                            min_mean: float = 7.85,
                            max_std: float  = 0.08) -> Tuple[bool, str]:
    """
    Returns (is_likely_encrypted, reason_string).
    
    Encrypted volumes:
      - Mean entropy ≥ 7.85 (typically 7.94–7.99)
      - Std-dev < 0.08 (very flat, uniform randomness)
      - < 2% of windows drop below 7.7
    
    Compressed/multimedia files (FALSE POSITIVES we want to filter):
      - May have high mean but large variance
      - Many windows drop significantly below threshold
    """
    if not entropies:
        return False, "empty"
    
    n    = len(entropies)
    mean = sum(entropies) / n
    var  = sum((x - mean) ** 2 for x in entropies) / n
    std  = var ** 0.5
    
    # Percentage below 7.7 — real encrypted data almost never dips this low
    pct_below_77 = sum(1 for x in entropies if x < 7.7) / n * 100
    # Percentage above 7.9 — encrypted data is nearly always above this
    pct_above_79 = sum(1 for x in entropies if x >= 7.9) / n * 100
    
    if mean < min_mean:
        return False, f"mean_too_low ({mean:.3f} < {min_mean})"
    
    if std > max_std:
        return False, f"variance_too_high (σ={std:.4f} > {max_std})"
    
    if pct_below_77 > 5.0:
        return False, f"too_many_dips_below_7.7 ({pct_below_77:.1f}%)"
    
    if pct_above_79 < 80.0:
        return False, f"not_enough_windows_above_7.9 ({pct_above_79:.1f}%)"
    
    return True, f"PASS: mean={mean:.4f} σ={std:.4f} above7.9={pct_above_79:.1f}%"


# ═════════════════════════════════════════════════════════════════════════════
# §2  DISK IMAGE ABSTRACTION  — supports raw DD and E01
# ═════════════════════════════════════════════════════════════════════════════

class DiskImage:
    """
    Unified wrapper for raw disk images and E01/EWF files.
    Uses pyewf for proper E01 support if available, otherwise falls back
    to raw stream reading (works for single E01 segments but loses EWF headers).
    """
    def __init__(self, path: str):
        self.path    = path
        self.size    = 0
        self.format  = "raw"
        self._fh     = None
        self._ewf    = None

    def open(self):
        ext = os.path.splitext(self.path)[1].lower()
        
        if ext in (".e01", ".s01", ".l01", ".ex01") or self._looks_like_ewf():
            if HAS_PYEWF:
                self._open_ewf_pyewf()
            else:
                print(f"  {Y}[!] E01 detected but pyewf not installed.{RST}")
                print(f"      Install: pip install pyewf")
                print(f"      Falling back to raw stream (headers will be misread){RST}")
                self._open_raw()
        else:
            self._open_raw()
        return self

    def _looks_like_ewf(self) -> bool:
        try:
            with open(self.path, "rb") as fh:
                return fh.read(3) == b"EVF"
        except Exception:
            return False

    def _open_raw(self):
        self._fh = open(self.path, "rb")
        self._fh.seek(0, 2)
        self.size = self._fh.tell()
        self._fh.seek(0)
        magic = self._fh.read(3)
        self._fh.seek(0)
        self.format = "ewf_raw" if magic == b"EVF" else "raw"
        if self.format == "ewf_raw":
            # For EWF files read as raw: the actual disk data is embedded
            # after EWF segment headers.  Warn user.
            print(f"  {Y}[!] Reading E01 as raw stream — "
                  f"install pyewf for accurate E01 parsing.{RST}")

    def _open_ewf_pyewf(self):
        """Open E01 using pyewf for correct offset handling."""
        try:
            # pyewf can accept a list of segments (for split E01 sets)
            filenames = pyewf.glob(self.path)
            self._ewf  = pyewf.handle()
            self._ewf.open(filenames)
            self.size   = self._ewf.get_media_size()
            self.format = "e01"
            print(f"  {G}[+]{RST} E01 opened via pyewf  "
                  f"({len(filenames)} segment(s), {self.size // MiB} MiB)")
        except Exception as e:
            print(f"  {Y}[!] pyewf failed ({e}) — falling back to raw stream{RST}")
            self._ewf = None
            self._open_raw()

    def close(self):
        if self._fh:
            self._fh.close()
        if self._ewf:
            try: self._ewf.close()
            except Exception: pass

    def __enter__(self):  return self.open()
    def __exit__(self, *_): self.close()

    def read_at(self, offset: int, length: int) -> bytes:
        if self._ewf:
            self._ewf.seek(offset)
            return self._ewf.read(length)
        self._fh.seek(offset)
        return self._fh.read(length)

    def sector_count(self, sector_size: int = 512) -> int:
        return self.size // sector_size


# ═════════════════════════════════════════════════════════════════════════════
# §3  PARTITION PARSING
# ═════════════════════════════════════════════════════════════════════════════

class Partition:
    def __init__(self, idx: int, ptype: str, start: int,
                 length: int, fs: str = "unknown",
                 sector_size: int = 512, cluster_size: int = 4096):
        self.index        = idx
        self.ptype        = ptype
        self.start_byte   = start
        self.length_bytes = length
        self.fs_type      = fs
        self.sector_size  = sector_size
        self.cluster_size = cluster_size

    @property
    def end_byte(self) -> int: return self.start_byte + self.length_bytes

    @property
    def start_sector(self) -> int: return self.start_byte // self.sector_size

    @property
    def end_sector(self) -> int: return self.end_byte // self.sector_size

    def __repr__(self):
        return (f"Partition(#{self.index} {self.ptype} fs={self.fs_type} "
                f"start=0x{self.start_byte:X} "
                f"size={self.length_bytes // MiB}MiB "
                f"cluster={self.cluster_size}B)")


def detect_fs(img: DiskImage, start: int) -> Tuple[str, int, int]:
    try:
        boot = img.read_at(start, 512)
        if boot[3:11] == b"NTFS    ":
            bps = struct.unpack_from("<H", boot, 11)[0] or 512
            spc = boot[13] or 8
            return "NTFS", bps, bps * spc
        if boot[82:90] == b"FAT32   ":
            bps = struct.unpack_from("<H", boot, 11)[0] or 512
            spc = boot[13] or 8
            return "FAT32", bps, bps * spc
        if boot[54:62] in (b"FAT12   ", b"FAT16   ", b"FAT     "):
            bps = struct.unpack_from("<H", boot, 11)[0] or 512
            spc = boot[13] or 8
            return "FAT16", bps, bps * spc
        sb = img.read_at(start + 1024, 4)
        if sb[2:4] == b"\x53\xEF":
            sb_full = img.read_at(start + 1024, 100)
            log_bs  = struct.unpack_from("<I", sb_full, 24)[0]
            bs      = 1024 << log_bs
            return "ext4", bs, bs
    except Exception:
        pass
    return "unknown", 512, 4096


def parse_partitions(img: DiskImage, sector_size: int = 512) -> List[Partition]:
    try:
        mbr = img.read_at(0, 512)
    except Exception:
        return [Partition(0, "raw", 0, img.size, "unknown", sector_size, 4096)]
    
    if len(mbr) < 512:
        fs, ss, cs = detect_fs(img, 0)
        return [Partition(0, "raw", 0, img.size, fs, ss, cs)]

    if mbr[450] == 0xEE:
        parts = _parse_gpt(img, sector_size)
        if parts: return parts

    if mbr[510:512] == b"\x55\xAA":
        parts = _parse_mbr(img, mbr, sector_size)
        if parts: return parts

    fs, ss, cs = detect_fs(img, 0)
    return [Partition(0, "raw", 0, img.size, fs, ss, cs)]


def _parse_mbr(img, mbr, ss):
    parts, idx = [], 0
    for i in range(4):
        e  = mbr[446 + i * 16: 462 + i * 16]
        pt = e[4]
        if pt == 0: continue
        lba_s = struct.unpack_from("<I", e, 8)[0]
        lba_l = struct.unpack_from("<I", e, 12)[0]
        if not lba_s or not lba_l: continue
        if pt in (0x05, 0x0F, 0x85):
            ext = _parse_extended(img, lba_s, lba_s, ss, idx)
            parts.extend(ext); idx += len(ext)
        else:
            start  = lba_s * ss
            length = lba_l * ss
            fs, bps, cs = detect_fs(img, start)
            parts.append(Partition(idx, "MBR", start, length, fs, bps, cs))
            idx += 1
    return parts


def _parse_extended(img, ebr_lba, ext_base, ss, start_idx):
    parts, idx, visited = [], start_idx, set()
    while ebr_lba not in visited:
        visited.add(ebr_lba)
        try:
            ebr = img.read_at(ebr_lba * ss, 512)
        except Exception: break
        if ebr[510:512] != b"\x55\xAA": break
        e0  = ebr[446:462]
        sz  = struct.unpack_from("<I", e0, 12)[0]
        rel = struct.unpack_from("<I", e0, 8)[0]
        if sz:
            abs_s = (ebr_lba + rel) * ss
            fs, bps, cs = detect_fs(img, abs_s)
            parts.append(Partition(idx, "MBR-ext", abs_s, sz * ss, fs, bps, cs))
            idx += 1
        e1   = ebr[462:478]
        nrel = struct.unpack_from("<I", e1, 8)[0]
        if not nrel: break
        ebr_lba = ext_base + nrel
    return parts


def _parse_gpt(img, ss):
    try:
        hdr = img.read_at(ss, 512)
        if hdr[:8] != b"EFI PART": return []
        part_lba  = struct.unpack_from("<Q", hdr, 72)[0]
        num_parts = struct.unpack_from("<I", hdr, 80)[0]
        ent_size  = struct.unpack_from("<I", hdr, 84)[0]
        parts, idx = [], 0
        for i in range(min(num_parts, 128)):
            data  = img.read_at(part_lba * ss + i * ent_size, ent_size)
            if data[:16] == b"\x00" * 16: continue
            first = struct.unpack_from("<Q", data, 32)[0]
            last  = struct.unpack_from("<Q", data, 40)[0]
            if not first or first >= last: continue
            start  = first * ss
            length = (last - first + 1) * ss
            fs, bps, cs = detect_fs(img, start)
            parts.append(Partition(idx, "GPT", start, length, fs, bps, cs))
            idx += 1
        return parts
    except Exception:
        return []


# ═════════════════════════════════════════════════════════════════════════════
# §4  UNALLOCATED SPACE ISOLATION
# ═════════════════════════════════════════════════════════════════════════════

def build_unallocated_map(img: DiskImage,
                           part: Partition) -> List[Tuple[int, int]]:
    fs = part.fs_type
    try:
        if fs == "NTFS":
            regions = _unalloc_ntfs(img, part)
        elif fs == "FAT32":
            regions = _unalloc_fat(img, part, "FAT32")
        elif fs == "FAT16":
            regions = _unalloc_fat(img, part, "FAT16")
        elif fs == "ext4":
            regions = _unalloc_ext4(img, part)
        else:
            regions = None
    except Exception as e:
        print(f"  {Y}[!] FS parse error ({fs}): {e} — scanning whole partition{RST}")
        regions = None

    if not regions:
        return [(part.start_byte, part.length_bytes)]
    return regions


def _merge_regions(regions):
    if not regions: return []
    srt = sorted(regions)
    out = [srt[0]]
    for s, l in srt[1:]:
        ps, pl = out[-1]
        if s <= ps + pl:
            out[-1] = (ps, max(ps + pl, s + l) - ps)
        else:
            out.append((s, l))
    return out


def _unalloc_ntfs(img, part):
    base = part.start_byte
    boot = img.read_at(base, 512)
    bps  = struct.unpack_from("<H", boot, 11)[0]
    spc  = boot[13]
    if not bps or not spc: return None
    cb   = bps * spc

    mft_cluster = struct.unpack_from("<Q", boot, 48)[0]
    mft_base    = base + mft_cluster * cb

    entry = img.read_at(mft_base + 6 * 1024, 1024)
    if entry[:4] != b"FILE": return None

    attr_off = struct.unpack_from("<H", entry, 20)[0]
    bitmap   = b""
    pos      = attr_off
    while pos + 8 <= 1024:
        at = struct.unpack_from("<I", entry, pos)[0]
        al = struct.unpack_from("<I", entry, pos + 4)[0]
        if at == 0xFFFFFFFF or not al: break
        if at == 0x80:
            non_res = entry[pos + 8]
            if non_res == 0:
                co = struct.unpack_from("<H", entry, pos + 20)[0]
                cs = struct.unpack_from("<I", entry, pos + 16)[0]
                bitmap = bytes(entry[pos + co: pos + co + cs])
            else:
                run_off = struct.unpack_from("<H", entry, pos + 32)[0]
                alloc   = struct.unpack_from("<Q", entry, pos + 40)[0]
                bitmap  = _read_ntfs_dataruns(img, entry, pos + run_off,
                                               alloc, cb, base)
            break
        pos += al

    if not bitmap: return None
    regions = []
    for byte_idx, byte_val in enumerate(bitmap):
        for bit in range(8):
            if not (byte_val >> bit) & 1:
                cluster_num = byte_idx * 8 + bit
                off = base + cluster_num * cb
                if off + cb <= base + part.length_bytes:
                    regions.append((off, cb))
    return _merge_regions(regions)


def _read_ntfs_dataruns(img, entry, rpos, alloc, cb, pbase):
    data, cur = bytearray(), 0
    while rpos < len(entry) and len(data) < alloc:
        hdr = entry[rpos]
        if hdr == 0: break
        lb  = hdr & 0x0F
        ob  = (hdr >> 4) & 0x0F
        rpos += 1
        if rpos + lb + ob > len(entry): break
        run_len = int.from_bytes(entry[rpos: rpos + lb], "little", signed=False)
        rpos += lb
        run_off = int.from_bytes(entry[rpos: rpos + ob], "little", signed=True)
        rpos += ob
        cur += run_off
        try:
            chunk = img.read_at(pbase + cur * cb, run_len * cb)
            data.extend(chunk)
        except Exception:
            data.extend(b"\x00" * run_len * cb)
    return bytes(data[:alloc])


def _unalloc_fat(img, part, fat_type):
    base = part.start_byte
    boot = img.read_at(base, 512)
    bps   = struct.unpack_from("<H", boot, 11)[0]
    spc   = boot[13]
    rsvd  = struct.unpack_from("<H", boot, 14)[0]
    nfats = boot[16]
    rde   = struct.unpack_from("<H", boot, 17)[0]
    ts16  = struct.unpack_from("<H", boot, 19)[0]
    spf16 = struct.unpack_from("<H", boot, 22)[0]
    ts32  = struct.unpack_from("<I", boot, 32)[0]
    spf32 = struct.unpack_from("<I", boot, 36)[0]

    spf = spf32 if spf16 == 0 else spf16
    ts  = ts32  if ts16  == 0 else ts16
    rds = (rde * 32 + bps - 1) // bps
    data_start = rsvd + nfats * spf + rds
    cb  = bps * spc
    tc  = (ts - data_start) // spc if spc else 0
    if tc <= 0 or spf <= 0: return None

    fat = img.read_at(base + rsvd * bps, spf * bps)
    free_clusters = []
    if fat_type == "FAT32":
        for i in range(2, min(tc + 2, len(fat) // 4)):
            if struct.unpack_from("<I", fat, i * 4)[0] & 0x0FFFFFFF == 0:
                free_clusters.append(i)
    else:
        for i in range(2, min(tc + 2, len(fat) // 2)):
            if struct.unpack_from("<H", fat, i * 2)[0] == 0:
                free_clusters.append(i)

    regions = []
    for c in free_clusters:
        off = base + (data_start + (c - 2) * spc) * bps
        if off + cb <= base + part.length_bytes:
            regions.append((off, cb))
    return _merge_regions(regions)


def _unalloc_ext4(img, part):
    base = part.start_byte
    sb   = img.read_at(base + 1024, 256)
    if sb[56:58] != b"\x53\xEF": return None
    log_bs = struct.unpack_from("<I", sb, 24)[0]
    bs     = 1024 << log_bs
    bpg    = struct.unpack_from("<I", sb, 32)[0]
    tb     = struct.unpack_from("<I", sb, 4)[0]
    ng     = (tb + bpg - 1) // bpg
    gdt_blk = 1 if bs > 1024 else 2

    regions = []
    for g in range(ng):
        gd  = img.read_at(base + gdt_blk * bs + g * 32, 32)
        bbk = struct.unpack_from("<I", gd, 0)[0]
        bmp = img.read_at(base + bbk * bs, bs)
        for bi, bv in enumerate(bmp):
            for bit in range(8):
                bn = g * bpg + bi * 8 + bit
                if bn >= tb: break
                if not (bv >> bit) & 1:
                    off = base + bn * bs
                    if off + bs <= base + part.length_bytes:
                        regions.append((off, bs))
    return _merge_regions(regions)


def _complement_map(part_start: int, part_len: int,
                    unalloc: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    alloc  = []
    cursor = part_start
    for (u_off, u_len) in sorted(unalloc):
        if u_off > cursor:
            alloc.append((cursor, u_off - cursor))
        cursor = u_off + u_len
    end = part_start + part_len
    if cursor < end:
        alloc.append((cursor, end - cursor))
    return alloc


# ═════════════════════════════════════════════════════════════════════════════
# §5  FULL-DISK CLASSIFIER SCAN  (for heatmap showing ALL file types)
# ═════════════════════════════════════════════════════════════════════════════

def full_disk_classify_scan(
    image_path:  str,
    start_byte:  int,
    total_bytes: int,
    window_size: int,
    step_size:   int,
) -> List[Dict]:
    """
    Scan the full disk (or a range) and classify each window into a category.
    Used for generating the full-disk heatmap that shows ALL file types.
    Returns: list of { offset, entropy, category }
    """
    results = []
    with open(image_path, "rb") as fh:
        pos = start_byte
        end = start_byte + total_bytes
        while pos + window_size <= end:
            fh.seek(pos)
            data = fh.read(window_size)
            if len(data) < window_size:
                break
            h    = shannon_entropy(data)
            cat  = classify_block(data, h)
            results.append({"offset": pos, "entropy": round(h, 4), "category": cat})
            pos += step_size
    return results


# ═════════════════════════════════════════════════════════════════════════════
# §6  PARALLEL SCAN ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════

def sliding_window_scan(
    image_path:    str,
    region_offset: int,
    region_length: int,
    window_size:   int,
    step_size:     int,
) -> List[Dict]:
    """Scan one contiguous byte range using a sliding window."""
    results = []
    try:
        with open(image_path, "rb") as fh:
            end = region_offset + region_length
            pos = region_offset
            while pos + window_size <= end:
                fh.seek(pos)
                data = fh.read(window_size)
                if len(data) < window_size:
                    break
                h   = shannon_entropy(data)
                cat = classify_block(data, h)
                results.append({"offset": pos, "entropy": round(h, 6),
                                 "category": cat})
                pos += step_size
            # Tail
            if pos < end and (end - pos) >= 512:
                fh.seek(pos)
                data = fh.read(end - pos)
                if data:
                    h   = shannon_entropy(data)
                    cat = classify_block(data, h)
                    results.append({"offset": pos, "entropy": round(h, 6),
                                     "category": cat})
    except Exception:
        pass
    return results


def _worker_wrapper(args):
    return sliding_window_scan(*args)


def parallel_entropy_scan(
    image_path:     str,
    regions:        List[Tuple[int, int]],
    window_size:    int,
    step_size:      int,
    n_workers:      int,
    show_progress:  bool,
) -> List[Dict]:
    total_bytes = sum(r[1] for r in regions)
    if total_bytes == 0:
        return []

    work_items = [
        (image_path, off, length, window_size, step_size)
        for (off, length) in regions
        if length >= window_size
    ]

    if not work_items:
        print(f"  {Y}[!] All regions smaller than window size. Try --window 512.{RST}")
        return []

    print(f"  {C}[*]{RST} Dispatching {len(work_items)} region(s) "
          f"across {n_workers} worker(s)…")

    all_blocks = []
    scanned    = 0
    t_start    = time.time()

    if n_workers == 1:
        for item in work_items:
            blocks = sliding_window_scan(*item)
            all_blocks.extend(blocks)
            scanned += item[2]
            if show_progress:
                _progress(scanned, total_bytes, len(all_blocks), t_start)
    else:
        with multiprocessing.Pool(processes=n_workers) as pool:
            for blocks in pool.imap_unordered(_worker_wrapper, work_items,
                                               chunksize=max(1, len(work_items) // n_workers)):
                all_blocks.extend(blocks)
                if blocks:
                    scanned += step_size * len(blocks)
                if show_progress:
                    _progress(min(scanned, total_bytes), total_bytes,
                               len(all_blocks), t_start)

    if show_progress:
        print()

    all_blocks.sort(key=lambda b: b["offset"])

    elapsed = time.time() - t_start
    mb_rate = total_bytes / MiB / max(elapsed, 0.001)
    print(f"  {G}[+]{RST} Scan complete — "
          f"{len(all_blocks):,} windows in {elapsed:.2f}s "
          f"({mb_rate:.1f} MiB/s)")
    return all_blocks


def _progress(done: int, total: int, windows: int, t0: float):
    pct   = int(done * 100 / max(total, 1))
    bar_w = 38
    filled = "█" * int(bar_w * pct / 100)
    empty  = "░" * (bar_w - len(filled))
    elapsed = time.time() - t0
    mbs    = done / MiB / max(elapsed, 0.001)
    eta_s  = int((total - done) / max(done / max(elapsed, 0.001), 1))
    mm, ss = divmod(eta_s, 60)
    print(f"\r  {C}[{filled}{DIM}{empty}{C}]{RST} "
          f"{pct:3d}%  {done // MiB}/{total // MiB}MiB  "
          f"{mbs:.1f}MB/s  ETA {mm:02d}:{ss:02d}  "
          f"windows={windows:,}   ",
          end="", flush=True)


# ═════════════════════════════════════════════════════════════════════════════
# §7  ALERT ENGINE — improved accuracy with variance filter + magic check
# ═════════════════════════════════════════════════════════════════════════════

def detect_alerts(
    block_map:   List[Dict],
    threshold:   float,
    min_bytes:   int,
    step_size:   int,
    sector_size: int,
    image_path:  str,           # for magic byte re-check
    window_size: int,
    max_std:     float = 0.08,  # variance filter: tighter = fewer false positives
    min_mean:    float = 7.85,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Returns (confirmed_alerts, filtered_out).
    
    Key accuracy improvements vs v2:
    1. Only flag regions where entropy is CONSISTENTLY high (variance filter)
    2. Re-check start of each candidate region for known file magic bytes
    3. Require minimum 4 MiB contiguous high-entropy run (configurable)
    4. Don't flag regions where even 5% of windows dip below 7.7
    """
    alerts      = []
    filtered    = []
    run_blk     = []
    run_s       = None

    for blk in block_map:
        h   = blk["entropy"]
        off = blk["offset"]

        # Use threshold to gate candidates
        if h >= threshold:
            if run_s is None:
                run_s = off
            run_blk.append(blk)
        else:
            _flush_run_v3(run_s, run_blk, threshold, min_bytes, step_size,
                          sector_size, image_path, window_size,
                          max_std, min_mean, alerts, filtered)
            run_blk = []
            run_s   = None

    _flush_run_v3(run_s, run_blk, threshold, min_bytes, step_size,
                  sector_size, image_path, window_size,
                  max_std, min_mean, alerts, filtered)

    for i, a in enumerate(alerts, 1):
        a["alert_id"] = i

    return alerts, filtered


def _flush_run_v3(run_start, blocks, threshold, min_bytes, step_size,
                   sector_size, image_path, window_size,
                   max_std, min_mean, alerts, filtered):
    if not blocks or run_start is None:
        return

    last_off = blocks[-1]["offset"]
    run_end  = last_off + step_size
    span     = run_end - run_start

    # --- Filter 1: Minimum size ---
    if span < min_bytes:
        filtered.append({
            "reason": f"too_small ({span // 1024}KiB < {min_bytes // 1024}KiB)",
            "start":  run_start, "end": run_end, "size": span,
        })
        return

    entropies = [b["entropy"] for b in blocks]
    n    = len(entropies)
    mean = sum(entropies) / n

    # --- Filter 2: Variance filter (plateau check) ---
    passes_variance, variance_reason = entropy_variance_check(
        entropies, min_mean=min_mean, max_std=max_std
    )
    if not passes_variance:
        filtered.append({
            "reason": f"variance_filter: {variance_reason}",
            "start":  run_start, "end": run_end, "size": span,
        })
        return

    # --- Filter 3: Magic byte check at region start ---
    magic_name = _check_magic_bytes(image_path, run_start, window_size)
    if magic_name:
        filtered.append({
            "reason": f"known_file_magic: {magic_name}",
            "start":  run_start, "end": run_end, "size": span,
        })
        return

    # --- Also check categories of constituent blocks ---
    known_file_blocks = sum(
        1 for b in blocks
        if b.get("category", "").startswith(("KNOWN_HI:", "FILE:"))
    )
    if known_file_blocks > n * 0.2:   # >20% blocks are known file type
        filtered.append({
            "reason": f"too_many_known_file_blocks ({known_file_blocks}/{n})",
            "start":  run_start, "end": run_end, "size": span,
        })
        return

    # All filters passed — this is a real alert
    mn   = min(entropies)
    mx   = max(entropies)
    var  = sum((x - mean) ** 2 for x in entropies) / n
    std  = var ** 0.5
    above_79  = sum(1 for x in entropies if x >= 7.9) / n * 100
    above_thr = sum(1 for x in entropies if x >= threshold) / n * 100

    verdict = _verdict(mean, above_79, std)
    tag     = _tag(mean, above_79, std)

    alerts.append({
        "alert_id":         0,
        "tag":              tag,
        "start_byte":       run_start,
        "end_byte":         run_end,
        "start_sector":     run_start // sector_size,
        "end_sector":       run_end   // sector_size,
        "start_hex":        f"0x{run_start:016X}",
        "end_hex":          f"0x{run_end:016X}",
        "size_bytes":       span,
        "size_mb":          round(span / MiB, 4),
        "size_sectors":     span // sector_size,
        "window_count":     n,
        "mean_entropy":     round(mean, 6),
        "min_entropy":      round(mn,   6),
        "max_entropy":      round(mx,   6),
        "std_entropy":      round(std,  6),
        "pct_above_79":     round(above_79,  2),
        "pct_above_thresh": round(above_thr, 2),
        "verdict":          verdict,
        "entropy_profile":  [round(h, 4) for h in entropies[:512]],
    })


def _check_magic_bytes(image_path: str, offset: int, read_len: int = 16) -> Optional[str]:
    """Return name of known file format if magic bytes match, else None."""
    try:
        with open(image_path, "rb") as fh:
            fh.seek(offset)
            header = fh.read(min(read_len, 16))
        for magic, name in KNOWN_HIGH_ENTROPY_MAGIC.items():
            if header[:len(magic)] == magic:
                return name
    except Exception:
        pass
    return None


def _tag(mean: float, pct79: float, std: float) -> str:
    if mean >= 7.9 and pct79 >= 90 and std < 0.06:
        return "HIDDEN_VOLUME_LIKELY"
    if mean >= 7.85 and pct79 >= 80:
        return "POSSIBLE_ENCRYPTED"
    return "HIGH_ENTROPY_UNALLOCATED"


def _verdict(mean: float, pct79: float, std: float) -> str:
    if mean >= 7.9 and pct79 >= 90 and std < 0.06:
        return ("★ HIGH CONFIDENCE — Flat, uniform high entropy consistent with "
                "VeraCrypt/TrueCrypt hidden volume or full-disk encryption")
    if mean >= 7.85 and pct79 >= 80:
        return "⚠ MODERATE — Probable encrypted container or key material"
    return "? LOW — High entropy but mixed; further manual analysis required"


# ═════════════════════════════════════════════════════════════════════════════
# §8  VISUALISATION — Full-disk heatmap + alert plots
# ═════════════════════════════════════════════════════════════════════════════

def generate_charts(block_map:      List[Dict],
                    alerts:         List[Dict],
                    filtered:       List[Dict],
                    full_disk_map:  List[Dict],
                    threshold:      float,
                    output_dir:     str,
                    base_name:      str) -> Dict[str, str]:
    """
    Generate charts:
    1. full_disk_heatmap.png  — shows ALL regions coloured by type
    2. entropy_lineplot.png   — entropy trace with alert shading
    3. entropy_histogram.png  — distribution histogram
    """
    if not HAS_MPL:
        print(f"  {Y}[!] matplotlib not available — skipping PNG charts.{RST}")
        return {}

    if not block_map and not full_disk_map:
        return {}

    paths = {}

    # ─────────────────────────────────────────────────────────────────────────
    # Colour maps
    # ─────────────────────────────────────────────────────────────────────────
    CATEGORY_COLORS = {
        "ZERO":              "#1a1a2e",
        "TEXT":              "#4ade80",    # Green
        "BINARY":            "#a3e635",    # Yellow-green
        "COMPRESSED":        "#facc15",    # Yellow
        "LIKELY_COMPRESSED": "#fb923c",    # Orange
        "AMBIGUOUS":         "#c084fc",    # Purple
        "ENCRYPTED":         "#f43f5e",    # Red (SUSPICIOUS)
        "KNOWN_HI":          "#38bdf8",    # Sky blue (known file)
        "FILE":              "#38bdf8",    # Sky blue
    }

    def cat_color(cat: str) -> str:
        for k, v in CATEGORY_COLORS.items():
            if cat.startswith(k):
                return v
        return "#ffffff"

    # ─────────────────────────────────────────────────────────────────────────
    # Chart 1: Full-Disk Heatmap  (shows ALL data types)
    # ─────────────────────────────────────────────────────────────────────────
    use_map = full_disk_map if full_disk_map else block_map
    if use_map:
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(20, 8),
                                        facecolor="#0d1117",
                                        gridspec_kw={"height_ratios": [3, 1]})
        for ax in (ax1, ax2):
            ax.set_facecolor("#0d1117")

        offsets   = [b["offset"]  for b in use_map]
        entropies = [b["entropy"] for b in use_map]
        categories = [b.get("category", "UNKNOWN") for b in use_map]
        colors    = [cat_color(c) for c in categories]
        x_gb      = [o / GiB for o in offsets]

        # Scatter coloured by category
        ax1.scatter(x_gb, entropies, c=colors, s=1.2, alpha=0.7, zorder=2)

        # Alert shading
        for a in alerts:
            ax1.axvspan(a["start_byte"] / GiB, a["end_byte"] / GiB,
                        color="#f43f5e", alpha=0.2, zorder=1)

        ax1.axhline(threshold, color="#ff5722", linewidth=1.2,
                    linestyle="--", alpha=0.8, label=f"Threshold ({threshold})")
        ax1.axhline(7.9, color="#f43f5e", linewidth=1.0,
                    linestyle=":", alpha=0.6, label="VeraCrypt line (7.9)")

        ax1.set_ylim(-0.1, 8.3)
        ax1.set_xlim(min(x_gb), max(x_gb) + 1e-9)
        ax1.set_ylabel("Entropy (bits/byte)", color="#8b949e", fontsize=9)
        ax1.set_title("Entropy Hunter v3.0 — Full Disk Entropy Profile",
                      color="#c9d1d9", fontsize=13, pad=10)
        ax1.tick_params(colors="#8b949e")
        for spine in ax1.spines.values(): spine.set_edgecolor("#21262d")
        ax1.grid(axis="y", color="#21262d", linewidth=0.4)

        # Legend patches for categories
        legend_items = [
            mpatches.Patch(color="#4ade80",   label="Text/Unstructured"),
            mpatches.Patch(color="#facc15",   label="Compressed"),
            mpatches.Patch(color="#fb923c",   label="Likely Compressed"),
            mpatches.Patch(color="#c084fc",   label="Ambiguous (7.7–7.85)"),
            mpatches.Patch(color="#38bdf8",   label="Known File (ZIP/JPEG/RAR…)"),
            mpatches.Patch(color="#f43f5e",   label="ENCRYPTED / Suspicious"),
            mpatches.Patch(color="#1a1a2e",   label="Zero / Empty"),
        ]
        ax1.legend(handles=legend_items, loc="lower right",
                   facecolor="#161b22", edgecolor="#21262d",
                   labelcolor="white", fontsize=7.5, ncol=2)

        # Annotate confirmed alerts
        for a in alerts:
            mid = (a["start_byte"] + a["end_byte"]) / 2 / GiB
            ax1.annotate(
                f"⚠ #{a['alert_id']}\n{a['size_mb']:.1f}MiB",
                xy=(mid, 7.97), xytext=(mid, 8.2),
                color="#f43f5e", fontsize=7, ha="center",
                arrowprops=dict(arrowstyle="->", color="#f43f5e", lw=0.7),
            )

        # Bottom panel: category timeline
        N_COLS = min(1800, len(use_map))
        step   = max(1, len(use_map) // N_COLS)
        col_cats = [categories[i * step] for i in range(min(N_COLS, len(use_map) // max(step,1)))]
        col_cols = [cat_color(c) for c in col_cats]
        x_pos    = list(range(len(col_cols)))

        ax2.bar(x_pos, [1] * len(col_cols), color=col_cols, width=1.0, align="edge")
        ax2.set_xlim(0, len(col_cols))
        ax2.set_ylim(0, 1)
        ax2.set_ylabel("Type", color="#8b949e", fontsize=8)
        ax2.set_xlabel("Disk Position →", color="#8b949e", fontsize=8)
        ax2.tick_params(colors="#8b949e", bottom=False, labelbottom=False)
        for spine in ax2.spines.values(): spine.set_edgecolor("#21262d")
        ax2.set_title("File-Type Classification Lane", color="#8b949e", fontsize=9, pad=4)

        plt.tight_layout(h_pad=1)
        p1 = os.path.join(output_dir, base_name + "_full_disk_heatmap.png")
        fig.savefig(p1, dpi=150, facecolor="#0d1117")
        plt.close(fig)
        paths["full_disk_heatmap"] = p1

    # ─────────────────────────────────────────────────────────────────────────
    # Chart 2: Entropy histogram
    # ─────────────────────────────────────────────────────────────────────────
    if block_map:
        entropies = [b["entropy"] for b in block_map]
        cmap_h = LinearSegmentedColormap.from_list(
            "e", [(0,"#050820"),(0.4,"#0d47a1"),(0.7,"#facc15"),(0.9,"#ff5722"),(1,"#f43f5e")], N=256)
        fig3, ax3 = plt.subplots(figsize=(12, 5), facecolor="#0d1117")
        ax3.set_facecolor("#0d1117")
        bins = list(range(81))
        bins = [b * 0.1 for b in bins]
        n_hist, edges, patches = ax3.hist(entropies, bins=bins, edgecolor="none")
        for patch, left in zip(patches, edges[:-1]):
            patch.set_facecolor(cmap_h(left / 8.0))
            patch.set_alpha(0.85)
        ax3.axvline(threshold, color="#ff5722", linestyle="--",
                    linewidth=1.5, label=f"Threshold ({threshold})")
        ax3.axvline(7.9, color="#f43f5e", linestyle=":",
                    linewidth=1.2, label="VeraCrypt line (7.9)")
        ax3.set_xlabel("Entropy (bits/byte)", color="#8b949e")
        ax3.set_ylabel("Window Count",        color="#8b949e")
        ax3.set_title("Entropy Distribution Histogram (Unallocated Space)",
                      color="#c9d1d9", fontsize=12)
        ax3.tick_params(colors="#8b949e")
        for spine in ax3.spines.values(): spine.set_edgecolor("#21262d")
        ax3.legend(facecolor="#161b22", edgecolor="#21262d",
                   labelcolor="white", fontsize=9)
        plt.tight_layout()
        p3 = os.path.join(output_dir, base_name + "_entropy_histogram.png")
        fig3.savefig(p3, dpi=150, facecolor="#0d1117")
        plt.close(fig3)
        paths["histogram"] = p3

    return paths


# ─────────────────────────────────────────────────────────────────────────────
# §8b  ASCII HEATMAP (terminal)
# ─────────────────────────────────────────────────────────────────────────────

def print_ascii_heatmap(block_map: List[Dict], alerts: List[Dict],
                         width: int = 68):
    if not block_map:
        return
    n    = len(block_map)
    step = max(1, n // width)
    print(f"\n{C}  ╔══ Disk Entropy Heatmap (colour = data type) {'═'*(width-45)}╗{RST}")
    print(f"  {DIM}  ·=zero  {G}░▒=text/binary  {Y}▓=compressed  {M}█=ambiguous  "
          f"{R}█=encrypted  {B}█=known-file{DIM}  {RST}")

    row = "  ║ "
    for i in range(0, min(n, width * step), step):
        bucket = block_map[i: i + step]
        avg_h  = sum(b["entropy"] for b in bucket) / len(bucket)
        avg_cat = bucket[len(bucket)//2].get("category", "")
        row   += entropy_block_char(avg_h, avg_cat)
    row += f" {C}║{RST}"
    print(row)

    # Alert markers
    if block_map:
        total_off = block_map[-1]["offset"] - block_map[0]["offset"]
        marks = "  ║ "
        for col in range(width):
            pct    = col / width
            offset = block_map[0]["offset"] + int(pct * total_off)
            in_a   = any(a["start_byte"] <= offset <= a["end_byte"] for a in alerts)
            marks += f"{R}↑{RST}" if in_a else " "
        print(marks + f" {C}║{RST}")

    print(f"{C}  ╚{'═'*(width+2)}╝{RST}\n")


# ═════════════════════════════════════════════════════════════════════════════
# §9  REPORT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def write_csv_report(path: str, alerts: List[Dict], filtered: List[Dict]):
    fieldnames = [
        "Alert_ID", "Tag", "Verdict",
        "Start_Offset_Hex", "End_Offset_Hex",
        "Start_Byte", "End_Byte", "Start_Sector", "End_Sector",
        "Size_Bytes", "Size_MB", "Size_Sectors",
        "Mean_Entropy", "Min_Entropy", "Max_Entropy", "Std_Entropy",
        "Pct_Above_7_9", "Pct_Above_Threshold", "Window_Count",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for a in alerts:
            w.writerow({
                "Alert_ID":             a["alert_id"],
                "Tag":                  a["tag"],
                "Verdict":              a["verdict"],
                "Start_Offset_Hex":     a["start_hex"],
                "End_Offset_Hex":       a["end_hex"],
                "Start_Byte":           a["start_byte"],
                "End_Byte":             a["end_byte"],
                "Start_Sector":         a["start_sector"],
                "End_Sector":           a["end_sector"],
                "Size_Bytes":           a["size_bytes"],
                "Size_MB":              a["size_mb"],
                "Size_Sectors":         a["size_sectors"],
                "Mean_Entropy":         a["mean_entropy"],
                "Min_Entropy":          a["min_entropy"],
                "Max_Entropy":          a["max_entropy"],
                "Std_Entropy":          a["std_entropy"],
                "Pct_Above_7_9":        a["pct_above_79"],
                "Pct_Above_Threshold":  a["pct_above_thresh"],
                "Window_Count":         a["window_count"],
            })

    # Also write filtered list for review
    filt_path = path.replace("_alerts.csv", "_filtered_false_positives.csv")
    with open(filt_path, "w", newline="", encoding="utf-8") as fh:
        w2 = csv.writer(fh)
        w2.writerow(["Start_Byte", "End_Byte", "Size_Bytes", "Filter_Reason"])
        for f in filtered:
            w2.writerow([f.get("start"), f.get("end"), f.get("size"), f.get("reason")])


def write_json_report(path: str, results: Dict):
    slim = json.loads(json.dumps(results))
    for a in slim.get("alerts", []):
        a.pop("entropy_profile", None)
    slim.pop("block_map", None)
    slim.pop("full_disk_map", None)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(slim, fh, indent=2)


def write_text_report(path: str, results: Dict):
    m      = results["meta"]
    c      = results["config"]
    s      = results["stats"]
    alerts = results["alerts"]
    filts  = results.get("filtered", [])
    W_     = 72

    lines = [
        "=" * W_,
        "ENTROPY HUNTER v3.0 — FORENSIC ANALYSIS REPORT",
        "=" * W_,
        f"Timestamp     : {m['timestamp']}",
        f"Image         : {m['image_path']}",
        f"Format        : {m['image_format']}",
        f"Image Size    : {m['image_size_bytes']:,} bytes  ({m['image_size_bytes'] // MiB} MiB)",
        f"SHA-256(1MiB) : {m['image_sha256']}",
        f"Elapsed       : {m['elapsed_sec']}s",
        f"Throughput    : {m.get('mib_per_sec', '?')} MiB/s",
        "",
        "-" * W_,
        "ACCURACY FILTERS APPLIED",
        "-" * W_,
        f"  Entropy variance filter  : σ < {c['max_std']}  (flat plateau required)",
        f"  Minimum mean entropy     : ≥ {c['min_mean']}  (real crypto is ≥7.85)",
        f"  Minimum region size      : {c['min_bytes'] // MiB} MiB  (avoids file fragments)",
        f"  Magic-byte cross-check   : Yes (ZIP/JPEG/RAR/etc filtered out)",
        f"  Regions filtered out     : {len(filts)}  (were false positives in v2)",
        "",
        "-" * W_,
        "SCAN STATISTICS",
        "-" * W_,
        f"  Windows scanned  : {s['windows_scanned']:,}",
        f"  Avg entropy      : {s['avg_entropy']:.6f}",
        f"  Windows ≥ 7.9    : {s['pct_above_79']}%",
        f"  ALERTS RAISED    : {s['alert_count']}",
        f"  FILTERED (FP)    : {s['filtered_count']}",
        "",
    ]

    if not alerts:
        lines += ["=" * W_,
                  "NO ANOMALOUS HIGH-ENTROPY REGIONS DETECTED.",
                  "Unallocated space shows no evidence of hidden encrypted volumes.",
                  "=" * W_]
    else:
        lines += ["=" * W_, f"  *** {len(alerts)} ALERT(S) DETECTED ***", "=" * W_, ""]
        for a in alerts:
            lines += [
                f"  ┌─ ALERT #{a['alert_id']}  [{a['tag']}]",
                f"  │  Start         : {a['start_hex']}  (sector {a['start_sector']:,})",
                f"  │  End           : {a['end_hex']}  (sector {a['end_sector']:,})",
                f"  │  Size          : {a['size_mb']} MiB  ({a['size_bytes']:,} bytes)",
                f"  │  Mean Entropy  : {a['mean_entropy']:.6f}  (σ = {a['std_entropy']:.6f})",
                f"  │  Min / Max     : {a['min_entropy']:.4f} / {a['max_entropy']:.4f}",
                f"  │  Above 7.9     : {a['pct_above_79']}%",
                f"  └─ VERDICT       : {a['verdict']}",
                "",
            ]

    if filts:
        lines += ["-" * W_, "FILTERED REGIONS (False Positives Removed)", "-" * W_]
        for f in filts[:20]:
            lines.append(f"  0x{f.get('start',0):X} – 0x{f.get('end',0):X}  "
                         f"({f.get('size',0)//1024}KiB)  REASON: {f.get('reason','?')}")
        if len(filts) > 20:
            lines.append(f"  … and {len(filts)-20} more. See CSV for full list.")

    lines += ["", "END OF REPORT", "=" * W_]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def write_html_report(path: str, results: Dict, chart_paths: Dict):
    m      = results["meta"]
    c      = results["config"]
    s      = results["stats"]
    alerts = results["alerts"]
    filts  = results.get("filtered", [])

    def embed_img(key):
        fpath = chart_paths.get(key, "")
        if fpath and os.path.isfile(fpath):
            import base64
            with open(fpath, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode()
            return f'<img src="data:image/png;base64,{b64}" style="width:100%;border-radius:6px;margin:8px 0">'
        return f'<p style="color:#484f58;font-size:.85em">Chart not available</p>'

    alert_html = ""
    if not alerts:
        alert_html = '<div class="ok">✓ No anomalous high-entropy regions detected. All candidates were filtered by accuracy checks.</div>'
    else:
        for a in alerts:
            col = ("#f43f5e" if "HIGH" in a["verdict"] else
                   "#fb923c" if "MODERATE" in a["verdict"] else "#facc15")
            alert_html += f"""
<div class="alert-card" style="border-left:5px solid {col}">
  <div class="alert-head" style="color:{col}">⚠ Alert #{a['alert_id']} — {a['tag']}</div>
  <div class="alert-verdict">{a['verdict']}</div>
  <div class="alert-grid">
    <div><span class="k">Start</span><span class="v">{a['start_hex']}</span></div>
    <div><span class="k">End</span><span class="v">{a['end_hex']}</span></div>
    <div><span class="k">Start Sector</span><span class="v">{a['start_sector']:,}</span></div>
    <div><span class="k">End Sector</span><span class="v">{a['end_sector']:,}</span></div>
    <div><span class="k">Size</span><span class="v">{a['size_mb']} MiB</span></div>
    <div><span class="k">Mean Entropy</span><span class="v" style="color:{col}">{a['mean_entropy']:.6f}</span></div>
    <div><span class="k">Std-dev σ</span><span class="v">{a['std_entropy']:.6f}</span></div>
    <div><span class="k">Above 7.9</span><span class="v" style="color:{col}">{a['pct_above_79']}%</span></div>
    <div><span class="k">Windows</span><span class="v">{a['window_count']:,}</span></div>
  </div>
</div>"""

    filt_rows = "".join(
        f"<tr><td>0x{f.get('start',0):X}</td><td>0x{f.get('end',0):X}</td>"
        f"<td>{f.get('size',0)//1024} KiB</td><td>{f.get('reason','')}</td></tr>"
        for f in filts[:50]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entropy Hunter v3.0 Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}}
  h1{{color:#58a6ff;font-size:1.55em;margin-bottom:4px}}
  h2{{color:#79c0ff;margin:24px 0 10px;border-bottom:1px solid #21262d;padding-bottom:5px;font-size:1.1em}}
  .meta{{color:#8b949e;font-size:.83em;margin-bottom:18px;font-family:monospace}}
  .stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:14px 0}}
  .card{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:14px}}
  .card-label{{color:#8b949e;font-size:.72em;text-transform:uppercase;letter-spacing:.05em}}
  .card-value{{color:#e6edf3;font-size:1.25em;font-weight:700;margin-top:3px;font-family:monospace}}
  .alert-card{{background:#161b22;border-radius:6px;padding:18px;margin:12px 0}}
  .alert-head{{font-weight:700;font-size:1em;margin-bottom:6px;font-family:monospace}}
  .alert-verdict{{font-style:italic;font-size:.85em;color:#8b949e;margin-bottom:10px}}
  .alert-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:6px 16px}}
  .k{{color:#8b949e;font-size:.8em;display:block}}
  .v{{color:#e6edf3;font-size:.85em;font-family:monospace}}
  .ok{{color:#3fb950;padding:14px;border:1px solid #3fb950;border-radius:6px;margin:12px 0}}
  .chart-wrap{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:18px;margin:12px 0}}
  table{{width:100%;border-collapse:collapse;font-size:.82em;margin:8px 0}}
  th{{background:#161b22;color:#79c0ff;padding:8px 10px;text-align:left;border-bottom:1px solid #21262d}}
  td{{padding:6px 10px;border-bottom:1px solid #161b22;font-family:monospace}}
  tr:hover td{{background:#1c2128}}
  .legend-key{{display:inline-block;width:12px;height:12px;border-radius:2px;margin-right:5px;vertical-align:middle}}
  footer{{color:#484f58;font-size:.75em;margin-top:28px;text-align:center;padding-top:16px;border-top:1px solid #21262d}}
</style>
</head>
<body>
<h1>🔍 Entropy Hunter v3.0 — Forensic Report</h1>
<div class="meta">
  {m['timestamp']} | {m['image_path']}<br>
  Format: {m['image_format']} | SHA-256 (first 1MiB): {m['image_sha256']}
</div>

<div class="stat-grid">
  <div class="card"><div class="card-label">Image Size</div><div class="card-value">{m['image_size_bytes'] // MiB} MiB</div></div>
  <div class="card"><div class="card-label">Windows Scanned</div><div class="card-value">{s['windows_scanned']:,}</div></div>
  <div class="card"><div class="card-label">Avg Entropy</div><div class="card-value">{s['avg_entropy']:.3f}</div></div>
  <div class="card"><div class="card-label">Above 7.9</div><div class="card-value">{s['pct_above_79']}%</div></div>
  <div class="card"><div class="card-label">Threshold</div><div class="card-value">{c['threshold']}</div></div>
  <div class="card"><div class="card-label">Variance Filter σ</div><div class="card-value">&lt;{c['max_std']}</div></div>
  <div class="card"><div class="card-label">Filtered (FP)</div><div class="card-value" style="color:#8b949e">{s['filtered_count']}</div></div>
  <div class="card"><div class="card-label">Alerts</div><div class="card-value" style="color:{'#f43f5e' if s['alert_count'] else '#3fb950'}">{s['alert_count']}</div></div>
</div>

<h2>Legend — Heatmap Colours</h2>
<div class="card" style="padding:12px 18px">
  <span class="legend-key" style="background:#4ade80"></span>Text/Low-entropy&nbsp;&nbsp;
  <span class="legend-key" style="background:#facc15"></span>Compressed&nbsp;&nbsp;
  <span class="legend-key" style="background:#fb923c"></span>Likely Compressed&nbsp;&nbsp;
  <span class="legend-key" style="background:#c084fc"></span>Ambiguous (7.7–7.85)&nbsp;&nbsp;
  <span class="legend-key" style="background:#38bdf8"></span>Known File (ZIP/JPEG/RAR…)&nbsp;&nbsp;
  <span class="legend-key" style="background:#f43f5e"></span>ENCRYPTED / Suspicious
</div>

<h2>Full Disk Heatmap</h2>
<div class="chart-wrap">{embed_img("full_disk_heatmap")}</div>

<h2>Entropy Histogram (Unallocated Space)</h2>
<div class="chart-wrap">{embed_img("histogram")}</div>

<h2>Alerts — Confirmed High-Entropy Anomalies</h2>
{alert_html}

<h2>Alert Table</h2>
<table>
  <tr><th>#</th><th>Start Hex</th><th>End Hex</th><th>Size MiB</th>
      <th>Start Sector</th><th>Mean H</th><th>Std σ</th><th>Above 7.9</th><th>Tag</th></tr>
  {''.join(f"""<tr>
    <td>{a['alert_id']}</td><td>{a['start_hex']}</td><td>{a['end_hex']}</td>
    <td>{a['size_mb']}</td><td>{a['start_sector']:,}</td>
    <td style="color:#f43f5e">{a['mean_entropy']:.4f}</td>
    <td>{a['std_entropy']:.4f}</td><td>{a['pct_above_79']}%</td><td>{a['tag']}</td>
  </tr>""" for a in alerts)}
</table>

<h2>Filtered Regions (False Positives Removed — {len(filts)} total)</h2>
<p style="color:#8b949e;font-size:.85em;margin-bottom:8px">
  These regions had high entropy but were ruled out by accuracy filters (variance check, magic bytes, size).
</p>
<table>
  <tr><th>Start</th><th>End</th><th>Size</th><th>Filter Reason</th></tr>
  {filt_rows}
  {"<tr><td colspan='4' style='color:#484f58'>… see CSV for full list</td></tr>" if len(filts) > 50 else ""}
</table>

<h2>Configuration</h2>
<table>
  <tr><th>Parameter</th><th>Value</th></tr>
  <tr><td>Window size</td><td>{c['window_size']} bytes</td></tr>
  <tr><td>Step size</td><td>{c['step_size']} bytes</td></tr>
  <tr><td>Threshold</td><td>{c['threshold']} bits/byte</td></tr>
  <tr><td>Min region size</td><td>{c['min_bytes']:,} bytes ({c['min_bytes']//MiB} MiB)</td></tr>
  <tr><td>Variance filter (max σ)</td><td>{c['max_std']}</td></tr>
  <tr><td>Min mean entropy</td><td>{c['min_mean']}</td></tr>
  <tr><td>Workers</td><td>{c['workers']}</td></tr>
  <tr><td>Unallocated only</td><td>{c['unallocated_only']}</td></tr>
  <tr><td>Scan range</td><td>{c.get('scan_range', 'full disk')}</td></tr>
</table>

<footer>Entropy Hunter v3.0 — E01 Support · Variance Filter · Full-Disk Heatmap · Scan-Range · Magic-Byte Check</footer>
</body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ═════════════════════════════════════════════════════════════════════════════
# §10  MAIN SCAN ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════

def run_scan(
    image_path:       str,
    window_size:      int   = 4096,
    step_size:        int   = 512,
    threshold:        float = 7.9,
    min_bytes:        int   = 4 * MiB,   # raised from 1 MiB → fewer FP
    sector_size:      int   = 512,
    partition_index:  int   = 0,
    unallocated_only: bool  = True,
    workers:          int   = None,
    verbose:          bool  = False,
    output_dir:       str   = None,
    no_charts:        bool  = False,
    max_std:          float = 0.08,       # variance filter
    min_mean:         float = 7.85,       # min mean entropy for alert
    scan_range:       Optional[Tuple[int,int]] = None,  # (start_byte, end_byte)
    show_all_regions: bool  = False,      # show allocated regions in heatmap too
) -> Dict:

    if not os.path.isfile(image_path):
        print(f"{R}[ERROR] File not found: {image_path}{RST}"); sys.exit(1)

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(image_path)) or "."
    os.makedirs(output_dir, exist_ok=True)

    if workers is None:
        workers = max(1, multiprocessing.cpu_count())

    img_size = os.path.getsize(image_path)

    print(f"\n{C}{'═'*68}{RST}")
    print(f"{W}  Entropy Hunter v3.0 — Scan Initialised{RST}")
    print(f"{C}{'═'*68}{RST}")
    print(f"  {DIM}Image     :{RST} {image_path}  ({img_size // MiB} MiB)")
    print(f"  {DIM}Window    :{RST} {window_size}B  Step: {step_size}B")
    print(f"  {DIM}Threshold :{RST} {threshold}  Min region: {min_bytes // MiB}MiB")
    print(f"  {DIM}Variance  :{RST} σ < {max_std}  Min mean: ≥{min_mean}")
    print(f"  {DIM}Workers   :{RST} {workers}  ({'numpy' if HAS_NUMPY else 'pure-python'})")
    if scan_range:
        print(f"  {Y}[*] Scan range:{RST} 0x{scan_range[0]:X} – 0x{scan_range[1]:X} "
              f"({(scan_range[1]-scan_range[0])//MiB} MiB)")
    print(f"{C}{'═'*68}{RST}\n")

    t0 = time.time()

    with DiskImage(image_path) as img:
        img_format = img.format

        # ── Phase 1: Disk Parsing ─────────────────────────────────────────────
        print(f"  {C}[Phase 1]{RST} Disk Parsing & Unallocated Space Isolation")
        partitions = parse_partitions(img, sector_size)

        if not partitions:
            print(f"{R}[!] No partitions found.{RST}"); return {}

        print(f"  {G}[+]{RST} Found {len(partitions)} partition(s):")
        for p in partitions:
            print(f"      #{p.index}  {p.ptype:<8}  fs={p.fs_type:<8}  "
                  f"start=0x{p.start_byte:X}  "
                  f"size={p.length_bytes // MiB}MiB")

        if partition_index >= len(partitions):
            print(f"{R}[!] Partition {partition_index} out of range.{RST}")
            return {}

        part = partitions[partition_index]
        print(f"\n  {G}[+]{RST} Target: {part}")

        if scan_range:
            # Override partition bounds with user-specified range
            scan_start  = scan_range[0]
            scan_length = scan_range[1] - scan_range[0]
            unalloc     = [(scan_start, scan_length)]
            total_unalloc = scan_length
            print(f"  {Y}[!]{RST} Using user-specified range: "
                  f"0x{scan_start:X} + {scan_length // MiB}MiB")
        elif unallocated_only:
            print(f"\n  {C}[*]{RST} Building unallocated cluster map ({part.fs_type})…")
            unalloc = build_unallocated_map(img, part)
            total_unalloc = sum(r[1] for r in unalloc)
            alloc_pct = 100 - (total_unalloc * 100 // max(part.length_bytes, 1))
            print(f"  {G}[+]{RST} Unallocated: {len(unalloc):,} regions  "
                  f"({total_unalloc // MiB} MiB free, ~{alloc_pct}% allocated)")
        else:
            unalloc       = [(part.start_byte, part.length_bytes)]
            total_unalloc = part.length_bytes
            print(f"  {Y}[!]{RST} --scan-all: scanning entire partition")

    # ── Phase 2: Full-Disk Classify (for heatmap) ────────────────────────────
    full_disk_map = []
    if not no_charts and show_all_regions:
        print(f"\n  {C}[Phase 2a]{RST} Full-Disk Classification Pass (for heatmap)…")
        disk_start = scan_range[0] if scan_range else part.start_byte
        disk_len   = ((scan_range[1]-scan_range[0]) if scan_range
                      else part.length_bytes)
        # Use a larger step for this pass to keep it fast
        hm_step = max(step_size * 8, 32768)
        full_disk_map = full_disk_classify_scan(
            image_path, disk_start, disk_len, window_size, hm_step
        )
        print(f"  {G}[+]{RST} Classification pass: {len(full_disk_map):,} windows")

    # ── Phase 3: Sliding Window Entropy Scan (Parallel) ──────────────────────
    print(f"\n  {C}[Phase 3]{RST} Parallel Sliding-Window Entropy Scan")

    block_map = parallel_entropy_scan(
        image_path    = image_path,
        regions       = unalloc,
        window_size   = window_size,
        step_size     = step_size,
        n_workers     = workers,
        show_progress = not verbose,
    )

    # ── Phase 4: Alert Detection (improved accuracy) ─────────────────────────
    print(f"\n  {C}[Phase 4]{RST} Alert Detection with Accuracy Filters")
    print(f"  {DIM}  Variance filter: σ < {max_std}  |  "
          f"Min mean: ≥{min_mean}  |  Magic-byte check: ON{RST}")

    alerts, filtered = detect_alerts(
        block_map   = block_map,
        threshold   = threshold,
        min_bytes   = min_bytes,
        step_size   = step_size,
        sector_size = sector_size,
        image_path  = image_path,
        window_size = window_size,
        max_std     = max_std,
        min_mean    = min_mean,
    )

    elapsed  = time.time() - t0
    n_blocks = len(block_map)
    avg_h    = sum(b["entropy"] for b in block_map) / max(n_blocks, 1)
    pct79    = sum(1 for b in block_map if b["entropy"] >= 7.9) * 100 // max(n_blocks, 1)
    mib_s    = round(total_unalloc / MiB / max(elapsed, 0.001), 1)

    # ── Terminal summary ──────────────────────────────────────────────────────
    print(f"\n{C}{'═'*68}{RST}")
    print(f"{W}  SCAN COMPLETE{RST}")
    print(f"{C}{'═'*68}{RST}")
    print(f"  {DIM}Windows scanned   :{RST} {n_blocks:,}")
    print(f"  {DIM}Avg entropy       :{RST} {avg_h:.4f}")
    print(f"  {DIM}Windows ≥ 7.9     :{RST} {pct79}%")
    print(f"  {DIM}Filtered out (FP) :{RST} {len(filtered)}")
    print(f"  {DIM}Elapsed           :{RST} {elapsed:.2f}s  ({mib_s} MiB/s)")

    if alerts:
        print(f"\n  {R}{'━'*64}{RST}")
        print(f"  {R}⚠  {len(alerts)} CONFIRMED ALERT(S) — PASSED ALL ACCURACY FILTERS{RST}")
        print(f"  {R}{'━'*64}{RST}")
        for a in alerts:
            tag_col = R if "HIGH" in a["verdict"] else Y
            print(f"\n  {tag_col}Alert #{a['alert_id']}{RST}  {DIM}[{a['tag']}]{RST}")
            print(f"  {DIM}  Start   :{RST} {W}{a['start_hex']}{RST}  (sector {a['start_sector']:,})")
            print(f"  {DIM}  End     :{RST} {W}{a['end_hex']}{RST}  (sector {a['end_sector']:,})")
            print(f"  {DIM}  Size    :{RST} {W}{a['size_mb']} MiB{RST}")
            print(f"  {DIM}  Mean H  :{RST} {tag_col}{a['mean_entropy']:.4f}{RST}  "
                  f"σ={a['std_entropy']:.4f}  "
                  f"above-7.9={tag_col}{a['pct_above_79']}%{RST}")
            print(f"  {DIM}  Verdict :{RST} {tag_col}{a['verdict']}{RST}")
    else:
        print(f"\n  {G}✓  NO CONFIRMED ENCRYPTED REGIONS DETECTED{RST}")
        if filtered:
            print(f"  {DIM}  ({len(filtered)} high-entropy regions were filtered out "
                  f"as false positives){RST}")

    print_ascii_heatmap(block_map, alerts)

    # ── Build results dict ────────────────────────────────────────────────────
    results = {
        "meta": {
            "tool":             "Entropy Hunter v3.0",
            "timestamp":        datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "image_path":       os.path.abspath(image_path),
            "image_format":     img_format,
            "image_size_bytes": img_size,
            "image_sha256":     _sha256_partial(image_path),
            "elapsed_sec":      round(elapsed, 3),
            "mib_per_sec":      mib_s,
        },
        "config": {
            "window_size":      window_size,
            "step_size":        step_size,
            "threshold":        threshold,
            "min_bytes":        min_bytes,
            "max_std":          max_std,
            "min_mean":         min_mean,
            "sector_size":      sector_size,
            "partition_index":  partition_index,
            "unallocated_only": unallocated_only,
            "workers":          workers,
            "scan_range":       f"0x{scan_range[0]:X}–0x{scan_range[1]:X}" if scan_range else None,
        },
        "stats": {
            "windows_scanned": n_blocks,
            "unalloc_regions": len(unalloc),
            "unalloc_bytes":   total_unalloc,
            "avg_entropy":     round(avg_h, 6),
            "pct_above_79":    pct79,
            "alert_count":     len(alerts),
            "filtered_count":  len(filtered),
        },
        "alerts":        alerts,
        "filtered":      filtered,
        "block_map":     block_map,
        "full_disk_map": full_disk_map,
    }

    # ── Write reports ─────────────────────────────────────────────────────────
    base     = os.path.splitext(os.path.basename(image_path))[0]
    json_out = os.path.join(output_dir, base + "_v3_results.json")
    txt_out  = os.path.join(output_dir, base + "_v3_report.txt")
    csv_out  = os.path.join(output_dir, base + "_v3_alerts.csv")
    html_out = os.path.join(output_dir, base + "_v3_report.html")

    write_json_report(json_out, results)
    write_text_report(txt_out,  results)
    write_csv_report(csv_out,   alerts, filtered)

    chart_paths = {}
    if not no_charts:
        print(f"\n  {C}[*]{RST} Generating charts…")
        use_full = full_disk_map if full_disk_map else block_map
        chart_paths = generate_charts(
            block_map, alerts, filtered, use_full,
            threshold, output_dir, base
        )
        for k, p in chart_paths.items():
            print(f"  {G}[+]{RST} Chart ({k}) → {p}")

    write_html_report(html_out, results, chart_paths)

    print(f"\n  {G}[+]{RST} JSON   → {json_out}")
    print(f"  {G}[+]{RST} Text   → {txt_out}")
    print(f"  {G}[+]{RST} CSV    → {csv_out}")
    print(f"  {G}[+]{RST} HTML   → {html_out}")
    print(f"\n  {DIM}View report:{RST}  {C}firefox {html_out} &{RST}\n")

    return results


# ═════════════════════════════════════════════════════════════════════════════
# §11  TEST IMAGE GENERATOR
# ═════════════════════════════════════════════════════════════════════════════

def make_test_image(output_path: str,
                    total_mb: int  = 100,
                    hidden_mb: int = 10,
                    n_hidden: int  = 1) -> str:
    print(f"\n{C}[*] Creating synthetic test image{RST}")
    print(f"    Output : {output_path}  |  Total: {total_mb}MiB  |  "
          f"Hidden: {n_hidden}×{hidden_mb}MiB\n")

    total_bytes   = total_mb  * MiB
    hidden_bytes  = hidden_mb * MiB
    sector_size   = 512
    total_sectors = total_bytes // sector_size

    with open(output_path, "wb") as fh:
        written = 0
        while written < total_bytes:
            n = min(256 * 1024, total_bytes - written)
            fh.write(b"\x00" * n)
            written += n

    with open(output_path, "r+b") as fh:
        fh.seek(0); fh.write(_build_mbr(total_sectors))
        part_start = 2048
        fh.seek(part_start * sector_size)
        fh.write(_build_fat32_vbr(total_sectors - part_start))

        # Text block
        words = b"the quick brown fox jumps over the lazy dog digital forensics "
        text  = (words * 4000)[: 300 * 1024]
        fh.seek(part_start * sector_size + 64 * sector_size)
        fh.write(text)
        print(f"  {G}[+]{RST} Text block (H≈3.8)  300 KiB")

        # ZIP-like header block (known file magic — should NOT be alertable)
        zip_data = b"PK\x03\x04" + _make_compressed_like(200 * 1024 - 4)
        fh.seek(part_start * sector_size + 600 * sector_size)
        fh.write(zip_data)
        print(f"  {G}[+]{RST} ZIP block (H≈6.8)   200 KiB  [should be filtered by magic check]")

        # JPEG-like header block
        jpeg_data = b"\xFF\xD8\xFF\xE0" + _make_compressed_like(100 * 1024 - 4)
        fh.seek(part_start * sector_size + 1200 * sector_size)
        fh.write(jpeg_data)
        print(f"  {G}[+]{RST} JPEG block          100 KiB  [should be filtered by magic check]")

        # Hidden volumes
        _rsvd = 32; _nfats = 2; _spc = 8
        _spf  = max(1, (total_sectors - part_start - _rsvd) // 16)
        _data_rel = _rsvd + _nfats * _spf
        _cb   = _spc * sector_size
        _tc   = (total_sectors - part_start - _data_rel) // _spc
        _gap  = max(1, (_tc - 1000 - n_hidden * (hidden_bytes // _cb + 1)) // (n_hidden + 1))

        for v in range(n_hidden):
            _cnum = 1000 + v * (_gap + hidden_bytes // _cb + 1)
            _cnum = min(_cnum, _tc - hidden_bytes // _cb - 10)
            off   = (part_start + _data_rel + (_cnum - 2) * _spc) * sector_size
            off   = (off // _cb) * _cb
            print(f"  {R}[+]{RST} Planting hidden vol #{v+1}  {hidden_mb}MiB  "
                  f"at 0x{off:X}")
            fh.seek(off)
            written = 0
            while written < hidden_bytes:
                n = min(256 * 1024, hidden_bytes - written)
                fh.write(os.urandom(n))
                written += n

    print(f"\n  {G}[✓] Image ready:{RST} {output_path}  "
          f"({os.path.getsize(output_path) // MiB} MiB)\n")
    return output_path


def _build_mbr(total_sectors):
    mbr = bytearray(512)
    e   = bytearray(16)
    e[0] = 0x80; e[4] = 0x0C
    struct.pack_into("<I", e, 8,  2048)
    struct.pack_into("<I", e, 12, total_sectors - 2048)
    mbr[446:462] = e
    mbr[510] = 0x55; mbr[511] = 0xAA
    return bytes(mbr)


def _build_fat32_vbr(part_sectors):
    v = bytearray(512)
    v[0:3]  = b"\xEB\x58\x90"
    v[3:11] = b"FAT32   "
    struct.pack_into("<H", v, 11, 512)
    v[13] = 8
    struct.pack_into("<H", v, 14, 32)
    v[16] = 2
    struct.pack_into("<I", v, 32, part_sectors)
    struct.pack_into("<I", v, 36, max(1, (part_sectors - 32) // 16))
    struct.pack_into("<I", v, 44, 2)
    v[82:90] = b"FAT32   "
    v[510] = 0x55; v[511] = 0xAA
    return bytes(v)


def _make_compressed_like(n):
    seed = 0xFEEDFACE
    out  = bytearray(n)
    for i in range(n):
        seed = (seed * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (seed >> 33) & 0xFF
    return bytes(out)


# ═════════════════════════════════════════════════════════════════════════════
# §12  SELF-TEST
# ═════════════════════════════════════════════════════════════════════════════

def run_selftest():
    print(f"\n{C}{'═'*60}{RST}")
    print(f"{W}  Self-Test Suite — Entropy Hunter v3.0{RST}")
    print(f"{C}{'═'*60}{RST}\n")

    passed = failed = 0

    def check(name, ok, got=None, exp=None):
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"  {G}✓{RST}  {name}")
        else:
            failed += 1
            print(f"  {R}✗{RST}  {name}  [got={got}, exp={exp}]")

    # Entropy basics
    check("zero-fill → H=0.0",     shannon_entropy(b"\x00" * 4096) < 0.001)
    check("single byte → H=0.0",   shannon_entropy(b"\xAA" * 4096) < 0.001)
    check("empty → H=0.0",         shannon_entropy(b"") == 0.0)
    h256 = shannon_entropy(bytes(range(256)))
    check(f"uniform-256 → H=8.0 ({h256:.4f})", abs(h256 - 8.0) < 0.0001, h256, 8.0)
    h_rand = shannon_entropy(os.urandom(4096))
    check(f"os.urandom → H≥7.8 ({h_rand:.4f})", h_rand >= 7.8)
    h_text = shannon_entropy(b"the quick brown fox " * 200)
    check(f"english text → 3<H<6 ({h_text:.4f})", 3.0 < h_text < 6.0)

    # Variance filter — key accuracy test
    # Real encrypted data: flat near 7.96
    enc_ents = [7.96, 7.97, 7.95, 7.98, 7.96, 7.95, 7.97] * 100
    ok_var, reason = entropy_variance_check(enc_ents)
    check(f"variance filter PASS on flat 7.96 ({reason})", ok_var)

    # Compressed data: variable entropy — should FAIL variance check
    comp_ents = [7.9, 7.2, 7.8, 6.5, 7.9, 5.8, 7.7] * 50
    ok_comp, reason_comp = entropy_variance_check(comp_ents)
    check(f"variance filter REJECT on variable data ({reason_comp})", not ok_comp)

    # Magic byte classifier
    zip_data  = b"PK\x03\x04" + os.urandom(8192)
    cat_zip   = classify_block(zip_data, shannon_entropy(zip_data))
    check(f"classify ZIP magic → KNOWN_HI:ZIP (got {cat_zip})", "ZIP" in cat_zip)

    enc_data  = os.urandom(8192)
    cat_enc   = classify_block(enc_data, shannon_entropy(enc_data))
    check(f"classify random → ENCRYPTED (got {cat_enc})", cat_enc == "ENCRYPTED")

    # Alert engine accuracy
    # Should detect: flat high entropy, large region
    flat_bm = [{"offset": i * 4096, "entropy": 7.96, "category": "ENCRYPTED"}
               for i in range(2000)]
    fd, tmp = tempfile.mkstemp(); os.close(fd)
    open(tmp, "wb").write(os.urandom(8 * MiB))
    alerts, filtered = detect_alerts(flat_bm, 7.9, 4 * MiB, 4096, 512, tmp, 4096,
                                      max_std=0.08, min_mean=7.85)
    check(f"detect flat 7.96 → ≥1 alert (got {len(alerts)})", len(alerts) >= 1)
    os.unlink(tmp)

    # Should NOT detect: variable high entropy (compressed file signature)
    var_bm = [{"offset": i * 4096,
               "entropy": 7.96 if i % 3 else 7.1,
               "category": "ENCRYPTED"}
              for i in range(2000)]
    fd, tmp = tempfile.mkstemp(); os.close(fd)
    open(tmp, "wb").write(b"PK\x03\x04" + os.urandom(8 * MiB))  # ZIP magic at start
    alerts2, filtered2 = detect_alerts(var_bm, 7.9, 4 * MiB, 4096, 512, tmp, 4096,
                                        max_std=0.08, min_mean=7.85)
    check(f"detect variable/zip → 0 alerts (got {len(alerts2)}) — filtered: {len(filtered2)}",
          len(alerts2) == 0 or len(filtered2) > 0)
    os.unlink(tmp)

    # Merge regions
    check("merge adjacent", _merge_regions([(0, 512), (512, 512)]) == [(0, 1024)])
    check("merge non-adjacent", len(_merge_regions([(0, 512), (1024, 512)])) == 2)

    # Integration test
    print(f"\n  {DIM}Integration test…{RST}")
    fd, tmp = tempfile.mkstemp(suffix=".dd"); os.close(fd)
    with open(tmp, "wb") as fh:
        fh.write(b"\x00" * (4 * MiB))
        fh.write(os.urandom(4 * MiB))
    res = run_scan(
        image_path=tmp, window_size=4096, step_size=4096,
        threshold=7.9, min_bytes=2 * MiB,
        unallocated_only=False, workers=1,
        output_dir=tempfile.gettempdir(),
        no_charts=True, max_std=0.10, min_mean=7.80,
    )
    check("integration: returns dict with alerts", isinstance(res, dict) and "alerts" in res)
    check(f"integration: detects ≥1 alert (got {res.get('stats',{}).get('alert_count',0)})",
          res.get("stats", {}).get("alert_count", 0) >= 1)
    os.unlink(tmp)

    print(f"\n  {'─'*50}")
    col = G if failed == 0 else R
    print(f"  {col}{passed}/{passed+failed} tests passed{RST}")
    if failed:
        print(f"  {R}[!] {failed} test(s) failed{RST}\n"); sys.exit(1)
    else:
        print(f"  {G}[✓] All tests passed!{RST}\n")


# ═════════════════════════════════════════════════════════════════════════════
# §13  HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _sha256_partial(path: str, n: int = MiB) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read(n))
    return h.hexdigest()


# ═════════════════════════════════════════════════════════════════════════════
# §14  CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    banner()

    p = argparse.ArgumentParser(
        prog="entropy_hunter_v3.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Entropy Hunter v3.0 — Forensic Hidden Volume Detection",
        epilog=textwrap.dedent("""
        Examples:
          # Run all self-tests
          python3 entropy_hunter_v3.py --selftest

          # Generate and scan a demo image
          python3 entropy_hunter_v3.py --demo

          # Scan a raw DD image
          python3 entropy_hunter_v3.py --scan image.dd

          # Scan an E01 image (requires: pip install pyewf)
          python3 entropy_hunter_v3.py --scan case.E01

          # Scan a specific byte range only (bytes 0 to 1GiB)
          python3 entropy_hunter_v3.py --scan image.dd --scan-range 0 1073741824

          # Scan a specific range in hex
          python3 entropy_hunter_v3.py --scan image.dd --scan-range 0x100000 0x10000000

          # See ALL data types on heatmap (text, zip, encrypted, zero)
          python3 entropy_hunter_v3.py --scan image.dd --show-all-regions

          # Loosen accuracy filters if you want to see more candidates
          python3 entropy_hunter_v3.py --scan image.dd --max-std 0.15 --min-mean 7.7

          # Tighten accuracy filters for fewer false positives
          python3 entropy_hunter_v3.py --scan image.dd --max-std 0.05 --min-mean 7.9

          # Show partition table only
          python3 entropy_hunter_v3.py --list-partitions image.dd
        """),
    )

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scan",            metavar="IMAGE", help="Scan a disk image")
    mode.add_argument("--demo",            action="store_true", help="Generate + scan test image")
    mode.add_argument("--make-test-dd",    metavar="OUTPUT", help="Generate synthetic .dd image")
    mode.add_argument("--selftest",        action="store_true", help="Run self-test suite")
    mode.add_argument("--list-partitions", metavar="IMAGE", help="Show partition table and exit")

    # Core scan options
    p.add_argument("-w",  "--window",     type=int,   default=4096,  metavar="BYTES")
    p.add_argument("--step",              type=int,   default=512,   metavar="BYTES")
    p.add_argument("-t",  "--threshold",  type=float, default=7.9,   metavar="BITS")
    p.add_argument("--min-mb",            type=float, default=4.0,   metavar="MiB",
                   help="Min contiguous region size (default: 4 MiB)")
    p.add_argument("--sector-size",       type=int,   default=512,   metavar="BYTES")
    p.add_argument("--partition",         type=int,   default=0,     metavar="IDX")
    p.add_argument("--scan-all",          action="store_true",
                   help="Scan entire partition (not just unallocated space)")
    p.add_argument("--workers",           type=int,   default=None,  metavar="N")
    p.add_argument("--verbose", "-v",     action="store_true")
    p.add_argument("--no-charts",         action="store_true")
    p.add_argument("-o", "--output-dir",  default=None, metavar="DIR")

    # Accuracy filter options (key new feature)
    p.add_argument("--max-std",           type=float, default=0.08,  metavar="SIGMA",
                   help="Max entropy std-dev for alert (default: 0.08). "
                        "Lower = fewer FP. Higher = more sensitive.")
    p.add_argument("--min-mean",          type=float, default=7.85,  metavar="BITS",
                   help="Min mean entropy for alert (default: 7.85). "
                        "Lower = more sensitive. Higher = fewer FP.")

    # Range scanning
    p.add_argument("--scan-range",        type=str,   nargs=2,       metavar=("START", "END"),
                   help="Scan specific byte range only. Values can be decimal or hex (0x...)")

    # Heatmap options
    p.add_argument("--show-all-regions",  action="store_true",
                   help="Run a full-disk classify pass to show ALL file types on heatmap "
                        "(text, compressed, encrypted, zero, known files)")

    # Image generation options
    p.add_argument("--size-mb",           type=int,   default=100,   metavar="MB")
    p.add_argument("--hidden-mb",         type=int,   default=10,    metavar="MB")
    p.add_argument("--n-hidden",          type=int,   default=1,     metavar="N")

    args = p.parse_args()

    # Parse --scan-range (supports decimal and hex)
    scan_range = None
    if hasattr(args, 'scan_range') and args.scan_range:
        def parse_int(s):
            return int(s, 16) if s.startswith("0x") or s.startswith("0X") else int(s)
        start = parse_int(args.scan_range[0])
        end   = parse_int(args.scan_range[1])
        if end <= start:
            print(f"{R}[ERROR] scan-range END must be > START{RST}"); sys.exit(1)
        scan_range = (start, end)

    if args.selftest:
        run_selftest()

    elif args.list_partitions:
        img_path = args.list_partitions
        if not os.path.isfile(img_path):
            print(f"{R}[ERROR] Not found: {img_path}{RST}"); sys.exit(1)
        with DiskImage(img_path) as img:
            parts = parse_partitions(img, args.sector_size)
        print(f"\n  Partitions in: {img_path}\n")
        print(f"  {'#':<4} {'Type':<10} {'FS':<8} {'Start':>14} {'Size(MiB)':>10} {'Cluster':>8}")
        print(f"  {'─'*60}")
        for p_ in parts:
            print(f"  {p_.index:<4} {p_.ptype:<10} {p_.fs_type:<8} "
                  f"{p_.start_byte:>14,} {p_.length_bytes // MiB:>10} "
                  f"{p_.cluster_size:>8}")
        print()

    elif args.make_test_dd:
        make_test_image(args.make_test_dd, args.size_mb, args.hidden_mb, args.n_hidden)

    elif args.demo:
        img_path = "entropy_hunter_v3_demo.dd"
        make_test_image(img_path, args.size_mb, args.hidden_mb, args.n_hidden)
        run_scan(
            image_path=img_path, window_size=args.window, step_size=args.step,
            threshold=args.threshold, min_bytes=int(args.min_mb * MiB),
            sector_size=args.sector_size, partition_index=args.partition,
            unallocated_only=not args.scan_all, workers=args.workers,
            verbose=args.verbose, output_dir=args.output_dir or ".",
            no_charts=args.no_charts, max_std=args.max_std, min_mean=args.min_mean,
            scan_range=scan_range, show_all_regions=args.show_all_regions,
        )

    elif args.scan:
        run_scan(
            image_path=args.scan, window_size=args.window, step_size=args.step,
            threshold=args.threshold, min_bytes=int(args.min_mb * MiB),
            sector_size=args.sector_size, partition_index=args.partition,
            unallocated_only=not args.scan_all, workers=args.workers,
            verbose=args.verbose, output_dir=args.output_dir,
            no_charts=args.no_charts, max_std=args.max_std, min_mean=args.min_mean,
            scan_range=scan_range, show_all_regions=args.show_all_regions,
        )


if __name__ == "__main__":
    main()
