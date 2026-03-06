# 🔍 Entropy Hunter v4.0
### Forensic Hidden Volume & Encrypted Data Detection for Disk Images

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu%20%7C%20macOS-informational)](https://www.kali.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![NumPy](https://img.shields.io/badge/NumPy-optional%20fast%20path-orange)](https://numpy.org)
[![Matplotlib](https://img.shields.io/badge/Matplotlib-charts%20%26%20heatmaps-orange)](https://matplotlib.org)
[![pyewf](https://img.shields.io/badge/pyewf-E01%20support-blue)](https://github.com/libyal/libewf)

---

Entropy Hunter is an **all-in-one forensic tool** for detecting hidden encrypted volumes, VeraCrypt/TrueCrypt containers, BitLocker partitions, and LUKS volumes inside raw disk images (`.dd`) and forensic evidence files (`.E01`). It uses **Shannon entropy analysis**, **chi-square uniformity testing**, **byte frequency flatness scoring**, and **encryption header fingerprinting** to produce a precise confidence score (0–100) for every anomalous region — dramatically reducing false positives from compressed files and multimedia.

---

## ✨ What's New in v4.0

| Feature | Description |
|---|---|
| **Chi-Square Test** | Second independent randomness test alongside Shannon entropy. AES-256 must pass **both** for `HIDDEN_VOLUME_LIKELY` |
| **Encryption Header Detection** | Fingerprints VeraCrypt, TrueCrypt, BitLocker, and LUKS headers at exact byte offsets |
| **Sector Alignment Check** | Deliberate hidden volumes are **always** sector/cluster aligned — unaligned regions are deprioritised |
| **Numeric Confidence Score (0–100)** | Replaces vague `HIGH/LOW` strings with a precise, citable score |
| **Byte Frequency Flatness** | Per-alert 256-bar histogram showing byte distribution (AES = flat; compressed = spiky) |
| **Encrypted Region Extractor** | Automatically carves confirmed regions to `.bin` files in `suspicious_regions/` with SHA-256 sidecar |

---

## 🧠 How It Works

Entropy Hunter does not decrypt anything. Instead, it exploits a fundamental property of strong encryption: **encrypted data looks maximally random**. The tool measures this "randomness" using two independent statistical tests, then cross-checks against known file signatures and structural metadata to eliminate false positives.

### Detection Pipeline

```
Disk Image (.dd / .E01)
        │
        ▼
┌─────────────────────┐
│  Phase 1: Partition  │  MBR / GPT / FAT32 / NTFS / ext4 parsing
│  Parsing & Unalloc  │  → isolates only unallocated clusters
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│  Phase 2: Sliding   │  4 KiB windows, 512-byte steps
│  Window Entropy     │  Shannon H(X) computed per window
│  Scan (Parallel)    │  Multi-core via Python multiprocessing
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│  Phase 3: Alert      │  Consecutive windows above threshold (7.9 bits)
│  Detection +         │  → Variance filter (σ < 0.08 required)
│  False Positive      │  → Magic-byte check (ZIP/JPEG/RAR rejected)
│  Filters             │  → Chi-square uniformity test
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│  Phase 4: Deep       │  Confidence score (0–100)
│  Analysis per Alert  │  Byte frequency flatness
│                      │  Encryption header fingerprinting
│                      │  Sector/cluster alignment check
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│  Phase 5: Extraction │  Carve .bin + SHA-256 sidecar JSON
│  & Reporting         │  HTML / JSON / CSV / TXT reports
│                      │  PNG heatmaps per alert
└─────────────────────┘
```

### Confidence Score Breakdown (0–100 pts)

| Component | Weight | Notes |
|---|---|---|
| Shannon entropy mean | 35 pts | Linear: 7.85→0 pts … 8.0→35 pts |
| Chi-square p-value | 25 pts | p≥0.5→25 pts; p<0.001→0 pts |
| Entropy σ flatness | 20 pts | σ=0.00→20 pts; σ=0.08→0 pts |
| Sector alignment | 10 pts | Cluster-aligned=10; sector-aligned=6 |
| Region size | 5 pts | ≥100 MiB=5; ≥20 MiB=3; ≥4 MiB=1 |
| Header fingerprint | 5 pts | Any encryption header found |

A score ≥ 80 with chi-square passing triggers the `HIDDEN_VOLUME_LIKELY` tag.

### What Gets Filtered Out (False Positives)

| Type | Filter Used |
|---|---|
| ZIP / 7z / RAR archives | Magic-byte check (`PK\x03\x04`, `Rar!`, `7z\xBC\xAF`) |
| JPEG / PNG / GIF images | Magic-byte check (`\xFF\xD8\xFF`, `\x89PNG`) |
| GZIP / BZIP2 / XZ files | Magic-byte check |
| Mixed media / video | Entropy variance filter (high σ — not flat enough) |
| Small file fragments | Minimum region size filter (default 4 MiB) |
| Obviously non-uniform data | Chi-square hard reject (p < 0.0001 with mean < 7.92) |

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/entropy-hunter.git
cd entropy-hunter
```

### 2. Install Dependencies

**Required (Python standard library only — zero deps for basic scan):**
```bash
python3 --version  # 3.8+ required
```

**Optional but strongly recommended:**
```bash
# Fast entropy computation (10–40× faster)
pip install numpy

# PNG heatmaps and byte-frequency charts
pip install matplotlib

# Proper E01/EWF forensic image support
pip install pyewf
```

**Or install everything at once:**
```bash
pip install numpy matplotlib pyewf
```

**Kali Linux / Debian full setup:**
```bash
sudo apt-get install python3-numpy python3-matplotlib
pip install pyewf --break-system-packages
```

---

## 🚀 Usage

### Quick Start

```bash
# Run self-test suite (verify everything works)
python3 entropy_hunter_v4.py --selftest

# Generate a synthetic demo image with a planted hidden volume, then scan it
python3 entropy_hunter_v4.py --demo

# Scan a real disk image
python3 entropy_hunter_v4.py --scan image.dd

# Scan an E01 forensic image (requires pyewf)
python3 entropy_hunter_v4.py --scan case.E01
```

### All Command Options

```bash
# ── Core scan ──────────────────────────────────────────────────────────
python3 entropy_hunter_v4.py --scan image.dd

# Scan a specific byte range only (decimal or hex)
python3 entropy_hunter_v4.py --scan image.dd --scan-range 0 1073741824
python3 entropy_hunter_v4.py --scan image.dd --scan-range 0x100000 0x10000000

# Show ALL data types on the heatmap (text, ZIP, encrypted, zero, JPEG…)
python3 entropy_hunter_v4.py --scan image.dd --show-all-regions

# Scan entire partition (not just unallocated space)
python3 entropy_hunter_v4.py --scan image.dd --scan-all

# Target a specific partition (0-indexed)
python3 entropy_hunter_v4.py --scan image.dd --partition 2

# Save output to a custom directory
python3 entropy_hunter_v4.py --scan image.dd --output-dir /cases/case001/

# ── Accuracy tuning ────────────────────────────────────────────────────
# Tighten filters → fewer false positives (stricter)
python3 entropy_hunter_v4.py --scan image.dd --max-std 0.05 --min-mean 7.90

# Loosen filters → catch more candidates (more sensitive)
python3 entropy_hunter_v4.py --scan image.dd --max-std 0.15 --min-mean 7.70

# Adjust alert threshold (default 7.9 bits/byte)
python3 entropy_hunter_v4.py --scan image.dd --threshold 7.85

# Set minimum alert region size (default 4 MiB)
python3 entropy_hunter_v4.py --scan image.dd --min-mb 1.0

# ── Performance ────────────────────────────────────────────────────────
# Use all CPU cores (default) or limit workers
python3 entropy_hunter_v4.py --scan image.dd --workers 4

# Custom window and step size
python3 entropy_hunter_v4.py --scan image.dd --window 4096 --step 512

# ── Output control ─────────────────────────────────────────────────────
# Skip chart generation (faster, headless)
python3 entropy_hunter_v4.py --scan image.dd --no-charts

# Disable automatic region extraction
python3 entropy_hunter_v4.py --scan image.dd --no-extract

# ── Utility ────────────────────────────────────────────────────────────
# List partition table and exit
python3 entropy_hunter_v4.py --list-partitions image.dd

# Generate a synthetic test image (without scanning)
python3 entropy_hunter_v4.py --make-test-dd test.dd --size-mb 200 --hidden-mb 20 --n-hidden 2

# Run full self-test suite
python3 entropy_hunter_v4.py --selftest
```

---

## 📁 Output Files

After scanning `image.dd`, the following files are produced:

```
./
├── image_v4_results.json          ← Full results (all metadata, per-alert JSON)
├── image_v4_report.txt            ← Human-readable forensic report
├── image_v4_alerts.csv            ← Alert table (Excel/pandas-compatible)
├── image_v4_filtered_false_positives.csv
├── image_v4_report.html           ← Interactive HTML report with embedded charts
├── image_full_disk_heatmap.png    ← Full-disk entropy heatmap (all data types)
├── image_entropy_histogram.png    ← Distribution histogram
├── image_alert01_byte_freq.png    ← Byte frequency chart per alert
└── suspicious_regions/
    └── image/
        ├── 00_EXTRACTION_INDEX.json
        ├── alert_01_offset0x823000_conf94_9.2MiB.bin   ← Carved region
        └── alert_01_offset0x823000_conf94_9.2MiB_metadata.json  ← SHA-256 + chain of custody
```

### HTML Report

Open the `.html` report in a browser for an interactive dashboard:

```bash
firefox image_v4_report.html &
# or
xdg-open image_v4_report.html
```

The HTML report includes:
- Stats dashboard (windows scanned, avg entropy, alerts)
- Full-disk heatmap with colour-coded data types
- Per-alert cards with confidence score, chi-square result, and byte frequency chart
- Filtration table showing what was ruled out and why
- Configuration summary

---

## 🔬 Supported Container Types

| Container | Detection Method | Confidence Boost |
|---|---|---|
| **VeraCrypt Standard Volume** | Backup header heuristic (last 512 bytes, chi-square p > 0.10) | +20 pts |
| **VeraCrypt Hidden Volume** | Offset 65536 header heuristic (entropy + chi-square) | +15 pts |
| **TrueCrypt** | Same as VeraCrypt (same format) | +20 pts |
| **BitLocker** | `-FVE-FS-` magic at byte offset 3 | +30 pts |
| **LUKS** | `LUKS\xBA\xBE` magic at byte 0 | +30 pts |
| **Unknown encrypted volumes** | Statistical signature only (entropy + chi-sq + flatness) | — |

---

## 🗂️ Supported Disk Image Formats

| Format | Extension | Support |
|---|---|---|
| Raw DD image | `.dd`, `.img`, `.raw` | ✅ Native |
| EnCase EWF / E01 | `.E01`, `.S01`, `.L01` | ✅ With `pyewf` |
| Split E01 sets | `.E01`, `.E02`, … | ✅ With `pyewf` |
| E01 without pyewf | `.E01` | ⚠️ Raw stream fallback (reduced accuracy) |

---

## 📊 Interpreting Results

### Confidence Score Guide

| Score | Label | Meaning |
|---|---|---|
| 85–100 | ★ VERY HIGH | Near-certain AES-encrypted volume. Immediate action warranted. |
| 70–84 | HIGH | Highly probable encrypted container. Investigate further. |
| 55–69 | MODERATE | High entropy with flat distribution. Manual review recommended. |
| 40–54 | LOW | High entropy but weak secondary indicators. May be false positive. |
| 0–39 | VERY LOW | High entropy alone; likely compressed or multimedia data. |

### Tags

| Tag | Condition |
|---|---|
| `HIDDEN_VOLUME_LIKELY` | Confidence ≥ 80 **and** chi-square passes (p > 0.05) |
| `POSSIBLE_ENCRYPTED` | Confidence ≥ 60 |
| `HIGH_ENTROPY_UNALLOCATED` | Confidence < 60 — high entropy but unclear origin |

---

## ⚡ Performance

Benchmark on a 500 GiB raw image (SSD, 8-core CPU, numpy installed):

| Configuration | Throughput |
|---|---|
| 8 workers + numpy | ~850–1,200 MiB/s |
| 4 workers + numpy | ~500–700 MiB/s |
| 1 worker + numpy | ~250–400 MiB/s |
| 1 worker, pure Python | ~30–60 MiB/s |

For a full 500 GiB disk with 8 workers: approximately **7–10 minutes**.

---

## 🔎 Example Workflow — Real Investigation

```bash
# Step 1: Check what partitions exist
python3 entropy_hunter_v4.py --list-partitions suspect_drive.dd

# Step 2: Scan unallocated space of partition 0 (fastest, most targeted)
python3 entropy_hunter_v4.py --scan suspect_drive.dd \
    --partition 0 \
    --output-dir /cases/case042/ \
    --workers 8

# Step 3: If no results, scan the entire disk (including allocated space)
python3 entropy_hunter_v4.py --scan suspect_drive.dd \
    --scan-all \
    --min-mb 1.0 \
    --max-std 0.12 \
    --output-dir /cases/case042/

# Step 4: Review the HTML report
firefox /cases/case042/suspect_drive_v4_report.html &

# Step 5: Examine carved .bin files
ls -lh /cases/case042/suspicious_regions/suspect_drive/
sha256sum /cases/case042/suspicious_regions/suspect_drive/*.bin

# Step 6: Attempt to mount (VeraCrypt GUI or veracrypt CLI)
veracrypt --text --mount \
    /cases/case042/suspicious_regions/suspect_drive/alert_01_offset0x200000_conf91_512.0MiB.bin \
    /mnt/evidence/
```

---

## 🧪 Self-Test Suite

Run the built-in test suite to verify the installation:

```bash
python3 entropy_hunter_v4.py --selftest
```

Tests cover:
- Shannon entropy correctness (zero-fill, uniform, random)
- Chi-square implementation and p-value accuracy
- Byte frequency flatness scoring
- Confidence score computation
- LUKS header detection
- Entropy variance filter (pass and reject cases)
- Magic-byte classifier (ZIP, JPEG)
- Alert engine (flat encrypted region detection)
- Region extraction with SHA-256 integrity
- Full integration scan (generates + scans a synthetic image)

Expected output: `✓ All tests passed!`

---

## 🏗️ Project Structure

```
entropy-hunter/
├── entropy_hunter_v4.py    ← Single-file tool (everything included)
├── README.md
└── LICENSE
```

The tool is intentionally designed as a **single Python file** for easy deployment on forensic workstations without package management overhead. All dependencies are either standard-library or optional enhancements.

---

## 📚 Technical Background

### Why Shannon Entropy?

Shannon entropy H(X) measures the average information content per byte. For data drawn from a uniform distribution (like AES-256 ciphertext), every byte value (0x00–0xFF) appears with equal probability, giving H(X) = 8.0 bits/byte — the theoretical maximum. Compressed data also has high entropy but typically falls in the 6.5–7.8 range.

### Why Chi-Square as a Second Test?

Shannon entropy measures average randomness but can be fooled. The chi-square goodness-of-fit test measures whether the **distribution** of byte values is uniform (not just the average). For a 64 KiB AES ciphertext sample, the expected chi-square statistic is ~255 (degrees of freedom). Values far outside this range indicate non-uniform distributions. Using both tests simultaneously eliminates nearly all false positives from compressed archives.

### Why Entropy Variance Matters

A real encrypted volume produces **consistently** high entropy across every 4 KiB window — the standard deviation across windows is < 0.05. Compressed or multimedia files, even with high average entropy, show wide variation between blocks. The variance filter (σ < 0.08) is the single most effective false-positive reducer in the tool.

---

## 🤝 Contributing

Contributions are welcome! Areas where help would be particularly valuable:

- Additional encryption container signatures (AxCrypt, dm-crypt, FileVault)
- APFS and exFAT filesystem unallocated cluster parsing
- YARA rule integration for header detection
- GUI frontend (PyQt or web-based)
- Automated VeraCrypt mount attempt on high-confidence alerts

Please open an issue before submitting large pull requests.

---

## ⚠️ Legal & Ethical Notice

This tool is designed for **lawful forensic investigation** on disk images you have legal authority to examine. Always obtain proper authorisation before imaging or analysing storage media. The tool does not bypass encryption — it only identifies regions that *may* be encrypted based on statistical properties.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- **libewf / pyewf** — E01 forensic image library
- **The Sleuth Kit** — foundational forensic concepts
- **VeraCrypt** — open-source disk encryption (whose output this tool detects)
- Shannon (1948) — *A Mathematical Theory of Communication*

---

*Built for digital forensics investigators, security researchers, and incident responders.*
