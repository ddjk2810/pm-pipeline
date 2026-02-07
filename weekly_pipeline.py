"""
Daily PM Discovery & Re-scan Pipeline

Orchestrates:
1. Seed DB from pm_results.csv (DB is gitignored, reconstructed each CI run)
2. (Monday only) Scrape new property managers + detect PM software + RBP
3. (Daily) Re-scan 1/8 of existing domains (full rotation every ~8 days)
4. DNS recovery pass on unknowns
5. Export DB back to pm_results.csv
6. Snapshot/diff when a full rotation completes
7. Log daily summary

Usage:
  python weekly_pipeline.py                  # Full pipeline (scrape if Monday + rescan chunk)
  python weekly_pipeline.py --skip-scrape    # Skip scraping, use existing new_property_managers.csv
  python weekly_pipeline.py --skip-rescan    # Skip chunk re-scan
  python weekly_pipeline.py --skip-recovery  # Skip DNS recovery pass
"""

import argparse
import csv
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import date
from urllib.parse import urlparse


PIPELINE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRAPER_DIR = os.path.join(PIPELINE_DIR, "scraper")
PM_DETECTION_DIR = os.path.join(PIPELINE_DIR, "pm_detection")
RBP_DETECTION_DIR = os.path.join(PIPELINE_DIR, "rbp_detection")
DATA_DIR = os.path.join(PIPELINE_DIR, "data")
WEEKLY_LOGS_DIR = os.path.join(DATA_DIR, "weekly_logs")
SNAPSHOTS_DIR = os.path.join(DATA_DIR, "snapshots")

# Data files
PROPERTY_MANAGERS_CSV = os.path.join(DATA_DIR, "property_managers.csv")
DOMAINS_DOORS_CSV = os.path.join(DATA_DIR, "domains_doors.csv")
PM_RESULTS_CSV = os.path.join(DATA_DIR, "pm_results.csv")
RBP_RESULTS_CSV = os.path.join(DATA_DIR, "rbp_results.csv")
CUMULATIVE_STATS_JSON = os.path.join(WEEKLY_LOGS_DIR, "cumulative_stats.json")
PIPELINE_STATE_JSON = os.path.join(DATA_DIR, "pipeline_state.json")

# Intermediate files (gitignored)
NEW_DOMAINS_CSV = os.path.join(DATA_DIR, "new_domains.csv")
PM_RESULTS_NEW_CSV = os.path.join(DATA_DIR, "pm_results_new.csv")
PM_RESULTS_FOR_RBP_CSV = os.path.join(DATA_DIR, "pm_results_for_rbp.csv")
CHUNK_DOMAINS_CSV = os.path.join(DATA_DIR, "chunk_domains.csv")
CHUNK_RESULTS_CSV = os.path.join(DATA_DIR, "chunk_results.csv")

# Scraper files (relative to scraper cwd)
SCRAPER_BASELINE = os.path.join(SCRAPER_DIR, "property_managers.csv")
SCRAPER_NEW_OUTPUT = os.path.join(SCRAPER_DIR, "new_property_managers.csv")

# DB path inside pm_detection/
PM_DB_PATH = os.path.join(PM_DETECTION_DIR, "pm_system_results.db")
RECOVERY_DB_PATH = os.path.join(PM_DETECTION_DIR, "pm_recovery_results.db")

SCRAPE_TIMEOUT = 4 * 3600  # 4 hours
DETECTION_TIMEOUT = 3 * 3600  # 3 hours (chunk can take a while)
RECOVERY_TIMEOUT = 30 * 60  # 30 minutes

# Summary files for GitHub Issues (gitignored, read by workflow before commit)
ISSUE_SUMMARY_PATH = os.path.join(PIPELINE_DIR, "daily_summary.md")
ISSUE_TITLE_PATH = os.path.join(PIPELINE_DIR, "daily_summary_title.txt")
ROTATION_SUMMARY_PATH = os.path.join(DATA_DIR, "rotation_summary.md")


def log(msg):
    print(f"[pipeline] {msg}", flush=True)


def extract_domain(url):
    """Extract domain from a URL."""
    if not url:
        return None
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain if domain else None
    except Exception:
        return None


def read_csv(path):
    """Read a CSV file and return list of dicts."""
    if not os.path.exists(path):
        return []
    csv.field_size_limit(sys.maxsize)
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    """Write a CSV file from list of dicts."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_step(cmd, cwd, timeout, step_name):
    """Run a subprocess, stream output, raise on failure."""
    log(f"Running: {' '.join(cmd)}")
    log(f"  cwd: {cwd}")
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        timeout=timeout,
        capture_output=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{step_name} failed with exit code {proc.returncode}")
    log(f"{step_name} completed successfully.")


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def load_state():
    """Load pipeline state (chunk index, last run date, etc.)."""
    if not os.path.exists(PIPELINE_STATE_JSON):
        return {
            "last_chunk_index": -1,
            "last_run_date": None,
            "last_snapshot_date": "2026-02-02",
            "total_chunks": 8,
        }
    with open(PIPELINE_STATE_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state):
    """Persist pipeline state."""
    with open(PIPELINE_STATE_JSON, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    log(f"State saved: chunk={state['last_chunk_index']}, date={state['last_run_date']}")


# ---------------------------------------------------------------------------
# DB seeding & export
# ---------------------------------------------------------------------------

def step_seed_db():
    """Reconstruct SQLite DB from pm_results.csv so CI starts with full history."""
    log("=" * 60)
    log("STEP: Seed database from pm_results.csv")
    log("=" * 60)

    # Remove stale DB if present
    if os.path.exists(PM_DB_PATH):
        os.remove(PM_DB_PATH)
    if os.path.exists(RECOVERY_DB_PATH):
        os.remove(RECOVERY_DB_PATH)

    rows = read_csv(PM_RESULTS_CSV)
    if not rows:
        log("WARNING: pm_results.csv is empty or missing — starting with empty DB")
        return 0

    conn = sqlite3.connect(PM_DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            portal_system TEXT,
            portal_subdomain TEXT,
            confidence TEXT,
            detection_method TEXT,
            validated INTEGER,
            validation_website TEXT,
            error TEXT,
            timestamp TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON results(domain)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_portal_system ON results(portal_system)')

    inserted = 0
    for row in rows:
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO results
                (domain, portal_system, portal_subdomain, confidence,
                 detection_method, validated, validation_website,
                 error, timestamp, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                row.get("domain", ""),
                row.get("portal_system", ""),
                row.get("portal_subdomain", ""),
                row.get("confidence", ""),
                row.get("detection_method", ""),
                int(row.get("validated", 0)),
                row.get("validation_website", ""),
                row.get("error", ""),
                row.get("timestamp", ""),
            ))
            inserted += 1
        except Exception as e:
            log(f"  Seed error for {row.get('domain', '?')}: {e}")

    conn.commit()
    conn.close()
    log(f"Seeded DB with {inserted} domains from {PM_RESULTS_CSV}")
    return inserted


def step_export_db():
    """Export SQLite DB back to pm_results.csv (overwrites)."""
    log("=" * 60)
    log("STEP: Export database to pm_results.csv")
    log("=" * 60)

    if not os.path.exists(PM_DB_PATH):
        log("WARNING: No DB to export")
        return

    run_step(
        [sys.executable, "pm_system_detector.py",
         "export", PM_RESULTS_CSV,
         "--db", "pm_system_results.db"],
        cwd=PM_DETECTION_DIR,
        timeout=60,
        step_name="Export DB to CSV",
    )

    rows = read_csv(PM_RESULTS_CSV)
    log(f"Exported {len(rows)} domains to {PM_RESULTS_CSV}")


def _get_db_stats():
    """Get high-level DB stats for the issue summary."""
    if not os.path.exists(PM_DB_PATH):
        return None
    try:
        conn = sqlite3.connect(PM_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM results")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM results WHERE portal_system != 'unknown' AND portal_system NOT LIKE 'custom:%'")
        known = cursor.fetchone()[0]
        cursor.execute("SELECT portal_system, COUNT(*) FROM results GROUP BY portal_system")
        by_system = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        return {
            "total": total,
            "known": known,
            "unknown": by_system.get("unknown", 0),
            "by_system": by_system,
        }
    except Exception as e:
        log(f"Warning: could not get DB stats: {e}")
        return None


# ---------------------------------------------------------------------------
# Chunked re-scan
# ---------------------------------------------------------------------------

def get_chunk_domains(chunk_index, total_chunks):
    """Return domains for a given chunk (deterministic, alphabetically sorted)."""
    rows = read_csv(PM_RESULTS_CSV)
    all_domains = sorted(set(r.get("domain", "") for r in rows if r.get("domain")))

    chunk_size = len(all_domains) // total_chunks
    remainder = len(all_domains) % total_chunks

    # Distribute remainder across first 'remainder' chunks
    start = 0
    for i in range(chunk_index):
        start += chunk_size + (1 if i < remainder else 0)
    end = start + chunk_size + (1 if chunk_index < remainder else 0)

    chunk = all_domains[start:end]
    log(f"Chunk {chunk_index}/{total_chunks}: domains {start}-{end-1} "
        f"({len(chunk)} domains, total corpus: {len(all_domains)})")
    return chunk


def step_rescan_chunk(state):
    """Re-scan one chunk of existing domains with --no-skip to force re-detection."""
    total_chunks = state.get("total_chunks", 8)
    chunk_index = (state["last_chunk_index"] + 1) % total_chunks

    log("=" * 60)
    log(f"STEP: Re-scan chunk {chunk_index}/{total_chunks}")
    log("=" * 60)

    domains = get_chunk_domains(chunk_index, total_chunks)
    if not domains:
        log("No domains in this chunk — skipping")
        return chunk_index, 0

    # Write chunk domains to temp CSV
    write_csv(CHUNK_DOMAINS_CSV, [{"domain": d} for d in domains], ["domain"])

    run_step(
        [sys.executable, "pm_system_detector.py",
         "batch", CHUNK_DOMAINS_CSV, CHUNK_RESULTS_CSV,
         "--db", "pm_system_results.db",
         "--no-skip"],
        cwd=PM_DETECTION_DIR,
        timeout=DETECTION_TIMEOUT,
        step_name=f"Re-scan Chunk {chunk_index}",
    )

    results = read_csv(CHUNK_RESULTS_CSV)
    unknowns = sum(1 for r in results if r.get("portal_system") == "unknown")
    detected = len(results) - unknowns
    log(f"Chunk {chunk_index} complete: {len(results)} domains "
        f"({detected} detected, {unknowns} unknown)")

    return chunk_index, len(domains)


# ---------------------------------------------------------------------------
# DNS recovery
# ---------------------------------------------------------------------------

def step_dns_recovery():
    """Run DNS-based recovery strategies on unknown domains in the DB."""
    log("=" * 60)
    log("STEP: DNS recovery for unknown domains")
    log("=" * 60)

    if not os.path.exists(PM_DB_PATH):
        log("No DB found — skipping recovery")
        return 0

    # Count unknowns in DB
    conn = sqlite3.connect(PM_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM results WHERE portal_system = 'unknown'")
    unknowns = cursor.fetchone()[0]
    conn.close()

    if unknowns == 0:
        log("No unknown domains — skipping recovery")
        return 0

    log(f"Found {unknowns} unknown domains, running DNS recovery (strategies 2,6)")

    run_step(
        [sys.executable, "pm_unknown_recovery.py",
         "run", "--strategies", "2,6",
         "--main-db", "pm_system_results.db",
         "--db", "pm_recovery_results.db"],
        cwd=PM_DETECTION_DIR,
        timeout=RECOVERY_TIMEOUT,
        step_name="DNS Recovery",
    )

    # Consolidate recoveries back into main DB
    run_step(
        [sys.executable, "pm_unknown_recovery.py",
         "consolidate",
         "--main-db", "pm_system_results.db",
         "--db", "pm_recovery_results.db"],
        cwd=PM_DETECTION_DIR,
        timeout=60,
        step_name="Consolidate Recovery",
    )

    # Count unknowns after recovery
    conn = sqlite3.connect(PM_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM results WHERE portal_system = 'unknown'")
    new_unknowns = cursor.fetchone()[0]
    conn.close()

    recovered = unknowns - new_unknowns
    log(f"DNS recovery: {recovered} recovered ({new_unknowns} still unknown)")
    return recovered


# ---------------------------------------------------------------------------
# Snapshot & diff on rotation completion
# ---------------------------------------------------------------------------

def step_snapshot_if_rotation_complete(chunk_index, state):
    """Take a snapshot and diff when the chunk rotation wraps back to 0."""
    if chunk_index != 0:
        return False

    # First run (last_chunk_index was -1) — don't snapshot
    if state.get("last_chunk_index", -1) == -1:
        log("First rotation starting — skipping snapshot")
        return False

    log("=" * 60)
    log("STEP: Full rotation complete — taking snapshot and diffing")
    log("=" * 60)

    today = date.today().isoformat()
    os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
    snapshot_path = os.path.join(SNAPSHOTS_DIR, f"snapshot_{today}.csv")

    # Take snapshot via detector CLI
    run_step(
        [sys.executable, "pm_system_detector.py",
         "snapshot", snapshot_path,
         "--db", "pm_system_results.db"],
        cwd=PM_DETECTION_DIR,
        timeout=60,
        step_name="Take Snapshot",
    )

    # Find previous snapshot to diff against
    prev_snapshot_date = state.get("last_snapshot_date", "2026-02-02")
    prev_snapshot = os.path.join(SNAPSHOTS_DIR, f"snapshot_{prev_snapshot_date}_clean.csv")
    if not os.path.exists(prev_snapshot):
        prev_snapshot = os.path.join(SNAPSHOTS_DIR, f"snapshot_{prev_snapshot_date}.csv")

    if os.path.exists(prev_snapshot):
        log(f"Diffing against previous snapshot: {prev_snapshot}")

        # Run diff and capture output for the issue
        diff_output_csv = os.path.join(SNAPSHOTS_DIR, f"diff_{prev_snapshot_date}_to_{today}.csv")
        proc = subprocess.run(
            [sys.executable, "pm_system_detector.py",
             "diff", prev_snapshot,
             "--db", "pm_system_results.db",
             "--output", diff_output_csv],
            cwd=PM_DETECTION_DIR,
            timeout=60,
            capture_output=True,
            text=True,
        )

        diff_report = proc.stdout if proc.stdout else "No diff output captured."
        log(f"Diff complete. Report saved to {diff_output_csv}")

        # Write rotation summary for GitHub Issue
        _write_rotation_summary(today, prev_snapshot_date, diff_report, diff_output_csv)
    else:
        log(f"No previous snapshot found at {prev_snapshot} — skipping diff")

    # Update state with new snapshot date
    state["last_snapshot_date"] = today
    log(f"Snapshot saved: {snapshot_path}")
    return True


def _write_rotation_summary(today, prev_date, diff_report, diff_csv_path):
    """Write a markdown summary file for the GitHub Issue."""
    # Read the diff CSV if it exists for structured data
    changes = read_csv(diff_csv_path) if os.path.exists(diff_csv_path) else []

    switches = [c for c in changes if c.get("change_type") == "switch"]
    new_detections = [c for c in changes if c.get("change_type") == "new_detection"]
    lost_detections = [c for c in changes if c.get("change_type") == "lost_detection"]

    lines = [
        f"## PM Software Detection - Full Rotation Report",
        f"",
        f"**Period:** {prev_date} to {today}",
        f"**Changes detected:** {len(changes)}",
        f"",
        f"### Summary",
        f"- PM system switches: {len(switches)}",
        f"- New detections (unknown -> known): {len(new_detections)}",
        f"- Lost detections (known -> unknown): {len(lost_detections)}",
        f"",
    ]

    if switches:
        lines.append("### PM System Switches")
        lines.append("| Domain | Doors | From | To |")
        lines.append("|--------|-------|------|----|")
        for s in sorted(switches, key=lambda x: -int(x.get("doors", 0) or 0))[:20]:
            lines.append(f"| {s['domain']} | {s.get('doors', '?')} | {s['previous']} | {s['current']} |")
        if len(switches) > 20:
            lines.append(f"| ... | | | ({len(switches) - 20} more) |")
        lines.append("")

    if new_detections:
        lines.append("### New Detections")
        lines.append("| Domain | Doors | Detected As |")
        lines.append("|--------|-------|-------------|")
        for s in sorted(new_detections, key=lambda x: -int(x.get("doors", 0) or 0))[:20]:
            lines.append(f"| {s['domain']} | {s.get('doors', '?')} | {s['current']} |")
        if len(new_detections) > 20:
            lines.append(f"| ... | | ({len(new_detections) - 20} more) |")
        lines.append("")

    if lost_detections:
        lines.append("### Lost Detections")
        lines.append("| Domain | Doors | Was |")
        lines.append("|--------|-------|-----|")
        for s in sorted(lost_detections, key=lambda x: -int(x.get("doors", 0) or 0))[:20]:
            lines.append(f"| {s['domain']} | {s.get('doors', '?')} | {s['previous']} |")
        if len(lost_detections) > 20:
            lines.append(f"| ... | | ({len(lost_detections) - 20} more) |")
        lines.append("")

    # Append the raw diff report text
    lines.append("<details><summary>Full diff report</summary>")
    lines.append("")
    lines.append("```")
    lines.append(diff_report.strip())
    lines.append("```")
    lines.append("</details>")

    with open(ROTATION_SUMMARY_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log(f"Wrote rotation summary: {ROTATION_SUMMARY_PATH}")


# ---------------------------------------------------------------------------
# Existing pipeline steps (scrape, process, detect new, RBP)
# ---------------------------------------------------------------------------

def step_scrape():
    """Step 1: Copy baseline and run scraper --new-only."""
    log("=" * 60)
    log("STEP 1: Scrape new property managers")
    log("=" * 60)

    # Copy baseline so scraper can diff against it
    shutil.copy2(PROPERTY_MANAGERS_CSV, SCRAPER_BASELINE)
    log(f"Copied baseline ({PROPERTY_MANAGERS_CSV} -> {SCRAPER_BASELINE})")

    # Clean up any previous scraper state
    for f in [SCRAPER_NEW_OUTPUT,
              os.path.join(SCRAPER_DIR, "scraper_progress_new_only.json"),
              os.path.join(SCRAPER_DIR, "new_property_managers_partial.csv")]:
        if os.path.exists(f):
            os.remove(f)

    run_step(
        [sys.executable, "scraper.py", "--new-only"],
        cwd=SCRAPER_DIR,
        timeout=SCRAPE_TIMEOUT,
        step_name="Scraper",
    )

    # Read results
    if not os.path.exists(SCRAPER_NEW_OUTPUT):
        log("No new_property_managers.csv produced (0 new PMs found).")
        return []

    new_pms = read_csv(SCRAPER_NEW_OUTPUT)
    log(f"Found {len(new_pms)} new property managers.")
    return new_pms


def step_process(new_pms):
    """Step 2: Append new PMs to baseline, extract domains."""
    log("=" * 60)
    log("STEP 2: Process new PMs and extract domains")
    log("=" * 60)

    today = date.today().isoformat()

    # Append to property_managers.csv
    pm_fieldnames = ["name", "doors_managed", "website", "state", "city", "profile_url"]
    with open(PROPERTY_MANAGERS_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=pm_fieldnames)
        for pm in new_pms:
            writer.writerow({k: pm.get(k, "") for k in pm_fieldnames})
    log(f"Appended {len(new_pms)} PMs to {PROPERTY_MANAGERS_CSV}")

    # Extract domains and build domain lists
    new_domains = []
    domains_doors_rows = []
    for pm in new_pms:
        domain = extract_domain(pm.get("website", ""))
        if domain:
            doors = pm.get("doors_managed", "0")
            new_domains.append({
                "domain": domain,
                "doors": doors,
                "company": pm.get("name", ""),
                "state": pm.get("state", ""),
                "city": pm.get("city", ""),
            })
            domains_doors_rows.append({"domain": domain, "doors": doors})

    log(f"Extracted {len(new_domains)} domains with websites (out of {len(new_pms)} PMs)")

    # Write new_domains.csv for PM detection input
    write_csv(NEW_DOMAINS_CSV, new_domains, ["domain", "doors", "company", "state", "city"])

    # Append to domains_doors.csv
    with open(DOMAINS_DOORS_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "doors"])
        for row in domains_doors_rows:
            writer.writerow(row)
    log(f"Appended {len(domains_doors_rows)} domains to {DOMAINS_DOORS_CSV}")

    return new_domains


def step_pm_detection_new():
    """Detect PM software for newly discovered domains (DB already seeded)."""
    log("=" * 60)
    log("STEP: Detect PM software for new domains")
    log("=" * 60)

    run_step(
        [sys.executable, "pm_system_detector.py",
         "batch", NEW_DOMAINS_CSV, PM_RESULTS_NEW_CSV,
         "--db", "pm_system_results.db",
         "--no-playwright"],
        cwd=PM_DETECTION_DIR,
        timeout=DETECTION_TIMEOUT,
        step_name="PM Detection (new)",
    )

    pm_results = read_csv(PM_RESULTS_NEW_CSV)
    unknowns = sum(1 for r in pm_results if r.get("portal_system") == "unknown")
    log(f"PM detection completed for {len(pm_results)} new domains ({unknowns} unknown).")

    # Prepare input for RBP detection
    rbp_input = []
    for row in pm_results:
        rbp_input.append({
            "domain": row.get("domain", ""),
            "portal_system": row.get("portal_system", ""),
            "portal_subdomain": row.get("portal_subdomain", ""),
        })
    write_csv(PM_RESULTS_FOR_RBP_CSV, rbp_input, ["domain", "portal_system", "portal_subdomain"])
    log(f"Wrote {len(rbp_input)} domains to {PM_RESULTS_FOR_RBP_CSV} for RBP detection")

    return pm_results


def step_rbp_detection():
    """Run RBP detection on newly PM-detected domains."""
    log("=" * 60)
    log("STEP: Detect RBP offerings for new domains")
    log("=" * 60)

    run_step(
        [sys.executable, "rbp_detector.py",
         "batch", PM_RESULTS_FOR_RBP_CSV,
         "--workers", "4"],
        cwd=RBP_DETECTION_DIR,
        timeout=DETECTION_TIMEOUT,
        step_name="RBP Detection",
    )

    # Export RBP results to CSV for reading
    rbp_export_path = os.path.join(RBP_DETECTION_DIR, "rbp_results.csv")
    run_step(
        [sys.executable, "rbp_detector.py", "export", rbp_export_path],
        cwd=RBP_DETECTION_DIR,
        timeout=60,
        step_name="RBP Export",
    )

    # Read back the new domains' RBP results
    all_rbp = read_csv(rbp_export_path)
    new_domain_set = set(row["domain"] for row in read_csv(PM_RESULTS_FOR_RBP_CSV))
    rbp_results = [r for r in all_rbp if r.get("domain") in new_domain_set]
    log(f"RBP detection completed. {len(rbp_results)} results for new domains.")

    # Append to cumulative rbp_results.csv
    if rbp_results:
        rbp_fieldnames = list(rbp_results[0].keys())
        file_exists = os.path.exists(RBP_RESULTS_CSV)
        with open(RBP_RESULTS_CSV, "a", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rbp_fieldnames)
            if not file_exists:
                writer.writeheader()
            for row in rbp_results:
                writer.writerow(row)
        log(f"Appended {len(rbp_results)} results to cumulative {RBP_RESULTS_CSV}")

    return rbp_results


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def compute_rbp_stats(rbp_rows):
    """Compute RBP statistics from a list of RBP result dicts."""
    total = len(rbp_rows)
    offered = 0
    vendors = Counter()
    categories = Counter()
    by_pm_system = Counter()  # pm_system -> rbp_offered count

    for r in rbp_rows:
        is_offered = str(r.get("rbp_offered", "0")) == "1"
        if is_offered:
            offered += 1
            pm = r.get("pm_system", "unknown") or "unknown"
            by_pm_system[pm] += 1

        known = r.get("known_vendors", "").strip()
        if known:
            for vendor in known.split(";"):
                v = vendor.strip()
                if v:
                    vendors[v] += 1

        cats = r.get("vendors_by_category", "").strip()
        if cats:
            for entry in cats.split(";"):
                cat = entry.split(":")[0].strip() if ":" in entry else entry.strip()
                if cat:
                    categories[cat] += 1

    return {
        "total_scanned": total,
        "rbp_offered": offered,
        "rbp_rate": round(100 * offered / total, 1) if total else 0,
        "vendors": dict(vendors.most_common()),
        "categories": dict(categories.most_common()),
        "rbp_by_pm_system": dict(by_pm_system.most_common()),
    }


def load_previous_stats():
    """Load the previous week's cumulative stats for delta comparison."""
    if not os.path.exists(CUMULATIVE_STATS_JSON):
        return None
    with open(CUMULATIVE_STATS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def save_cumulative_stats(stats, week):
    """Save this week's cumulative stats for next week's comparison."""
    stats["week"] = week
    os.makedirs(WEEKLY_LOGS_DIR, exist_ok=True)
    with open(CUMULATIVE_STATS_JSON, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)


def fmt_delta(current, previous, is_pct=False):
    """Format a value with its week-on-week delta."""
    if previous is None:
        return str(current)
    diff = current - previous
    if diff == 0:
        return f"{current} (unchanged)"
    sign = "+" if diff > 0 else ""
    if is_pct:
        return f"{current}% ({sign}{diff:+.1f}pp)"
    return f"{current} ({sign}{diff})"


def _write_issue_summary(today, chunk_info, new_pms, new_domains, pm_results,
                         rbp_results, db_stats):
    """Write GitHub Issue markdown summary + title file."""
    is_monday = date.today().weekday() == 0
    day_name = date.today().strftime("%A")

    # Title
    parts = [f"PM Pipeline: {today}"]
    if chunk_info:
        parts.append(f"chunk {chunk_info['chunk_index']}/{chunk_info['total_chunks']}")
    if new_pms:
        parts.append(f"{len(new_pms)} new PMs")
    if chunk_info and chunk_info.get("rotation_complete"):
        parts.append("ROTATION COMPLETE")
    title = " - ".join(parts)

    with open(ISSUE_TITLE_PATH, "w", encoding="utf-8") as f:
        f.write(title)

    # Body
    lines = []

    # Chunk progress section
    if chunk_info:
        idx = chunk_info["chunk_index"]
        total = chunk_info["total_chunks"]
        rescanned = chunk_info["domains_rescanned"]
        recovered = chunk_info.get("dns_recovered", 0)
        rotation = chunk_info.get("rotation_complete", False)

        progress = "".join(
            ":green_square:" if i < idx else
            ":blue_square:" if i == idx else
            ":white_large_square:"
            for i in range(total)
        )
        lines.append(f"### Chunk Re-scan")
        lines.append(f"{progress} **{idx}/{total}**")
        lines.append(f"- Domains re-scanned: **{rescanned:,}**")
        lines.append(f"- DNS recovered: **{recovered}**")
        if rotation:
            lines.append(f"- :tada: **Full rotation complete** — snapshot & diff generated")
        lines.append("")

    # New PMs (Monday only)
    if new_pms:
        with_website = len(new_domains)
        pm_detected = sum(1 for r in pm_results
                          if r.get("portal_system") and r.get("portal_system") != "unknown")
        lines.append("### New PMs Discovered")
        lines.append(f"| Metric | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| New PMs found | {len(new_pms)} |")
        lines.append(f"| With website | {with_website} |")
        lines.append(f"| PM software detected | {pm_detected} |")
        lines.append("")

        pm_systems = Counter()
        for r in pm_results:
            system = r.get("portal_system", "unknown")
            if system and system != "unknown":
                pm_systems[system] += 1
        if pm_systems:
            lines.append("**PM System Breakdown:**")
            for system, count in pm_systems.most_common():
                lines.append(f"- {system}: {count}")
            lines.append("")

    # DB-wide stats
    if db_stats:
        total_domains = db_stats.get("total", 0)
        known = db_stats.get("known", 0)
        unknown = db_stats.get("unknown", 0)
        detection_rate = round(100 * known / total_domains, 1) if total_domains else 0

        lines.append("### Database Summary")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total domains | {total_domains:,} |")
        lines.append(f"| Detected (known PM) | {known:,} ({detection_rate}%) |")
        lines.append(f"| Unknown | {unknown:,} |")

        # Top PM systems
        by_system = db_stats.get("by_system", {})
        if by_system:
            lines.append("")
            lines.append("**Market share:**")
            lines.append("| PM System | Count |")
            lines.append("|-----------|-------|")
            for system, count in sorted(by_system.items(), key=lambda x: -x[1]):
                if system not in ("unknown",) and not system.startswith("custom:"):
                    lines.append(f"| {system} | {count:,} |")
        lines.append("")

    with open(ISSUE_SUMMARY_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log(f"Wrote issue summary: {ISSUE_SUMMARY_PATH}")


def step_log(new_pms, new_domains, pm_results, rbp_results, chunk_info=None):
    """Write daily log CSV and summary."""
    log("=" * 60)
    log("STEP: Generate daily log")
    log("=" * 60)

    today = date.today().isoformat()
    os.makedirs(WEEKLY_LOGS_DIR, exist_ok=True)
    log_csv_path = os.path.join(WEEKLY_LOGS_DIR, f"weekly_{today}.csv")
    summary_path = os.path.join(WEEKLY_LOGS_DIR, f"weekly_{today}_summary.txt")

    # Build lookup tables
    pm_by_domain = {r.get("domain", ""): r for r in pm_results}
    rbp_by_domain = {r.get("domain", ""): r for r in rbp_results}

    # Build combined rows
    log_fieldnames = [
        "week", "domain", "company", "doors", "state", "city",
        "pm_system", "pm_subdomain", "pm_confidence",
        "rbp_offered", "rbp_vendors",
    ]
    log_rows = []
    for d in new_domains:
        domain = d["domain"]
        pm = pm_by_domain.get(domain, {})
        rbp = rbp_by_domain.get(domain, {})
        log_rows.append({
            "week": today,
            "domain": domain,
            "company": d.get("company", ""),
            "doors": d.get("doors", ""),
            "state": d.get("state", ""),
            "city": d.get("city", ""),
            "pm_system": pm.get("portal_system", ""),
            "pm_subdomain": pm.get("portal_subdomain", ""),
            "pm_confidence": pm.get("confidence", ""),
            "rbp_offered": rbp.get("rbp_offered", ""),
            "rbp_vendors": rbp.get("known_vendors", ""),
        })

    write_csv(log_csv_path, log_rows, log_fieldnames)
    log(f"Wrote daily log: {log_csv_path} ({len(log_rows)} rows)")

    # --- Summary ---
    with_website = len(new_domains)
    pm_detected = sum(1 for r in pm_results if r.get("portal_system") and r.get("portal_system") != "unknown")
    new_rbp_offered = sum(1 for r in rbp_results if str(r.get("rbp_offered", "0")) == "1")

    pm_systems = Counter()
    for r in pm_results:
        system = r.get("portal_system", "unknown")
        if system and system != "unknown":
            pm_systems[system] += 1

    summary_lines = [
        f"Daily Pipeline Report: {today}",
        "=" * 60,
    ]

    # Chunk re-scan info
    if chunk_info:
        summary_lines.extend([
            "",
            "CHUNK RE-SCAN",
            "-" * 40,
            f"Chunk: {chunk_info['chunk_index']}/{chunk_info['total_chunks']}",
            f"Domains re-scanned: {chunk_info['domains_rescanned']}",
            f"DNS recovered: {chunk_info.get('dns_recovered', 0)}",
            f"Rotation complete: {'Yes' if chunk_info.get('rotation_complete') else 'No'}",
        ])

    # New PMs section (Monday runs)
    if new_pms or new_domains:
        summary_lines.extend([
            "",
            "NEW PMs DISCOVERED",
            "-" * 40,
            f"New property managers found: {len(new_pms)}",
            f"  With website: {with_website}",
            f"  PM software detected: {pm_detected}",
            f"  RBP offered: {new_rbp_offered}",
        ])
        if pm_systems:
            summary_lines.append("  PM System Breakdown:")
            for system, count in pm_systems.most_common():
                summary_lines.append(f"    {system}: {count}")

    # --- Database-Wide RBP Summary ---
    summary_lines.extend(["", ""])
    summary_lines.append("DATABASE-WIDE RBP SUMMARY")
    summary_lines.append("-" * 40)

    all_rbp = read_csv(RBP_RESULTS_CSV)
    prev_stats = load_previous_stats()
    curr_stats = compute_rbp_stats(all_rbp)

    prev_total = prev_stats.get("total_scanned") if prev_stats else None
    prev_offered = prev_stats.get("rbp_offered") if prev_stats else None
    prev_rate = prev_stats.get("rbp_rate") if prev_stats else None
    prev_vendors = prev_stats.get("vendors", {}) if prev_stats else {}
    prev_categories = prev_stats.get("categories", {}) if prev_stats else {}
    prev_by_pm = prev_stats.get("rbp_by_pm_system", {}) if prev_stats else {}

    summary_lines.append(f"Total domains scanned: {fmt_delta(curr_stats['total_scanned'], prev_total)}")
    summary_lines.append(f"RBP offered: {fmt_delta(curr_stats['rbp_offered'], prev_offered)}")
    summary_lines.append(f"RBP adoption rate: {fmt_delta(curr_stats['rbp_rate'], prev_rate, is_pct=True)}")

    if curr_stats["rbp_by_pm_system"]:
        summary_lines.append("")
        summary_lines.append("RBP Adoption by PM System:")
        for system, count in sorted(curr_stats["rbp_by_pm_system"].items(), key=lambda x: -x[1]):
            prev_count = prev_by_pm.get(system)
            summary_lines.append(f"  {system}: {fmt_delta(count, prev_count)}")

    if curr_stats["categories"]:
        summary_lines.append("")
        summary_lines.append("Vendor Categories (domains using each):")
        for cat, count in sorted(curr_stats["categories"].items(), key=lambda x: -x[1]):
            prev_count = prev_categories.get(cat)
            summary_lines.append(f"  {cat}: {fmt_delta(count, prev_count)}")

    if curr_stats["vendors"]:
        summary_lines.append("")
        summary_lines.append("Top Vendors (domains using each):")
        top_vendors = sorted(curr_stats["vendors"].items(), key=lambda x: -x[1])[:15]
        for vendor, count in top_vendors:
            prev_count = prev_vendors.get(vendor)
            summary_lines.append(f"  {vendor}: {fmt_delta(count, prev_count)}")

    if prev_stats:
        prev_week = prev_stats.get("week", "unknown")
        summary_lines.extend(["", f"(Deltas vs. previous run: {prev_week})"])

    # Save current stats for next run
    save_cumulative_stats(curr_stats, today)

    summary_text = "\n".join(summary_lines) + "\n"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_text)

    log(f"Wrote summary: {summary_path}")
    print()
    print(summary_text)

    return log_csv_path, summary_path


def write_empty_log(reason="No new property managers found"):
    """Write an empty weekly log when there's nothing to process."""
    today = date.today().isoformat()
    os.makedirs(WEEKLY_LOGS_DIR, exist_ok=True)
    log_csv_path = os.path.join(WEEKLY_LOGS_DIR, f"weekly_{today}.csv")
    summary_path = os.path.join(WEEKLY_LOGS_DIR, f"weekly_{today}_summary.txt")

    log_fieldnames = [
        "week", "domain", "company", "doors", "state", "city",
        "pm_system", "pm_subdomain", "pm_confidence",
        "rbp_offered", "rbp_vendors",
    ]
    write_csv(log_csv_path, [], log_fieldnames)

    summary_text = (
        f"Daily Pipeline Report: {today}\n"
        f"{'=' * 50}\n"
        f"{reason}\n"
        f"No further processing needed.\n"
    )
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_text)

    log(f"Wrote empty log: {log_csv_path}")
    print(summary_text)


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Daily PM Discovery & Re-scan Pipeline")
    parser.add_argument(
        "--skip-scrape",
        action="store_true",
        help="Skip scraping step; use existing scraper/new_property_managers.csv",
    )
    parser.add_argument(
        "--skip-rescan",
        action="store_true",
        help="Skip the chunk re-scan of existing domains",
    )
    parser.add_argument(
        "--skip-recovery",
        action="store_true",
        help="Skip DNS recovery pass",
    )
    args = parser.parse_args()

    today = date.today()
    is_monday = today.weekday() == 0
    today_str = today.isoformat()

    log(f"Pipeline started: {today_str} ({'Monday' if is_monday else today.strftime('%A')})")
    log(f"Pipeline dir: {PIPELINE_DIR}")

    # 1. Load state
    state = load_state()
    log(f"State: chunk={state['last_chunk_index']}, "
        f"last_run={state['last_run_date']}, "
        f"chunks={state['total_chunks']}")

    # 2. Seed DB from pm_results.csv
    step_seed_db()

    # 3. Monday: Scrape new PMs + detect + process
    new_pms = []
    new_domains = []
    pm_results_new = []
    rbp_results = []

    if is_monday and not args.skip_scrape:
        new_pms = step_scrape()
        if new_pms:
            new_domains = step_process(new_pms)
            if new_domains:
                pm_results_new = step_pm_detection_new()
    elif is_monday and args.skip_scrape:
        log("Monday but --skip-scrape set. Checking for existing new PMs...")
        if os.path.exists(SCRAPER_NEW_OUTPUT):
            new_pms = read_csv(SCRAPER_NEW_OUTPUT)
            log(f"Loaded {len(new_pms)} PMs from {SCRAPER_NEW_OUTPUT}")
            if new_pms:
                new_domains = step_process(new_pms)
                if new_domains:
                    pm_results_new = step_pm_detection_new()
        else:
            log("No existing new_property_managers.csv found.")
    else:
        log("Not Monday — skipping new PM scraping")

    # 4. Daily: Re-scan chunk of existing domains
    chunk_index = None
    domains_rescanned = 0
    if not args.skip_rescan:
        chunk_index, domains_rescanned = step_rescan_chunk(state)
    else:
        log("Skipping chunk re-scan (--skip-rescan)")

    # 5. DNS recovery on unknowns
    dns_recovered = 0
    if not args.skip_recovery:
        dns_recovered = step_dns_recovery()
    else:
        log("Skipping DNS recovery (--skip-recovery)")

    # 6. Export DB back to pm_results.csv
    step_export_db()

    # 7. Monday + new domains: RBP detection
    if is_monday and new_domains and pm_results_new:
        rbp_results = step_rbp_detection()

    # 8. Snapshot/diff if rotation complete
    rotation_complete = False
    if chunk_index is not None:
        rotation_complete = step_snapshot_if_rotation_complete(chunk_index, state)

    # 9. Generate daily log
    chunk_info = None
    if chunk_index is not None:
        chunk_info = {
            "chunk_index": chunk_index,
            "total_chunks": state["total_chunks"],
            "domains_rescanned": domains_rescanned,
            "dns_recovered": dns_recovered,
            "rotation_complete": rotation_complete,
        }

    step_log(new_pms, new_domains, pm_results_new, rbp_results, chunk_info=chunk_info)

    # 10. Write GitHub Issue summary
    db_stats = _get_db_stats()
    _write_issue_summary(today_str, chunk_info, new_pms, new_domains,
                         pm_results_new, rbp_results, db_stats)

    # 11. Save state
    if chunk_index is not None:
        state["last_chunk_index"] = chunk_index
    state["last_run_date"] = today_str
    save_state(state)

    # Clean up intermediate files
    for f in [CHUNK_DOMAINS_CSV, CHUNK_RESULTS_CSV]:
        if os.path.exists(f):
            os.remove(f)

    log("Pipeline complete!")


if __name__ == "__main__":
    main()
