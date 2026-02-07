"""
Weekly PM Discovery Pipeline

Orchestrates:
1. Scrape new property managers (appfolio-2 scraper, --new-only)
2. Detect PM software for new domains (appfolio-tech pm_system_detector)
3. Detect RBP offerings for new domains (appfolio-rbp-detection rbp_detector)
4. Log all findings to weekly CSV + summary

Usage:
  python weekly_pipeline.py              # Full pipeline
  python weekly_pipeline.py --skip-scrape  # Skip scraping, use existing new_property_managers.csv
"""

import argparse
import csv
import json
import os
import shutil
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

# Data files
PROPERTY_MANAGERS_CSV = os.path.join(DATA_DIR, "property_managers.csv")
DOMAINS_DOORS_CSV = os.path.join(DATA_DIR, "domains_doors.csv")
PM_RESULTS_CSV = os.path.join(DATA_DIR, "pm_results.csv")
RBP_RESULTS_CSV = os.path.join(DATA_DIR, "rbp_results.csv")
CUMULATIVE_STATS_JSON = os.path.join(WEEKLY_LOGS_DIR, "cumulative_stats.json")

# Intermediate files (gitignored)
NEW_DOMAINS_CSV = os.path.join(DATA_DIR, "new_domains.csv")
PM_RESULTS_NEW_CSV = os.path.join(DATA_DIR, "pm_results_new.csv")
PM_RESULTS_FOR_RBP_CSV = os.path.join(DATA_DIR, "pm_results_for_rbp.csv")

# Scraper files (relative to scraper cwd)
SCRAPER_BASELINE = os.path.join(SCRAPER_DIR, "property_managers.csv")
SCRAPER_NEW_OUTPUT = os.path.join(SCRAPER_DIR, "new_property_managers.csv")

SCRAPE_TIMEOUT = 4 * 3600  # 4 hours
DETECTION_TIMEOUT = 2 * 3600  # 2 hours


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


def step_pm_detection():
    """Step 3: Run PM software detection on new domains."""
    log("=" * 60)
    log("STEP 3: Detect PM software for new domains")
    log("=" * 60)

    run_step(
        [sys.executable, "pm_system_detector.py",
         "batch", NEW_DOMAINS_CSV, PM_RESULTS_NEW_CSV,
         "--db", "pm_system_results.db",
         "--no-playwright"],
        cwd=PM_DETECTION_DIR,
        timeout=DETECTION_TIMEOUT,
        step_name="PM Detection",
    )

    # Read initial detection results
    pm_results = read_csv(PM_RESULTS_NEW_CSV)
    unknowns = sum(1 for r in pm_results if r.get("portal_system") == "unknown")
    log(f"PM detection completed for {len(pm_results)} domains ({unknowns} unknown).")

    # Step 3.5: DNS recovery for unknowns (strategies 2=CNAME, 6=SPF/MX/TXT)
    if unknowns > 0:
        log("-" * 40)
        log(f"STEP 3.5: DNS recovery for {unknowns} unknown domains")
        log("-" * 40)
        pm_db = os.path.join(PM_DETECTION_DIR, "pm_system_results.db")
        recovery_db = os.path.join(PM_DETECTION_DIR, "pm_recovery_results.db")

        run_step(
            [sys.executable, "pm_unknown_recovery.py",
             "run", "--strategies", "2,6",
             "--main-db", "pm_system_results.db",
             "--db", "pm_recovery_results.db"],
            cwd=PM_DETECTION_DIR,
            timeout=DETECTION_TIMEOUT,
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

        # Re-export to pick up recovered domains
        run_step(
            [sys.executable, "pm_system_detector.py",
             "export", PM_RESULTS_NEW_CSV,
             "--db", "pm_system_results.db"],
            cwd=PM_DETECTION_DIR,
            timeout=60,
            step_name="Re-export PM Results",
        )
        pm_results = read_csv(PM_RESULTS_NEW_CSV)
        new_unknowns = sum(1 for r in pm_results if r.get("portal_system") == "unknown")
        recovered = unknowns - new_unknowns
        log(f"DNS recovery recovered {recovered} domains ({new_unknowns} still unknown).")

    # Append new results to the cumulative pm_results.csv
    if pm_results and os.path.exists(PM_RESULTS_CSV):
        pm_fieldnames = list(pm_results[0].keys())
        with open(PM_RESULTS_CSV, "a", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=pm_fieldnames)
            for row in pm_results:
                writer.writerow(row)
        log(f"Appended {len(pm_results)} results to cumulative {PM_RESULTS_CSV}")

    # Prepare input for RBP detection: need domain, portal_system, portal_subdomain
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
    """Step 4: Run RBP detection on newly PM-detected domains."""
    log("=" * 60)
    log("STEP 4: Detect RBP offerings for new domains")
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
    # Filter to just the domains we processed this week
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


def step_log(new_pms, new_domains, pm_results, rbp_results):
    """Step 5: Write weekly log CSV and summary."""
    log("=" * 60)
    log("STEP 5: Generate weekly log")
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
    log(f"Wrote weekly log: {log_csv_path} ({len(log_rows)} rows)")

    # --- This Week's New PMs Summary ---
    with_website = len(new_domains)
    pm_detected = sum(1 for r in pm_results if r.get("portal_system") and r.get("portal_system") != "unknown")
    new_rbp_offered = sum(1 for r in rbp_results if str(r.get("rbp_offered", "0")) == "1")

    pm_systems = Counter()
    for r in pm_results:
        system = r.get("portal_system", "unknown")
        if system and system != "unknown":
            pm_systems[system] += 1

    summary_lines = [
        f"Weekly Pipeline Report: {today}",
        "=" * 60,
        "",
        "THIS WEEK'S NEW PMs",
        "-" * 40,
        f"New property managers found: {len(new_pms)}",
        f"  With website: {with_website}",
        f"  PM software detected: {pm_detected}",
        f"  RBP offered: {new_rbp_offered}",
    ]

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
        summary_lines.extend(["", f"(Deltas vs. previous week: {prev_week})"])

    # Save current stats for next week
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
        f"Weekly Pipeline Report: {today}\n"
        f"{'=' * 50}\n"
        f"{reason}\n"
        f"No further processing needed.\n"
    )
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_text)

    log(f"Wrote empty log: {log_csv_path}")
    print(summary_text)


def main():
    parser = argparse.ArgumentParser(description="Weekly PM Discovery Pipeline")
    parser.add_argument(
        "--skip-scrape",
        action="store_true",
        help="Skip scraping step; use existing scraper/new_property_managers.csv",
    )
    args = parser.parse_args()

    log(f"Pipeline started: {date.today().isoformat()}")
    log(f"Pipeline dir: {PIPELINE_DIR}")

    # Step 1: Scrape (or load existing)
    if args.skip_scrape:
        log("Skipping scrape (--skip-scrape). Loading existing new PMs...")
        if not os.path.exists(SCRAPER_NEW_OUTPUT):
            log(f"ERROR: {SCRAPER_NEW_OUTPUT} not found. Cannot skip scrape without it.")
            sys.exit(1)
        new_pms = read_csv(SCRAPER_NEW_OUTPUT)
        log(f"Loaded {len(new_pms)} PMs from {SCRAPER_NEW_OUTPUT}")
    else:
        new_pms = step_scrape()

    # Early exit if no new PMs
    if not new_pms:
        write_empty_log()
        log("Pipeline complete (no new PMs).")
        return

    # Step 2: Process new PMs, extract domains
    new_domains = step_process(new_pms)

    if not new_domains:
        write_empty_log("New PMs found but none had websites")
        log("Pipeline complete (no domains to process).")
        return

    # Step 3: PM software detection
    pm_results = step_pm_detection()

    # Step 4: RBP detection
    rbp_results = step_rbp_detection()

    # Step 5: Generate weekly log
    step_log(new_pms, new_domains, pm_results, rbp_results)

    log("Pipeline complete!")


if __name__ == "__main__":
    main()
