# PM Discovery Pipeline

Automated weekly pipeline that discovers new property managers and analyzes their technology stack.

## Pipeline Steps

1. **Scrape** — Finds new PMs on propertymanagement.com (`scraper.py --new-only`)
2. **PM Detection** — Identifies PM software (AppFolio, Yardi, Buildium, etc.) for each domain
3. **RBP Detection** — Detects Resident Benefits Package offerings and vendor usage
4. **Log** — Writes weekly CSV + summary to `data/weekly_logs/`

## Usage

```bash
# Full pipeline (scrape + detect + log)
python weekly_pipeline.py

# Skip scraping (retry detection on existing new PMs)
python weekly_pipeline.py --skip-scrape
```

## Automation

Runs weekly via GitHub Actions (Monday 6 AM UTC). Can also be triggered manually via `workflow_dispatch`.

## Data Files

| File | Description |
|------|-------------|
| `data/property_managers.csv` | Cumulative list of all PMs (baseline for scraper) |
| `data/domains_doors.csv` | Domain → door count mapping |
| `data/pm_results.csv` | Cumulative PM software detection results |
| `data/weekly_logs/weekly_YYYY-MM-DD.csv` | Per-week discovery log |
| `data/weekly_logs/weekly_YYYY-MM-DD_summary.txt` | Per-week summary |

## Seeded Data

- **PM detection results** from `appfolio-tech` (~8,241 domains already detected)
- **RBP results** from `appfolio-rbp-detection` (~8,243 domains already scanned)
- **Property managers** from `appfolio-2` (9,091 PMs baseline)

The seeded databases (`pm_detection/pm_system_results.db`, `rbp_detection/rbp_results.db`) allow detection steps to skip already-processed domains.
