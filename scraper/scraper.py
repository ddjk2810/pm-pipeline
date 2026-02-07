"""
Property Manager Scraper for propertymanagement.com
Scrapes: Property Manager Name, # of Doors Managed, Website

Features:
- Saves progress to resume after interruption/disconnection
- Retries on network errors with exponential backoff
- Periodic saves to prevent data loss
- Quick mode (--quick) for incremental updates - skips empty cities
- New-only mode (--new-only) for finding net new property managers

Usage:
  python scraper.py            # Full scrape (or resume)
  python scraper.py --quick    # Quick incremental update (skips empty cities)
  python scraper.py --new-only # Find only NEW managers not in existing data
"""

import argparse
import csv
import json
import os
import random
import re
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# File paths
PROGRESS_FILE = "scraper_progress.json"
OUTPUT_FILE = "property_managers.csv"
PARTIAL_FILE = "property_managers_partial.csv"
NEW_ONLY_OUTPUT_FILE = "new_property_managers.csv"
NEW_ONLY_PROGRESS_FILE = "scraper_progress_new_only.json"


def random_delay():
    """Sleep for 3-6 seconds randomly."""
    delay = random.uniform(3, 6)
    print(f"    [Waiting {delay:.1f}s]")
    time.sleep(delay)


def wait_for_network(max_wait=300):
    """Wait for network to come back, checking every 10 seconds."""
    import socket

    start_time = time.time()
    attempt = 0

    while time.time() - start_time < max_wait:
        attempt += 1
        try:
            # Try to connect to a reliable host
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            print(f"    Network restored after {attempt} attempts")
            return True
        except OSError:
            wait_time = min(10 * attempt, 60)  # Cap at 60 seconds
            print(f"    Network unavailable, retrying in {wait_time}s... (attempt {attempt})")
            time.sleep(wait_time)

    return False


def setup_driver():
    """Set up Chrome driver with options."""
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
    return webdriver.Chrome(options=options)


def save_progress(progress):
    """Save current progress to file."""
    # Convert sets to lists for JSON serialization
    progress_serializable = {}
    for key, value in progress.items():
        if isinstance(value, set):
            progress_serializable[key] = list(value)
        else:
            progress_serializable[key] = value
    with open(PROGRESS_FILE, 'w', encoding='utf-8') as f:
        json.dump(progress_serializable, f, indent=2)


def load_progress():
    """Load progress from file if it exists."""
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return None


def load_existing_data():
    """Load existing scraped data from partial file and return data + profile URLs."""
    data = []
    profile_urls = set()
    if os.path.exists(PARTIAL_FILE):
        try:
            with open(PARTIAL_FILE, 'r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                data = list(reader)
            # Extract profile URLs for deduplication
            for row in data:
                if row.get('profile_url'):
                    profile_urls.add(row['profile_url'])
            print(f"  Loaded {len(data)} existing records from {PARTIAL_FILE}")
            print(f"  Found {len(profile_urls)} unique profiles for deduplication")
        except:
            pass
    return data, profile_urls


def load_baseline_urls():
    """Load all profile URLs from the main output file as baseline for new-only mode."""
    baseline_urls = set()
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('profile_url'):
                        baseline_urls.add(row['profile_url'])
            print(f"  Loaded {len(baseline_urls)} baseline URLs from {OUTPUT_FILE}")
        except Exception as e:
            print(f"  Warning: Could not load baseline file: {e}")
    else:
        print(f"  Warning: No baseline file found at {OUTPUT_FILE}")
    return baseline_urls


def fetch_with_retry(driver, url, wait_selector=None, max_retries=5):
    """Fetch a URL with retry logic for network errors."""
    for attempt in range(max_retries):
        try:
            driver.get(url)
            if wait_selector:
                WebDriverWait(driver, 15).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, wait_selector))
                )
            else:
                WebDriverWait(driver, 15).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            time.sleep(2)  # Extra wait for JS
            return True

        except WebDriverException as e:
            error_msg = str(e).lower()
            if 'net::err' in error_msg or 'timeout' in error_msg or 'disconnected' in error_msg:
                print(f"    Network error on attempt {attempt + 1}: {str(e)[:100]}")
                if wait_for_network():
                    # Recreate driver after network restore
                    continue
                else:
                    raise Exception("Network unavailable for too long")
            else:
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                raise
        except TimeoutException:
            if attempt < max_retries - 1:
                print(f"    Timeout on attempt {attempt + 1}, retrying...")
                time.sleep(5)
                continue
            return False

    return False


def get_states(driver):
    """Get all state links from the all locations page."""
    url = "https://propertymanagement.com/location/all"

    if not fetch_with_retry(driver, url, "a"):
        return []

    state_links = []
    links = driver.find_elements(By.TAG_NAME, "a")

    for link in links:
        href = link.get_attribute("href")
        if href and "/location/" in href and href != url and "/location/all" not in href:
            parts = href.rstrip('/').split('/')
            if len(parts) == 5 and parts[3] == "location":
                state_name = link.text.strip()
                if state_name and href not in [s[1] for s in state_links]:
                    state_links.append((state_name, href))

    return state_links


def get_cities(driver, state_url):
    """Get all city links from a state page."""
    if not fetch_with_retry(driver, state_url, "a"):
        return []

    city_links = []
    links = driver.find_elements(By.TAG_NAME, "a")

    for link in links:
        href = link.get_attribute("href")
        if href and "/location/" in href and href != state_url:
            parts = href.rstrip('/').split('/')
            if len(parts) == 6 and parts[3] == "location":
                city_name = link.text.strip()
                if city_name and href not in [c[1] for c in city_links]:
                    city_links.append((city_name, href))

    return city_links


def get_manager_profiles_from_city(driver, city_url):
    """Get property manager names and profile URLs from a city page."""
    if not fetch_with_retry(driver, city_url, ".property-manager-card"):
        return []

    profiles = []
    cards = driver.find_elements(By.CSS_SELECTOR, ".property-manager-card.block")

    for card in cards:
        try:
            name_elem = card.find_element(By.CSS_SELECTOR, ".company-title")
            name = name_elem.text.strip()
            profile_url = card.get_attribute("href")

            if name and profile_url:
                profiles.append({'name': name, 'profile_url': profile_url})
        except:
            continue

    return profiles


def scrape_profile_details(driver, profile_url):
    """Visit a profile page and extract doors managed + website."""
    details = {'doors_managed': '', 'website': ''}

    if not fetch_with_retry(driver, profile_url):
        return details

    try:
        page_text = driver.find_element(By.TAG_NAME, "body").text
        lines = page_text.split('\n')

        # Extract doors managed (number is on line BEFORE "Doors Managed")
        for i, line in enumerate(lines):
            if 'doors managed' in line.lower():
                if i > 0:
                    prev_line = lines[i - 1].strip()
                    match = re.search(r'([\d,]+)\+?', prev_line)
                    if match:
                        details['doors_managed'] = match.group(1).replace(',', '')
                break

        # Extract website - first try "Website" label in text
        for i, line in enumerate(lines):
            if line.strip().lower() == 'website' and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if next_line.startswith('http'):
                    details['website'] = next_line
                    break

        # Fallback: find link where text looks like a URL
        if not details['website']:
            all_links = driver.find_elements(By.TAG_NAME, "a")
            for link in all_links:
                href = link.get_attribute("href") or ""
                link_text = link.text.strip()

                if not href or "propertymanagement.com" in href:
                    continue
                if any(s in href for s in ['linkedin.com', 'facebook.com', 'twitter.com', 'youtube.com', 'instagram.com', 'bbb.org', 'yelp.com', 'google.com', 'spotify.com', 'calendly.com']):
                    continue

                if link_text.startswith('http') and href.startswith('http'):
                    details['website'] = href
                    break
    except:
        pass

    return details


def save_to_csv(data, filename):
    """Save scraped data to CSV file."""
    if not data:
        return

    fieldnames = ['name', 'doors_managed', 'website', 'state', 'city', 'profile_url']

    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    print(f"  Saved {len(data)} records to {filename}")


def main():
    """Main scraping function with resume capability."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Property Manager Scraper')
    parser.add_argument('--quick', action='store_true',
                        help='Quick mode: skip cities that previously had 0 profiles')
    parser.add_argument('--new-only', action='store_true',
                        help='New-only mode: find only NEW managers not in existing data')
    args = parser.parse_args()
    quick_mode = args.quick
    new_only_mode = args.new_only

    # In new-only mode, use separate progress file
    global PROGRESS_FILE
    if new_only_mode:
        PROGRESS_FILE = NEW_ONLY_PROGRESS_FILE

    print("=" * 60)
    if new_only_mode:
        print("Property Manager Scraper (NEW-ONLY MODE)")
        print("Finding property managers not in existing dataset...")
    elif quick_mode:
        print("Property Manager Scraper (QUICK MODE - incremental)")
    else:
        print("Property Manager Scraper (with auto-resume)")
    print("=" * 60)

    # In new-only mode, load baseline URLs from main output file
    baseline_urls = set()
    if new_only_mode:
        print("\nLoading baseline data...")
        baseline_urls = load_baseline_urls()
        if not baseline_urls:
            print("ERROR: No baseline data found. Run a full scrape first.")
            return

    # Check for existing progress
    progress = load_progress()
    all_managers = []

    if progress:
        print(f"\nFound saved progress!")
        print(f"  Last state: {progress.get('current_state', 'N/A')}")
        print(f"  Last city: {progress.get('current_city', 'N/A')}")
        print(f"  Profiles scraped: {progress.get('total_scraped', 0)}")
        if new_only_mode:
            # In new-only mode, load from new-only partial file
            partial_file = "new_property_managers_partial.csv"
            if os.path.exists(partial_file):
                try:
                    with open(partial_file, 'r', encoding='utf-8', newline='') as f:
                        reader = csv.DictReader(f)
                        all_managers = list(reader)
                    print(f"  Loaded {len(all_managers)} new managers from {partial_file}")
                except:
                    pass
            existing_urls = set()
        else:
            all_managers, existing_urls = load_existing_data()
        print(f"  Resuming from where we left off...\n")
    else:
        progress = {
            'completed_states': [],
            'completed_cities': {},
            'completed_profiles': set(),
            'city_profile_counts': {},  # Track profile counts per city for quick mode
            'current_state': None,
            'current_city': None,
            'total_scraped': 0
        }
        all_managers = []
        existing_urls = set()

    # Ensure city_profile_counts exists (for older progress files)
    if 'city_profile_counts' not in progress:
        progress['city_profile_counts'] = {}

    # Convert completed_profiles back to set if loaded from JSON
    if isinstance(progress.get('completed_profiles'), list):
        progress['completed_profiles'] = set(progress['completed_profiles'])

    # Merge existing URLs from CSV with progress file (for robust deduplication)
    progress['completed_profiles'].update(existing_urls)

    # Track duplicates skipped
    duplicates_skipped = 0
    empty_cities_skipped = 0
    new_profiles_found = 0

    driver = None

    try:
        driver = setup_driver()

        # Get all states
        print("Fetching states list...")
        states = get_states(driver)

        if not states:
            print("No states found. Check your connection.")
            return

        print(f"Found {len(states)} states\n")
        random_delay()

        for state_idx, (state_name, state_url) in enumerate(states):
            # Skip completed states (in full mode only - quick/new-only modes check all)
            if not quick_mode and not new_only_mode and state_name in progress['completed_states']:
                print(f"[State {state_idx + 1}/{len(states)}] {state_name} - SKIPPED (already done)")
                continue

            progress['current_state'] = state_name
            print(f"\n[State {state_idx + 1}/{len(states)}] {state_name}")

            # Get cities for this state
            cities = get_cities(driver, state_url)
            print(f"  Found {len(cities)} cities")

            if not cities:
                progress['completed_states'].append(state_name)
                progress_to_save = progress.copy()
                progress_to_save['completed_profiles'] = list(progress['completed_profiles'])
                save_progress(progress_to_save)
                continue

            random_delay()

            # Initialize completed cities for this state if not exists
            if state_name not in progress['completed_cities']:
                progress['completed_cities'][state_name] = []

            for city_idx, (city_name, city_url) in enumerate(cities):
                # Skip completed cities (in full mode only - new-only mode checks all)
                if not quick_mode and not new_only_mode and city_name in progress['completed_cities'].get(state_name, []):
                    continue

                # In new-only mode, skip cities already processed in THIS run
                if new_only_mode and city_name in progress['completed_cities'].get(state_name, []):
                    continue

                # In quick mode, skip cities that previously had 0 profiles
                city_key = f"{state_name}|{city_name}"
                prev_count = progress['city_profile_counts'].get(city_key, -1)

                if quick_mode and prev_count == 0:
                    print(f"  [City {city_idx + 1}/{len(cities)}] {city_name} - SKIPPED (empty)")
                    empty_cities_skipped += 1
                    continue

                progress['current_city'] = city_name
                print(f"  [City {city_idx + 1}/{len(cities)}] {city_name}")

                # Get manager profiles from city page
                profiles = get_manager_profiles_from_city(driver, city_url)
                profile_count = len(profiles)
                print(f"    Found {profile_count} property managers")

                # Store profile count for future quick mode runs
                progress['city_profile_counts'][city_key] = profile_count

                if not profiles:
                    progress['completed_cities'][state_name].append(city_name)
                    progress_to_save = progress.copy()
                    progress_to_save['completed_profiles'] = list(progress['completed_profiles'])
                    save_progress(progress_to_save)
                    random_delay()
                    continue

                # Visit each profile to get details
                for profile_idx, profile in enumerate(profiles):
                    # Skip duplicates (same company in multiple cities)
                    if profile['profile_url'] in progress['completed_profiles']:
                        print(f"      [{profile_idx + 1}/{len(profiles)}] {profile['name'][:40]}... SKIPPED (duplicate)")
                        duplicates_skipped += 1
                        continue

                    # In new-only mode, skip profiles that exist in baseline
                    if new_only_mode and profile['profile_url'] in baseline_urls:
                        print(f"      [{profile_idx + 1}/{len(profiles)}] {profile['name'][:40]}... SKIPPED (in baseline)")
                        duplicates_skipped += 1
                        continue

                    random_delay()

                    print(f"      [{profile_idx + 1}/{len(profiles)}] {profile['name'][:40]}...")

                    details = scrape_profile_details(driver, profile['profile_url'])

                    manager_data = {
                        'name': profile['name'],
                        'doors_managed': details['doors_managed'],
                        'website': details['website'],
                        'state': state_name,
                        'city': city_name,
                        'profile_url': profile['profile_url']
                    }
                    all_managers.append(manager_data)
                    new_profiles_found += 1

                    # Update progress
                    progress['completed_profiles'].add(profile['profile_url'])
                    progress['total_scraped'] = len(all_managers)

                    # Save periodically (every 10 profiles)
                    if len(all_managers) % 10 == 0:
                        print(f"\n    >>> Progress: {len(all_managers)} total scraped")
                        partial_output = "new_property_managers_partial.csv" if new_only_mode else PARTIAL_FILE
                        save_to_csv(all_managers, partial_output)
                        # Convert set to list for JSON serialization
                        progress_to_save = progress.copy()
                        progress_to_save['completed_profiles'] = list(progress['completed_profiles'])
                        save_progress(progress_to_save)

                # Mark city as completed
                progress['completed_cities'][state_name].append(city_name)
                progress_to_save = progress.copy()
                progress_to_save['completed_profiles'] = list(progress['completed_profiles'])
                save_progress(progress_to_save)

                random_delay()

            # Mark state as completed
            progress['completed_states'].append(state_name)
            progress_to_save = progress.copy()
            progress_to_save['completed_profiles'] = list(progress['completed_profiles'])
            save_progress(progress_to_save)

        # Final save
        final_output = NEW_ONLY_OUTPUT_FILE if new_only_mode else OUTPUT_FILE
        save_to_csv(all_managers, final_output)

        # Clean up progress file on successful completion
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)
        # Clean up partial file for new-only mode
        if new_only_mode:
            partial_file = "new_property_managers_partial.csv"
            if os.path.exists(partial_file):
                os.remove(partial_file)

        print("\n" + "=" * 60)
        print(f"COMPLETE!")
        print(f"  Total records: {len(all_managers)}")
        print(f"  New profiles found: {new_profiles_found}")
        print(f"  Duplicates skipped: {duplicates_skipped}")
        if quick_mode:
            print(f"  Empty cities skipped: {empty_cities_skipped}")
        if new_only_mode:
            print(f"  Baseline profiles: {len(baseline_urls)}")
        print(f"  Output saved to: {final_output}")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Saving progress...")
        partial_output = "new_property_managers_partial.csv" if new_only_mode else PARTIAL_FILE
        save_to_csv(all_managers, partial_output)
        progress_to_save = progress.copy()
        progress_to_save['completed_profiles'] = list(progress.get('completed_profiles', set()))
        save_progress(progress_to_save)
        print("Progress saved. Run again to resume.")

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        partial_output = "new_property_managers_partial.csv" if new_only_mode else PARTIAL_FILE
        save_to_csv(all_managers, partial_output)
        progress_to_save = progress.copy()
        progress_to_save['completed_profiles'] = list(progress.get('completed_profiles', set()))
        save_progress(progress_to_save)
        print("Progress saved. Run again to resume.")

    finally:
        if driver:
            driver.quit()


if __name__ == "__main__":
    main()
