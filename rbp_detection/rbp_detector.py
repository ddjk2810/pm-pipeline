#!/usr/bin/env python3
"""
RBP (Resident Benefits Package) Detection Tool v2

Takes PM detection results as input and identifies which property managers
offer RBP programs and which vendors they use.

Key improvements over v1:
- Checks both main website AND portal subdomains
- Stores evidence (matched text, URL, pattern)
- Tighter keyword matching to reduce false positives
- Correct RBP provider list (excludes maintenance tools)
"""

import argparse
import csv
import json
import logging
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse, urljoin
import threading

import requests
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class RBPEvidence:
    """Evidence of RBP detection."""
    url: str
    pattern_matched: str
    matched_text: str
    context: str  # Surrounding text for verification
    evidence_type: str  # 'rbp_keyword' or 'provider'


@dataclass
class UnknownVendor:
    """An unknown/discovered vendor link."""
    domain: str
    url: str
    link_text: str
    found_on_page: str


@dataclass
class RBPResult:
    """Result of RBP detection for a domain."""
    domain: str
    portal_subdomain: Optional[str] = None
    pm_system: Optional[str] = None
    rbp_offered: bool = False
    vendors: list = field(default_factory=list)  # Known vendors found
    vendors_by_category: dict = field(default_factory=dict)  # Known vendors grouped by category
    unknown_vendors: list = field(default_factory=list)  # Unknown/discovered vendor links
    evidence: list = field(default_factory=list)
    pages_checked: list = field(default_factory=list)
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            'domain': self.domain,
            'portal_subdomain': self.portal_subdomain,
            'pm_system': self.pm_system,
            'rbp_offered': self.rbp_offered,
            'vendors': self.vendors,
            'vendors_by_category': self.vendors_by_category,
            'unknown_vendors': [
                {
                    'domain': v.domain,
                    'url': v.url,
                    'link_text': v.link_text,
                    'found_on_page': v.found_on_page
                } for v in self.unknown_vendors
            ],
            'evidence': [
                {
                    'url': e.url,
                    'pattern_matched': e.pattern_matched,
                    'matched_text': e.matched_text,
                    'context': e.context,
                    'evidence_type': e.evidence_type
                } for e in self.evidence
            ],
            'pages_checked': self.pages_checked,
            'error': self.error,
            'timestamp': self.timestamp
        }


class RateLimiter:
    """Per-host rate limiter."""

    def __init__(self, requests_per_second: float = 0.5):
        self.min_interval = 1.0 / requests_per_second
        self.last_request = {}
        self.lock = threading.Lock()

    def wait(self, host: str):
        with self.lock:
            now = time.time()
            if host in self.last_request:
                elapsed = now - self.last_request[host]
                if elapsed < self.min_interval:
                    time.sleep(self.min_interval - elapsed)
            self.last_request[host] = time.time()


class RBPDetector:
    """Detects RBP offerings and providers from PM company websites."""

    # All vendors that may appear on RBP-related pages
    # Includes RBP providers, maintenance tools, insurance, utilities, etc.
    RBP_VENDORS = {
        # === RBP Program Providers ===
        'second_nature': {
            'patterns': [r'secondnature\.com', r'second\s*nature'],
            'display_name': 'Second Nature',
            'category': 'rbp_provider'
        },
        'beagle': {
            'patterns': [r'hellobeagle\.com', r'\bbeagle\b.*(?:resident|benefit|renew)'],
            'display_name': 'Beagle',
            'category': 'rbp_provider'
        },
        'corgi': {
            'patterns': [r'meetcorgi\.com', r'corgi\.com', r'\bcorgi\b.*(?:resident|benefit|home)'],
            'display_name': 'Corgi',
            'category': 'rbp_provider'
        },

        # === Deposit Alternatives / Security ===
        'obligo': {
            'patterns': [r'obligo\.com', r'\bobligo\b'],
            'display_name': 'Obligo',
            'category': 'deposit_alternative'
        },
        'jetty': {
            'patterns': [r'jetty\.com', r'jetty\s*(?:deposit|insurance|rent)'],
            'display_name': 'Jetty',
            'category': 'deposit_alternative'
        },
        'rhino': {
            'patterns': [r'sayrhino\.com', r'\brhino\s*(?:deposit|security)'],
            'display_name': 'Rhino',
            'category': 'deposit_alternative'
        },
        'leaselock': {
            'patterns': [r'leaselock\.com', r'\bleaselock\b'],
            'display_name': 'LeaseLock',
            'category': 'deposit_alternative'
        },

        # === Renters Insurance ===
        'assurant': {
            'patterns': [r'assurant\.com', r'assurant\s*renter'],
            'display_name': 'Assurant',
            'category': 'renters_insurance'
        },
        'surevestor': {
            'patterns': [r'surevestor\.com', r'\bsurevestor\b'],
            'display_name': 'SureVestor',
            'category': 'renters_insurance'
        },
        'lemonade': {
            'patterns': [r'lemonade\.com', r'\blemonade\s*(?:insurance|renters)'],
            'display_name': 'Lemonade',
            'category': 'renters_insurance'
        },
        'effectiv': {
            'patterns': [r'effectiv\.com', r'\beffectiv\b'],
            'display_name': 'Effectiv',
            'category': 'renters_insurance'
        },

        # === Maintenance / Service Requests ===
        'property_meld': {
            'patterns': [r'propertymeld\.com', r'property\s*meld'],
            'display_name': 'Property Meld',
            'category': 'maintenance'
        },
        'latchel': {
            'patterns': [r'latchel\.com', r'\blatchel\b'],
            'display_name': 'Latchel',
            'category': 'maintenance'
        },

        # === Utility Setup / Concierge ===
        'utility_concierge': {
            'patterns': [r'utilityconcierge\.com', r'utility\s*concierge', r'citizens\s*home\s*solutions'],
            'display_name': 'Utility Concierge',
            'category': 'utility_concierge'
        },
        'moved': {
            'patterns': [r'moved\.com/', r'\bmoved\b.*(?:moving|utilities)'],
            'display_name': 'Moved',
            'category': 'utility_concierge'
        },
        'updater': {
            'patterns': [r'updater\.com/', r'\bupdater\b'],
            'display_name': 'Updater',
            'category': 'utility_concierge'
        },

        # === Credit Reporting / Building ===
        'rent_relief': {
            'patterns': [r'rentrelief\.com', r'rent\s*relief'],
            'display_name': 'Rent Relief',
            'category': 'credit_reporting'
        },
        'pinata': {
            'patterns': [r'pinata\.ai', r'\bpinata\b.*(?:rent|credit|reward)'],
            'display_name': 'Pinata',
            'category': 'credit_reporting'
        },
        'boom': {
            'patterns': [r'boom\.rent', r'\bboom\b.*(?:credit|report)'],
            'display_name': 'Boom',
            'category': 'credit_reporting'
        },
        'rental_kharma': {
            'patterns': [r'rentalkharma\.com', r'rental\s*kharma'],
            'display_name': 'Rental Kharma',
            'category': 'credit_reporting'
        },

        # === Air Filters / HVAC ===
        'filter_easy': {
            'patterns': [r'filtereasy\.com', r'filter\s*easy'],
            'display_name': 'FilterEasy',
            'category': 'air_filter'
        },
        'second_nature_filters': {
            'patterns': [r'filtersecondnature\.com'],
            'display_name': 'Second Nature Filters',
            'category': 'air_filter'
        },

        # === Rewards / Perks ===
        'rent_perks': {
            'patterns': [r'rentperks\.com', r'rent\s*perks'],
            'display_name': 'Rent Perks',
            'category': 'rewards'
        },
        'resident_perks': {
            'patterns': [r'residentperks\.com', r'resident\s*perks'],
            'display_name': 'Resident Perks',
            'category': 'rewards'
        },

        # === Pet Services ===
        'pet_screening': {
            'patterns': [r'petscreening\.com', r'pet\s*screening'],
            'display_name': 'PetScreening',
            'category': 'pet_services'
        },
        'ourpetpolicy': {
            'patterns': [r'ourpetpolicy\.com', r'our\s*pet\s*policy'],
            'display_name': 'OurPetPolicy',
            'category': 'pet_services'
        },

        # === Showing / Scheduling ===
        'showmojo': {
            'patterns': [r'showmojo\.com', r'showmojo'],
            'display_name': 'ShowMojo',
            'category': 'showing_scheduling'
        },

        # === Resident Screening / Payments ===
        'boompay': {
            'patterns': [r'boompay\.app', r'boompay'],
            'display_name': 'BoomPay',
            'category': 'screening_payments'
        },

        # === Community / HOA Platforms ===
        'townsq': {
            'patterns': [r'townsq\.io', r'townsq'],
            'display_name': 'TownSq',
            'category': 'community_platform'
        },

        # === Reviews / Reputation ===
        'fourandhalf': {
            'patterns': [r'fourandhalf\.com', r'four\s*and\s*a?\s*half'],
            'display_name': 'Four and a Half',
            'category': 'reviews_reputation'
        },
    }

    # Domains to exclude from unknown vendor detection (noise)
    EXCLUDED_DOMAINS = {
        # Social media
        'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
        'youtube.com', 'pinterest.com', 'tiktok.com', 'threads.net',

        # Search & tech giants
        'google.com', 'googleapis.com', 'gstatic.com', 'googletagmanager.com',
        'apple.com', 'microsoft.com', 'bing.com',

        # CDN & infrastructure
        'cloudflare.com', 'cloudfront.net', 'amazonaws.com', 'aws.amazon.com',
        'jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'bootstrapcdn.com',

        # Web tools & analytics
        'jquery.com', 'wordpress.com', 'wordpress.org', 'wp.com', 'wpengine.com',
        'w3.org', 'schema.org', 'gravatar.com', 'cookieyes.com', 'cookiebot.com',
        'hotjar.com', 'mouseflow.com', 'crazyegg.com', 'optimizely.com',

        # Fonts
        'fontawesome.com', 'fonts.googleapis.com', 'fonts.gstatic.com', 'typekit.net',

        # Maps
        'maps.google.com', 'mapbox.com', 'openstreetmap.org',

        # Reviews & directories
        'yelp.com', 'bbb.org', 'g.page', 'trustpilot.com', 'expertise.com',

        # App stores
        'play.google.com', 'apps.apple.com', 'itunes.apple.com',

        # Email & forms
        'mailchimp.com', 'mailchi.mp', 'constantcontact.com', 'hubspot.com',
        'jotform.com', 'typeform.com', 'wufoo.com', 'formstack.com',

        # Video & media
        'vimeo.com', 'wistia.com', 'vidyard.com', 'loom.com',

        # Chat & support
        'zendesk.com', 'intercom.com', 'drift.com', 'livechat.com', 'tawk.to',
        'livechatinc.com',

        # Scheduling (generic)
        'calendly.com', 'acuityscheduling.com',

        # Payment (generic)
        'paypal.com', 'stripe.com', 'square.com', 'venmo.com',

        # Document sharing
        'dropbox.com', 'box.com', 'sharepoint.com', 'onedrive.com',

        # Website builders (not vendors)
        'wix.com', 'squarespace.com', 'weebly.com', 'godaddy.com',
        'propertymanagerwebsites.com', 'placester.com', 'webflow.com',

        # Link shorteners
        'goo.gl', 'bit.ly', 'tinyurl.com', 'youtu.be', 't.co',
        'maps.app.goo.gl', 'g.page',

        # CDN / Asset hosting
        'irp.cdn-website.com', 'cdn.website.com',

        # Job / HR platforms
        'workforcenow.adp.com', 'adp.com', 'paychex.com',

        # Franchise networks (not vendors)
        'neighborlybrands.com', 'realpropertymgt.com', 'neighborly.com',
        'evernest.co', 'community.evernest.co', 'homeriver.com',

        # Free listing sites
        'freerentalsite.com',
    }

    # Domain patterns to exclude (regex)
    EXCLUDED_DOMAIN_PATTERNS = [
        r'.*\.gov$',           # Government sites
        r'.*\.edu$',           # Education sites
        r'.*\.jobs$',          # Job sites
        r'^jobs\.',            # jobs.* subdomains
        r'^careers\.',         # careers.* subdomains
        r'^career\.',          # career.* subdomains
        r'.*icims\.com$',      # iCIMS job platform
        r'.*workday\.com$',    # Workday
        r'.*greenhouse\.io$',  # Greenhouse jobs
        r'.*lever\.co$',       # Lever jobs
        r'.*indeed\.com$',     # Indeed
        r'.*glassdoor\.com$',  # Glassdoor
        r'.*ziprecruiter\.com$', # ZipRecruiter
    ]

    # PM software domains (already tracked separately)
    PM_SOFTWARE_DOMAINS = {
        'appfolio.com', 'appfolioconnect.com', 'appfolioim.com',
        'rentcafe.com', 'securecafe.com', 'yardi.com',
        'buildium.com', 'managebuilding.com',
        'rentmanager.com',
        'rentvine.com',
        'propertyware.com',
        'entrata.com',
    }

    # RBP keywords - tightened to reduce false positives
    # These should specifically indicate an RBP program, not generic terms
    RBP_KEYWORDS = {
        'high_confidence': [
            r'resident\s*benefits?\s*package',
            r'resident\s*benefit\s*program',
            r'\brbp\b(?:\s*program)?',
            r'tenant\s*benefits?\s*package',
            r'renter\s*benefits?\s*package',
        ],
        'medium_confidence': [
            r'(?:included|mandatory|required)\s*(?:resident|renter)?\s*benefits?',
            r'benefits?\s*(?:included|required)\s*(?:with|in)\s*(?:your\s*)?lease',
            r'(?:monthly|lease)\s*benefits?\s*(?:package|program)',
            r'move[\s-]?in\s*benefits?\s*(?:package|program)',
        ],
        'low_confidence': [
            # These need additional context validation
            r'credit\s*(?:building|reporting|boost)\s*(?:program|service|included)',
            r'(?:hvac|air)\s*filter\s*(?:delivery|program|service)',
            r'renters?\s*insurance\s*(?:required|included|provided)',
        ]
    }

    # Pages to check on main website
    WEBSITE_PAGES = [
        '/',
        '/residents/',
        '/residents',
        '/tenants/',
        '/tenants',
        '/resident-benefits/',
        '/resident-benefits',
        '/resident-benefit-package/',
        '/rbp/',
        '/rbp',
        '/benefits/',
        '/benefits',
        '/resident-resources/',
        '/resident-resources',
        '/renters/',
        '/resources/',
        '/leasing/',
        '/move-in/',
    ]

    # Pages to check on portal subdomains
    PORTAL_PAGES = {
        'appfolio': ['/', '/resident_benefits', '/resident-benefits'],
        'yardi': ['/', '/residentservices', '/resident-services'],
        'buildium': ['/'],
        'rentmanager': ['/'],
        'rentvine': ['/'],
        'propertyware': ['/'],
        'entrata': ['/'],
        'default': ['/'],
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.rate_limiter = RateLimiter(requests_per_second=0.5)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

    def detect(self, domain: str, portal_subdomain: Optional[str] = None,
               pm_system: Optional[str] = None) -> RBPResult:
        """Detect RBP for a domain."""
        result = RBPResult(
            domain=domain,
            portal_subdomain=portal_subdomain,
            pm_system=pm_system
        )

        try:
            # Check main website
            self._check_website(domain, result)

            # Check portal subdomain if available
            if portal_subdomain:
                self._check_portal(portal_subdomain, pm_system, result)

            # Determine final RBP status based on evidence
            self._evaluate_evidence(result)

        except Exception as e:
            logger.error(f"Error detecting RBP for {domain}: {e}")
            result.error = str(e)

        return result

    def _fetch_page(self, url: str) -> Optional[tuple[str, str]]:
        """Fetch a page and return (html, final_url)."""
        parsed = urlparse(url)
        host = parsed.netloc
        self.rate_limiter.wait(host)

        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if response.status_code == 200:
                return response.text, response.url
            else:
                logger.debug(f"Got status {response.status_code} for {url}")
                return None
        except Exception as e:
            logger.debug(f"Error fetching {url}: {e}")
            return None

    def _extract_text(self, html: str) -> str:
        """Extract readable text from HTML."""
        soup = BeautifulSoup(html, 'html.parser')

        # Remove script and style elements
        for element in soup(['script', 'style', 'nav', 'footer', 'header']):
            element.decompose()

        return soup.get_text(separator=' ', strip=True)

    def _check_website(self, domain: str, result: RBPResult):
        """Check main website for RBP indicators."""
        for page in self.WEBSITE_PAGES:
            url = f"https://www.{domain}{page}"

            fetched = self._fetch_page(url)
            if not fetched:
                # Try without www
                url = f"https://{domain}{page}"
                fetched = self._fetch_page(url)

            if fetched:
                html, final_url = fetched
                result.pages_checked.append(final_url)
                self._analyze_content(html, final_url, result)

    def _check_portal(self, portal_subdomain: str, pm_system: Optional[str], result: RBPResult):
        """Check portal subdomain for RBP indicators."""
        # Normalize portal subdomain
        if not portal_subdomain.startswith('http'):
            portal_url = f"https://{portal_subdomain}"
        else:
            portal_url = portal_subdomain

        # Get pages to check based on PM system
        pages = self.PORTAL_PAGES.get(pm_system, self.PORTAL_PAGES['default'])

        for page in pages:
            url = f"{portal_url.rstrip('/')}{page}"

            fetched = self._fetch_page(url)
            if fetched:
                html, final_url = fetched
                result.pages_checked.append(final_url)
                self._analyze_content(html, final_url, result)

    def _analyze_content(self, html: str, url: str, result: RBPResult):
        """Analyze page content for RBP indicators."""
        text = self._extract_text(html)
        text_lower = text.lower()
        html_lower = html.lower()

        # Check for RBP keywords (check both text and HTML for links)
        for confidence, patterns in self.RBP_KEYWORDS.items():
            for pattern in patterns:
                # Check in visible text
                matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
                for match in matches[:3]:  # Limit matches per pattern
                    context = self._get_context(text, match.start(), match.end())
                    evidence = RBPEvidence(
                        url=url,
                        pattern_matched=pattern,
                        matched_text=match.group(),
                        context=context,
                        evidence_type=f'rbp_keyword_{confidence}'
                    )
                    result.evidence.append(evidence)

        # Check for vendor indicators (check HTML for links too)
        for vendor_key, vendor_info in self.RBP_VENDORS.items():
            for pattern in vendor_info['patterns']:
                # Check in HTML (catches links)
                matches = list(re.finditer(pattern, html_lower, re.IGNORECASE))
                for match in matches[:2]:
                    # Get context from text if possible, otherwise from HTML
                    text_match = re.search(pattern, text_lower, re.IGNORECASE)
                    if text_match:
                        context = self._get_context(text, text_match.start(), text_match.end())
                    else:
                        context = self._get_context(html, match.start(), match.end(), max_len=100)

                    category = vendor_info.get('category', 'unknown')
                    evidence = RBPEvidence(
                        url=url,
                        pattern_matched=pattern,
                        matched_text=match.group(),
                        context=context,
                        evidence_type=f'vendor:{vendor_key}:{category}'
                    )
                    result.evidence.append(evidence)

        # Extract unknown vendor links (dynamic discovery)
        self._extract_external_links(html, url, result)

    def _get_context(self, text: str, start: int, end: int, max_len: int = 80) -> str:
        """Get surrounding context for a match."""
        context_start = max(0, start - max_len)
        context_end = min(len(text), end + max_len)
        context = text[context_start:context_end]
        # Clean up whitespace
        context = ' '.join(context.split())
        return f"...{context}..."

    def _is_excluded_domain(self, domain: str) -> bool:
        """Check if a domain should be excluded from unknown vendor detection."""
        domain_lower = domain.lower()

        # Check exact matches
        if domain_lower in self.EXCLUDED_DOMAINS:
            return True

        # Check if it's a subdomain of an excluded domain
        for excluded in self.EXCLUDED_DOMAINS:
            if domain_lower.endswith('.' + excluded):
                return True

        # Check PM software domains
        for pm_domain in self.PM_SOFTWARE_DOMAINS:
            if pm_domain in domain_lower:
                return True

        # Check regex patterns
        for pattern in self.EXCLUDED_DOMAIN_PATTERNS:
            if re.match(pattern, domain_lower):
                return True

        return False

    def _is_known_vendor(self, domain: str) -> bool:
        """Check if a domain matches a known vendor."""
        domain_lower = domain.lower()
        for vendor_info in self.RBP_VENDORS.values():
            for pattern in vendor_info['patterns']:
                # Check if pattern matches domain
                if re.search(pattern, domain_lower):
                    return True
        return False

    def _extract_external_links(self, html: str, page_url: str, result: RBPResult):
        """Extract external links that might be unknown vendors."""
        soup = BeautifulSoup(html, 'html.parser')
        source_domain = result.domain.lower()

        seen_domains = set()  # Avoid duplicates within same page

        for a in soup.find_all('a', href=True):
            href = a.get('href', '')

            # Skip empty, anchor, javascript, mailto, tel links
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue

            # Make absolute URL
            try:
                full_url = urljoin(page_url, href)
                parsed = urlparse(full_url)
            except Exception:
                continue

            # Skip non-http(s) URLs
            if parsed.scheme not in ('http', 'https'):
                continue

            link_domain = parsed.netloc.lower()

            # Remove www prefix for comparison
            if link_domain.startswith('www.'):
                link_domain = link_domain[4:]

            # Skip empty domains
            if not link_domain:
                continue

            # Skip internal links (same domain or subdomain)
            if source_domain in link_domain or link_domain in source_domain:
                continue

            # Skip if already seen on this page
            if link_domain in seen_domains:
                continue
            seen_domains.add(link_domain)

            # Skip excluded domains (noise)
            if self._is_excluded_domain(link_domain):
                continue

            # Skip if it's a known vendor (already captured by pattern matching)
            if self._is_known_vendor(link_domain):
                continue

            # Get link text
            link_text = a.get_text(strip=True)[:100] if a.get_text(strip=True) else ''

            # Skip links with no text and generic URLs
            if not link_text and '?' not in full_url:
                # Allow links with query params even without text (often app links)
                continue

            # Add as unknown vendor
            unknown_vendor = UnknownVendor(
                domain=link_domain,
                url=full_url,
                link_text=link_text,
                found_on_page=page_url
            )

            # Check if we already have this domain in unknown_vendors
            existing_domains = {v.domain for v in result.unknown_vendors}
            if link_domain not in existing_domains:
                result.unknown_vendors.append(unknown_vendor)

    def _evaluate_evidence(self, result: RBPResult):
        """Evaluate collected evidence to determine RBP status."""
        if not result.evidence:
            result.rbp_offered = False
            return

        # Check for high confidence RBP keywords
        high_conf_evidence = [e for e in result.evidence if 'high_confidence' in e.evidence_type]
        medium_conf_evidence = [e for e in result.evidence if 'medium_confidence' in e.evidence_type]
        vendor_evidence = [e for e in result.evidence if e.evidence_type.startswith('vendor:')]

        # Determine if RBP is offered
        if high_conf_evidence:
            result.rbp_offered = True
        elif medium_conf_evidence and len(medium_conf_evidence) >= 1:
            result.rbp_offered = True
        elif vendor_evidence:
            # Check if any vendor is an RBP provider category
            rbp_provider_vendors = [e for e in vendor_evidence if ':rbp_provider' in e.evidence_type]
            if rbp_provider_vendors:
                result.rbp_offered = True

        # Collect all vendors found and organize by category
        vendors_found = set()
        vendors_by_category = {}

        for e in vendor_evidence:
            # Parse evidence_type: "vendor:{vendor_key}:{category}"
            parts = e.evidence_type.split(':')
            if len(parts) >= 3:
                vendor_key = parts[1]
                category = parts[2]

                vendors_found.add(vendor_key)

                if category not in vendors_by_category:
                    vendors_by_category[category] = []
                if vendor_key not in vendors_by_category[category]:
                    vendors_by_category[category].append(vendor_key)

        result.vendors = sorted(list(vendors_found))
        result.vendors_by_category = vendors_by_category


class RBPDatabase:
    """SQLite database for RBP detection results."""

    def __init__(self, db_path: str = "rbp_results.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rbp_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                portal_subdomain TEXT,
                pm_system TEXT,
                rbp_offered INTEGER,
                vendors_json TEXT,
                vendors_by_category_json TEXT,
                unknown_vendors_json TEXT,
                evidence_json TEXT,
                pages_checked_json TEXT,
                error TEXT,
                timestamp TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Index for common queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rbp_offered ON rbp_results(rbp_offered)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_pm_system ON rbp_results(pm_system)')

        conn.commit()
        conn.close()

    def save_result(self, result: RBPResult):
        """Save or update a result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        evidence_json = json.dumps([
            {
                'url': e.url,
                'pattern_matched': e.pattern_matched,
                'matched_text': e.matched_text,
                'context': e.context,
                'evidence_type': e.evidence_type
            } for e in result.evidence
        ])

        unknown_vendors_json = json.dumps([
            {
                'domain': v.domain,
                'url': v.url,
                'link_text': v.link_text,
                'found_on_page': v.found_on_page
            } for v in result.unknown_vendors
        ])

        cursor.execute('''
            INSERT INTO rbp_results (
                domain, portal_subdomain, pm_system, rbp_offered, vendors_json,
                vendors_by_category_json, unknown_vendors_json, evidence_json, pages_checked_json, error, timestamp, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(domain) DO UPDATE SET
                portal_subdomain = excluded.portal_subdomain,
                pm_system = excluded.pm_system,
                rbp_offered = excluded.rbp_offered,
                vendors_json = excluded.vendors_json,
                vendors_by_category_json = excluded.vendors_by_category_json,
                unknown_vendors_json = excluded.unknown_vendors_json,
                evidence_json = excluded.evidence_json,
                pages_checked_json = excluded.pages_checked_json,
                error = excluded.error,
                timestamp = excluded.timestamp,
                updated_at = CURRENT_TIMESTAMP
        ''', (
            result.domain,
            result.portal_subdomain,
            result.pm_system,
            1 if result.rbp_offered else 0,
            json.dumps(result.vendors),
            json.dumps(result.vendors_by_category),
            unknown_vendors_json,
            evidence_json,
            json.dumps(result.pages_checked),
            result.error,
            result.timestamp
        ))

        conn.commit()
        conn.close()

    def get_processed_domains(self) -> set:
        """Get set of already processed domains."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT domain FROM rbp_results')
        domains = {row[0].lower() for row in cursor.fetchall()}
        conn.close()
        return domains

    def get_stats(self) -> dict:
        """Get detection statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        cursor.execute('SELECT COUNT(*) FROM rbp_results')
        stats['total'] = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM rbp_results WHERE rbp_offered = 1')
        stats['rbp_offered_count'] = cursor.fetchone()[0]

        # Count vendors across all results
        cursor.execute('SELECT vendors_json FROM rbp_results WHERE vendors_json IS NOT NULL')
        vendor_counts = {}
        for row in cursor.fetchall():
            vendors = json.loads(row[0]) if row[0] else []
            for vendor in vendors:
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
        stats['by_vendor'] = dict(sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True))

        # Count by category
        cursor.execute('SELECT vendors_by_category_json FROM rbp_results WHERE vendors_by_category_json IS NOT NULL')
        category_counts = {}
        for row in cursor.fetchall():
            categories = json.loads(row[0]) if row[0] else {}
            for category in categories.keys():
                category_counts[category] = category_counts.get(category, 0) + 1
        stats['by_category'] = dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True))

        cursor.execute('SELECT pm_system, COUNT(*) FROM rbp_results WHERE rbp_offered = 1 GROUP BY pm_system ORDER BY COUNT(*) DESC')
        stats['rbp_by_pm_system'] = {row[0]: row[1] for row in cursor.fetchall()}

        # Count unknown vendors across all results
        cursor.execute('SELECT unknown_vendors_json FROM rbp_results WHERE unknown_vendors_json IS NOT NULL')
        unknown_vendor_counts = {}
        for row in cursor.fetchall():
            unknown_vendors = json.loads(row[0]) if row[0] else []
            for vendor in unknown_vendors:
                domain = vendor.get('domain', '')
                if domain:
                    unknown_vendor_counts[domain] = unknown_vendor_counts.get(domain, 0) + 1
        stats['unknown_vendors'] = dict(sorted(unknown_vendor_counts.items(), key=lambda x: x[1], reverse=True)[:50])  # Top 50

        cursor.execute('SELECT COUNT(*) FROM rbp_results WHERE error IS NOT NULL AND error != ""')
        stats['error_count'] = cursor.fetchone()[0]

        conn.close()
        return stats

    def export_csv(self, output_path: str):
        """Export results to CSV."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT domain, portal_subdomain, pm_system, rbp_offered, vendors_json,
                   vendors_by_category_json, unknown_vendors_json, evidence_json, pages_checked_json, error, timestamp
            FROM rbp_results
            ORDER BY domain
        ''')

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'domain', 'portal_subdomain', 'pm_system', 'rbp_offered', 'known_vendors',
                'vendors_by_category', 'unknown_vendors', 'evidence_summary', 'pages_checked_count', 'error', 'timestamp'
            ])

            for row in cursor.fetchall():
                vendors = json.loads(row[4]) if row[4] else []
                vendors_by_cat = json.loads(row[5]) if row[5] else {}
                unknown_vendors = json.loads(row[6]) if row[6] else []
                evidence = json.loads(row[7]) if row[7] else []
                pages = json.loads(row[8]) if row[8] else []

                # Format vendors by category for readability
                vendors_cat_str = '; '.join([
                    f"{cat}: {', '.join(v)}" for cat, v in vendors_by_cat.items()
                ])

                # Format unknown vendors
                unknown_vendors_str = '; '.join([
                    f"{v['domain']} ({v['link_text'][:30]})" if v.get('link_text') else v['domain']
                    for v in unknown_vendors[:10]  # Limit to 10
                ])

                # Create evidence summary
                evidence_summary = '; '.join([
                    f"{e['evidence_type']}: \"{e['matched_text']}\" on {e['url']}"
                    for e in evidence[:5]  # Limit to 5 pieces of evidence
                ])

                writer.writerow([
                    row[0], row[1], row[2], row[3], ', '.join(vendors),
                    vendors_cat_str, unknown_vendors_str, evidence_summary, len(pages), row[9], row[10]
                ])

        conn.close()
        logger.info(f"Exported results to {output_path}")


def load_pm_results(csv_path: str) -> list[dict]:
    """Load PM detection results from CSV."""
    results = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append({
                'domain': row.get('domain', '').strip(),
                'portal_subdomain': row.get('portal_subdomain', '').strip() or None,
                'pm_system': row.get('portal_system', '').strip() or None,
            })
    return results


def main():
    parser = argparse.ArgumentParser(description='RBP Detection Tool v2')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Detect single domain
    detect_parser = subparsers.add_parser('detect', help='Detect RBP for a single domain')
    detect_parser.add_argument('domain', help='Domain to check')
    detect_parser.add_argument('--portal', help='Portal subdomain')
    detect_parser.add_argument('--pm-system', help='PM system name')

    # Batch process
    batch_parser = subparsers.add_parser('batch', help='Batch process from PM results')
    batch_parser.add_argument('input_csv', help='PM results CSV file')
    batch_parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers')
    batch_parser.add_argument('--limit', type=int, help='Limit number of domains to process')
    batch_parser.add_argument('--no-skip', action='store_true', help='Reprocess already processed domains')

    # Export results
    export_parser = subparsers.add_parser('export', help='Export results to CSV')
    export_parser.add_argument('output_csv', help='Output CSV file')

    # Show stats
    subparsers.add_parser('stats', help='Show detection statistics')

    args = parser.parse_args()

    if args.command == 'detect':
        detector = RBPDetector()
        result = detector.detect(args.domain, args.portal, args.pm_system)
        print(json.dumps(result.to_dict(), indent=2))

    elif args.command == 'batch':
        detector = RBPDetector()
        db = RBPDatabase()

        # Load PM results
        pm_results = load_pm_results(args.input_csv)
        logger.info(f"Loaded {len(pm_results)} domains from PM results")

        # Filter already processed
        if not args.no_skip:
            processed = db.get_processed_domains()
            pm_results = [r for r in pm_results if r['domain'].lower() not in processed]
            logger.info(f"Skipping {len(processed)} already processed domains")

        # Apply limit
        if args.limit:
            pm_results = pm_results[:args.limit]

        logger.info(f"Processing {len(pm_results)} domains")

        # Process with thread pool
        processed_count = 0
        error_count = 0

        def process_domain(pm_result):
            try:
                result = detector.detect(
                    pm_result['domain'],
                    pm_result['portal_subdomain'],
                    pm_result['pm_system']
                )
                db.save_result(result)
                return result
            except Exception as e:
                logger.error(f"Error processing {pm_result['domain']}: {e}")
                return None

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_domain, r): r for r in pm_results}

            for future in as_completed(futures):
                processed_count += 1
                result = future.result()

                if result and result.error:
                    error_count += 1

                if processed_count % 10 == 0:
                    logger.info(f"Progress: {processed_count}/{len(pm_results)} processed, {error_count} errors")

        logger.info(f"Batch complete: {processed_count} processed, {error_count} errors")

        # Show final stats
        stats = db.get_stats()
        print(json.dumps(stats, indent=2))

    elif args.command == 'export':
        db = RBPDatabase()
        db.export_csv(args.output_csv)

    elif args.command == 'stats':
        db = RBPDatabase()
        stats = db.get_stats()
        print(json.dumps(stats, indent=2))

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
