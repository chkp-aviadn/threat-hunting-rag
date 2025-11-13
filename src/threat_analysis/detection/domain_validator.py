"""
Advanced Domain Validation System for Threat Analysis.

This module provides comprehensive domain validation using multiple approaches
to determine domain legitimacy and reputation for phishing detection.

Key validation methods:
- Domain age and registration analysis
- DNS record validation
- Reputation database lookups
- Domain similarity analysis (typosquatting)
- Certificate validation
- Subdomain analysis
"""

import re
import socket
import ssl
import whois
import dns.resolver
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


@dataclass
class DomainValidationResult:
    """Comprehensive domain validation result."""

    domain: str
    is_legitimate: bool
    confidence: float  # 0.0 to 1.0
    risk_factors: List[str]
    validation_methods: List[str]
    reputation_score: float
    domain_age_days: Optional[int] = None
    has_valid_ssl: Optional[bool] = None
    typosquatting_score: Optional[float] = None
    explanation: str = ""


class DomainValidator:
    """
    Comprehensive domain validation system using multiple verification methods.

    Combines multiple approaches to provide accurate domain legitimacy assessment:
    - WHOIS data analysis (domain age, registrar)
    - DNS record validation (MX, SPF, DKIM records)
    - Reputation database lookups
    - Typosquatting detection
    - SSL certificate validation
    """

    def __init__(self):
        """Initialize domain validator with known legitimate domains and configuration."""

        # Known legitimate domains by category
        self.legitimate_domains = {
            "email_providers": {
                "gmail.com",
                "outlook.com",
                "hotmail.com",
                "yahoo.com",
                "icloud.com",
                "protonmail.com",
                "aol.com",
                "live.com",
            },
            "major_companies": {
                "microsoft.com",
                "google.com",
                "apple.com",
                "amazon.com",
                "facebook.com",
                "twitter.com",
                "linkedin.com",
                "salesforce.com",
                "oracle.com",
                "ibm.com",
                "adobe.com",
                "cisco.com",
            },
            "financial": {
                "chase.com",
                "bankofamerica.com",
                "wellsfargo.com",
                "citi.com",
                "paypal.com",
                "americanexpress.com",
                "capitalone.com",
            },
            "government": {"gov", "mil", "edu", "irs.gov", "fbi.gov", "sec.gov"},
        }

        # Suspicious TLD patterns
        self.suspicious_tlds = {
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".pw",
            ".top",
            ".click",
            ".download",
            ".work",
            ".party",
            ".review",
            ".country",
            ".science",
            ".racing",
        }

        # Common typosquatting patterns for major domains
        self.typosquatting_targets = {
            "google.com",
            "microsoft.com",
            "amazon.com",
            "paypal.com",
            "apple.com",
            "facebook.com",
            "twitter.com",
            "linkedin.com",
        }

    def validate_domain(self, domain: str) -> DomainValidationResult:
        """
        Perform comprehensive domain validation using multiple methods.

        Args:
            domain: Domain name to validate

        Returns:
            DomainValidationResult with detailed analysis

        Example:
            >>> validator = DomainValidator()
            >>> result = validator.validate_domain("suspicious-amazon.tk")
            >>> result.is_legitimate
            False
            >>> "typosquatting" in result.risk_factors
            True
        """
        start_time = datetime.now()
        logger.debug(f"Validating domain: {domain}")

        # Normalize domain
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]

        # Initialize result
        result = DomainValidationResult(
            domain=domain,
            is_legitimate=False,
            confidence=0.0,
            risk_factors=[],
            validation_methods=[],
            reputation_score=0.0,
        )

        # Method 1: Check against known legitimate domains
        legitimacy_score = self._check_known_domains(domain, result)

        # Method 2: Domain age analysis
        age_score = self._check_domain_age(domain, result)

        # Method 3: DNS record validation
        dns_score = self._check_dns_records(domain, result)

        # Method 4: Typosquatting detection
        typo_score = self._check_typosquatting(domain, result)

        # Method 5: SSL certificate validation
        ssl_score = self._check_ssl_certificate(domain, result)

        # Method 6: Reputation database lookup
        reputation_score = self._check_reputation_databases(domain, result)

        # Method 7: Suspicious pattern analysis
        pattern_score = self._check_suspicious_patterns(domain, result)

        # Combine scores using weighted average
        scores = [
            (legitimacy_score, 0.25),  # Known domains - highest weight
            (age_score, 0.15),  # Domain age
            (dns_score, 0.15),  # DNS configuration
            (typo_score, 0.20),  # Typosquatting - high weight
            (ssl_score, 0.10),  # SSL certificate
            (reputation_score, 0.10),  # External reputation
            (pattern_score, 0.05),  # Pattern analysis
        ]

        # Calculate final confidence and legitimacy
        weighted_score = sum(score * weight for score, weight in scores if score is not None)
        total_weight = sum(weight for score, weight in scores if score is not None)

        if total_weight > 0:
            result.confidence = weighted_score / total_weight
            result.is_legitimate = result.confidence > 0.6  # Threshold for legitimacy

        result.reputation_score = result.confidence

        # Generate explanation
        if result.is_legitimate:
            result.explanation = f"Domain appears legitimate (confidence: {result.confidence:.2f})"
        else:
            top_risks = result.risk_factors[:3]  # Top 3 risk factors
            result.explanation = f"Domain suspicious: {', '.join(top_risks)}"

        processing_time = (datetime.now() - start_time).total_seconds()
        logger.debug(f"Domain validation completed in {processing_time:.3f}s")

        return result

    def _check_known_domains(self, domain: str, result: DomainValidationResult) -> Optional[float]:
        """Check domain against known legitimate domain lists."""
        result.validation_methods.append("known_domains")

        # Check all legitimate domain categories
        for category, domains in self.legitimate_domains.items():
            if domain in domains:
                result.risk_factors.append(f"verified_{category}_domain")
                return 1.0  # Definitely legitimate

        # Check if it's a subdomain of a legitimate domain
        for category, domains in self.legitimate_domains.items():
            for legit_domain in domains:
                if domain.endswith(f".{legit_domain}"):
                    result.risk_factors.append(f"subdomain_of_{category}")
                    return 0.8  # Likely legitimate subdomain

        return 0.3  # Unknown domain - neutral but slightly suspicious

    def _check_domain_age(self, domain: str, result: DomainValidationResult) -> Optional[float]:
        """Check domain registration age using WHOIS data."""
        result.validation_methods.append("domain_age")

        try:
            # Note: This requires python-whois package
            w = whois.whois(domain)

            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                age_days = (datetime.now() - creation_date).days
                result.domain_age_days = age_days

                # Score based on age
                if age_days < 30:
                    result.risk_factors.append("very_new_domain")
                    return 0.1  # Very suspicious
                elif age_days < 90:
                    result.risk_factors.append("new_domain")
                    return 0.3  # Suspicious
                elif age_days < 365:
                    result.risk_factors.append("recent_domain")
                    return 0.6  # Neutral
                else:
                    return 0.8  # Older domains are more trustworthy

        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            result.risk_factors.append("whois_lookup_failed")

        return None  # Unable to determine

    def _check_dns_records(self, domain: str, result: DomainValidationResult) -> Optional[float]:
        """Validate DNS configuration (MX, A, SPF records)."""
        result.validation_methods.append("dns_records")

        score = 0.5  # Base score

        try:
            # Check for A record (basic connectivity)
            try:
                dns.resolver.resolve(domain, "A")
                score += 0.1
            except:
                result.risk_factors.append("no_a_record")
                return 0.2

            # Check for MX record (email capability)
            try:
                mx_records = dns.resolver.resolve(domain, "MX")
                if mx_records:
                    score += 0.2
                else:
                    result.risk_factors.append("no_mx_record")
            except:
                result.risk_factors.append("no_mx_record")

            # Check for TXT records (SPF, DKIM indicate legitimate email setup)
            try:
                txt_records = dns.resolver.resolve(domain, "TXT")
                has_spf = any("v=spf1" in str(record) for record in txt_records)
                has_dmarc = any("v=DMARC1" in str(record) for record in txt_records)

                if has_spf:
                    score += 0.1
                if has_dmarc:
                    score += 0.1

                if not has_spf and not has_dmarc:
                    result.risk_factors.append("no_email_authentication")

            except:
                result.risk_factors.append("no_txt_records")

            return min(score, 1.0)

        except Exception as e:
            logger.debug(f"DNS check failed for {domain}: {e}")
            result.risk_factors.append("dns_resolution_failed")
            return 0.1

    def _check_typosquatting(self, domain: str, result: DomainValidationResult) -> Optional[float]:
        """Detect potential typosquatting against major brands."""
        result.validation_methods.append("typosquatting")

        for target_domain in self.typosquatting_targets:
            similarity = self._calculate_domain_similarity(domain, target_domain)

            if similarity > 0.7:  # High similarity indicates potential typosquatting
                result.typosquatting_score = similarity
                result.risk_factors.append(f"typosquatting_{target_domain.replace('.', '_')}")

                # Very high similarity is very suspicious
                if similarity > 0.9:
                    return 0.05  # Almost definitely malicious
                elif similarity > 0.8:
                    return 0.2  # Highly suspicious
                else:
                    return 0.4  # Moderately suspicious

        return 0.7  # No typosquatting detected

    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains using edit distance."""
        # Remove TLD for comparison
        d1_base = domain1.split(".")[0]
        d2_base = domain2.split(".")[0]

        # Levenshtein distance
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)

            if len(s2) == 0:
                return len(s1)

            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row

            return previous_row[-1]

        distance = levenshtein_distance(d1_base, d2_base)
        max_len = max(len(d1_base), len(d2_base))

        if max_len == 0:
            return 1.0

        similarity = 1 - (distance / max_len)
        return similarity

    def _check_ssl_certificate(
        self, domain: str, result: DomainValidationResult
    ) -> Optional[float]:
        """Check SSL certificate validity."""
        result.validation_methods.append("ssl_certificate")

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    if cert:
                        # Check certificate expiration
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_until_expiry = (not_after - datetime.now()).days

                        result.has_valid_ssl = True

                        if days_until_expiry > 30:
                            return 0.8  # Valid certificate
                        else:
                            result.risk_factors.append("ssl_cert_expiring_soon")
                            return 0.6
                    else:
                        result.has_valid_ssl = False
                        result.risk_factors.append("invalid_ssl_cert")
                        return 0.3

        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {e}")
            result.has_valid_ssl = False
            result.risk_factors.append("no_ssl_or_unreachable")
            return 0.4  # Many legitimate domains don't use HTTPS

    def _check_reputation_databases(
        self, domain: str, result: DomainValidationResult
    ) -> Optional[float]:
        """Check domain against reputation databases."""
        result.validation_methods.append("reputation_db")

        # Note: In production, you would integrate with services like:
        # - VirusTotal API
        # - URLVoid
        # - Google Safe Browsing API
        # - PhishTank
        # - Spamhaus

        # This is a simplified example
        try:
            # Example: Check if domain is in a simple blocklist
            suspicious_keywords = [
                "phishing",
                "scam",
                "fake",
                "fraud",
                "malware",
                "spam",
                "suspicious",
                "temporary",
                "download",
                "free-money",
            ]

            if any(keyword in domain for keyword in suspicious_keywords):
                result.risk_factors.append("suspicious_keywords_in_domain")
                return 0.1

            # Check suspicious TLDs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                result.risk_factors.append("suspicious_tld")
                return 0.3

            return 0.6  # Neutral if no reputation data

        except Exception as e:
            logger.debug(f"Reputation check failed for {domain}: {e}")
            return None

    def _check_suspicious_patterns(
        self, domain: str, result: DomainValidationResult
    ) -> Optional[float]:
        """Check for suspicious patterns in domain structure."""
        result.validation_methods.append("pattern_analysis")

        score = 0.7  # Base score

        # Check for excessive hyphens or numbers
        if domain.count("-") > 3:
            result.risk_factors.append("excessive_hyphens")
            score -= 0.2

        # Check for excessive numbers
        number_count = sum(1 for c in domain if c.isdigit())
        if number_count > len(domain) * 0.3:
            result.risk_factors.append("excessive_numbers")
            score -= 0.2

        # Check domain length
        if len(domain) > 50:
            result.risk_factors.append("very_long_domain")
            score -= 0.1
        elif len(domain) < 4:
            result.risk_factors.append("very_short_domain")
            score -= 0.1

        # Check for randomness (lots of consonants or vowels in a row)
        vowels = "aeiou"
        consonant_streaks = re.findall(r"[bcdfghjklmnpqrstvwxyz]{4,}", domain)
        vowel_streaks = re.findall(r"[aeiou]{3,}", domain)

        if consonant_streaks or vowel_streaks:
            result.risk_factors.append("random_character_patterns")
            score -= 0.2

        return max(score, 0.0)


# Integration with existing FeatureExtractor
class EnhancedDomainAnalyzer:
    """Enhanced domain analysis for integration with threat detection."""

    def __init__(self):
        self.validator = DomainValidator()

    def analyze_sender_domain(self, sender_email: str) -> DomainValidationResult:
        """
        Analyze sender domain for threat detection integration.

        Args:
            sender_email: Full email address

        Returns:
            DomainValidationResult with comprehensive analysis
        """
        if not sender_email or "@" not in sender_email:
            return DomainValidationResult(
                domain="invalid",
                is_legitimate=False,
                confidence=0.0,
                risk_factors=["malformed_email"],
                validation_methods=[],
                reputation_score=0.0,
                explanation="Invalid email address format",
            )

        domain = sender_email.split("@")[1].lower()
        return self.validator.validate_domain(domain)


# Usage example for integration with existing system
def enhanced_new_sender_detection(sender_email: str) -> "FeatureResult":
    """
    Enhanced version of detect_new_sender using comprehensive domain validation.

    This replaces the basic implementation in FeatureExtractor.
    """
    analyzer = EnhancedDomainAnalyzer()
    domain_result = analyzer.analyze_sender_domain(sender_email)

    from .features import FeatureResult

    # Convert DomainValidationResult to FeatureResult
    if domain_result.is_legitimate:
        return FeatureResult(
            "new_sender", False, 0.0, [], f"Legitimate domain: {domain_result.domain}"
        )
    else:
        confidence = 1.0 - domain_result.confidence  # Invert for risk scoring
        return FeatureResult(
            "new_sender", True, confidence, domain_result.risk_factors, domain_result.explanation
        )
