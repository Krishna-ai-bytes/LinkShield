import re
from urllib.parse import urlsplit

from risk_calculator import calculate_risk, get_risk_level

from trusted_domain_checker import (
    check_trusted_domain,
    detect_brand_impersonation,
    detect_brand_in_subdomain,
    detect_typosquatting,
    load_trusted_domains,
)


def analyze_url(url):
    """
    Analyze a URL and return the security results.
    """

    url = url.strip()

    # --------------------------------------------------
    # URL VALIDATION
    # --------------------------------------------------

    try:
        parsed_url = urlsplit(url)
        hostname = parsed_url.hostname

    except ValueError:
        return {
            "valid": False,
            "error": "Invalid URL format."
        }

    if (
        not parsed_url
        or parsed_url.scheme not in ("http", "https")
        or not hostname
    ):
        return {
            "valid": False,
            "error": (
                "Invalid URL. Enter a full URL beginning "
                "with http:// or https://"
            )
        }

    hostname = hostname.lower().rstrip(".")

    # --------------------------------------------------
    # TRUSTED / OFFICIAL DOMAIN CHECK
    # --------------------------------------------------

    trusted, trusted_hostname = check_trusted_domain(url)

    if trusted:

        return {
            "valid": True,
            "trusted": True,
            "hostname": trusted_hostname,

            "risk_score": 0,
            "risk_level": "Trusted",

            "risk_message": (
                "This domain is recognized as an official "
                "domain in the trusted database."
            )
        }

    # --------------------------------------------------
    # LOAD TRUSTED DOMAINS
    # --------------------------------------------------

    trusted_domains = load_trusted_domains()

    # --------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------

    brand_impersonation, detected_brand = (
        detect_brand_impersonation(
            hostname,
            trusted_domains
        )
    )

    # --------------------------------------------------
    # BRAND IN SUBDOMAIN
    # --------------------------------------------------

    subdomain_impersonation, subdomain_brand = (
        detect_brand_in_subdomain(
            hostname,
            trusted_domains
        )
    )

    # --------------------------------------------------
    # TYPOSQUATTING
    # --------------------------------------------------

    typosquatting, typo_brand = (
        detect_typosquatting(
            hostname,
            trusted_domains
        )
    )

    # --------------------------------------------------
    # SECURITY CHECKS
    # --------------------------------------------------

    checks = {}

    # HTTPS
    checks["no_https"] = parsed_url.scheme != "https"

    # Suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "account",
        "password",
        "bank",
        "update",
        "security",
        "confirm",
        "signin"
    ]

    url_lower = url.lower()

    found_keywords = [
        word
        for word in suspicious_keywords
        if word in url_lower
    ]

    checks["suspicious_keyword"] = bool(found_keywords)

    # IP address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    checks["ip_address"] = bool(
        re.fullmatch(ip_pattern, hostname)
    )

    # Unusual subdomains
    host_labels = hostname.split(".")

    checks["unusual_subdomains"] = len(host_labels) > 4

    # Combined pattern
    checks["combined_pattern"] = (
        checks["no_https"]
        and checks["suspicious_keyword"]
        and checks["ip_address"]
    )

    # --------------------------------------------------
    # BASE RISK SCORE
    # --------------------------------------------------

    risk_score = calculate_risk(checks)

    # Brand impersonation
    if brand_impersonation or subdomain_impersonation:
        risk_score += 4

    # Typosquatting
    elif typosquatting:
        risk_score += 3

    # Maximum score
    if risk_score > 10:
        risk_score = 10

    # --------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------

    risk_level = get_risk_level(risk_score)

    # --------------------------------------------------
    # RESULT MESSAGE
    # --------------------------------------------------

    if risk_level == "Low Risk":

        risk_message = (
            "No major suspicious indicators were detected "
            "in this URL."
        )

    elif risk_level == "Medium Risk":

        risk_message = (
            "Some suspicious indicators were detected. "
            "The URL should be treated with caution."
        )

    else:

        risk_message = (
            "Multiple strong suspicious indicators were "
            "detected. This URL may represent a phishing "
            "or impersonation attempt."
        )

    # --------------------------------------------------
    # NUMBER OF WARNING INDICATORS
    # --------------------------------------------------

    warning_count = 0

    if checks["no_https"]:
        warning_count += 1

    if checks["suspicious_keyword"]:
        warning_count += 1

    if checks["ip_address"]:
        warning_count += 1

    if checks["unusual_subdomains"]:
        warning_count += 1

    if brand_impersonation or subdomain_impersonation:
        warning_count += 1

    if typosquatting:
        warning_count += 1

    # --------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------

    return {
        "valid": True,

        "trusted": False,

        "hostname": hostname,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "risk_message": risk_message,

        "warning_count": warning_count,

        "brand_impersonation": (
            brand_impersonation
            or subdomain_impersonation
        ),

        "detected_brand": (
            detected_brand
            if brand_impersonation
            else subdomain_brand
            if subdomain_impersonation
            else typo_brand
        ),

        "typosquatting": typosquatting,

        "typo_brand": typo_brand,

        "https": not checks["no_https"],

        "suspicious_keywords": found_keywords,

        "ip_address": checks["ip_address"],

        "unusual_subdomains": (
            checks["unusual_subdomains"]
        ),

        "combined_pattern": (
            checks["combined_pattern"]
        )
    }