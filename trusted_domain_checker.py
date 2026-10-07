import json
from urllib.parse import urlsplit


def load_trusted_domains():
    """Load all trusted domains from trusted_domains.json."""

    with open("trusted_domains.json", "r", encoding="utf-8") as file:
        data = json.load(file)

    trusted_domains = set()

    for category in data.values():
        for domain in category:
            trusted_domains.add(domain.lower().strip())

    return trusted_domains


def get_hostname(url):
    """Extract the hostname from a URL."""

    try:
        parsed_url = urlsplit(url)
        hostname = parsed_url.hostname

        if hostname:
            return hostname.lower().rstrip(".")

    except ValueError:
        pass

    return None


def get_registered_domain(hostname):
    """Extract the main registered domain from a hostname."""

    if not hostname:
        return None

    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    multi_part_suffixes = {
        "co.in",
        "org.in",
        "gov.in",
        "ac.in",
        "net.in",
        "co.uk",
        "org.uk",
        "gov.uk",
        "com.au",
        "co.nz"
    }

    last_two = ".".join(parts[-2:])

    if last_two in multi_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def is_trusted_domain(hostname, trusted_domains):
    """Check whether the hostname belongs to a trusted domain."""

    if not hostname:
        return False

    for trusted_domain in trusted_domains:

        if hostname == trusted_domain:
            return True

        if hostname.endswith("." + trusted_domain):
            return True

    return False


def check_trusted_domain(url):
    """Check whether a URL belongs to a trusted domain."""

    hostname = get_hostname(url)

    if not hostname:
        return False, None

    trusted_domains = load_trusted_domains()

    trusted = is_trusted_domain(
        hostname,
        trusted_domains
    )

    return trusted, hostname


def detect_brand_impersonation(hostname, trusted_domains):
    """
    Detect whether a hostname is trying to imitate
    a trusted brand.
    """

    if not hostname:
        return False, None

    registered_domain = get_registered_domain(hostname)

    if not registered_domain:
        return False, None

    for trusted_domain in trusted_domains:

        trusted_registered_domain = get_registered_domain(
            trusted_domain
        )

        if not trusted_registered_domain:
            continue

        brand_name = trusted_registered_domain.split(".")[0]

        if len(brand_name) < 4:
            continue

        if registered_domain == trusted_registered_domain:
            continue

        if brand_name in registered_domain:
            return True, brand_name

    return False, None


def detect_brand_in_subdomain(hostname, trusted_domains):
    """
    Detect whether a trusted brand is being used
    inside a suspicious subdomain.
    """

    if not hostname:
        return False, None

    registered_domain = get_registered_domain(hostname)

    if not registered_domain:
        return False, None

    if hostname == registered_domain:
        subdomain = ""
    else:
        subdomain = hostname[
            :-(len(registered_domain) + 1)
        ]

    if not subdomain:
        return False, None

    for trusted_domain in trusted_domains:

        trusted_registered_domain = get_registered_domain(
            trusted_domain
        )

        if not trusted_registered_domain:
            continue

        brand_name = trusted_registered_domain.split(".")[0]

        if len(brand_name) < 4:
            continue

        if registered_domain == trusted_registered_domain:
            continue

        if brand_name in subdomain:
            return True, brand_name

    return False, None


# ==========================================================
# TYPOSQUATTING DETECTION
# ==========================================================

def calculate_edit_distance(first, second):
    """
    Calculate the number of single-character edits needed
    to change one string into another.

    Allowed operations:
    1. Insert a character
    2. Delete a character
    3. Replace a character
    """

    rows = len(first) + 1
    columns = len(second) + 1

    matrix = [
        [0 for _ in range(columns)]
        for _ in range(rows)
    ]

    for i in range(rows):
        matrix[i][0] = i

    for j in range(columns):
        matrix[0][j] = j

    for i in range(1, rows):

        for j in range(1, columns):

            if first[i - 1] == second[j - 1]:

                cost = 0

            else:

                cost = 1

            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            )

    return matrix[-1][-1]


def detect_typosquatting(hostname, trusted_domains):
    """
    Detect domains that are very similar to a trusted
    brand but are not the official domain.
    """

    if not hostname:
        return False, None

    registered_domain = get_registered_domain(hostname)

    if not registered_domain:
        return False, None

    suspicious_name = registered_domain.split(".")[0]

    for trusted_domain in trusted_domains:

        trusted_registered_domain = get_registered_domain(
            trusted_domain
        )

        if not trusted_registered_domain:
            continue

        if registered_domain == trusted_registered_domain:
            continue

        trusted_brand = trusted_registered_domain.split(".")[0]

        # Avoid very short names because they can
        # create too many false positives.
        if len(trusted_brand) < 5:
            continue

        distance = calculate_edit_distance(
            suspicious_name,
            trusted_brand
        )

        # Allow only very small spelling differences.
        if distance == 1:

            return True, trusted_brand

    return False, None


if __name__ == "__main__":

    url = input("Enter a URL: ").strip()

    trusted, hostname = check_trusted_domain(url)

    trusted_domains = load_trusted_domains()

    print()

    if trusted:

        print("Trusted/Official Domain ✅")
        print("Hostname:", hostname)

    else:

        print("Domain is NOT in the trusted database ❌")
        print("Hostname:", hostname)

        impersonation, brand = detect_brand_impersonation(
            hostname,
            trusted_domains
        )

        subdomain_impersonation, subdomain_brand = (
            detect_brand_in_subdomain(
                hostname,
                trusted_domains
            )
        )

        typosquatting, typo_brand = (
            detect_typosquatting(
                hostname,
                trusted_domains
            )
        )

        if impersonation:

            print("Possible Brand Impersonation ⚠️")
            print("Brand detected:", brand)

        elif subdomain_impersonation:

            print("Possible Brand Impersonation ⚠️")
            print("Brand detected:", subdomain_brand)

        elif typosquatting:

            print("Possible Typosquatting ⚠️")
            print("Similar brand:", typo_brand)

        else:

            print("No known brand impersonation detected.")