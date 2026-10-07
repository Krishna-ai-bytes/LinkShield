def calculate_risk(checks):
    """Calculate risk score on a scale of 0 to 10."""

    risk_score = 0

    # No HTTPS
    if checks["no_https"]:
        risk_score += 1

    # Suspicious keyword(s)
    if checks["suspicious_keyword"]:
        risk_score += 2

    # IP address
    if checks["ip_address"]:
        risk_score += 2

    # Unusual subdomains
    if checks["unusual_subdomains"]:
        risk_score += 1

    # Strong combination of warning signs
    if checks["combined_pattern"]:
        risk_score += 1

    # Maximum base score
    if risk_score > 10:
        risk_score = 10

    return risk_score


def get_risk_level(risk_score):

    if risk_score <= 3:
        return "Low Risk"

    elif risk_score <= 6:
        return "Medium Risk"

    else:
        return "High Risk"