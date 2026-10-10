def calculate_risk(result):

    score = 0

    for alert in result["alerts"]:

        severity = alert["severity"].upper()

        if severity == "CRITICAL":
            score += 40

        elif severity == "HIGH":
            score += 25

        elif severity == "MEDIUM":
            score += 15

        elif severity == "LOW":
            score += 5

    if score >= 70:
        level = "CRITICAL"

    elif score >= 40:
        level = "HIGH"

    elif score >= 20:
        level = "MEDIUM"

    else:
        level = "LOW"

    return score, level