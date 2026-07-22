"""
Risk Priority Scoring Tool
Author: Kesar
Description: Reads a CSV of security/compliance risk findings (with Likelihood,
Impact, and Control Maturity ratings), calculates residual risk using an
inherent-risk-minus-controls model, ranks findings by urgency, and exports
a prioritized report.
"""

import csv


def calculate_residual_risk(likelihood, impact, control_maturity):
    # Calculates residual risk from three inputs

    inherent_risk = likelihood * impact
    reduction_factor = max(0.05, 1 - (control_maturity / 5))
    residual_risk = inherent_risk * reduction_factor
    return round(residual_risk, 2)


def get_risk_level(residual_risk):
    # Converts a numeric residual risk score into a 5-tier severity label
    if residual_risk >= 18:
        return "Very High"
    elif residual_risk >= 12:
        return "High"
    elif residual_risk >= 7:
        return "Moderate"
    elif residual_risk >= 3:
        return "Low"
    else:
        return "Very Low"


def load_risks_from_csv(filename):
    # Reads risk findings from a CSV file.
    risks = []
    with open(filename, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            risks.append({
                "name": row["name"],
                "likelihood": float(row["likelihood"]),
                "impact": float(row["impact"]),
                "control_maturity": float(row["control_maturity"])
            })
    return risks


def score_and_rank_risks(risks):
    # Calculates residual risk for each entry.
    for risk in risks:
        risk["residual_risk"] = calculate_residual_risk(
            risk["likelihood"], risk["impact"], risk["control_maturity"]
        )
    return sorted(risks, key=lambda r: r["residual_risk"], reverse=True)


def export_report(sorted_risks, output_filename="risk_priority_report.csv"):
    fieldnames = ["rank", "name", "likelihood", "impact", "control_maturity", "residual_risk", "risk_level"]
    with open(output_filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, risk in enumerate(sorted_risks, start=1):
            writer.writerow({
                "rank": i,
                "name": risk["name"],
                "likelihood": risk["likelihood"],
                "impact": risk["impact"],
                "control_maturity": risk["control_maturity"],
                "residual_risk": risk["residual_risk"],
                "risk_level": get_risk_level(risk["residual_risk"])
            })
    print(f"Report saved as {output_filename}")


def print_report(sorted_risks):
    # Ranked results printed
    print("RISK PRIORITY RANKING")
    print("-" * 60)
    for i, risk in enumerate(sorted_risks, start=1):
        level = get_risk_level(risk["residual_risk"])
        print(f"{i}. {risk['name']} — Residual Risk: {risk['residual_risk']} ({level})")

if __name__ == "__main__":
    input_filename = "risk_register.csv" 
    risks = load_risks_from_csv(input_filename)
    ranked = score_and_rank_risks(risks)
    print_report(ranked)
    export_report(ranked)
