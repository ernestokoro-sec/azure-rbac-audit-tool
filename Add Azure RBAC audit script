import csv
import json
import subprocess
from collections import Counter

PRIVILEGED_ROLES = {
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Role Based Access Control Administrator",
}

def run_azure_cli():
    command = [
        "az.cmd",
        "role",
        "assignment",
        "list",
        "--all",
        "-o",
        "json",
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("Failed to run Azure CLI command.")
        print(result.stderr)
        raise SystemExit(1)

    return json.loads(result.stdout)

def is_subscription_scope(scope):
    parts = scope.strip("/").split("/")
    return len(parts) == 2 and parts[0] == "subscriptions"

def is_root_scope(scope):
    return scope == "/"

def classify_risk(role, scope, principal_type):
    risk_reasons = []

    if role in PRIVILEGED_ROLES:
        risk_reasons.append("Privileged role")

    if is_root_scope(scope):
        risk_reasons.append("Root scope assignment")

    if is_subscription_scope(scope):
        risk_reasons.append("Subscription-wide assignment")

    if (
        principal_type == "ServicePrincipal"
        and role in {"Owner", "Contributor"}
        and is_subscription_scope(scope)
    ):
        risk_reasons.append("Service principal has broad subscription access")

    if not risk_reasons:
        return "Low", ""

    if is_root_scope(scope) or role in {"Owner", "User Access Administrator"}:
        return "High", "; ".join(risk_reasons)

    if role == "Contributor" and is_subscription_scope(scope):
        return "Medium", "; ".join(risk_reasons)

    return "Review", "; ".join(risk_reasons)

def main():
    assignments = run_azure_cli()

    duplicate_tracker = Counter(
        (
            item.get("principalName"),
            item.get("roleDefinitionName"),
            item.get("scope"),
        )
        for item in assignments
    )

    findings = []

    for item in assignments:
        principal = item.get("principalName")
        principal_type = item.get("principalType")
        role = item.get("roleDefinitionName")
        scope = item.get("scope")

        risk_level, reason = classify_risk(role, scope, principal_type)

        duplicate_count = duplicate_tracker[(principal, role, scope)]

        if duplicate_count > 1:
            if reason:
                reason += "; Duplicate assignment"
            else:
                reason = "Duplicate assignment"

            if risk_level == "Low":
                risk_level = "Review"

        if risk_level != "Low":
            findings.append({
                "principal": principal,
                "principal_type": principal_type,
                "role": role,
                "scope": scope,
                "risk_level": risk_level,
                "reason": reason,
            })

    print("\nAzure RBAC Over-Permission Audit")
    print("=" * 50)

    if not findings:
        print("No privileged or suspicious RBAC assignments found.")
    else:
        for finding in findings:
            print(f"Principal:      {finding['principal']}")
            print(f"Type:           {finding['principal_type']}")
            print(f"Role:           {finding['role']}")
            print(f"Scope:          {finding['scope']}")
            print(f"Risk:           {finding['risk_level']}")
            print(f"Reason:         {finding['reason']}")
            print("-" * 50)

    with open("findings.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "principal",
                "principal_type",
                "role",
                "scope",
                "risk_level",
                "reason",
            ],
        )
        writer.writeheader()
        writer.writerows(findings)

    print("\nReport written to findings.csv")

if __name__ == "__main__":
    main()
