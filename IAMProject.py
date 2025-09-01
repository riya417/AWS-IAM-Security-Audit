import boto3
import csv
from datetime import datetime, timezone

# Initialize IAM client
iam = boto3.client("iam")

# CSV report setup
report_file = "iam_audit_report.csv"
headers = ["Username", "MFA Enabled", "Admin Access", "Wildcard Policy", "Last Used", "Inactive >90 days"]

def check_mfa(user):
    """Check if MFA is enabled for the IAM user"""
    mfa_devices = iam.list_mfa_devices(UserName=user)["MFADevices"]
    return len(mfa_devices) > 0

def check_admin(user):
    """Check if user has AdministratorAccess policy"""
    attached_policies = iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]
    return any(policy["PolicyName"] == "AdministratorAccess" for policy in attached_policies)

def check_wildcards(user):
    """Check for wildcard (*) permissions in inline or attached policies"""
    has_wildcard = False

    # Inline policies
    inline_policies = iam.list_user_policies(UserName=user)["PolicyNames"]
    for policy_name in inline_policies:
        policy_doc = iam.get_user_policy(UserName=user, PolicyName=policy_name)["PolicyDocument"]
        for stmt in policy_doc.get("Statement", []):
            if stmt["Effect"] == "Allow" and stmt["Action"] == "*" or stmt.get("Resource") == "*":
                has_wildcard = True

    return has_wildcard

def check_inactive(user):
    """Check if user has been inactive for >90 days"""
    try:
        access_keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
        for key in access_keys:
            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
            if "LastUsedDate" in last_used:
                last_used_date = last_used["LastUsedDate"].replace(tzinfo=timezone.utc)
                days_inactive = (datetime.now(timezone.utc) - last_used_date).days
                if days_inactive > 90:
                    return True, last_used_date.strftime("%Y-%m-%d")
        return False, "Active"
    except Exception:
        return False, "No Keys"
    
def main():
    users = iam.list_users()["Users"]

    with open(report_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for user in users:
            username = user["UserName"]
            mfa = check_mfa(username)
            admin = check_admin(username)
            wildcard = check_wildcards(username)
            inactive, last_used = check_inactive(username)

            writer.writerow([username, mfa, admin, wildcard, last_used, inactive])
            print(f"Checked {username} → MFA: {mfa}, Admin: {admin}, Wildcard: {wildcard}, Inactive: {inactive}")

    print(f"\n✅ IAM Audit Report saved to {report_file}")

if __name__ == "__main__":
    main()
