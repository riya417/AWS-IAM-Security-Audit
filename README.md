# AWS IAM Security Audit Tool

## Overview
This project is a **cloud security auditing tool** built with **Python (boto3)** that connects to AWS Identity and Access Management (IAM) to detect common misconfigurations and security risks.  

It simulates a **real-world security compliance audit** by analyzing IAM users, roles, and policies for risky permissions and weak security configurations.  

---

## Features
- List all IAM users and roles  
- Detect users with **AdministratorAccess** or wildcard (`*`) policies  
- Check **MFA status** for all users  
- Identify **inactive accounts** (no activity for 90+ days)  
- Export findings to **CSV/JSON** for reporting  

---

## Tools & Technologies
- **Python 3**  
- **Boto3 (AWS SDK for Python)**  
- **AWS IAM (Free Tier)**  
- **AWS CLI**  

---

## Sample Findings
Username,MFA Enabled,Admin Access,Wildcard Policy,Last Used,Inactive >90 days
admin_user,False,True,False,Active,False
dev-user,True,False,False,Active,False
inactive-user,False,False,False,Active,False
read_only_user,True,False,False,Active,False

---

## Code Explanation
The audit tool is written in **Python** and uses the **boto3 library** to interact with AWS IAM. The script begins by retrieving all IAM users through the `list_users()` API call. For each user, it checks whether **MFA is enabled**, whether their policies contain overly permissive access (such as `AdministratorAccess` or wildcard `*`), and when the user last logged in. Users without recent activity (over 90 days) are flagged as inactive.  

Each result is stored in memory and then exported into a **CSV/JSON report**, making the findings easy to analyze. The code is structured around modular functions — one for listing users, one for policy checks, one for MFA verification, and one for report generation. This separation ensures maintainability and scalability if additional IAM checks need to be added later.  

---

## Learning Outcomes
- Gained hands-on experience with **cloud security auditing** in AWS  
- Applied **IAM best practices** including principle of least privilege, MFA enforcement, and inactive user cleanup  
- Strengthened **Python automation** and **cloud security monitoring** skills  

---
