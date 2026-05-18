# Azure RBAC Over-Permission Audit Tool

A Python-based Azure RBAC audit tool for identifying overly permissive role assignments and governance risks.

## Overview

This project helps cloud security engineers review Azure RBAC assignments and detect privileged access patterns such as:

- Owner assignments
- Contributor assignments
- User Access Administrator assignments
- Root-scope assignments
- Subscription-wide assignments
- Duplicate privileged assignments
- Overly broad Service Principal permissions

## Security Problem

Overly permissive RBAC assignments increase the risk of privilege escalation, accidental resource changes, unauthorized access, and weak cloud governance.

This tool supports least-privilege reviews by identifying identities with broad or sensitive permissions.

## Features

- Lists Azure RBAC assignments
- Detects privileged roles
- Flags root-scope permissions
- Flags subscription-wide permissions
- Detects duplicate assignments
- Identifies risky Service Principal permissions
- Exports findings to CSV

## Technologies Used

- Python
- Azure CLI
- Azure RBAC
- JSON parsing
- CSV reporting

## Prerequisites

- Python 3
- Azure CLI
- Azure login session

Verify tools:

```powershell
python --version
az --version
