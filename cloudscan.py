#!/usr/bin/env python3
"""
CloudScan - Multi-Cloud Security Misconfiguration Scanner
==========================================================
Supports: AWS, Azure, Microsoft 365, GCP
Modes:    Authenticated (SDK/API) and Unauthenticated (external probing)

DISCLAIMER:
    Use ONLY against cloud accounts/resources you own or are explicitly
    authorized to test. Unauthorized scanning may violate laws and the
    provider's Acceptable Use Policy.

Dependencies (install only what you need):
    pip install boto3 azure-identity azure-mgmt-storage azure-mgmt-network \
                azure-mgmt-resource msgraph-sdk google-cloud-storage \
                google-api-python-client requests rich

Usage:
    python cloudscan.py --provider aws --mode auth
    python cloudscan.py --provider aws --mode unauth --targets buckets.txt
    python cloudscan.py --provider azure --mode auth
    python cloudscan.py --provider m365 --mode auth
    python cloudscan.py --provider gcp --mode auth
    python cloudscan.py --provider all --mode auth --output report.json
"""

import argparse
import json
import sys
import datetime
import concurrent.futures
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional

# Optional pretty output
try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None


# ----------------------------------------------------------------------------
# Core data model
# ----------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    provider: str
    service: str
    resource: str
    check_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    mode: str  # auth | unauth
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    started_at: str
    finished_at: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)

    def add(self, f: Finding):
        self.findings.append(f)

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [
            {**asdict(f), "severity": f.severity.value} for f in self.findings
        ]
        return d


# ----------------------------------------------------------------------------
# Base scanner interface
# ----------------------------------------------------------------------------
class BaseScanner:
    provider = "base"

    def __init__(self, report: ScanReport):
        self.report = report

    def scan_authenticated(self):
        raise NotImplementedError

    def scan_unauthenticated(self, targets: List[str]):
        raise NotImplementedError

    def _safe(self, fn, *args, **kwargs):
        """Run a check, never let one failure kill the whole scan."""
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            log(f"[{self.provider}] check '{getattr(fn, '__name__', fn)}' "
                f"failed: {e}", level="warn")
            return None


def log(msg, level="info"):
    colors = {"info": "cyan", "warn": "yellow", "err": "red", "ok": "green"}
    if RICH:
        console.print(f"[{colors.get(level,'white')}]{msg}[/]")
    else:
        print(msg)


# ============================================================================
# AWS SCANNER
# ============================================================================
class AWSScanner(BaseScanner):
    provider = "aws"

    def scan_authenticated(self):
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            log("boto3 not installed; skipping AWS auth scan.", "warn")
            return
        self.boto3 = boto3
        self.ClientError = ClientError

        log("[AWS] Starting authenticated scan...", "info")
        try:
            sts = boto3.client("sts")
            ident = sts.get_caller_identity()
            log(f"[AWS] Authenticated as {ident['Arn']}", "ok")
        except Exception as e:
            log(f"[AWS] No valid credentials: {e}", "err")
            return

        self._safe(self._check_s3_buckets)
        self._safe(self._check_security_groups)
        self._safe(self._check_iam_password_policy)
        self._safe(self._check_iam_mfa_root)
        self._safe(self._check_cloudtrail)
        self._safe(self._check_rds_public)
        self._safe(self._check_ebs_encryption)

    # ---- individual AWS checks ----
    def _check_s3_buckets(self):
        s3 = self.boto3.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            # Public access block
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab["PublicAccessBlockConfiguration"]
                if not all(cfg.values()):
                    self.report.add(Finding(
                        "aws", "S3", name, "AWS-S3-001",
                        "S3 bucket public access not fully blocked",
                        Severity.HIGH,
                        "One or more Block Public Access settings are disabled.",
                        "Enable all four Block Public Access settings.",
                        "auth", {"config": cfg}))
            except self.ClientError:
                self.report.add(Finding(
                    "aws", "S3", name, "AWS-S3-002",
                    "S3 bucket missing Public Access Block",
                    Severity.HIGH,
                    "No Public Access Block configuration found.",
                    "Apply a Public Access Block to the bucket.",
                    "auth"))
            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
            except self.ClientError:
                self.report.add(Finding(
                    "aws", "S3", name, "AWS-S3-003",
                    "S3 bucket has no default encryption",
                    Severity.MEDIUM,
                    "Server-side encryption is not configured.",
                    "Enable SSE-S3 or SSE-KMS default encryption.",
                    "auth"))
            # ACL public grants
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for g in acl.get("Grants", []):
                    uri = g.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        self.report.add(Finding(
                            "aws", "S3", name, "AWS-S3-004",
                            "S3 bucket ACL grants public access",
                            Severity.CRITICAL,
                            f"ACL grants access to {uri}",
                            "Remove public ACL grants.",
                            "auth"))
            except self.ClientError:
                pass

    def _check_security_groups(self):
        ec2 = self.boto3.client("ec2")
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        risky_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL",
                       5432: "Postgres", 1433: "MSSQL", 6379: "Redis",
                       27017: "MongoDB", 9200: "Elasticsearch"}
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                for rng in perm.get("IpRanges", []):
                    if rng.get("CidrIp") == "0.0.0.0/0":
                        frm = perm.get("FromPort", 0)
                        to = perm.get("ToPort", 65535)
                        for p, svc in risky_ports.items():
                            if frm <= p <= to:
                                self.report.add(Finding(
                                    "aws", "EC2/SG", sg["GroupId"],
                                    "AWS-SG-001",
                                    f"Security group exposes {svc} to internet",
                                    Severity.CRITICAL,
                                    f"Port {p} open to 0.0.0.0/0",
                                    f"Restrict {svc} (port {p}) to known IPs.",
                                    "auth", {"group_name": sg.get("GroupName")}))

    def _check_iam_password_policy(self):
        iam = self.boto3.client("iam")
        try:
            pol = iam.get_account_password_policy()["PasswordPolicy"]
            if pol.get("MinimumPasswordLength", 0) < 14:
                self.report.add(Finding(
                    "aws", "IAM", "account", "AWS-IAM-001",
                    "Weak IAM password length policy", Severity.MEDIUM,
                    f"Minimum length is {pol.get('MinimumPasswordLength')}.",
                    "Set minimum password length to >= 14.", "auth"))
            if not pol.get("RequireSymbols") or not pol.get("RequireNumbers"):
                self.report.add(Finding(
                    "aws", "IAM", "account", "AWS-IAM-002",
                    "IAM password complexity weak", Severity.LOW,
                    "Symbols or numbers not required.",
                    "Require symbols, numbers, upper & lowercase.", "auth"))
        except self.ClientError:
            self.report.add(Finding(
                "aws", "IAM", "account", "AWS-IAM-003",
                "No IAM account password policy", Severity.HIGH,
                "No password policy configured.",
                "Configure a strong account password policy.", "auth"))

    def _check_iam_mfa_root(self):
        iam = self.boto3.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            self.report.add(Finding(
                "aws", "IAM", "root", "AWS-IAM-004",
                "Root account MFA disabled", Severity.CRITICAL,
                "MFA is not enabled on the root account.",
                "Enable hardware/virtual MFA on root.", "auth"))

    def _check_cloudtrail(self):
        ct = self.boto3.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            self.report.add(Finding(
                "aws", "CloudTrail", "account", "AWS-CT-001",
                "No CloudTrail trails configured", Severity.HIGH,
                "API activity is not being logged.",
                "Create a multi-region CloudTrail trail.", "auth"))
        for t in trails:
            status = ct.get_trail_status(Name=t["TrailARN"])
            if not status.get("IsLogging"):
                self.report.add(Finding(
                    "aws", "CloudTrail", t["Name"], "AWS-CT-002",
                    "CloudTrail logging disabled", Severity.HIGH,
                    "Trail exists but is not logging.",
                    "Start logging on the trail.", "auth"))

    def _check_rds_public(self):
        rds = self.boto3.client("rds")
        for db in rds.describe_db_instances().get("DBInstances", []):
            if db.get("PubliclyAccessible"):
                self.report.add(Finding(
                    "aws", "RDS", db["DBInstanceIdentifier"], "AWS-RDS-001",
                    "RDS instance is publicly accessible", Severity.HIGH,
                    "Database is reachable from the internet.",
                    "Disable public accessibility; use private subnets.",
                    "auth"))
            if not db.get("StorageEncrypted"):
                self.report.add(Finding(
                    "aws", "RDS", db["DBInstanceIdentifier"], "AWS-RDS-002",
                    "RDS storage not encrypted", Severity.MEDIUM,
                    "Storage encryption at rest is disabled.",
                    "Enable storage encryption (requires snapshot/restore).",
                    "auth"))

    def _check_ebs_encryption(self):
        ec2 = self.boto3.client("ec2")
        res = ec2.get_ebs_encryption_by_default()
        if not res.get("EbsEncryptionByDefault"):
            self.report.add(Finding(
                "aws", "EC2/EBS", "account", "AWS-EBS-001",
                "EBS default encryption disabled", Severity.MEDIUM,
                "New EBS volumes are not encrypted by default.",
                "Enable EBS encryption by default in EC2 settings.", "auth"))

    # ---- unauthenticated ----
    def scan_unauthenticated(self, targets):
        import requests
        log("[AWS] Starting unauthenticated S3 bucket probing...", "info")

        def probe(bucket):
            urls = [
                f"https://{bucket}.s3.amazonaws.com/",
                f"https://s3.amazonaws.com/{bucket}/",
            ]
            for url in urls:
                try:
                    r = requests.get(url, timeout=8)
                except requests.RequestException:
                    continue
                if r.status_code == 200 and ("<ListBucketResult" in r.text
                                             or "<Contents>" in r.text):
                    self.report.add(Finding(
                        "aws", "S3", bucket, "AWS-S3-U01",
                        "Public S3 bucket listing exposed", Severity.CRITICAL,
                        f"Bucket contents are publicly listable at {url}",
                        "Enable Block Public Access; remove public ACLs.",
                        "unauth", {"url": url}))
                    return
                elif r.status_code == 403:
                    self.report.add(Finding(
                        "aws", "S3", bucket, "AWS-S3-U02",
                        "S3 bucket exists (access denied)", Severity.INFO,
                        f"Bucket exists but listing denied at {url}",
                        "Verify intended access; bucket name enumerable.",
                        "unauth", {"url": url}))
                    return

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            ex.map(probe, [t.strip() for t in targets if t.strip()])


# ============================================================================
# AZURE SCANNER
# ============================================================================
class AzureScanner(BaseScanner):
    provider = "azure"

    def scan_authenticated(self):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import SubscriptionClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.network import NetworkManagementClient
        except ImportError:
            log("azure-* SDKs not installed; skipping Azure auth scan.", "warn")
            return

        log("[Azure] Starting authenticated scan...", "info")
        try:
            cred = DefaultAzureCredential()
            sub_client = SubscriptionClient(cred)
            subs = list(sub_client.subscriptions.list())
        except Exception as e:
            log(f"[Azure] Auth failed: {e}", "err")
            return

        for sub in subs:
            sub_id = sub.subscription_id
            log(f"[Azure] Scanning subscription {sub_id}", "ok")
            self._safe(self._check_storage_accounts,
                       StorageManagementClient(cred, sub_id))
            self._safe(self._check_nsgs,
                       NetworkManagementClient(cred, sub_id))

    def _check_storage_accounts(self, sc):
        for acct in sc.storage_accounts.list():
            if acct.allow_blob_public_access:
                self.report.add(Finding(
                    "azure", "Storage", acct.name, "AZ-STG-001",
                    "Storage account allows public blob access",
                    Severity.HIGH,
                    "allowBlobPublicAccess is enabled.",
                    "Set allowBlobPublicAccess = false.", "auth"))
            if not acct.enable_https_traffic_only:
                self.report.add(Finding(
                    "azure", "Storage", acct.name, "AZ-STG-002",
                    "Storage account allows HTTP traffic", Severity.MEDIUM,
                    "Secure transfer (HTTPS only) is disabled.",
                    "Enable 'Secure transfer required'.", "auth"))
            mtls = getattr(acct, "minimum_tls_version", None)
            if mtls and mtls < "TLS1_2":
                self.report.add(Finding(
                    "azure", "Storage", acct.name, "AZ-STG-003",
                    "Storage account weak minimum TLS", Severity.MEDIUM,
                    f"Minimum TLS version is {mtls}.",
                    "Set minimum TLS version to 1.2.", "auth"))
            net = getattr(acct, "network_rule_set", None)
            if net and net.default_action == "Allow":
                self.report.add(Finding(
                    "azure", "Storage", acct.name, "AZ-STG-004",
                    "Storage account network default-allow", Severity.MEDIUM,
                    "Firewall default action allows all networks.",
                    "Set default network action to Deny and whitelist.",
                    "auth"))

    def _check_nsgs(self, nc):
        risky = {22: "SSH", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL",
                 5432: "Postgres", 6379: "Redis", 27017: "MongoDB"}
        for nsg in nc.network_security_groups.list_all():
            for rule in nsg.security_rules or []:
                if (rule.access == "Allow" and rule.direction == "Inbound"
                        and rule.source_address_prefix in ("*", "0.0.0.0/0",
                                                            "Internet")):
                    ports = []
                    if rule.destination_port_range:
                        ports.append(rule.destination_port_range)
                    ports += rule.destination_port_ranges or []
                    for pr in ports:
                        hit = self._port_in_range(pr, risky)
                        if hit:
                            self.report.add(Finding(
                                "azure", "NSG", nsg.name, "AZ-NSG-001",
                                f"NSG exposes {risky[hit]} to internet",
                                Severity.CRITICAL,
                                f"Rule '{rule.name}' allows {pr} from any source.",
                                f"Restrict source for port {hit}.", "auth"))

    @staticmethod
    def _port_in_range(pr, risky):
        if pr == "*":
            return next(iter(risky))
        try:
            if "-" in pr:
                lo, hi = map(int, pr.split("-"))
                for p in risky:
                    if lo <= p <= hi:
                        return p
            else:
                p = int(pr)
                if p in risky:
                    return p
        except ValueError:
            return None
        return None

    def scan_unauthenticated(self, targets):
        import requests
        log("[Azure] Probing public blob containers...", "info")

        def probe(acct):
            url = f"https://{acct}.blob.core.windows.net/?comp=list"
            try:
                r = requests.get(url, timeout=8)
            except requests.RequestException:
                return
            if r.status_code == 200 and "<EnumerationResults" in r.text:
                self.report.add(Finding(
                    "azure", "Storage", acct, "AZ-STG-U01",
                    "Public Azure storage enumeration exposed",
                    Severity.CRITICAL,
                    f"Container listing exposed at {url}",
                    "Disable anonymous access on the storage account.",
                    "unauth", {"url": url}))
            elif r.status_code in (400, 403, 409):
                self.report.add(Finding(
                    "azure", "Storage", acct, "AZ-STG-U02",
                    "Azure storage account exists", Severity.INFO,
                    "Storage account name resolves (enumerable).",
                    "Account name is discoverable; ensure no anon access.",
                    "unauth", {"url": url}))

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            ex.map(probe, [t.strip() for t in targets if t.strip()])


# ============================================================================
# MICROSOFT 365 SCANNER  (uses Microsoft Graph)
# ============================================================================
class M365Scanner(BaseScanner):
    provider = "m365"

    def scan_authenticated(self):
        """
        Requires an Azure AD app registration with Graph application
        permissions (Directory.Read.All, Policy.Read.All,
        SecurityEvents.Read.All) and admin consent.
        Set env vars: M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET
        """
        import os
        try:
            import requests
        except ImportError:
            log("requests not installed; skipping M365 scan.", "warn")
            return

        tenant = os.getenv("M365_TENANT_ID")
        cid = os.getenv("M365_CLIENT_ID")
        secret = os.getenv("M365_CLIENT_SECRET")
        if not all([tenant, cid, secret]):
            log("[M365] Missing M365_TENANT_ID/CLIENT_ID/CLIENT_SECRET.", "err")
            return

        log("[M365] Acquiring Graph token...", "info")
        token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": cid,
            "client_secret": secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        try:
            tok = requests.post(token_url, data=data, timeout=15).json()
            self.token = tok["access_token"]
        except Exception as e:
            log(f"[M365] Token acquisition failed: {e}", "err")
            return
        self.requests = requests
        log("[M365] Authenticated.", "ok")

        self._safe(self._check_security_defaults)
        self._safe(self._check_legacy_auth_policies)
        self._safe(self._check_admin_mfa)
        self._safe(self._check_user_consent)

    def _graph(self, path):
        url = f"https://graph.microsoft.com/v1.0{path}"
        r = self.requests.get(
            url, headers={"Authorization": f"Bearer {self.token}"}, timeout=15)
        return r.json() if r.ok else {}

    def _check_security_defaults(self):
        data = self._graph(
            "/policies/identitySecurityDefaultsEnforcementPolicy")
        if data and data.get("isEnabled") is False:
            # Not necessarily bad if CA policies exist, but flag for review
            self.report.add(Finding(
                "m365", "AAD", "tenant", "M365-001",
                "Security Defaults disabled", Severity.MEDIUM,
                "Security Defaults are off. Ensure Conditional Access covers MFA.",
                "Enable Security Defaults or equivalent CA policies.", "auth"))

    def _check_legacy_auth_policies(self):
        data = self._graph("/policies/authorizationPolicy")
        if data:
            if data.get("allowedToSignUpEmailBasedSubscriptions"):
                self.report.add(Finding(
                    "m365", "AAD", "tenant", "M365-002",
                    "Self-service sign-up enabled", Severity.LOW,
                    "Users can sign up for email-based subscriptions.",
                    "Disable if not required.", "auth"))
            if data.get("defaultUserRolePermissions", {}).get(
                    "allowedToCreateApps"):
                self.report.add(Finding(
                    "m365", "AAD", "tenant", "M365-003",
                    "Users can register applications", Severity.MEDIUM,
                    "All users can create app registrations.",
                    "Restrict app registration to admins.", "auth"))

    def _check_admin_mfa(self):
        # Enumerate privileged role members for review
        roles = self._graph("/directoryRoles").get("value", [])
        for role in roles:
            if "admin" in (role.get("displayName") or "").lower():
                members = self._graph(
                    f"/directoryRoles/{role['id']}/members").get("value", [])
                if members:
                    self.report.add(Finding(
                        "m365", "AAD", role["displayName"], "M365-004",
                        "Privileged role members present (verify MFA)",
                        Severity.INFO,
                        f"{len(members)} member(s) in '{role['displayName']}'. "
                        "Confirm all enforce phishing-resistant MFA.",
                        "Enforce MFA/PIM for all privileged roles.", "auth",
                        {"member_count": len(members)}))

    def _check_user_consent(self):
        data = self._graph(
            "/policies/authorizationPolicy")
        grant = data.get("defaultUserRolePermissions", {}) if data else {}
        # Heuristic flag
        if grant.get("allowedToCreateSecurityGroups"):
            self.report.add(Finding(
                "m365", "AAD", "tenant", "M365-005",
                "All users can create security groups", Severity.LOW,
                "Group sprawl / access-control risk.",
                "Restrict group creation where possible.", "auth"))

    def scan_unauthenticated(self, targets):
        """
        Unauthenticated M365 recon: tenant existence + domain federation info
        via the public OpenID/realm endpoints. targets = list of domains.
        """
        import requests
        log("[M365] Tenant/domain recon...", "info")

        def probe(domain):
            # Tenant existence via OpenID configuration
            cfg_url = (f"https://login.microsoftonline.com/{domain}/"
                       ".well-known/openid-configuration")
            try:
                r = requests.get(cfg_url, timeout=8)
            except requests.RequestException:
                return
            if r.status_code == 200:
                self.report.add(Finding(
                    "m365", "AAD", domain, "M365-U01",
                    "Microsoft 365 tenant exists for domain", Severity.INFO,
                    f"Domain {domain} is backed by an Entra ID tenant.",
                    "Informational; ensure tenant hardening applied.",
                    "unauth", {"openid_config": cfg_url}))
            # Federation / auth type via GetUserRealm
            realm_url = (f"https://login.microsoftonline.com/getuserrealm.srf"
                         f"?login=user@{domain}&xml=1")
            try:
                r2 = requests.get(realm_url, timeout=8)
                if r2.ok and "Federated" in r2.text:
                    self.report.add(Finding(
                        "m365", "AAD", domain, "M365-U02",
                        "Domain uses federated authentication", Severity.INFO,
                        "Federated (e.g. ADFS) auth detected; review IdP security.",
                        "Ensure on-prem federation infra is hardened/patched.",
                        "unauth"))
            except requests.RequestException:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            ex.map(probe, [t.strip() for t in targets if t.strip()])


# ============================================================================
# GCP SCANNER
# ============================================================================
class GCPScanner(BaseScanner):
    provider = "gcp"

    def scan_authenticated(self):
        """
        Requires Application Default Credentials:
            gcloud auth application-default login
        or GOOGLE_APPLICATION_CREDENTIALS pointing to a service-account key.
        Set GCP_PROJECT_ID env var or pass project.
        """
        import os
        try:
            from google.cloud import storage
            from googleapiclient import discovery
            import google.auth
        except ImportError:
            log("google-cloud libs not installed; skipping GCP scan.", "warn")
            return

        log("[GCP] Starting authenticated scan...", "info")
        try:
            creds, project = google.auth.default()
            project = os.getenv("GCP_PROJECT_ID") or project
            log(f"[GCP] Project: {project}", "ok")
        except Exception as e:
            log(f"[GCP] Auth failed: {e}", "err")
            return

        self.project = project
        self.creds = creds
        self.discovery = discovery
        self.storage = storage

        self._safe(self._check_buckets)
        self._safe(self._check_firewall_rules)
        self._safe(self._check_service_account_keys)

    def _check_buckets(self):
        client = self.storage.Client(project=self.project, credentials=self.creds)
        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get("members", set())
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    self.report.add(Finding(
                        "gcp", "GCS", bucket.name, "GCP-GCS-001",
                        "GCS bucket publicly accessible", Severity.CRITICAL,
                        f"IAM binding '{binding['role']}' grants public access.",
                        "Remove allUsers/allAuthenticatedUsers bindings.",
                        "auth", {"role": binding["role"]}))
            ubla = bucket.iam_configuration.uniform_bucket_level_access_enabled
            if not ubla:
                self.report.add(Finding(
                    "gcp", "GCS", bucket.name, "GCP-GCS-002",
                    "Uniform bucket-level access disabled", Severity.MEDIUM,
                    "Legacy ACLs may grant unintended access.",
                    "Enable uniform bucket-level access.", "auth"))

    def _check_firewall_rules(self):
        compute = self.discovery.build("compute", "v1", credentials=self.creds)
        risky = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "Postgres",
                 1433: "MSSQL", 6379: "Redis", 27017: "MongoDB"}
        req = compute.firewalls().list(project=self.project)
        while req is not None:
            resp = req.execute()
            for fw in resp.get("items", []):
                if fw.get("direction", "INGRESS") != "INGRESS":
                    continue
                if "0.0.0.0/0" not in fw.get("sourceRanges", []):
                    continue
                for allowed in fw.get("allowed", []):
                    ports = allowed.get("ports", [])
                    if not ports:  # all ports
                        self.report.add(Finding(
                            "gcp", "VPC", fw["name"], "GCP-FW-001",
                            "Firewall allows all ports from internet",
                            Severity.CRITICAL,
                            f"Rule '{fw['name']}' opens all ports to 0.0.0.0/0.",
                            "Scope source ranges and ports.", "auth"))
                        continue
                    for pr in ports:
                        for p, svc in risky.items():
                            if self._port_match(pr, p):
                                self.report.add(Finding(
                                    "gcp", "VPC", fw["name"], "GCP-FW-002",
                                    f"Firewall exposes {svc} to internet",
                                    Severity.CRITICAL,
                                    f"Rule '{fw['name']}' opens {p} to 0.0.0.0/0.",
                                    f"Restrict source range for port {p}.",
                                    "auth"))
            req = compute.firewalls().list_next(req, resp)

    @staticmethod
    def _port_match(pr, p):
        if "-" in pr:
            lo, hi = map(int, pr.split("-"))
            return lo <= p <= hi
        return pr == str(p)

    def _check_service_account_keys(self):
        iam = self.discovery.build("iam", "v1", credentials=self.creds)
        sas = iam.projects().serviceAccounts().list(
            name=f"projects/{self.project}").execute().get("accounts", [])
        for sa in sas:
            keys = iam.projects().serviceAccounts().keys().list(
                name=sa["name"], keyTypes="USER_MANAGED").execute().get(
                "keys", [])
            for k in keys:
                self.report.add(Finding(
                    "gcp", "IAM", sa["email"], "GCP-IAM-001",
                    "User-managed service account key exists", Severity.MEDIUM,
                    f"Key {k['name'].split('/')[-1]} is user-managed (rotation risk).",
                    "Prefer workload identity / short-lived creds; rotate keys.",
                    "auth"))

    def scan_unauthenticated(self, targets):
        import requests
        log("[GCP] Probing public GCS buckets...", "info")

        def probe(bucket):
            url = (f"https://storage.googleapis.com/storage/v1/b/{bucket}/o")
            try:
                r = requests.get(url, timeout=8)
            except requests.RequestException:
                return
            if r.status_code == 200:
                self.report.add(Finding(
                    "gcp", "GCS", bucket, "GCP-GCS-U01",
                    "Public GCS bucket listing exposed", Severity.CRITICAL,
                    f"Object listing publicly accessible at {url}",
                    "Remove allUsers IAM bindings.", "unauth", {"url": url}))
            elif r.status_code in (401, 403):
                self.report.add(Finding(
                    "gcp", "GCS", bucket, "GCP-GCS-U02",
                    "GCS bucket exists (access denied)", Severity.INFO,
                    "Bucket exists but listing is denied (enumerable).",
                    "Bucket name discoverable; verify intended access.",
                    "unauth", {"url": url}))

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            ex.map(probe, [t.strip() for t in targets if t.strip()])


# ============================================================================
# Reporting
# ============================================================================
SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.INFO: 4}


def print_report(report: ScanReport):
    findings = sorted(report.findings, key=lambda f: SEV_ORDER[f.severity])
    if not findings:
        log("No findings.", "ok")
        return

    if RICH:
        table = Table(title="CloudScan Findings", show_lines=False)
        for col in ("Severity", "Provider", "Service", "Resource",
                    "Check", "Title", "Mode"):
            table.add_column(col, overflow="fold")
        sev_color = {Severity.CRITICAL: "bold red", Severity.HIGH: "red",
                     Severity.MEDIUM: "yellow", Severity.LOW: "cyan",
                     Severity.INFO: "white"}
        for f in findings:
            table.add_row(
                f"[{sev_color[f.severity]}]{f.severity.value}[/]",
                f.provider, f.service, f.resource, f.check_id, f.title, f.mode)
        console.print(table)
    else:
        for f in findings:
            print(f"[{f.severity.value}] {f.provider}/{f.service} "
                  f"{f.resource} - {f.title} ({f.check_id})")

    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    log(f"\nSummary: {counts}", "info")


# ============================================================================
# Main
# ============================================================================
SCANNERS = {
    "aws": AWSScanner,
    "azure": AzureScanner,
    "m365": M365Scanner,
    "gcp": GCPScanner,
}


def main():
    p = argparse.ArgumentParser(
        description="CloudScan - Multi-Cloud Misconfiguration Scanner")
    p.add_argument("--provider", required=True,
                   choices=["aws", "azure", "m365", "gcp", "all"])
    p.add_argument("--mode", required=True, choices=["auth", "unauth", "both"])
    p.add_argument("--targets",
                   help="File with target names/domains (unauth mode)")
    p.add_argument("--output", help="Write JSON report to this file")
    args = p.parse_args()

    targets = []
    if args.targets:
        with open(args.targets) as fh:
            targets = [line.strip() for line in fh if line.strip()]

    report = ScanReport(
        started_at=datetime.datetime.utcnow().isoformat() + "Z")

    providers = (list(SCANNERS) if args.provider == "all"
                 else [args.provider])

    for prov in providers:
        scanner = SCANNERS[prov](report)
        if args.mode in ("auth", "both"):
            scanner.scan_authenticated()
        if args.mode in ("unauth", "both"):
            if not targets:
                log(f"[{prov}] unauth mode needs --targets; skipping.", "warn")
            else:
                scanner.scan_unauthenticated(targets)

    report.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
    print_report(report)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report.to_dict(), fh, indent=2)
        log(f"\nJSON report written to {args.output}", "ok")


if __name__ == "__main__":
    main()
