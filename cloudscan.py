#!/usr/bin/env python3
"""
CloudScan - Multi-Cloud Security Misconfiguration Scanner (v2)
==============================================================
Supports: AWS, Azure, Microsoft 365, GCP
Modes:    Authenticated (SDK/API) and Unauthenticated (external probing)

New in v2:
  * Inline --target flag (repeatable) in addition to --targets file
  * CIS Benchmark control mappings on every finding
  * --discover: derive likely bucket/storage/tenant names from a domain
                so a single domain can feed ALL unauthenticated modules

DISCLAIMER:
    Use ONLY against cloud accounts/resources you own or are explicitly
    authorized to test. Unauthorized scanning may violate laws (e.g. CFAA)
    and the provider's Acceptable Use Policy.

Dependencies (install only what you need):
    pip install boto3 azure-identity azure-mgmt-storage azure-mgmt-network \
                azure-mgmt-resource msgraph-sdk google-cloud-storage \
                google-api-python-client requests rich

Usage:
    # Authenticated
    python cloudscan.py --provider aws --mode auth
    python cloudscan.py --provider all --mode auth --output report.json

    # Unauthenticated - inline targets (buckets / storage accounts / domains)
    python cloudscan.py --provider aws   --mode unauth --target mycompany-backups
    python cloudscan.py --provider m365  --mode unauth --target example.com

    # Unauthenticated - target file
    python cloudscan.py --provider gcp --mode unauth --targets buckets.txt

    # Auto-discovery: derive likely resource names from one domain and probe
    python cloudscan.py --provider all --mode unauth --discover example.com

    # Both modes
    python cloudscan.py --provider aws --mode both --target mybucket
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
    cis: str = "N/A"          # CIS Benchmark control reference
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
# CIS Benchmark mapping table
#   Centralized so check IDs map cleanly to published CIS controls.
#   (References approximate published CIS Foundations Benchmark sections.)
# ----------------------------------------------------------------------------
CIS_MAP = {
    # AWS  (CIS AWS Foundations Benchmark v3.0.0)
    "AWS-S3-001": "CIS AWS 2.1.5 - S3 Block Public Access (account/bucket)",
    "AWS-S3-002": "CIS AWS 2.1.5 - S3 Block Public Access",
    "AWS-S3-003": "CIS AWS 2.1.1 - S3 default encryption (SSE)",
    "AWS-S3-004": "CIS AWS 2.1.5 - No public S3 ACLs",
    "AWS-SG-001": "CIS AWS 5.2/5.3 - No 0.0.0.0/0 to admin/db ports",
    "AWS-IAM-001": "CIS AWS 1.8 - IAM password min length >= 14",
    "AWS-IAM-002": "CIS AWS 1.8/1.9 - Password complexity/reuse",
    "AWS-IAM-003": "CIS AWS 1.8 - Maintain IAM password policy",
    "AWS-IAM-004": "CIS AWS 1.5 - MFA enabled for root account",
    "AWS-CT-001": "CIS AWS 3.1 - CloudTrail enabled all regions",
    "AWS-CT-002": "CIS AWS 3.1 - CloudTrail logging active",
    "AWS-RDS-001": "CIS AWS 2.3.3 - RDS not publicly accessible",
    "AWS-RDS-002": "CIS AWS 2.3.1 - RDS encryption at rest",
    "AWS-EBS-001": "CIS AWS 2.2.1 - EBS encryption by default",
    "AWS-S3-U01": "CIS AWS 2.1.5 - S3 Block Public Access (external)",
    "AWS-S3-U02": "CIS AWS 2.1.5 - S3 bucket exposure (external)",
    # Azure (CIS Microsoft Azure Foundations Benchmark v2.1.0)
    "AZ-STG-001": "CIS Azure 3.7 - Disallow public blob access",
    "AZ-STG-002": "CIS Azure 3.1 - Secure transfer required",
    "AZ-STG-003": "CIS Azure 3.15 - Minimum TLS 1.2",
    "AZ-STG-004": "CIS Azure 3.8 - Default network access = Deny",
    "AZ-NSG-001": "CIS Azure 6.1/6.2 - No 0.0.0.0/0 to RDP/SSH/db",
    "AZ-STG-U01": "CIS Azure 3.7 - Public blob exposure (external)",
    "AZ-STG-U02": "CIS Azure 3.7 - Storage account exposure (external)",
    # Microsoft 365 (CIS Microsoft 365 Foundations Benchmark v3.x)
    "M365-001": "CIS M365 1.1.1 - Security Defaults / CA MFA enforced",
    "M365-002": "CIS M365 1.1.6 - Restrict self-service sign-up",
    "M365-003": "CIS M365 1.1.3 - Restrict app registration to admins",
    "M365-004": "CIS M365 1.1.1 - MFA for privileged roles (PIM)",
    "M365-005": "CIS M365 1.3.x - Restrict group creation",
    "M365-U01": "CIS M365 1.x - Tenant exposure (external recon)",
    "M365-U02": "CIS M365 1.x - Federation/IdP review (external recon)",
    # GCP (CIS Google Cloud Platform Foundation Benchmark v2.0.0)
    "GCP-GCS-001": "CIS GCP 5.1 - Buckets not anonymously/public accessible",
    "GCP-GCS-002": "CIS GCP 5.2 - Uniform bucket-level access enabled",
    "GCP-FW-001": "CIS GCP 3.6/3.7 - No 0.0.0.0/0 to all/admin ports",
    "GCP-FW-002": "CIS GCP 3.6/3.7 - No 0.0.0.0/0 to RDP/SSH/db",
    "GCP-IAM-001": "CIS GCP 1.4 - Rotate/avoid user-managed SA keys",
    "GCP-GCS-U01": "CIS GCP 5.1 - Public bucket exposure (external)",
    "GCP-GCS-U02": "CIS GCP 5.1 - Bucket exposure (external)",
}


def cis_for(check_id: str) -> str:
    return CIS_MAP.get(check_id, "N/A")


# ----------------------------------------------------------------------------
# Logging helper
# ----------------------------------------------------------------------------
def log(msg, level="info"):
    colors = {"info": "cyan", "warn": "yellow", "err": "red", "ok": "green"}
    if RICH:
        console.print(f"[{colors.get(level,'white')}]{msg}[/]")
    else:
        print(msg)


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

    def add_finding(self, **kwargs):
        """Wrapper that auto-injects the CIS mapping for a check_id."""
        kwargs.setdefault("cis", cis_for(kwargs.get("check_id", "")))
        self.report.add(Finding(**kwargs))

    def _safe(self, fn, *args, **kwargs):
        """Run a check, never let one failure kill the whole scan."""
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            log(f"[{self.provider}] check '{getattr(fn, '__name__', fn)}' "
                f"failed: {e}", level="warn")
            return None


# ----------------------------------------------------------------------------
# DNS-based auto-discovery
#   Given a domain (e.g. example.com), generate likely resource names for
#   each cloud and verify which actually exist via lightweight HTTP probes.
# ----------------------------------------------------------------------------
class Discovery:
    """Derive candidate resource names from a domain and validate existence."""

    # Common naming permutations seen in the wild.
    SUFFIXES = [
        "", "-prod", "-dev", "-staging", "-test", "-backup", "-backups",
        "-data", "-assets", "-static", "-media", "-logs", "-public",
        "-private", "-storage", "-files", "-uploads", "-images", "-cdn",
        "-archive", "-db", "-config", "-secret", "-secrets", "-internal",
    ]
    PREFIXES = ["", "prod-", "dev-", "staging-", "backup-", "data-",
                "assets-", "static-", "internal-"]

    def __init__(self):
        try:
            import requests
            self.requests = requests
        except ImportError:
            self.requests = None

    @staticmethod
    def _base_tokens(domain: str) -> List[str]:
        """Extract usable base tokens from a domain.
        example.com         -> ['example']
        my-app.co.uk        -> ['my-app', 'myapp', 'my']
        """
        host = domain.strip().lower().split("://")[-1].split("/")[0]
        labels = host.split(".")
        # drop common public-suffix tail labels
        tail = {"com", "net", "org", "io", "co", "uk", "us", "gov", "edu",
                "cloud", "app", "dev", "ai"}
        core = [l for l in labels if l not in tail] or labels
        base = core[0]
        tokens = {base, base.replace("-", ""), base.replace("-", "")}
        if "-" in base:
            tokens.add(base.split("-")[0])
        # also include full second-level label set joined
        tokens.add("".join(core))
        return sorted({t for t in tokens if t})

    def candidate_names(self, domain: str, limit: int = 200) -> List[str]:
        """Generate candidate bucket/account names for AWS/GCP/Azure."""
        names = set()
        for base in self._base_tokens(domain):
            for pre in self.PREFIXES:
                for suf in self.SUFFIXES:
                    name = f"{pre}{base}{suf}"
                    if 3 <= len(name) <= 63:
                        names.add(name)
        out = sorted(names)
        return out[:limit]

    def azure_candidate_names(self, domain: str, limit: int = 200) -> List[str]:
        """Azure storage account names: 3-24 chars, lowercase alnum only."""
        names = set()
        for base in self._base_tokens(domain):
            b = "".join(ch for ch in base if ch.isalnum())
            for suf in ["", "prod", "dev", "data", "backup", "store",
                        "storage", "assets", "logs", "files", "media",
                        "static", "archive"]:
                name = f"{b}{suf}"
                if 3 <= len(name) <= 24:
                    names.add(name)
        out = sorted(names)
        return out[:limit]

    def domains_for(self, domain: str) -> List[str]:
        """M365 module just needs the domain itself."""
        host = domain.strip().lower().split("://")[-1].split("/")[0]
        return [host]


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
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab["PublicAccessBlockConfiguration"]
                if not all(cfg.values()):
                    self.add_finding(
                        provider="aws", service="S3", resource=name,
                        check_id="AWS-S3-001",
                        title="S3 bucket public access not fully blocked",
                        severity=Severity.HIGH,
                        description="One or more Block Public Access settings are disabled.",
                        remediation="Enable all four Block Public Access settings.",
                        mode="auth", metadata={"config": cfg})
            except self.ClientError:
                self.add_finding(
                    provider="aws", service="S3", resource=name,
                    check_id="AWS-S3-002",
                    title="S3 bucket missing Public Access Block",
                    severity=Severity.HIGH,
                    description="No Public Access Block configuration found.",
                    remediation="Apply a Public Access Block to the bucket.",
                    mode="auth")
            try:
                s3.get_bucket_encryption(Bucket=name)
            except self.ClientError:
                self.add_finding(
                    provider="aws", service="S3", resource=name,
                    check_id="AWS-S3-003",
                    title="S3 bucket has no default encryption",
                    severity=Severity.MEDIUM,
                    description="Server-side encryption is not configured.",
                    remediation="Enable SSE-S3 or SSE-KMS default encryption.",
                    mode="auth")
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for g in acl.get("Grants", []):
                    uri = g.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        self.add_finding(
                            provider="aws", service="S3", resource=name,
                            check_id="AWS-S3-004",
                            title="S3 bucket ACL grants public access",
                            severity=Severity.CRITICAL,
                            description=f"ACL grants access to {uri}",
                            remediation="Remove public ACL grants.",
                            mode="auth")
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
                                self.add_finding(
                                    provider="aws", service="EC2/SG",
                                    resource=sg["GroupId"],
                                    check_id="AWS-SG-001",
                                    title=f"Security group exposes {svc} to internet",
                                    severity=Severity.CRITICAL,
                                    description=f"Port {p} open to 0.0.0.0/0",
                                    remediation=f"Restrict {svc} (port {p}) to known IPs.",
                                    mode="auth",
                                    metadata={"group_name": sg.get("GroupName")})

    def _check_iam_password_policy(self):
        iam = self.boto3.client("iam")
        try:
            pol = iam.get_account_password_policy()["PasswordPolicy"]
            if pol.get("MinimumPasswordLength", 0) < 14:
                self.add_finding(
                    provider="aws", service="IAM", resource="account",
                    check_id="AWS-IAM-001",
                    title="Weak IAM password length policy",
                    severity=Severity.MEDIUM,
                    description=f"Minimum length is {pol.get('MinimumPasswordLength')}.",
                    remediation="Set minimum password length to >= 14.",
                    mode="auth")
            if not pol.get("RequireSymbols") or not pol.get("RequireNumbers"):
                self.add_finding(
                    provider="aws", service="IAM", resource="account",
                    check_id="AWS-IAM-002",
                    title="IAM password complexity weak",
                    severity=Severity.LOW,
                    description="Symbols or numbers not required.",
                    remediation="Require symbols, numbers, upper & lowercase.",
                    mode="auth")
        except self.ClientError:
            self.add_finding(
                provider="aws", service="IAM", resource="account",
                check_id="AWS-IAM-003",
                title="No IAM account password policy",
                severity=Severity.HIGH,
                description="No password policy configured.",
                remediation="Configure a strong account password policy.",
                mode="auth")

    def _check_iam_mfa_root(self):
        iam = self.boto3.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            self.add_finding(
                provider="aws", service="IAM", resource="root",
                check_id="AWS-IAM-004",
                title="Root account MFA disabled",
                severity=Severity.CRITICAL,
                description="MFA is not enabled on the root account.",
                remediation="Enable hardware/virtual MFA on root.",
                mode="auth")

    def _check_cloudtrail(self):
        ct = self.boto3.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            self.add_finding(
                provider="aws", service="CloudTrail", resource="account",
                check_id="AWS-CT-001",
                title="No CloudTrail trails configured",
                severity=Severity.HIGH,
                description="API activity is not being logged.",
                remediation="Create a multi-region CloudTrail trail.",
                mode="auth")
        for t in trails:
            status = ct.get_trail_status(Name=t["TrailARN"])
            if not status.get("IsLogging"):
                self.add_finding(
                    provider="aws", service="CloudTrail", resource=t["Name"],
                    check_id="AWS-CT-002",
                    title="CloudTrail logging disabled",
                    severity=Severity.HIGH,
                    description="Trail exists but is not logging.",
                    remediation="Start logging on the trail.",
                    mode="auth")

    def _check_rds_public(self):
        rds = self.boto3.client("rds")
        for db in rds.describe_db_instances().get("DBInstances", []):
            if db.get("PubliclyAccessible"):
                self.add_finding(
                    provider="aws", service="RDS",
                    resource=db["DBInstanceIdentifier"],
                    check_id="AWS-RDS-001",
                    title="RDS instance is publicly accessible",
                    severity=Severity.HIGH,
                    description="Database is reachable from the internet.",
                    remediation="Disable public accessibility; use private subnets.",
                    mode="auth")
            if not db.get("StorageEncrypted"):
                self.add_finding(
                    provider="aws", service="RDS",
                    resource=db["DBInstanceIdentifier"],
                    check_id="AWS-RDS-002",
                    title="RDS storage not encrypted",
                    severity=Severity.MEDIUM,
                    description="Storage encryption at rest is disabled.",
                    remediation="Enable storage encryption (snapshot/restore).",
                    mode="auth")

    def _check_ebs_encryption(self):
        ec2 = self.boto3.client("ec2")
        res = ec2.get_ebs_encryption_by_default()
        if not res.get("EbsEncryptionByDefault"):
            self.add_finding(
                provider="aws", service="EC2/EBS", resource="account",
                check_id="AWS-EBS-001",
                title="EBS default encryption disabled",
                severity=Severity.MEDIUM,
                description="New EBS volumes are not encrypted by default.",
                remediation="Enable EBS encryption by default in EC2 settings.",
                mode="auth")

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
                    self.add_finding(
                        provider="aws", service="S3", resource=bucket,
                        check_id="AWS-S3-U01",
                        title="Public S3 bucket listing exposed",
                        severity=Severity.CRITICAL,
                        description=f"Bucket contents are publicly listable at {url}",
                        remediation="Enable Block Public Access; remove public ACLs.",
                        mode="unauth", metadata={"url": url})
                    return
                elif r.status_code == 403:
                    self.add_finding(
                        provider="aws", service="S3", resource=bucket,
                        check_id="AWS-S3-U02",
                        title="S3 bucket exists (access denied)",
                        severity=Severity.INFO,
                        description=f"Bucket exists but listing denied at {url}",
                        remediation="Verify intended access; name is enumerable.",
                        mode="unauth", metadata={"url": url})
                    return

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(probe, [t.strip() for t in targets if t.strip()]))


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

        from azure.mgmt.storage import StorageManagementClient
        from azure.mgmt.network import NetworkManagementClient
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
                self.add_finding(
                    provider="azure", service="Storage", resource=acct.name,
                    check_id="AZ-STG-001",
                    title="Storage account allows public blob access",
                    severity=Severity.HIGH,
                    description="allowBlobPublicAccess is enabled.",
                    remediation="Set allowBlobPublicAccess = false.",
                    mode="auth")
            if not acct.enable_https_traffic_only:
                self.add_finding(
                    provider="azure", service="Storage", resource=acct.name,
                    check_id="AZ-STG-002",
                    title="Storage account allows HTTP traffic",
                    severity=Severity.MEDIUM,
                    description="Secure transfer (HTTPS only) is disabled.",
                    remediation="Enable 'Secure transfer required'.",
                    mode="auth")
            mtls = getattr(acct, "minimum_tls_version", None)
            if mtls and mtls < "TLS1_2":
                self.add_finding(
                    provider="azure", service="Storage", resource=acct.name,
                    check_id="AZ-STG-003",
                    title="Storage account weak minimum TLS",
                    severity=Severity.MEDIUM,
                    description=f"Minimum TLS version is {mtls}.",
                    remediation="Set minimum TLS version to 1.2.",
                    mode="auth")
            net = getattr(acct, "network_rule_set", None)
            if net and net.default_action == "Allow":
                self.add_finding(
                    provider="azure", service="Storage", resource=acct.name,
                    check_id="AZ-STG-004",
                    title="Storage account network default-allow",
                    severity=Severity.MEDIUM,
                    description="Firewall default action allows all networks.",
                    remediation="Set default network action to Deny and whitelist.",
                    mode="auth")

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
                            self.add_finding(
                                provider="azure", service="NSG",
                                resource=nsg.name,
                                check_id="AZ-NSG-001",
                                title=f"NSG exposes {risky[hit]} to internet",
                                severity=Severity.CRITICAL,
                                description=f"Rule '{rule.name}' allows {pr} from any source.",
                                remediation=f"Restrict source for port {hit}.",
                                mode="auth")

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
                self.add_finding(
                    provider="azure", service="Storage", resource=acct,
                    check_id="AZ-STG-U01",
                    title="Public Azure storage enumeration exposed",
                    severity=Severity.CRITICAL,
                    description=f"Container listing exposed at {url}",
                    remediation="Disable anonymous access on the storage account.",
                    mode="unauth", metadata={"url": url})
            elif r.status_code in (400, 403, 409):
                self.add_finding(
                    provider="azure", service="Storage", resource=acct,
                    check_id="AZ-STG-U02",
                    title="Azure storage account exists",
                    severity=Severity.INFO,
                    description="Storage account name resolves (enumerable).",
                    remediation="Account name discoverable; ensure no anon access.",
                    mode="unauth", metadata={"url": url})

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(probe, [t.strip() for t in targets if t.strip()]))


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
            self.add_finding(
                provider="m365", service="AAD", resource="tenant",
                check_id="M365-001",
                title="Security Defaults disabled",
                severity=Severity.MEDIUM,
                description="Security Defaults are off. Ensure Conditional Access enforces MFA.",
                remediation="Enable Security Defaults or equivalent CA policies.",
                mode="auth")

    def _check_legacy_auth_policies(self):
        data = self._graph("/policies/authorizationPolicy")
        if data:
            if data.get("allowedToSignUpEmailBasedSubscriptions"):
                self.add_finding(
                    provider="m365", service="AAD", resource="tenant",
                    check_id="M365-002",
                    title="Self-service sign-up enabled",
                    severity=Severity.LOW,
                    description="Users can sign up for email-based subscriptions.",
                    remediation="Disable if not required.",
                    mode="auth")
            if data.get("defaultUserRolePermissions", {}).get(
                    "allowedToCreateApps"):
                self.add_finding(
                    provider="m365", service="AAD", resource="tenant",
                    check_id="M365-003",
                    title="Users can register applications",
                    severity=Severity.MEDIUM,
                    description="All users can create app registrations.",
                    remediation="Restrict app registration to admins.",
                    mode="auth")

    def _check_admin_mfa(self):
        roles = self._graph("/directoryRoles").get("value", [])
        for role in roles:
            if "admin" in (role.get("displayName") or "").lower():
                members = self._graph(
                    f"/directoryRoles/{role['id']}/members").get("value", [])
                if members:
                    self.add_finding(
                        provider="m365", service="AAD",
                        resource=role["displayName"],
                        check_id="M365-004",
                        title="Privileged role members present (verify MFA)",
                        severity=Severity.INFO,
                        description=(f"{len(members)} member(s) in "
                                     f"'{role['displayName']}'. Confirm all "
                                     "enforce phishing-resistant MFA."),
                        remediation="Enforce MFA/PIM for all privileged roles.",
                        mode="auth", metadata={"member_count": len(members)})

    def _check_user_consent(self):
        data = self._graph("/policies/authorizationPolicy")
        grant = data.get("defaultUserRolePermissions", {}) if data else {}
        if grant.get("allowedToCreateSecurityGroups"):
            self.add_finding(
                provider="m365", service="AAD", resource="tenant",
                check_id="M365-005",
                title="All users can create security groups",
                severity=Severity.LOW,
                description="Group sprawl / access-control risk.",
                remediation="Restrict group creation where possible.",
                mode="auth")

    def scan_unauthenticated(self, targets):
        """
        Unauthenticated M365 recon: tenant existence + domain federation info
        via public OpenID/realm endpoints. targets = list of domains.
        """
        import requests
        log("[M365] Tenant/domain recon...", "info")

        def probe(domain):
            cfg_url = (f"https://login.microsoftonline.com/{domain}/"
                       ".well-known/openid-configuration")
            try:
                r = requests.get(cfg_url, timeout=8)
            except requests.RequestException:
                return
            if r.status_code == 200:
                self.add_finding(
                    provider="m365", service="AAD", resource=domain,
                    check_id="M365-U01",
                    title="Microsoft 365 tenant exists for domain",
                    severity=Severity.INFO,
                    description=f"Domain {domain} is backed by an Entra ID tenant.",
                    remediation="Informational; ensure tenant hardening applied.",
                    mode="unauth", metadata={"openid_config": cfg_url})
            realm_url = (f"https://login.microsoftonline.com/getuserrealm.srf"
                         f"?login=user@{domain}&xml=1")
            try:
                r2 = requests.get(realm_url, timeout=8)
                if r2.ok and "Federated" in r2.text:
                    self.add_finding(
                        provider="m365", service="AAD", resource=domain,
                        check_id="M365-U02",
                        title="Domain uses federated authentication",
                        severity=Severity.INFO,
                        description="Federated (e.g. ADFS) auth detected; review IdP security.",
                        remediation="Ensure on-prem federation infra is hardened/patched.",
                        mode="unauth")
            except requests.RequestException:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(probe, [t.strip() for t in targets if t.strip()]))


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
        Set GCP_PROJECT_ID env var or rely on ADC default project.
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
                    self.add_finding(
                        provider="gcp", service="GCS", resource=bucket.name,
                        check_id="GCP-GCS-001",
                        title="GCS bucket publicly accessible",
                        severity=Severity.CRITICAL,
                        description=f"IAM binding '{binding['role']}' grants public access.",
                        remediation="Remove allUsers/allAuthenticatedUsers bindings.",
                        mode="auth", metadata={"role": binding["role"]})
            ubla = bucket.iam_configuration.uniform_bucket_level_access_enabled
            if not ubla:
                self.add_finding(
                    provider="gcp", service="GCS", resource=bucket.name,
                    check_id="GCP-GCS-002",
                    title="Uniform bucket-level access disabled",
                    severity=Severity.MEDIUM,
                    description="Legacy ACLs may grant unintended access.",
                    remediation="Enable uniform bucket-level access.",
                    mode="auth")

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
                    if not ports:
                        self.add_finding(
                            provider="gcp", service="VPC", resource=fw["name"],
                            check_id="GCP-FW-001",
                            title="Firewall allows all ports from internet",
                            severity=Severity.CRITICAL,
                            description=f"Rule '{fw['name']}' opens all ports to 0.0.0.0/0.",
                            remediation="Scope source ranges and ports.",
                            mode="auth")
                        continue
                    for pr in ports:
                        for p, svc in risky.items():
                            if self._port_match(pr, p):
                                self.add_finding(
                                    provider="gcp", service="VPC",
                                    resource=fw["name"],
                                    check_id="GCP-FW-002",
                                    title=f"Firewall exposes {svc} to internet",
                                    severity=Severity.CRITICAL,
                                    description=f"Rule '{fw['name']}' opens {p} to 0.0.0.0/0.",
                                    remediation=f"Restrict source range for port {p}.",
                                    mode="auth")
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
                self.add_finding(
                    provider="gcp", service="IAM", resource=sa["email"],
                    check_id="GCP-IAM-001",
                    title="User-managed service account key exists",
                    severity=Severity.MEDIUM,
                    description=(f"Key {k['name'].split('/')[-1]} is "
                                 "user-managed (rotation risk)."),
                    remediation="Prefer workload identity / short-lived creds; rotate keys.",
                    mode="auth")

    def scan_unauthenticated(self, targets):
        import requests
        log("[GCP] Probing public GCS buckets...", "info")

        def probe(bucket):
            url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o"
            try:
                r = requests.get(url, timeout=8)
            except requests.RequestException:
                return
            if r.status_code == 200:
                self.add_finding(
                    provider="gcp", service="GCS", resource=bucket,
                    check_id="GCP-GCS-U01",
                    title="Public GCS bucket listing exposed",
                    severity=Severity.CRITICAL,
                    description=f"Object listing publicly accessible at {url}",
                    remediation="Remove allUsers IAM bindings.",
                    mode="unauth", metadata={"url": url})
            elif r.status_code in (401, 403):
                self.add_finding(
                    provider="gcp", service="GCS", resource=bucket,
                    check_id="GCP-GCS-U02",
                    title="GCS bucket exists (access denied)",
                    severity=Severity.INFO,
                    description="Bucket exists but listing denied (enumerable).",
                    remediation="Bucket name discoverable; verify intended access.",
                    mode="unauth", metadata={"url": url})

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(probe, [t.strip() for t in targets if t.strip()]))


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
                    "Check", "Title", "Mode", "CIS"):
            table.add_column(col, overflow="fold")
        sev_color = {Severity.CRITICAL: "bold red", Severity.HIGH: "red",
                     Severity.MEDIUM: "yellow", Severity.LOW: "cyan",
                     Severity.INFO: "white"}
        for f in findings:
            table.add_row(
                f"[{sev_color[f.severity]}]{f.severity.value}[/]",
                f.provider, f.service, f.resource, f.check_id, f.title,
                f.mode, f.cis)
        console.print(table)
    else:
        for f in findings:
            print(f"[{f.severity.value}] {f.provider}/{f.service} "
                  f"{f.resource} - {f.title} ({f.check_id}) | {f.cis}")

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


def build_targets(args, provider):
    """Assemble the target list for a given provider, honoring
    --target (inline, repeatable), --targets (file), and --discover (domain).
    Returns provider-appropriate names (bucket/account names vs domains)."""
    targets = list(args.target)  # inline first
    if args.targets:
        try:
            with open(args.targets) as fh:
                targets += [line.strip() for line in fh if line.strip()]
        except OSError as e:
            log(f"Could not read targets file: {e}", "err")

    # Auto-discovery from a domain -> provider-specific candidate names
    if args.discover:
        disc = Discovery()
        if provider == "azure":
            generated = disc.azure_candidate_names(args.discover)
        elif provider == "m365":
            generated = disc.domains_for(args.discover)
        else:  # aws, gcp
            generated = disc.candidate_names(args.discover)
        log(f"[{provider}] Discovery generated {len(generated)} "
            f"candidate(s) from '{args.discover}'.", "info")
        targets += generated

    # de-duplicate preserving order
    return list(dict.fromkeys(t for t in targets if t))


def main():
    p = argparse.ArgumentParser(
        description="CloudScan v2 - Multi-Cloud Misconfiguration Scanner")
    p.add_argument("--provider", required=True,
                   choices=["aws", "azure", "m365", "gcp", "all"])
    p.add_argument("--mode", required=True, choices=["auth", "unauth", "both"])
    p.add_argument("--target", action="append", default=[],
                   help="Inline target (repeatable): bucket/account name or "
                        "domain. e.g. --target mybucket --target example.com")
    p.add_argument("--targets",
                   help="File with target names/domains (one per line)")
    p.add_argument("--discover", metavar="DOMAIN",
                   help="Derive likely resource names from a domain and probe "
                        "them (unauth mode). e.g. --discover example.com")
    p.add_argument("--output", help="Write JSON report to this file")
    args = p.parse_args()

    report = ScanReport(
        started_at=datetime.datetime.utcnow().isoformat() + "Z")

    providers = (list(SCANNERS) if args.provider == "all"
                 else [args.provider])

    for prov in providers:
        scanner = SCANNERS[prov](report)
        if args.mode in ("auth", "both"):
            scanner.scan_authenticated()
        if args.mode in ("unauth", "both"):
            targets = build_targets(args, prov)
            if not targets:
                log(f"[{prov}] unauth mode needs --target/--targets/--discover; "
                    "skipping.", "warn")
            else:
                scanner.scan_unauthenticated(targets)

    report.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
    print_report(report)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                json.dump(report.to_dict(), fh, indent=2)
            log(f"\nJSON report written to {args.output}", "ok")
        except OSError as e:
            log(f"Could not write output file: {e}", "err")


if __name__ == "__main__":
    main()
