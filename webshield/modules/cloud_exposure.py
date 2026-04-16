"""
Cloud Exposure Module
Checks for exposed cloud storage buckets, misconfigurations, and leaked cloud metadata.
Learned from: GSEC (cloud_security.py — most comprehensive cloud scanner found)
NEW in v1.1.0
"""

from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Patterns to identify S3-like open bucket responses
S3_OPEN_INDICATORS = [
    r"<ListBucketResult",
    r"<Contents>",
    r"<Key>",
    r"AmazonS3",
]

GCS_OPEN_INDICATORS = [
    r'"kind":\s*"storage#objects"',
    r'"items":\s*\[',
]

AZURE_OPEN_INDICATORS = [
    r"<EnumerationResults",
    r"<Blobs>",
    r"<BlobPrefix>",
]


def _extract_bucket_names(hostname: str, body: str) -> List[str]:
    """Guess bucket names from hostname and page content."""
    names = set()
    # From hostname: company.com -> company, www.company.com -> company
    parts = hostname.split(".")
    if len(parts) >= 2:
        names.add(parts[-2])          # example
        if parts[0] != "www":
            names.add(parts[0])       # subdomain
    # From page body
    for match in re.findall(r'[a-z0-9][a-z0-9\-]{2,62}[a-z0-9]', body[:2000]):
        if 4 <= len(match) <= 40:
            names.add(match)
    return list(names)[:8]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    with get_client(timeout=min(timeout, 8.0)) as client:
        # ── 1. Check if site IS an S3/GCS/Azure static site ──────────
        try:
            resp = client.get(url)
            headers_str = str(dict(resp.headers)).lower()
            body = resp.text

            # S3 hosting detected
            if "x-amz-request-id" in headers_str or "x-amz-id-2" in headers_str:
                findings.append(Finding(
                    title="Site Hosted on AWS S3",
                    severity=Severity.INFO,
                    description="This site is hosted on AWS S3. Ensure the bucket ACL is not set to public-read-write.",
                    evidence=f"x-amz-request-id header detected",
                    remediation="Verify bucket policy blocks public write access.",
                    code_fix=(
                        "# AWS CLI — block all public access:\n"
                        "aws s3api put-public-access-block \\\n"
                        "  --bucket YOUR_BUCKET \\\n"
                        "  --public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                ))

                # Check if bucket listing is enabled
                if any(re.search(p, body) for p in S3_OPEN_INDICATORS):
                    findings.append(Finding(
                        title="AWS S3 Bucket Listing Enabled",
                        severity=Severity.HIGH,
                        description=(
                            "The S3 bucket has directory listing enabled. Attackers can "
                            "enumerate all stored files, potentially finding sensitive data, "
                            "backups, credentials, or private user files."
                        ),
                        evidence=f"S3 bucket listing XML found in response",
                        remediation="Disable bucket listing and restrict bucket ACL.",
                        code_fix=(
                            "# Remove public-read ACL:\n"
                            "aws s3api put-bucket-acl --bucket YOUR_BUCKET --acl private\n\n"
                            "# Block all public access:\n"
                            "aws s3api put-public-access-block --bucket YOUR_BUCKET \\\n"
                            "  --public-access-block-configuration BlockPublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
                        cvss=7.5,
                    ))

            # GCS hosting detected
            if "x-guploader-uploadid" in headers_str or "storage.googleapis.com" in headers_str:
                findings.append(Finding(
                    title="Site Hosted on Google Cloud Storage",
                    severity=Severity.INFO,
                    description="This site is hosted on Google Cloud Storage.",
                    evidence="x-guploader-uploadid header detected",
                    remediation="Ensure bucket IAM policy prevents allUsers from writing.",
                    reference="https://cloud.google.com/storage/docs/access-control",
                ))

            # Azure Blob hosting
            if "x-ms-request-id" in headers_str or "blob.core.windows.net" in hostname:
                findings.append(Finding(
                    title="Site Hosted on Azure Blob Storage",
                    severity=Severity.INFO,
                    description="This site is hosted on Azure Blob Storage.",
                    evidence="x-ms-request-id header detected",
                    remediation="Ensure container access level is set to Private.",
                    code_fix=(
                        "# Azure CLI — set container to private:\n"
                        "az storage container set-permission \\\n"
                        "  --name CONTAINER --public-access off"
                    ),
                    reference="https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure",
                ))
        except Exception:
            pass

        # ── 2. Probe guessed bucket names ────────────────────────────
        try:
            resp_main = client.get(url)
            bucket_names = _extract_bucket_names(hostname, resp_main.text)
        except Exception:
            bucket_names = [hostname.split(".")[0]] if hostname else []

        for name in bucket_names[:4]:
            # AWS S3 bucket probe
            s3_url = f"https://{name}.s3.amazonaws.com/"
            try:
                resp = client.get(s3_url)
                if resp.status_code == 200 and any(
                    re.search(p, resp.text) for p in S3_OPEN_INDICATORS
                ):
                    findings.append(Finding(
                        title=f"Public AWS S3 Bucket Found: {name}",
                        severity=Severity.HIGH,
                        description=(
                            f"The AWS S3 bucket '{name}' is publicly accessible and "
                            "has directory listing enabled. All stored objects are enumerable."
                        ),
                        evidence=f"URL: {s3_url}\nHTTP 200 with S3 listing XML",
                        remediation="Set bucket ACL to private and enable block public access.",
                        code_fix=(
                            f"aws s3api put-public-access-block --bucket {name} \\\n"
                            "  --public-access-block-configuration "
                            "BlockPublicAcls=true,BlockPublicPolicy=true,"
                            "IgnorePublicAcls=true,RestrictPublicBuckets=true"
                        ),
                        reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                        cvss=7.5,
                    ))
            except Exception:
                pass

        # ── 3. Docker/K8s exposed endpoints ──────────────────────────
        dangerous_endpoints = [
            ("/metrics",          "Prometheus Metrics Exposed",        Severity.MEDIUM,
             "Prometheus metrics endpoint exposes internal application metrics, "
             "service topology, and sometimes sensitive operational data."),
            ("/_cat/indices",     "Elasticsearch Index List Exposed",  Severity.HIGH,
             "Elasticsearch /_cat/indices is accessible without authentication. "
             "Attackers can enumerate all indices and potentially read all data."),
            ("/v2/_catalog",      "Docker Registry Catalog Exposed",   Severity.HIGH,
             "Docker registry catalog is publicly accessible. "
             "Exposes all container image names and versions."),
            ("/api/v1/namespaces","Kubernetes API Exposed",            Severity.CRITICAL,
             "Kubernetes API server is accessible. Attackers can enumerate "
             "namespaces, pods, secrets, and potentially take over the cluster."),
        ]
        base = url.rstrip("/")
        for (path, title, severity, description) in dangerous_endpoints:
            try:
                resp = client.get(base + path)
                if resp.status_code in (200, 401) and len(resp.text.strip()) > 20:
                    if resp.status_code == 200:
                        findings.append(Finding(
                            title=title,
                            severity=severity,
                            description=description,
                            evidence=f"HTTP 200 at {base+path} ({len(resp.content)} bytes)",
                            remediation="Restrict access to this endpoint to internal networks only.",
                            code_fix=(
                                "# Nginx — restrict to internal IP:\n"
                                f"location {path} {{\n"
                                "    allow 10.0.0.0/8;\n"
                                "    deny all;\n}}"
                            ),
                            reference="https://owasp.org/www-project-web-security-testing-guide/",
                            cvss=9.8 if severity == Severity.CRITICAL else 7.5,
                        ))
            except Exception:
                continue

    return findings
