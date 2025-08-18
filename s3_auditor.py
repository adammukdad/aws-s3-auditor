#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from typing import List, Tuple, Dict, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


def make_session(profile: Optional[str], region: Optional[str], role_arn: Optional[str]):
    """
    Create a boto3 Session, optionally from a profile and/or by assuming a role.
    """
    try:
        base_sess = boto3.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as e:
        print(f"[ERROR] AWS profile not found: {e}", file=sys.stderr)
        sys.exit(2)

    if not role_arn:
        return base_sess

    sts = base_sess.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="s3-auditor-session"
        )
    except ClientError as e:
        print(f"[ERROR] Failed to assume role {role_arn}: {e}", file=sys.stderr)
        sys.exit(2)

    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def paginate_objects(s3_client, bucket_name: str) -> Tuple[int, float]:
    """
    Paginate through objects in a bucket and return (count, total_size_mb).
    Handles no objects, access denied, and large buckets.
    """
    paginator = s3_client.get_paginator("list_objects_v2")
    total_size_bytes = 0
    object_count = 0

    try:
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                object_count += 1
                total_size_bytes += obj.get("Size", 0)
    except ClientError as e:
        # Access denied or the bucket is in a different region: handle gracefully
        print(f"[WARN] Error listing objects for {bucket_name}: {e}", file=sys.stderr)
        return -1, -1.0

    total_size_mb = round(total_size_bytes / (1024 * 1024), 2)
    return object_count, total_size_mb


def check_bucket_public_access(s3_client, s3control_client, account_id: str, bucket_name: str) -> str:
    """
    Determine if a bucket is public using:
      1) ACL grants
      2) Bucket policy status (IsPublic)
      3) Public Access Block at bucket and (fallback) account level
    Returns one of: "Public (WARNING)", "Restricted by Block", "Private", or "Unknown"
    """
    is_public_acl = False
    is_public_policy = False
    bucket_block_applied = None
    account_block_applied = None

    # 1) ACL inspection
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") in (
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ):
                is_public_acl = True
                break
    except ClientError as e:
        # Some principals can't read ACL; don't fail the whole audit
        print(f"[INFO] ACL not readable for {bucket_name}: {e}", file=sys.stderr)

    # 2) Bucket policy status
    try:
        pol_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        is_public_policy = pol_status.get("PolicyStatus", {}).get("IsPublic", False)
    except ClientError:
        # No policy or no permission to read policy is fine
        pass

    # 3) Public access block (bucket)
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = pab.get("PublicAccessBlockConfiguration", {})
        bucket_block_applied = any([
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ])
    except ClientError:
        bucket_block_applied = False

    # 3b) Public access block (account) — fallback signal
    try:
        acct_pab = s3control_client.get_public_access_block(AccountId=account_id)
        cfg = acct_pab.get("PublicAccessBlockConfiguration", {})
        account_block_applied = any([
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ])
    except ClientError:
        account_block_applied = None

    if is_public_acl or is_public_policy:
        if bucket_block_applied:
            return "Restricted by Block"
        return "Public (WARNING)"

    if bucket_block_applied or account_block_applied:
        return "Restricted by Block"

    if (is_public_acl is False) and (is_public_policy is False):
        return "Private"

    return "Unknown"


def get_bucket_region(s3_client, bucket_name: str) -> str:
    """
    Return the bucket's region; needed because some calls require the correct region endpoint.
    """
    try:
        resp = s3_client.get_bucket_location(Bucket=bucket_name)
        loc = resp.get("LocationConstraint")
        # None means us-east-1
        return loc or "us-east-1"
    except ClientError as e:
        print(f"[INFO] Could not determine region for {bucket_name}: {e}", file=sys.stderr)
        return "us-east-1"


def audit_bucket(sess: boto3.Session, account_id: str, bucket_name: str) -> Dict:
    """
    Audit a single bucket: region, public access, object count, total size MB, versioning, encryption.
    """
    # Use region-specific client for accurate object listing
    global_s3 = sess.client("s3")
    region = get_bucket_region(global_s3, bucket_name)
    s3 = sess.client("s3", region_name=region)
    s3control = sess.client("s3control", region_name=region)

    public_access = check_bucket_public_access(s3, s3control, account_id, bucket_name)
    obj_count, total_mb = paginate_objects(s3, bucket_name)

    # Optional controls: versioning and default encryption
    versioning = "Unknown"
    try:
        v = s3.get_bucket_versioning(Bucket=bucket_name)
        status = v.get("Status")
        versioning = status if status else "Disabled"
    except ClientError:
        pass

    encryption = "Unknown"
    try:
        e = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = e.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
            algo = sse.get("SSEAlgorithm", "Enabled")
            encryption = f"Enabled ({algo})"
        else:
            encryption = "Disabled"
    except ClientError as e:
        # If there is no encryption config, AWS returns a specific error
        msg = str(e)
        if "ServerSideEncryptionConfigurationNotFoundError" in msg:
            encryption = "Disabled"
        else:
            encryption = "Unknown"

    return {
        "BucketName": bucket_name,
        "Region": region,
        "PublicAccess": public_access,
        "ObjectCount": obj_count,
        "TotalSizeMB": total_mb,
        "Versioning": versioning,
        "DefaultEncryption": encryption,
    }


def list_buckets(sess: boto3.Session) -> List[str]:
    try:
        s3 = sess.client("s3")
        resp = s3.list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]
    except NoCredentialsError:
        print("[ERROR] No AWS credentials found. Configure a profile or env vars.", file=sys.stderr)
        sys.exit(2)
    except ClientError as e:
        print(f"[ERROR] Could not list buckets: {e}", file=sys.stderr)
        sys.exit(2)


def write_csv(path: str, rows: List[Dict]):
    headers = [
        "BucketName", "Region", "PublicAccess",
        "ObjectCount", "TotalSizeMB",
        "Versioning", "DefaultEncryption",
    ]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(path: str, rows: List[Dict]):
    with open(path, "w") as f:
        json.dump(rows, f, indent=2)


def get_account_id(sess: boto3.Session) -> str:
    sts = sess.client("sts")
    return sts.get_caller_identity()["Account"]


def parse_args():
    p = argparse.ArgumentParser(
        description="Audit S3 buckets for public access, size, and security posture."
    )
    p.add_argument("--profile", help="AWS profile name (e.g., default)")
    p.add_argument("--region", help="Default AWS region (used for STS and global calls)")
    p.add_argument("--assume-role", help="Role ARN to assume for the audit (optional)")
    p.add_argument("--buckets", nargs="*", help="Specific bucket names to audit (default: all in account)")
    p.add_argument("--out-csv", default="s3_audit_report.csv", help="CSV output path")
    p.add_argument("--out-json", default=None, help="Optional JSON output path")
    p.add_argument("--quiet", action="store_true", help="Reduce console output")
    return p.parse_args()


def main():
    args = parse_args()
    sess = make_session(args.profile, args.region, args.assume_role)
    account_id = get_account_id(sess)

    targets = args.buckets or list_buckets(sess)
    if not targets:
        print("[INFO] No buckets found.", file=sys.stderr)
        return

    results = []
    for name in targets:
        rec = audit_bucket(sess, account_id, name)
        results.append(rec)
        if not args.quiet:
            print(f"- {rec['BucketName']} | {rec['Region']} | {rec['PublicAccess']} | "
                  f"{rec['ObjectCount']} objs | {rec['TotalSizeMB']} MB | "
                  f"Versioning: {rec['Versioning']} | Encryption: {rec['DefaultEncryption']}")

    write_csv(args.out_csv, results)
    if args.out_json:
        write_json(args.out_json, results)

    if not args.quiet:
        print(f"\n✅ Audit complete. CSV: {args.out_csv}" + (f" | JSON: {args.out_json}" if args.out_json else ""))


if __name__ == "__main__":
    main()
