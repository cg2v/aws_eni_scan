# AWS Organization ENI Scanner

Scan all ACTIVE accounts in an AWS Organization for network interfaces by public IP, ENI Name tag, or description.

This tool does not use AWS Resource Explorer.

## What it does

1. Lists ACTIVE accounts using Organizations in the management account.
2. Uses source credentials directly when the target account is the same as the caller account; otherwise assumes a role in each target account (default role name: `OrganizationAccountAccessRole`).
3. Discovers each account's enabled regions (or uses explicit region list).
4. Searches ENIs in each region via `DescribeNetworkInterfaces`.
5. Optionally searches Elastic IPs in each region via `DescribeAddresses`.
6. Writes a JSON report with matches, scan coverage, and errors.

## Requirements

- Python 3.10+
- Management account credentials available in your shell (environment variables, shared credentials file, or profile)
- Permissions in management account principal:
  - `organizations:ListAccounts`
  - `organizations:ListAccountsForParent` (needed when using `--include-ou`)
  - `organizations:ListOrganizationalUnitsForParent` (needed when using `--include-ou`)
  - `sts:AssumeRole` on member account role ARNs
- Permissions on assumed member role:
  - `ec2:DescribeRegions`
  - `ec2:DescribeNetworkInterfaces`
  - `ec2:DescribeAddresses` (needed when using `--include-elastic-ip`)

## Install

```bash
python -m pip install -r requirements.txt
```

## Usage

Exactly one query mode is required:

- `--public-ip`
- `--eni-name`
- `--description`

### 1) Search by public IP

```bash
python scan_enis.py \
  --public-ip 203.0.113.10 \
  --include-elastic-ip \
  --role-name OrganizationAccountAccessRole \
  --output-file reports/eni_public_ip.json
```

### 2) Search by ENI Name tag

```bash
python scan_enis.py \
  --eni-name my-eni-name \
  --match-mode exact \
  --role-name OrganizationAccountAccessRole \
  --output-file reports/eni_name.json
```

### 3) Search by description

```bash
python scan_enis.py \
  --description "Interface for NAT Gateway" \
  --match-mode contains \
  --role-name OrganizationAccountAccessRole \
  --output-file reports/eni_desc.json
```

### 4) Scope scan to OU subtree and include EIPs

```bash
python scan_enis.py \
  --public-ip 203.0.113.10 \
  --include-ou ou-abcd-12345678,ou-abcd-87654321 \
  --include-elastic-ip \
  --role-name OrganizationAccountAccessRole \
  --output-file reports/eni_ou_scope.json
```

## Useful options

- `--include-accounts 111111111111,222222222222`
- `--exclude-accounts 333333333333`
- `--include-ou ou-abcd-12345678,ou-abcd-87654321`
- `--regions all-enabled` (default)
- `--regions us-east-1,us-west-2`
- `--exclude-regions us-east-2`
- `--include-elastic-ip`
- `--account-concurrency 8`
- `--region-concurrency 5`
- `--max-retries 4`
- `--request-timeout-seconds 20`
- `--external-id your-external-id`
- `--verbose`
- `--fail-on-partial`

## Exit codes

- `0`: Success (all targeted account-regions scanned, no errors)
- `2`: Partial success (some account/region failures, results still produced)
- `1`: Fatal run failure (for example no regions scanned or startup failure)

## Notes and edge cases

- ENI "name" is the `Name` tag, not a native ENI field.
- Public IP results are point-in-time and can change quickly due to reassociation.
- Elastic IP matches include both associated and unassociated addresses when `--include-elastic-ip` is enabled.
- SCPs/permission boundaries can block calls even if the role appears admin.
- If regions are explicitly supplied and disabled in an account, region errors are captured in report.

## Output schema (high level)

- `query`: mode/value/match mode/timestamps
- `coverage`: targeted and scanned account-region counters
- `matches`: matched ENI details per account/region
- `elastic_ip_matches`: matched EIP details per account/region
- `errors`: structured account/region error records
- `status`: `success`, `partial_success`, or `failed`
