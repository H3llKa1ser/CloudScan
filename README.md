# CloudScan

Multi-Cloud Security Misconfiguration Scanner

### 1) Installation

    pip install boto3 azure-identity azure-mgmt-storage azure-mgmt-network \
                azure-mgmt-resource google-cloud-storage google-api-python-client \
                requests rich

### 2) Authenticated AWS scan

    python cloudscan.py --provider aws --mode auth --output report.json

### 3) Unauthenticated bucket probing

    python cloudscan.py --provider aws --mode unauth --targets buckets.txt

### 4) Everything

    python cloudscan.py --provider all --mode both --targets targets.txt
