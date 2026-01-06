CV Anonymiser – Developer Guide

Overview


This repository contains the CV Anonymiser application, a serverless, cloud-native system designed to reduce bias in hiring by removing personally identifiable information (PII) from CVs prior to recruiter review.


The system is built using FastAPI, AWS serverless services, and a GitOps-driven DevSecOps pipeline. All application logic, infrastructure definitions, and security controls are version-controlled and deployed automatically via GitHub Actions.


Key design principles:

No raw CV data is ever persisted
All deployments are automated, auditable, and reproducible
Security and testing are enforced at every stage of the pipeline


Architecture Summary


Frontend: Static web app served via Amazon S3 and CloudFront
API: Amazon API Gateway (REST)
Compute: AWS Lambda (FastAPI + Mangum)
Configuration: AWS SSM Parameter Store (encrypted)
Audit Trail: Amazon DynamoDB (salted hashes only)
Observability: CloudWatch logs, metrics, dashboards, and alarms
Infrastructure: AWS CDK (Infrastructure as Code)
CI/CD: GitHub Actions using OIDC (no long-lived credentials)



Repository Structure



.

├── frontend/               # Static frontend (HTML/CSS/JS)

├── lambda/                 # Lambda application (FastAPI)

│   ├── app.py

│   └── requirements.txt

├── tests/

│   └── api-regression.mjs  # Post-deploy API regression tests

├── .github/

│   └── workflows/

│       ├── ci.yml          # Linting, testing, security, SBOM

│       ├── deploy.yml      # CDK deploy + post-deploy checks

│       └── codeql.yml      # Semantic security analysis

├── cv_anonymiser_stack.py  # AWS CDK stack definition

├── requirements.txt        # CDK / application dependencies

└── README.md




Development Workflow (Mandatory)



This project follows a trunk-based GitOps workflow.





1. Branching Strategy





main is the only production branch
All work must be done on short-lived feature branches
Direct commits to main are not allowed






2. Pull Requests





All changes must be introduced via a Pull Request:



A PR template enforces:
Clear description of changes
Security and privacy considerations
Testing confirmation

At least one reviewer approval is required






3. Required Checks (Enforced)





A PR cannot be merged unless all checks pass:



Ruff linting
Unit tests
SAST (Bandit)
Dependency vulnerability scan (pip-audit)
CodeQL security analysis
SBOM generation




CI Pipeline (Pre-Merge)





Triggered on every Pull Request.



Stages:



Dependency installation
Ruff linting (fast static analysis)
SAST (Bandit)
Dependency vulnerability scanning (pip-audit)
Unit tests
SBOM generation (CycloneDX)
Artifact upload (SBOM)




If any stage fails, the PR is blocked.









CD Pipeline (Post-Merge)





Triggered automatically on merge to main.



Deployment steps:



CDK synth (infrastructure validation)
CDK bootstrap (idempotent environment setup)
CDK deploy (CloudFormation transactional deployment)
Automatic rollback on failure




Authentication uses OIDC-based role assumption, eliminating stored credentials.









Post-Deployment Validation





After deployment completes, the pipeline runs post-deploy assurance checks:



CloudFront availability check
Cypress end-to-end smoke tests
API regression tests against live endpoints
SNS alert sent on failure




These checks ensure that:



The UI loads correctly
Core anonymisation functionality works
API contracts remain stable










Anonymisation Logic





Redaction rules are loaded at runtime from AWS SSM Parameter Store
Rules are not hard-coded
Supported redactions (MVP):
Email addresses
Phone numbers

CV content is processed entirely in memory
Only a salted, non-reversible hash and metadata are written to DynamoDB




⚠️ Never log raw CV content

⚠️ Never store PII in persistent storage









Security & Compliance Expectations





All developers must adhere to the following:



Follow least-privilege IAM principles
Do not introduce secrets into Git
Use Parameter Store or IAM-provided credentials
Ensure logs remain free of PII
Treat anonymisation rule changes as high-risk
Expect peer review scrutiny for security-sensitive changes




This system is designed to support GDPR compliance by construction.









Observability & Incident Response





When an issue occurs:



CloudWatch alarms notify stakeholders via email
Metrics dashboards are used to correlate impact
Lambda logs are inspected for execution errors
Deployment history is checked for recent changes
A Jira ticket is raised with supporting evidence










Rollback Procedure





If an issue reaches production:



Revert the offending commit in Git
GitHub Actions redeploys the last known good state
CloudFormation ensures a clean, consistent rollback




No manual AWS intervention is required.


Future Enhancements

Planned improvements include:

Canary deployments using Lambda aliases
Bias testing datasets
Carbon-aware metrics (GreenOps)
Expanded anonymisation rules
Pre-commit hooks for faster feedback



Contribution Guidelines

By contributing to this repository, you agree to:

Follow the defined workflow
Respect privacy-first design principles
Write clear, atomic commits
Treat security as a shared responsibility




DEMO CODE FIX EXAMPLE 123







