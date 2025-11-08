# Wildbox Data Ingestion Workflows

## Overview

This directory contains the GitHub Actions workflows responsible for populating the Wildbox Datalake. These workflows are designed to be run manually (workflow_dispatch) to gather fresh, open-source security intelligence on demand. They form the foundation of Wildbox's threat intelligence and analysis capabilities.

The master workflow, ingest-all-data.yml, can be used to trigger all other ingestion workflows sequentially.

## Workflow Catalog

The following table provides a summary of all available data ingestion workflows, their purpose, and the destination of the collected data.

| Workflow File | Description | Datalake Path |
|---|---|---|
| ingest-cti-feeds.yml| Ingests Cyber Threat Intelligence feeds (IPs, domains, hashes) from sources like abuse.ch and Feodo Tracker. |datalake/raw/cti/ |
| ingest-vulnerability-feeds.yml| Ingests vulnerability databases from NVD, EPSS, and the CISA Known Exploited Vulnerabilities catalog. |datalake/raw/vulnerabilities/ |
| ingest-compliance-benchmarks.yml| Ingests compliance benchmarks and security guidelines from sources like CIS and OpenControl. |datalake/raw/compliance/ |
| ingest-osint-software-feeds.yml| Gathers OSINT data on popular open-source software from GitHub, npm, and pip. |datalake/raw/osint/software/ |
| ingest-attack-ttps.yml| Ingests the MITRE ATT&CK framework data (Tactics, Techniques, and Procedures). |datalake/raw/ttps/mitre/ |
| ingest-cloud-ip-ranges.yml| Ingests the official IP ranges for major cloud providers (AWS, Azure, GCP). |datalake/raw/cloud/ip-ranges/ |
| ingest-security-news.yml| Ingests RSS feeds from curated, high-quality security news websites and blogs. |datalake/raw/osint/news/ |
| ingest-gitleaks-rules.yml| Ingests rule packs for thegitleakstool for secret scanning. |datalake/raw/signatures/secret-detection/ |
| ingest-public-storage.yml| Ingests lists of known publicly exposed S3 buckets and other cloud storage. |datalake/raw/cloud/public-storage/ |
| ingest-sandbox-reports.yml| Ingests public reports from malware sandboxing services. |datalake/raw/malware/sandbox-reports/ |
| ingest-yara-rules.yml| Ingests YARA rules from various open-source repositories for malware hunting. |datalake/raw/signatures/yara/ |
| ingest-sigma-rules.yml| Ingests SIGMA rules for generic log-based threat detection. |datalake/raw/signatures/sigma/ |
| ingest-osquery-packs.yml| Ingests OSQuery packs for advanced endpoint threat detection. |datalake/raw/endpoint/osquery-packs/ |
| ingest-threat-actor-iocs.yml| Ingests Indicator of Compromise (IoC) sets related to specific APTs and threat actors. |datalake/raw/threat-actors/ |
| ingest-ja3-hashes.yml| Ingests lists of JA3/JA3S hashes associated with malicious clients. |datalake/raw/network/ja3/ |
| ingest-tor-exit-nodes.yml| Ingests the latest list of TOR network exit nodes. |datalake/raw/network/tor-nodes.txt |
| ingest-public-proxies.yml| Ingests lists of public HTTP/SOCKS proxies and VPNs. |datalake/raw/network/proxies/ |
| ingest-scanner-ips.yml| Ingests lists of known internet scanners from sources like GreyNoise and Shodan. |datalake/raw/network/scanners/ |
| ingest-phishing-domains.yml| Ingests feeds of newly registered phishing and typosquatting domains. |datalake/raw/phishing/ |
| ingest-saas-ip-ranges.yml| Ingests official IP ranges for popular SaaS platforms (e.g., Office 365, GitHub). |datalake/raw/cloud/saas-ips/ |
| ingest-cloud-security-policies.yml| Ingests "Policy as Code" examples from frameworks like OPA and Sentinel. |datalake/raw/compliance/policies-as-code/ |
| ingest-leaked-cred-patterns.yml| Ingests regex patterns for detecting leaked credentials in code. |datalake/raw/signatures/secret-detection/ |
| ingest-exposed-k8s-apis.yml| Uses Shodan to discover publicly exposed Kubernetes API servers. |datalake/raw/cloud/exposed-k8s.json |
| ingest-cloud-misconfigurations.yml| Ingests databases of common cloud misconfigurations and CWEs. |datalake/raw/compliance/cloud-cwe/ |
| ingest-leaked-passwords.yml| Ingests dumps of password hashes from known data breaches for proactive checks. |datalake/raw/credentials/leaked-passwords.txt |
| ingest-social-media-threats.yml| Monitors security-focused social media channels for emerging IoCs. |datalake/raw/osint/social-media/ |
| ingest-dark-web-trends.yml| Ingests public reports on dark web market trends. |datalake/raw/osint/dark-web-reports/ |
| ingest-pastebin-leaks.yml| Scans Pastebin and similar sites for data leaks matching specific keywords. |datalake/raw/osint/pastebin/ |
| ingest-security-blogs.yml| Aggregates RSS feeds from top security researchers. |datalake/raw/osint/blogs/ |
| ingest-domain-history.yml| Retrieves historical WHOIS and DNS data for suspicious domains. |datalake/raw/osint/domain-history/ |
| ingest-cert-transparency.yml| Monitors Certificate Transparency logs for suspicious subdomains and certificates. |datalake/raw/osint/cert-transparency/ |
| ingest-mobile-threats.yml| Ingests feeds related to mobile application vulnerabilities and malware. |datalake/raw/mobile-threats/ |
| ingest-ics-scada-intel.yml| Ingests intelligence on vulnerabilities in Industrial Control Systems. |datalake/raw/ics-scada/ |
| ingest-crypto-threats.yml| Ingests IoCs related to cryptojacking and cryptocurrency scams. |datalake/raw/crypto-threats/ |
| **ingest-all-data.yml** | **Orchestrator workflow to trigger all other ingestion pipelines.** | **N/A** |

## Usage

To run a workflow:
1. Navigate to the "Actions" tab of the Wildbox repository on GitHub.
2. Select the desired workflow from the list on the left.
3. Click the "Run workflow" dropdown button.
4. Click the "Run workflow" button to start the pipeline.

The workflow will execute and the collected data will be committed to the datalake/raw/ directory.

## Contribution

Contributions to this data ingestion framework are welcome. To add a new data source, please create a new workflow YAML file following the existing structure and submit a pull request. Ensure that the source is public, reliable, and provides data in a structured or semi-structured format.
