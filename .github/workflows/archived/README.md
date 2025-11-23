# Archived Workflow Files

**Date Archived:** November 23, 2025  
**Reason:** Consolidated into single parameterized workflow

## What Happened?

These 35+ individual `ingest-*.yml` workflow files were **consolidated into a single workflow**: 
- **New Workflow:** `../ ingest-threat-feeds.yml`

## Why?

### Problems with Old Approach
- ❌ **35 nearly identical files** - maintenance nightmare
- ❌ **Duplicate code** - same git clone logic repeated everywhere
- ❌ **Hard to update** - need to edit 35 files for single change
- ❌ **No orchestration** - couldn't run "all feeds" easily
- ❌ **Resource waste** - each workflow had separate trigger

### Benefits of New Approach
- ✅ **Single source of truth** - one workflow with matrix strategy
- ✅ **Parameterized** - select specific feed or run all
- ✅ **DRY principle** - shared steps, feed-specific config
- ✅ **Better monitoring** - unified reporting and artifacts
- ✅ **Scheduled automation** - daily ingestion for critical feeds

## Migration Guide

### Old Usage
```yaml
# Had to manually dispatch each workflow
- ingest-threat-actor-iocs.yml
- ingest-sigma-rules.yml
- ingest-vulnerability-feeds.yml
... (32 more files)
```

### New Usage

**Option 1: Ingest specific feed**
```bash
# Via GitHub Actions UI
Actions → Ingest Threat Intelligence Data → Run workflow
Select feed_type: "sigma-rules"
```

**Option 2: Ingest all feeds**
```bash
# Via GitHub Actions UI
Actions → Ingest Threat Intelligence Data → Run workflow
Select feed_type: "all"
```

**Option 3: Automated daily ingestion**
```yaml
# Already configured in workflow
schedule:
  - cron: '0 2 * * *'  # 2 AM UTC daily
```

## Feed Types Supported

The new workflow supports all previous feeds via dropdown selection:

- `threat-actor-iocs` - APT notes and threat intelligence
- `sigma-rules` - SIEM detection rules
- `vulnerability-feeds` - CVE and NVD data
- `phishing-domains` - OpenPhish feed
- `tor-exit-nodes` - Tor network nodes
- `cloud-ip-ranges` - AWS/Azure/GCP IP ranges
- `osquery-packs` - Endpoint detection packs
- `mobile-threats` - Mobile malware signatures
- `cloud-misconfigurations` - CSPM rules
- `sandbox-reports` - Malware analysis reports
- (and 12 more...)

## Restoring Old Workflows

If you absolutely need the old workflows (not recommended):

```bash
cd .github/workflows
mv archived/ingest-*.yml ./
```

## Adding New Feeds

Edit `.github/workflows/ingest-threat-feeds.yml`:

1. Add feed name to `inputs.feed_type.options`
2. Add case block in "Configure feed parameters" step:
   ```yaml
   "new-feed-name")
     echo "data_dir=datalake/raw/new-category" >> $GITHUB_OUTPUT
     echo "source_url=https://example.com/feed.json" >> $GITHUB_OUTPUT
     echo "source_type=url" >> $GITHUB_OUTPUT
     ;;
   ```

## Questions?

See: `docs/WORKFLOWS_CONSOLIDATION.md` (if created)  
Or: Open an issue with label `workflow/ingestion`

---

**Archived by:** GitHub Copilot  
**Consolidation PR:** (link to PR when merged)
