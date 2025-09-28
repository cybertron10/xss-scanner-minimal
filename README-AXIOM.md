# XSS Scanner Axiom Module

This module provides distributed XSS vulnerability scanning using Axiom fleet instances. It automatically splits domain lists across multiple instances and merges results.

## Features

- **Distributed Scanning**: Automatically splits domains across multiple Axiom instances
- **Domain Crawling**: Crawls each domain to discover all URLs before scanning
- **Concurrent Processing**: Configurable concurrency per instance
- **Result Merging**: Automatically merges results from all instances
- **Fleet Management**: Handles fleet creation, deployment, and cleanup

## Quick Start

### 1. Prepare Domain List

Create a file with domains to scan (one per line):

```bash
echo "example.com" > domains.txt
echo "test.com" >> domains.txt
echo "target.org" >> domains.txt
```

### 2. Run Axiom Scan

```bash
# Basic usage with 3 fleet instances
./axiom-scan.sh domains.txt

# Custom fleet size and concurrency
./axiom-scan.sh domains.txt -f 5 -c 5

# Custom output directory
./axiom-scan.sh domains.txt -o my-results
```

### 3. Review Results

Results are automatically merged into `merged_results_TIMESTAMP.json` in the output directory.

## Usage

```bash
./axiom-scan.sh <domains_file> [options]

Arguments:
  domains_file    File containing domains to scan (one per line)

Options:
  -f, --fleet-size SIZE    Number of fleet instances (default: 3)
  -c, --concurrency NUM    Concurrency per instance (default: 3)
  -o, --output DIR         Output directory (default: xss-scan-results)
  -h, --help              Show this help message
```

## Examples

### Basic Scan
```bash
./axiom-scan.sh domains.txt
```

### Large Scale Scan
```bash
./axiom-scan.sh large_domains.txt -f 10 -c 5 -o large-scan-results
```

### High Concurrency Scan
```bash
./axiom-scan.sh domains.txt -f 3 -c 8
```

## How It Works

1. **Domain Splitting**: The script splits your domain list evenly across fleet instances
2. **Fleet Deployment**: Creates Axiom instances and deploys the XSS scanner
3. **Dependency Installation**: Installs all required dependencies on each instance
4. **Concurrent Scanning**: Each instance scans its assigned domains with configurable concurrency
5. **Result Collection**: Downloads results from all instances
6. **Result Merging**: Combines all results into a single JSON file
7. **Cleanup**: Removes fleet instances to save costs

## Output Structure

```
xss-scan-results/
├── domains_fleet_1.txt          # Domains for instance 1
├── domains_fleet_2.txt          # Domains for instance 2
├── domains_fleet_3.txt          # Domains for instance 3
├── deploy_xss_scanner.sh        # Generated deployment script
├── merge_results.py             # Result merging script
├── scan_summary.txt             # Scan summary and statistics
├── results/                     # Individual result files
│   ├── results_example_com.json
│   ├── results_test_com.json
│   └── ...
└── merged_results_TIMESTAMP.json # Final merged results
```

## Result Format

The merged results file contains an array of vulnerability objects:

```json
[
  {
    "url": "https://example.com/search?q=<script>alert(1)</script>",
    "parameter": "q",
    "context": "query",
    "working_payloads": ["<script>alert(1)</script>"],
    "timestamp": "2024-01-15 10:30:45"
  }
]
```

## Configuration

### Fleet Size
- **Small scans** (1-10 domains): 1-2 instances
- **Medium scans** (10-50 domains): 3-5 instances  
- **Large scans** (50+ domains): 5-10 instances

### Concurrency
- **Conservative**: 2-3 concurrent scans per instance
- **Balanced**: 3-5 concurrent scans per instance
- **Aggressive**: 5-8 concurrent scans per instance

## Troubleshooting

### Common Issues

1. **Axiom not installed**: Install Axiom first
2. **Insufficient instances**: Reduce fleet size or increase Axiom quota
3. **Scan timeouts**: Reduce concurrency or increase timeout values
4. **Memory issues**: Reduce concurrency per instance

### Manual Result Merging

If automatic merging fails:

```bash
python3 merge_results.py xss-scan-results/results/ manual_merge.json
```

### Checking Individual Results

```bash
# View results from a specific instance
ls xss-scan-results/results/
cat xss-scan-results/results/results_example_com.json
```

## Performance Tips

1. **Optimize domain list**: Remove duplicates and invalid domains
2. **Balance fleet size**: More instances = faster scanning but higher cost
3. **Monitor resources**: Watch CPU and memory usage on instances
4. **Use appropriate concurrency**: Higher concurrency = faster but more resource intensive

## Cost Optimization

- Use fewer instances for smaller scans
- Monitor instance usage and terminate early if possible
- Consider using spot instances for cost savings
- Clean up instances promptly after scanning

## Security Considerations

- Only scan domains you own or have permission to test
- Be aware of rate limiting and WAF protections
- Monitor for false positives in results
- Use appropriate scanning parameters to avoid overwhelming targets

## Support

For issues or questions:
1. Check the scan summary file for details
2. Review individual result files for specific errors
3. Check Axiom instance logs for deployment issues
4. Verify domain file format and content
