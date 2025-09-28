#!/bin/bash

# Axiom XSS Scanner Script
# This script handles domain file splitting and fleet deployment for XSS scanning

set -e

# Configuration
FLEET_SIZE=3
CONCURRENCY=3
OUTPUT_DIR="xss-scan-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 <domains_file> [options]"
    echo ""
    echo "Arguments:"
    echo "  domains_file    File containing domains to scan (one per line)"
    echo ""
    echo "Options:"
    echo "  -f, --fleet-size SIZE    Number of fleet instances (default: 3)"
    echo "  -c, --concurrency NUM    Concurrency per instance (default: 3)"
    echo "  -o, --output DIR         Output directory (default: xss-scan-results)"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 domains.txt"
    echo "  $0 domains.txt -f 5 -c 5"
    echo "  $0 domains.txt -o my-results"
}

# Parse command line arguments
DOMAINS_FILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--fleet-size)
            FLEET_SIZE="$2"
            shift 2
            ;;
        -c|--concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -*)
            print_error "Unknown option $1"
            show_usage
            exit 1
            ;;
        *)
            if [[ -z "$DOMAINS_FILE" ]]; then
                DOMAINS_FILE="$1"
            else
                print_error "Multiple domain files specified"
                show_usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate arguments
if [[ -z "$DOMAINS_FILE" ]]; then
    print_error "Domain file is required"
    show_usage
    exit 1
fi

if [[ ! -f "$DOMAINS_FILE" ]]; then
    print_error "Domain file '$DOMAINS_FILE' not found"
    exit 1
fi

# Validate fleet size
if ! [[ "$FLEET_SIZE" =~ ^[0-9]+$ ]] || [[ "$FLEET_SIZE" -lt 1 ]]; then
    print_error "Fleet size must be a positive integer"
    exit 1
fi

# Validate concurrency
if ! [[ "$CONCURRENCY" =~ ^[0-9]+$ ]] || [[ "$CONCURRENCY" -lt 1 ]] || [[ "$CONCURRENCY" -gt 10 ]]; then
    print_error "Concurrency must be between 1 and 10"
    exit 1
fi

print_status "Starting XSS Scanner Axiom deployment"
print_status "Domain file: $DOMAINS_FILE"
print_status "Fleet size: $FLEET_SIZE"
print_status "Concurrency per instance: $CONCURRENCY"
print_status "Output directory: $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Count total domains
TOTAL_DOMAINS=$(grep -v '^#' "$DOMAINS_FILE" | grep -v '^$' | wc -l)
print_status "Total domains to scan: $TOTAL_DOMAINS"

if [[ $TOTAL_DOMAINS -eq 0 ]]; then
    print_error "No valid domains found in file"
    exit 1
fi

# Calculate domains per fleet instance
DOMAINS_PER_INSTANCE=$((TOTAL_DOMAINS / FLEET_SIZE))
REMAINDER=$((TOTAL_DOMAINS % FLEET_SIZE))

print_status "Domains per instance: $DOMAINS_PER_INSTANCE"
if [[ $REMAINDER -gt 0 ]]; then
    print_status "Remainder domains: $REMAINDER (will be distributed to first $REMAINDER instances)"
fi

# Split domains into separate files for each fleet instance
print_status "Splitting domains into fleet files..."

# Clean up any existing split files
rm -f "${OUTPUT_DIR}/domains_fleet_"*.txt

# Create split files
CURRENT_DOMAIN=0
for ((i=1; i<=FLEET_SIZE; i++)); do
    FLEET_FILE="${OUTPUT_DIR}/domains_fleet_${i}.txt"
    
    # Calculate domains for this instance
    DOMAINS_FOR_THIS_INSTANCE=$DOMAINS_PER_INSTANCE
    if [[ $i -le $REMAINDER ]]; then
        DOMAINS_FOR_THIS_INSTANCE=$((DOMAINS_FOR_THIS_INSTANCE + 1))
    fi
    
    print_status "Creating fleet file $i with $DOMAINS_FOR_THIS_INSTANCE domains"
    
    # Extract domains for this fleet instance
    tail -n +$((CURRENT_DOMAIN + 1)) "$DOMAINS_FILE" | head -n "$DOMAINS_FOR_THIS_INSTANCE" > "$FLEET_FILE"
    
    CURRENT_DOMAIN=$((CURRENT_DOMAIN + DOMAINS_FOR_THIS_INSTANCE))
    
    # Verify the file was created and has content
    if [[ -f "$FLEET_FILE" ]] && [[ -s "$FLEET_FILE" ]]; then
        print_success "Created $FLEET_FILE with $(wc -l < "$FLEET_FILE") domains"
    else
        print_error "Failed to create $FLEET_FILE"
        exit 1
    fi
done

# Create Axiom deployment script
AXIOM_SCRIPT="${OUTPUT_DIR}/deploy_xss_scanner.sh"
cat > "$AXIOM_SCRIPT" << EOF
#!/bin/bash

# Axiom XSS Scanner Deployment Script
# Generated on $(date)

set -e

FLEET_SIZE=$FLEET_SIZE
CONCURRENCY=$CONCURRENCY
OUTPUT_DIR="$OUTPUT_DIR"
TIMESTAMP="$TIMESTAMP"

echo "🚀 Deploying XSS Scanner to Axiom fleet..."

# Create fleet instances
echo "📦 Creating $FLEET_SIZE fleet instances..."
axiom-fleet xss-scanner \$FLEET_SIZE

# Wait for instances to be ready
echo "⏳ Waiting for instances to be ready..."
sleep 30

# Upload XSS scanner files to each instance
echo "📤 Uploading XSS scanner files..."
for i in \$(seq 1 \$FLEET_SIZE); do
    echo "Uploading to instance \$i..."
    axiom-scp xss-scanner-\$i xss-scanner-minimal/ /root/
done

# Install dependencies on each instance
echo "🔧 Installing dependencies on fleet instances..."
axiom-exec -f xss-scanner "cd /root/xss-scanner-minimal && chmod +x install-dependencies.sh && ./install-dependencies.sh"

# Build the scanner on each instance
echo "🏗️ Building XSS scanner on fleet instances..."
axiom-exec -f xss-scanner "cd /root/xss-scanner-minimal && chmod +x build.sh && ./build.sh"

# Upload domain files to each instance
echo "📤 Uploading domain files to fleet instances..."
for i in \$(seq 1 \$FLEET_SIZE); do
    echo "Uploading domains to instance \$i..."
    axiom-scp xss-scanner-\$i "\${OUTPUT_DIR}/domains_fleet_\${i}.txt" /root/domains.txt
done

# Start scanning on each instance
echo "🎯 Starting XSS scans on fleet instances..."
for i in \$(seq 1 \$FLEET_SIZE); do
    echo "Starting scan on instance \$i..."
    axiom-exec xss-scanner-\$i "cd /root/xss-scanner-minimal && while IFS= read -r domain; do echo \"Scanning \$domain...\"; ./xss-scanner -d \"\$domain\" -concurrency \$CONCURRENCY -headless -o \"results_\$(echo \$domain | tr '/' '_' | tr ':' '_').json\"; done < /root/domains.txt" &
done

# Wait for all scans to complete
echo "⏳ Waiting for all scans to complete..."
wait

# Download results from each instance
echo "📥 Downloading results from fleet instances..."
mkdir -p "\${OUTPUT_DIR}/results"
for i in \$(seq 1 \$FLEET_SIZE); do
    echo "Downloading results from instance \$i..."
    axiom-scp xss-scanner-\$i "/root/xss-scanner-minimal/results_*.json" "\${OUTPUT_DIR}/results/"
done

# Merge all results
echo "🔄 Merging results..."
python3 -c "
import json
import glob
import os

results = []
result_files = glob.glob('\${OUTPUT_DIR}/results/results_*.json')

for file in result_files:
    try:
        with open(file, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                results.extend(data)
            else:
                results.append(data)
    except Exception as e:
        print(f'Error reading {file}: {e}')

# Save merged results
with open('\${OUTPUT_DIR}/merged_results_\${TIMESTAMP}.json', 'w') as f:
    json.dump(results, f, indent=2)

print(f'Merged {len(results)} results into merged_results_\${TIMESTAMP}.json')
"

# Clean up fleet instances
echo "🧹 Cleaning up fleet instances..."
axiom-rm xss-scanner

echo "✅ XSS scanning completed!"
echo "📊 Results saved to: \${OUTPUT_DIR}/merged_results_\${TIMESTAMP}.json"
echo "📁 Individual results in: \${OUTPUT_DIR}/results/"

EOF

chmod +x "$AXIOM_SCRIPT"

print_success "Axiom deployment script created: $AXIOM_SCRIPT"

# Create a simple Python script for result merging (fallback)
MERGE_SCRIPT="${OUTPUT_DIR}/merge_results.py"
cat > "$MERGE_SCRIPT" << 'EOF'
#!/usr/bin/env python3
"""
XSS Scanner Results Merger
Merges multiple JSON result files into a single file
"""

import json
import glob
import os
import sys
from datetime import datetime

def merge_results(results_dir, output_file):
    """Merge all JSON result files in the results directory"""
    results = []
    result_files = glob.glob(os.path.join(results_dir, "results_*.json"))
    
    print(f"Found {len(result_files)} result files to merge")
    
    for file in result_files:
        try:
            with open(file, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    results.extend(data)
                else:
                    results.append(data)
            print(f"✓ Merged {file}")
        except Exception as e:
            print(f"✗ Error reading {file}: {e}")
    
    # Save merged results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Merged {len(results)} results into {output_file}")
    return len(results)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 merge_results.py <results_dir> <output_file>")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(results_dir):
        print(f"Error: Results directory '{results_dir}' not found")
        sys.exit(1)
    
    merge_results(results_dir, output_file)
EOF

chmod +x "$MERGE_SCRIPT"

print_success "Result merger script created: $MERGE_SCRIPT"

# Create a summary file
SUMMARY_FILE="${OUTPUT_DIR}/scan_summary.txt"
cat > "$SUMMARY_FILE" << EOF
XSS Scanner Axiom Deployment Summary
====================================

Generated: $(date)
Domain file: $DOMAINS_FILE
Total domains: $TOTAL_DOMAINS
Fleet size: $FLEET_SIZE
Concurrency per instance: $CONCURRENCY
Output directory: $OUTPUT_DIR

Fleet Distribution:
EOF

for ((i=1; i<=FLEET_SIZE; i++)); do
    FLEET_FILE="${OUTPUT_DIR}/domains_fleet_${i}.txt"
    DOMAIN_COUNT=$(wc -l < "$FLEET_FILE")
    echo "  Instance $i: $DOMAIN_COUNT domains" >> "$SUMMARY_FILE"
done

cat >> "$SUMMARY_FILE" << EOF

Files Created:
- domains_fleet_*.txt: Domain files for each fleet instance
- deploy_xss_scanner.sh: Axiom deployment script
- merge_results.py: Result merging script
- scan_summary.txt: This summary file

Next Steps:
1. Run: ./$AXIOM_SCRIPT
2. Wait for scans to complete
3. Results will be automatically merged into merged_results_${TIMESTAMP}.json

Manual Result Merging (if needed):
python3 $MERGE_SCRIPT $OUTPUT_DIR/results/ $OUTPUT_DIR/manual_merge_${TIMESTAMP}.json
EOF

print_success "Summary file created: $SUMMARY_FILE"

print_success "XSS Scanner Axiom setup completed!"
print_status "Run the deployment script: ./$AXIOM_SCRIPT"
print_status "Or review the setup in: $OUTPUT_DIR/"
