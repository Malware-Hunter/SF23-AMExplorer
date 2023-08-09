#!/bin/bash

echo "" 

echo "==========================================================="
echo "Running amexplorer.py ... "
echo "" 

python3 amexplorer.py --dataset-type-all \
    --androguard-features metadata/androguard/features \
    --androguard-metadata metadata/androguard/metadata \
    --virustotal-metadata metadata/virustotal \
    --androzoo-metadata metadata/androzoo/androzoo_metadata.csv \
    --output-dir outputs

echo "" 
echo "done."
echo "==========================================================="

echo "" 

bash
