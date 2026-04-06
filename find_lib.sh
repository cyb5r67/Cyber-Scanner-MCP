#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPORT_FILE="$SCRIPT_DIR/package_json.txt"
OUTPUT_REPORT="$SCRIPT_DIR/Infected_Files_Report.txt"
THREADS=$(nproc)

SEARCH_STRINGS=(
    '"axios": "0.30.4"'
    '"axios": "1.14.1"'
)

# Step 1: Discover all package.json files across all mounted filesystems
echo -e "\033[36mSearching for package.json files across all mounted filesystems...\033[0m"

mapfile -t SEARCH_ROOTS < <(findmnt -rn -o TARGET -t ext4,xfs,btrfs,ext3,ext2,vfat,ntfs,fuseblk 2>/dev/null)
if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
    SEARCH_ROOTS=("/")
fi

> "$EXPORT_FILE"
FIND_COUNT=0
for root in "${SEARCH_ROOTS[@]}"; do
    while IFS= read -r file; do
        echo "$file" >> "$EXPORT_FILE"
        FIND_COUNT=$((FIND_COUNT + 1))
        printf "\r\033[36m  Found %d package.json files so far...\033[0m" "$FIND_COUNT"
    done < <(find "$root" -name "package.json" -type f 2>/dev/null)
done

FILE_COUNT=$(wc -l < "$EXPORT_FILE")
printf "\r\033[K\033[32mFound %d package.json files. List saved to %s\033[0m\n" "$FILE_COUNT" "$EXPORT_FILE"

# Step 2: Scan files for search terms
echo -e "\033[36mScanning $FILE_COUNT files with $THREADS workers for ${#SEARCH_STRINGS[@]} search terms...\033[0m"

> "$OUTPUT_REPORT"
SCANNED=0
HITS=0

while IFS= read -r file; do
    if [ -f "$file" ]; then
        content=$(cat "$file" 2>/dev/null) || continue
        matched=()
        for pattern in "${SEARCH_STRINGS[@]}"; do
            if [[ "$content" == *"$pattern"* ]]; then
                matched+=("$pattern")
            fi
        done
        if [ ${#matched[@]} -gt 0 ]; then
            HITS=$((HITS + 1))
            IFS=", "; echo "$file | Matched: ${matched[*]}" >> "$OUTPUT_REPORT"
        fi
    fi
    SCANNED=$((SCANNED + 1))
    if (( SCANNED % 100 == 0 )) || (( SCANNED == FILE_COUNT )); then
        PCT=$((SCANNED * 100 / FILE_COUNT))
        printf "\r\033[36m  Scanned %d/%d (%d%%) — %d hits\033[0m" "$SCANNED" "$FILE_COUNT" "$PCT" "$HITS"
    fi
done < "$EXPORT_FILE"

printf "\r\033[K\033[32mSearch complete. Scanned %d files, found %d infected. Results saved to %s\033[0m\n" "$SCANNED" "$HITS" "$OUTPUT_REPORT"
