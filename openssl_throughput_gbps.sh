#!/bin/bash

echo "Benchmarking OpenSSL EVP throughput (8192-byte block)..."
echo

for CIPHER in aes-128-gcm aes-256-gcm chacha20-poly1305; do
  echo "Running: $CIPHER..."
  OUTPUT=$(openssl speed -evp "$CIPHER" 2>/dev/null)

  # Extract last column of the line containing the cipher name (assumes 8192 bytes)
  VALUE_KB=$(echo "$OUTPUT" | grep -i "$CIPHER" | awk '{print $(NF)}' | sed 's/[^0-9.]//g')

  # Convert to GB/s using dot-decimal separator, and make sure it's valid
  if [[ "$VALUE_KB" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    VALUE_GB=$(LC_ALL=C echo "scale=3; $VALUE_KB / 1000000" | bc -l)
    printf "%-20s : %10s GB/s (%s kB/s)\n" "$CIPHER" "$VALUE_GB" "$VALUE_KB"
  else
    echo "$CIPHER: Failed to parse throughput value: '$VALUE_KB'"
  fi
done
