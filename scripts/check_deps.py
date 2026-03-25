#!/usr/bin/env python3
import sys

REQUIRED = ["tenseal", "numpy"]

missing = []
for pkg in REQUIRED:
    try:
        __import__(pkg)
        print(f"  [ok] {pkg}")
    except ImportError:
        print(f"  [missing] {pkg}")
        missing.append(pkg)

if missing:
    print(f"\nmissing packages: {', '.join(missing)}")
    print("install with: pip install " + " ".join(missing))
    sys.exit(1)
else:
    print("\nall dependencies satisfied.")
