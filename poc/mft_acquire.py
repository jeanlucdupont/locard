"""Compatibility entry point for the shared native NTFS acquisition implementation."""
import sys
from pathlib import Path

# Direct invocation from a source checkout remains supported.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forensic_assistant.artifacts import ntfs_acquisition as implementation

if __name__ == '__main__':
    raise SystemExit(implementation.main())
else:
    sys.modules[__name__] = implementation
