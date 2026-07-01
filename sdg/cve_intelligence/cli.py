""""CLI for CVE Intelligence Gathering."""
from __future__ import annotations
import argparse
import json
from sdg.cve_intelligence.gatherer import CVEIntelligenceGatherer


def main():
    parser = argparse.ArgumentParser(description="CVE Intelligence Gathering — Secure Deploy Guard")
    parser.add_argument("cve_id", help="CVE identifier (e.g., CVE-2023-1234)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout per source")
    parser.add_argument("--offline", action="store_true", help="Do not perform network requests")
    args = parser.parse_args()

    if args.offline:
        print(json.dumps({"error": "Offline mode not yet implemented; use without --offline."}, indent=2))
        return

    gatherer = CVEIntelligenceGatherer(timeout=args.timeout)
    profile = gatherer.gather(args.cve_id)
    print(json.dumps(profile.to_dict(), indent=2))


if __name__ == "__main__":
    main()
