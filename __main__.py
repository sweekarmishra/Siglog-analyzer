import argparse
import sys

from .analyzer import analyze_file, format_report
from .flows import FLOWS


def main():
    ap = argparse.ArgumentParser(prog="siglog",
                                 description="Check a tshark JSON export against an expected NAS call flow.")
    ap.add_argument("trace", help="tshark JSON export (tshark -r x.pcap -T json > x.json)")
    ap.add_argument("--flow", choices=FLOWS, default="5g-registration")
    args = ap.parse_args()
    res = analyze_file(args.trace, args.flow)
    print(format_report(res))
    sys.exit(0 if res.passed else 1)


if __name__ == "__main__":
    main()
