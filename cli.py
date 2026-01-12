import argparse
import json
from .analyzer import parse_file, filter_time, summarize
import datetime


def iso_to_dt(s: str):
    return datetime.datetime.fromisoformat(s)


def main():
    p = argparse.ArgumentParser(description="Simple log analyzer")
    p.add_argument("--file", "-f", required=True, help="Path to log file")
    p.add_argument("--top", "-n", type=int, default=10, help="Top N items")
    p.add_argument("--start", help="Start time (ISO) e.g. 2020-01-01T00:00:00")
    p.add_argument("--end", help="End time (ISO)")
    p.add_argument("--json", action="store_true", help="Output JSON summary")
    args = p.parse_args()

    entries = list(parse_file(args.file))
    start = iso_to_dt(args.start) if args.start else None
    end = iso_to_dt(args.end) if args.end else None
    entries = filter_time(iter(entries), start=start, end=end)
    summary = summarize(entries, top=args.top)
    if args.json:
        print(json.dumps(summary, default=str, indent=2))
    else:
        print(f"Total lines: {summary['total_lines']}")
        print(f"Unique IPs: {summary['unique_ips']}")
        print("Top paths:")
        for pth, cnt in summary["top_paths"]:
            print(f"  {pth}: {cnt}")


if __name__ == "__main__":
    main()
