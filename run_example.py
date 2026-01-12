from .analyzer import parse_file, summarize
import json
from pathlib import Path


def main():
    here = Path(__file__).parent
    sample = here / "sample_logs" / "access.log"
    entries = list(parse_file(str(sample)))
    summary = summarize(entries)
    print(json.dumps(summary, default=str, indent=2))


if __name__ == "__main__":
    main()
