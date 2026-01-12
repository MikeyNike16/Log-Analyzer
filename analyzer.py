import re  # import the regular expression module for pattern matching
import json  # import json to parse JSON-formatted log lines
import datetime  # import datetime for parsing and comparing timestamps
from collections import Counter  # import Counter to count occurrences (ips, paths, statuses)
from typing import Iterator, Dict, Optional, List  # import type hints used in function signatures

COMMON_LOG_PATTERN = re.compile(  # compile a regex pattern to match Common Log Format lines
    r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'  # regex capturing ip, ident, user, time, request, status, size
)  # end of regex compilation

def parse_common_log_line(line: str) -> Optional[Dict]:  # function to parse a single common-log-format line, returns dict or None
    m = COMMON_LOG_PATTERN.match(line)  # attempt to match the line against the compiled pattern
    if not m:  # if there's no match
        return None  # return None to indicate parsing failed
    gd = m.groupdict()  # get the named groups as a dict
    time_raw = gd.get("time")  # extract the raw time string (e.g. "10/Oct/2000:13:55:36 -0700")
    try:  # try to parse the timestamp portion into a datetime
        time_part = time_raw.split()[0]  # split off timezone and keep the main time portion
        dt = datetime.datetime.strptime(time_part, "%d/%b/%Y:%H:%M:%S")  # parse time into a datetime object
    except Exception:  # on any parsing error
        dt = None  # set dt to None when the timestamp cannot be parsed
    req = gd.get("request") or ""  # get the request string (method path protocol) or empty string if missing
    method, path, proto = (None, None, None)  # initialize method, path, protocol to None
    parts = req.split()  # split the request into parts by whitespace
    if len(parts) == 3:  # if it has exactly three parts (method, path, protocol)
        method, path, proto = parts  # assign them accordingly
    size_raw = gd.get("size")  # get the raw size field (might be "-" when unknown)
    size = 0 if size_raw == "-" else int(size_raw)  # convert size to int, treating "-" as 0
    return {  # return a normalized dictionary representing the parsed log entry
        "ip": gd.get("ip"),  # client IP address
        "user": None if gd.get("user") == "-" else gd.get("user"),  # authenticated user or None if "-"
        "time": dt,  # parsed datetime or None
        "method": method,  # HTTP method or None
        "path": path,  # request path or None
        "protocol": proto,  # protocol/version or None
        "status": int(gd.get("status")),  # HTTP status as int
        "size": size,  # response size as int
    }  # end of returned dict

def parse_json_line(line: str) -> Optional[Dict]:  # function to parse a JSON-formatted log line
    try:  # try to decode the JSON
        obj = json.loads(line)  # load the JSON object from the line
        return obj if isinstance(obj, dict) else None  # return the dict if it's an object, otherwise None
    except Exception:  # on JSON decoding error
        return None  # return None to indicate parsing failed

def parse_line(line: str) -> Optional[Dict]:  # function that decides which parser to use for a line
    line = line.strip()  # strip whitespace/newlines from the ends of the line
    if not line:  # if the line is empty after stripping
        return None  # skip empty lines
    if line.startswith("{"):  # heuristic: JSON lines start with "{"
        return parse_json_line(line)  # parse as JSON
    parsed = parse_common_log_line(line)  # otherwise attempt to parse as common log format
    return parsed  # return the parsed dict or None

def parse_file(path: str) -> Iterator[Dict]:  # function to iterate over parsed entries from a file path
    with open(path, "r", encoding="utf-8") as f:  # open the file for reading with UTF-8 encoding
        for raw in f:  # iterate over each raw line in the file
            entry = parse_line(raw)  # parse the line into an entry dict or None
            if entry:  # if parsing succeeded and returned a dict
                yield entry  # yield the entry to the caller

def filter_time(entries: Iterator[Dict], start: Optional[datetime.datetime] = None, end: Optional[datetime.datetime] = None) -> List[Dict]:  # filter entries by optional start/end datetimes
    out = []  # prepare output list
    for e in entries:  # iterate over incoming entries (iterator)
        t = e.get("time")  # get the entry's timestamp (may be None)
        if t is None:  # if there's no timestamp
            out.append(e)  # keep the entry (cannot compare)
            continue  # continue to next entry
        if start and t < start:  # if a start bound is provided and entry is before it
            continue  # skip this entry
        if end and t > end:  # if an end bound is provided and entry is after it
            continue  # skip this entry
        out.append(e)  # entry passes the time filters; add to output
    return out  # return the filtered list of entries

def score_severity(entry: Dict) -> str:  # new function to score severity of a single log entry (LOW/MED/HIGH)
    status = entry.get("status")  # get HTTP status
    path = entry.get("path") or ""  # get request path
    method = entry.get("method")  # get HTTP method
    size = entry.get("size") or 0  # get response size
    # HIGH: suspicious paths (SQLi, admin), 5xx errors, large POSTs (>1MB)
    if (re.search(r"(union\s+select|--|\b(or|and)\b\s+\d+=\d+|\%27|\%3D)", path, re.I) or  # SQLi patterns
        "/admin" in path.lower() or "/phpmyadmin" in path.lower() or  # admin paths
        (status and 500 <= status < 600) or  # 5xx errors
        (method == "POST" and size > 1000000)):  # large POSTs
        return "HIGH"
    # MED: 4xx errors, repeated failures, unusual methods
    elif (status and 400 <= status < 500) or method not in ["GET", "POST", "HEAD"]:  # 4xx or odd methods
        return "MED"
    # LOW: normal 2xx/3xx
    else:
        return "LOW"

def summarize(entries: List[Dict], top: int = 10) -> Dict:  # produce summary stats from a list of entries, default top=10
    total = len(entries)  # total number of entries processed
    ips = Counter(e.get("ip") for e in entries if e.get("ip"))  # count occurrences of each IP (skip falsy IPs)
    paths = Counter(e.get("path") or "-" for e in entries)  # count occurrences of paths, use "-" when path is None
    statuses = Counter(str(e.get("status")) for e in entries if e.get("status") is not None)  # count status codes as strings, skip None
    bytes_total = sum(e.get("size") or 0 for e in entries)  # sum up sizes, treating None/0-like values as 0
    unique_ips = len([k for k in ips.keys() if k])  # count unique non-empty IP keys
    severities = Counter(score_severity(e) for e in entries)  # count severity levels across all entries
    return {  # return a dictionary with summary metrics
        "total_lines": total,  # total parsed lines
        "unique_ips": unique_ips,  # number of unique IPs seen
        "top_ips": ips.most_common(top),  # top N IPs by count
        "top_paths": paths.most_common(top),  # top N requested paths by count
        "status_counts": dict(statuses),  # status code counts as a plain dict
        "bytes_total": bytes_total,  # total bytes transferred
        "severity_counts": dict(severities),  # counts of LOW/MED/HIGH severities
    }  # end of summary dict

__all__ = [  # define public API symbols for "from analyzer import *"
    "parse_line",  # exported symbol parse_line
    "parse_file",  # exported symbol parse_file
    "filter_time",  # exported symbol filter_time
    "summarize",  # exported symbol summarize
    "score_severity",  # exported symbol score_severity
]  # end of __all__
