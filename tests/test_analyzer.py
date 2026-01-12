from log_analyzer.analyzer import parse_line, summarize


def test_parse_common_line():
    line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326'
    e = parse_line(line)
    assert e["ip"] == "127.0.0.1"
    assert e["method"] == "GET"
    assert e["path"] == "/index.html"


def test_summarize_small():
    lines = [
        {'ip': '1.1.1.1', 'path': '/a', 'status': 200, 'size': 10},
        {'ip': '2.2.2.2', 'path': '/b', 'status': 404, 'size': 0},
        {'ip': '1.1.1.1', 'path': '/a', 'status': 200, 'size': 5},
    ]
    s = summarize(lines, top=2)
    assert s['total_lines'] == 3
    assert s['bytes_total'] == 15
