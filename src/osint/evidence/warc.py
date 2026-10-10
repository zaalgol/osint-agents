"""WARC (ISO 28500) records for fetched responses.

Each fetch becomes a small gzipped WARC file with a warcinfo record, the request record
and the response record (with the headers and body as received). Standard web-archive
tools (pywb, replayweb.page) can replay it.
"""

from __future__ import annotations

import io

from warcio.statusandheaders import StatusAndHeaders
from warcio.warcwriter import WARCWriter

from osint import __version__
from osint.net.http import FetchResult

# Transfer framing is removed by the HTTP client, so recording it would mislead WARC readers.
_DROP = {"transfer-encoding"}


def build_warc(result: FetchResult) -> bytes:
    buf = io.BytesIO()
    writer = WARCWriter(buf, gzip=True)
    date = result.fetched_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    info = writer.create_warcinfo_record(
        "capture.warc.gz",
        {"software": f"osint-agents/{__version__}", "format": "WARC File Format 1.1",
         "description": "Single-capture WARC produced at collection time"},
    )
    writer.write_record(info)

    target = result.final_url
    path = target.split("://", 1)[-1]
    path = path[path.find("/"):] if "/" in path else "/"
    req_headers = StatusAndHeaders(f"GET {path} HTTP/1.1", result.request_headers,
                                   is_http_request=True)
    req = writer.create_warc_record(target, "request", http_headers=req_headers,
                                    warc_headers_dict={"WARC-Date": date})

    proto = "HTTP/2" if result.http_version.upper().startswith("HTTP/2") else "HTTP/1.1"
    headers = [(k, v) for k, v in result.response_headers if k.lower() not in _DROP]
    headers = [(k, v) for k, v in headers if k.lower() != "content-length"]
    headers.append(("Content-Length", str(len(result.wire_body))))
    resp_headers = StatusAndHeaders(f"{result.status} {result.reason}", headers, protocol=proto)
    warc_headers = {"WARC-Date": date}
    if result.resolved_ip:
        warc_headers["WARC-IP-Address"] = result.resolved_ip
    resp = writer.create_warc_record(
        target, "response", payload=io.BytesIO(result.wire_body),
        length=len(result.wire_body), http_headers=resp_headers,
        warc_headers_dict=warc_headers,
    )
    writer.write_record(resp)
    req.rec_headers.add_header("WARC-Concurrent-To", resp.rec_headers.get_header("WARC-Record-ID"))
    writer.write_record(req)
    return buf.getvalue()
