from brain.core.url_canonical import canonicalize_url


def test_canonicalize_url_rules() -> None:
    cases = {
        "https://Example.com:443/": "https://example.com/",
        "http://Example.com:80/path/": "http://example.com/path",
        "https://example.com/page/?b=2&a=1": "https://example.com/page?a=1&b=2",
        "https://example.com/page#section": "https://example.com/page",
        "https://example.com": "https://example.com/",
        "https://example.com/Case/Path/": "https://example.com/Case/Path",
        "https://[2001:db8::1]:443/health": "https://[2001:db8::1]/health",
    }

    for raw, expected in cases.items():
        assert canonicalize_url(raw) == expected
