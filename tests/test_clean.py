from bountyflow.summarize import build_clean_lists, extract_host, extract_url
from bountyflow.scope import apply_excludes


def test_extract_url_strips_httpx_suffix():
    assert extract_url("https://a.example.com [200] [Title] [tech]") == "https://a.example.com"
    assert extract_url("https://b.example.com") == "https://b.example.com"
    assert extract_url("") is None


def test_extract_host():
    assert extract_host("https://sub.example.com/path?q=1") == "sub.example.com"


def test_excludes_drop_subdomains():
    kept, removed = apply_excludes(
        ["https://help.arc.io [403]", "https://www.arc.io [200]", "https://sub.help.arc.io"],
        {"help.arc.io"},
    )
    assert kept == ["https://www.arc.io [200]"]
    assert len(removed) == 2


def test_build_clean_lists(tmp_path):
    (tmp_path / "live.txt").write_text(
        "https://a.example.com [200] [T]\nhttps://b.example.com [403] [C]\n"
    )
    res = build_clean_lists(tmp_path)
    assert res == {"raw": 2, "urls": 2, "hosts": 2}
    assert (tmp_path / "live_urls.txt").read_text().splitlines()[0] == "https://a.example.com"
