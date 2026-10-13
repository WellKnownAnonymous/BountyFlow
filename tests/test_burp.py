from bountyflow.burp import write_burp_bundle
from bountyflow.utils import proxy_flag


def test_proxy_flags():
    assert "-http-proxy" in proxy_flag("http://127.0.0.1:8080", "httpx")
    assert "-proxy" in proxy_flag("http://127.0.0.1:8080", "nuclei")
    assert "-x" in proxy_flag("http://127.0.0.1:8080", "ffuf")
    assert proxy_flag("", "nuclei") == ""


def test_burp_bundle(tmp_path):
    out = write_burp_bundle(
        tmp_path, "arc.io",
        ["https://www.arc.io [200]", "https://docs.arc.io [200]"],
        [{"severity": "high", "template": "t", "host": "h", "matched": "m"}],
        "https://rpc.testnet.arc.network", "https://explorer.testnet.arc.io",
    )
    assert out["hosts"] == 2
    assert (tmp_path / "burp" / "scope.txt").exists()
    assert (tmp_path / "burp" / "repeater.md").exists()
    assert (tmp_path / "burp" / "project-config.json").exists()
