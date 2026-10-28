import io
import json
from hashlib import sha256
from types import SimpleNamespace

import pytest

from scripts import verify_intelligence_sources
from vulnassess import intel_online
from vulnassess.errors import IntelUnavailable


def test_nvd_key_only_goes_to_exact_official_https_endpoint(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "synthetic-private-key")
    requests = []

    def open_request(request, **kwargs):
        requests.append(request)
        return io.BytesIO(b"{}")

    monkeypatch.setattr(intel_online.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(
        intel_online.urllib.request, "build_opener", lambda *_: SimpleNamespace(open=open_request)
    )
    urls = [
        intel_online.NVD_URL + "?cveId=CVE-2022-0543",
        intel_online.EPSS_URL,
        intel_online.KEV_URL,
        "https://services.nvd.nist.gov.attacker.invalid/rest/json/cves/2.0",
        "http://services.nvd.nist.gov/rest/json/cves/2.0",
        "https://services.nvd.nist.gov/unrelated",
        "https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId=CVE-2022-0543",
    ]
    for url in urls:
        intel_online.fetch_json(url, 10)
    for index, request in enumerate(requests):
        headers = {key.lower(): value for key, value in request.header_items()}
        assert (headers.get("apikey") == "synthetic-private-key") is (index in {0, 6})
        assert "synthetic-private-key" not in request.full_url


def test_authenticated_redirect_is_refused_and_errors_do_not_echo_key(monkeypatch):
    with pytest.raises(IntelUnavailable, match="redirects are refused"):
        intel_online._NoCredentialRedirect().redirect_request(
            None, None, 302, "", {}, "https://other.invalid"
        )
    monkeypatch.setenv("NVD_API_KEY", "synthetic\nsecret")
    with pytest.raises(IntelUnavailable) as error:
        intel_online.fetch_json(intel_online.NVD_URL, 10)
    assert "synthetic" not in str(error.value)


def publisher(url, limit):
    if "nist.gov" in url:
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2022-0543",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 10.0,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }
    if "first.org" in url:
        return {
            "status": "OK",
            "data": [
                {"cve": "CVE-2022-0543", "epss": "0.99", "percentile": "0.98", "date": "2026-10-23"}
            ],
        }
    return {
        "count": 1,
        "dateReleased": "2026-10-23T00:00:00Z",
        "vulnerabilities": [{"cveID": "CVE-2022-0543", "dateAdded": "2022-03-28"}],
    }


def test_reproducible_lookup_preserves_sources_dates_hashes_without_creating_findings(tmp_path):
    directory, result = verify_intelligence_sources.verify(
        ["CVE-2022-0543"], tmp_path, fetch=publisher
    )
    row = result["results"][0]
    assert row["cvss31_base"] == 10.0
    assert row["epss"]["score_date"] == "2026-10-23"
    assert row["kev_listed"] is True
    assert row["cve_applies_to_scanned_host"] == "not evaluated"
    assert result["scanner_launched"] is False
    assert "findings" not in result
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["status"] == "verified"
    assert len(manifest["sources"]) == 3
    for source in manifest["sources"]:
        assert sha256((directory / source["file"]).read_bytes()).hexdigest() == source["sha256"]
    assert not (tmp_path / "intel-cache.db").exists()


def test_failed_response_leaves_incomplete_manifest_and_no_claim_of_success(tmp_path):
    with pytest.raises(IntelUnavailable):
        verify_intelligence_sources.verify(["CVE-2022-0543"], tmp_path, fetch=lambda *_: {})
    directory = next(tmp_path.iterdir())
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["status"] == "incomplete"
    assert not (directory / "results.json").exists()
