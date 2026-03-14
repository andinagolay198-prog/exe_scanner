"""
VirusTotal API v3 Integration
- Tra cứu hash (không upload file)
- Upload file để quét
- Cache kết quả để tiết kiệm quota
"""
import os
import json
import time
import hashlib
import datetime
import threading
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Dict, List

CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "vt_cache.json"
)

VT_BASE = "https://www.virustotal.com/api/v3"


# ─────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────

@dataclass
class VTEngineResult:
    engine_name: str
    category: str       # malicious | suspicious | undetected | timeout
    result: str         # malware name / family


@dataclass
class VTReport:
    sha256: str
    found: bool = False
    error: str = ""
    cached: bool = False

    # Stats
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    total_engines: int = 0
    detection_rate: float = 0.0

    # Details
    names: List[str] = field(default_factory=list)     # malware names detected
    engines: List[VTEngineResult] = field(default_factory=list)
    file_type: str = ""
    first_seen: str = ""
    last_seen: str = ""
    tags: List[str] = field(default_factory=list)
    threat_label: str = ""

    # Timestamps
    queried_at: str = ""


# ─────────────────────────────────────────────
#  CACHE
# ─────────────────────────────────────────────

_cache_lock = threading.Lock()


def _load_cache() -> Dict:
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_cache(cache: Dict):
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def _get_cached(sha256: str) -> Optional[VTReport]:
    """Return cached VTReport if it's less than 24h old."""
    with _cache_lock:
        cache = _load_cache()
    entry = cache.get(sha256.lower())
    if not entry:
        return None
    # Expire after 24 hours
    try:
        age = time.time() - entry.get("cached_ts", 0)
        if age > 86400:
            return None
    except Exception:
        return None
    r = VTReport(**{k: v for k, v in entry.items()
                    if k not in ("cached_ts", "engines_raw")})
    r.engines = [VTEngineResult(**e) for e in entry.get("engines_raw", [])]
    r.cached = True
    return r


def _put_cache(report: VTReport):
    with _cache_lock:
        cache = _load_cache()
        cache[report.sha256.lower()] = {
            "sha256":         report.sha256,
            "found":          report.found,
            "error":          report.error,
            "cached":         True,
            "malicious":      report.malicious,
            "suspicious":     report.suspicious,
            "undetected":     report.undetected,
            "harmless":       report.harmless,
            "total_engines":  report.total_engines,
            "detection_rate": report.detection_rate,
            "names":          report.names,
            "engines_raw":    [
                {"engine_name": e.engine_name,
                 "category":    e.category,
                 "result":      e.result}
                for e in report.engines
            ],
            "file_type":      report.file_type,
            "first_seen":     report.first_seen,
            "last_seen":      report.last_seen,
            "tags":           report.tags,
            "threat_label":   report.threat_label,
            "queried_at":     report.queried_at,
            "cached_ts":      time.time(),
        }
        _save_cache(cache)


# ─────────────────────────────────────────────
#  CLIENT
# ─────────────────────────────────────────────

class VTClient:
    """
    VirusTotal API v3 client.
    Dùng urllib (không cần requests) để zero extra dependencies.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key.strip()
        self._headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    # ── Public API ────────────────────────────────────────────

    def lookup_hash(self, sha256: str) -> VTReport:
        """Tra cứu hash — không upload file, free quota."""
        sha256 = sha256.lower()
        cached = _get_cached(sha256)
        if cached:
            return cached

        report = VTReport(
            sha256=sha256,
            queried_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        try:
            data = self._get(f"/files/{sha256}")
            self._parse_file_report(data, report)
        except _VTNotFound:
            report.found = False
            report.error = "Hash không có trong VirusTotal database"
        except _VTRateLimit:
            report.error = "VirusTotal rate limit — thử lại sau 60 giây"
        except _VTAuthError:
            report.error = "API key không hợp lệ hoặc hết quota"
        except Exception as e:
            report.error = f"Lỗi API: {e}"

        _put_cache(report)
        return report

    def upload_file(self, filepath: str,
                    progress_cb=None) -> VTReport:
        """
        Upload file lên VT để quét.
        progress_cb(msg: str) — callback hiển thị tiến trình.
        """
        sha256 = self._sha256(filepath)
        cached = _get_cached(sha256)
        if cached and cached.found:
            if progress_cb:
                progress_cb("Dùng kết quả từ cache")
            return cached

        report = VTReport(
            sha256=sha256,
            queried_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        try:
            size = os.path.getsize(filepath)
            # Files > 32 MB need special upload URL
            if size > 32 * 1024 * 1024:
                if progress_cb:
                    progress_cb("File > 32MB — lấy upload URL đặc biệt...")
                upload_url_data = self._get("/files/upload_url")
                upload_url = upload_url_data.get("data", VT_BASE + "/files")
            else:
                upload_url = VT_BASE + "/files"

            if progress_cb:
                progress_cb(f"Đang upload {os.path.basename(filepath)} ({size:,} bytes)...")

            scan_id = self._upload(upload_url, filepath)

            if progress_cb:
                progress_cb("Upload xong. Chờ VT phân tích (có thể mất 1–3 phút)...")

            # Poll for result
            for attempt in range(20):
                time.sleep(15)
                if progress_cb:
                    progress_cb(f"  Đang kiểm tra kết quả... (lần {attempt+1}/20)")
                try:
                    data = self._get(f"/analyses/{scan_id}")
                    status = (data.get("data", {})
                                  .get("attributes", {})
                                  .get("status", ""))
                    if status == "completed":
                        # Fetch the actual file report by hash
                        file_data = self._get(f"/files/{sha256}")
                        self._parse_file_report(file_data, report)
                        break
                except Exception:
                    pass
            else:
                report.error = "Timeout chờ kết quả VT (>5 phút)"

        except _VTRateLimit:
            report.error = "Rate limit — thử lại sau"
        except _VTAuthError:
            report.error = "API key không hợp lệ"
        except Exception as e:
            report.error = f"Upload error: {e}"

        _put_cache(report)
        return report

    # ── Internals ─────────────────────────────────────────────

    def _get(self, path: str) -> Dict:
        url = VT_BASE + path
        req = urllib.request.Request(url, headers=self._headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise _VTNotFound()
            if e.code == 429:
                raise _VTRateLimit()
            if e.code in (401, 403):
                raise _VTAuthError()
            raise Exception(f"HTTP {e.code}: {e.reason}")

    def _upload(self, url: str, filepath: str) -> str:
        """Multipart upload, returns analysis ID."""
        boundary = "----VTBoundary" + str(int(time.time()))
        filename = os.path.basename(filepath)

        with open(filepath, "rb") as f:
            file_data = f.read()

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

        headers = dict(self._headers)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        headers["Content-Length"] = str(len(body))

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["data"]["id"]
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise _VTRateLimit()
            if e.code in (401, 403):
                raise _VTAuthError()
            raise Exception(f"Upload HTTP {e.code}")

    def _parse_file_report(self, data: Dict, report: VTReport):
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        report.found          = True
        report.malicious      = stats.get("malicious", 0)
        report.suspicious     = stats.get("suspicious", 0)
        report.undetected     = stats.get("undetected", 0)
        report.harmless       = stats.get("harmless", 0)
        report.total_engines  = sum(stats.values())
        if report.total_engines > 0:
            report.detection_rate = round(
                (report.malicious + report.suspicious) / report.total_engines * 100, 1
            )

        report.file_type    = attrs.get("type_description", "")
        report.tags         = attrs.get("tags", [])
        report.threat_label = (attrs.get("popular_threat_classification", {})
                                    .get("suggested_threat_label", ""))

        # First/last seen
        for key, attr in (("first_seen", "first_submission_date"),
                           ("last_seen",  "last_analysis_date")):
            ts = attrs.get(attr, 0)
            if ts:
                try:
                    setattr(report, key,
                            datetime.datetime.utcfromtimestamp(ts)
                            .strftime("%Y-%m-%d %H:%M UTC"))
                except Exception:
                    pass

        # Engine results
        results = attrs.get("last_analysis_results", {})
        engines = []
        names   = set()
        for eng_name, eng_data in results.items():
            cat = eng_data.get("category", "undetected")
            res = eng_data.get("result") or ""
            engines.append(VTEngineResult(
                engine_name=eng_name,
                category=cat,
                result=res,
            ))
            if cat == "malicious" and res:
                names.add(res)
        report.engines = sorted(engines,
                                key=lambda e: 0 if e.category == "malicious" else 1)
        report.names = sorted(names)[:10]

    @staticmethod
    def _sha256(filepath: str) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


class _VTNotFound(Exception):  pass
class _VTRateLimit(Exception):  pass
class _VTAuthError(Exception):  pass
