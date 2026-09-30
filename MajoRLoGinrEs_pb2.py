# Compatible MajorLogin response parser (OB55)
import base64, json

def _decode_jwt_account_id(token: str):
    if not token or not isinstance(token, str) or token.count(".") < 2:
        return 0
    try:
        payload_b64 = token.split(".")[1]
        pad = "=" * ((4 - len(payload_b64) % 4) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode("utf-8", errors="ignore"))
        for key in ("account_id", "accountId", "uid", "user_id", "sub"):
            if key in data and data[key] is not None:
                return int(data[key])
    except Exception:
        pass
    return 0

class MajorLoginRes:
    def __init__(self):
        self.account_uid = 0
        self.account_id = 0
        self.region = ""
        self.token = ""
        self.url = ""
        self.server_url = ""
        self.timestamp = 0
        self.server_time = 0
        self.key = b""
        self.iv = b""
        self.aes_ak = b""
        self.iv_i = b""

    def ParseFromString(self, data):
        if not data:
            return self
        if b"Protection Bypass" in data and b"eyJ" not in data:
            return self
        # try multiple offsets; keep best
        best = None
        best_score = -1
        for offset in [0] + list(range(1, min(96, len(data)))):
            try:
                cand = MajorLoginRes()
                cand._parse_at(data, offset)
                cand._normalize()
                sc = cand._score()
                if sc > best_score:
                    best_score = sc
                    best = cand
            except Exception:
                continue
        if best and best_score > 0:
            self.__dict__.update(best.__dict__)
        # JWT recovery
        if (not self.account_id or self.account_id <= 0) and self.token:
            aid = _decode_jwt_account_id(self.token)
            if aid:
                self.account_id = aid
                self.account_uid = aid
        if not self.token and b"eyJ" in data:
            i = data.find(b"eyJ")
            j = i
            while j < len(data) and data[j] in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.":
                j += 1
            tok = data[i:j].decode("ascii", errors="ignore")
            if tok.count(".") >= 2:
                self.token = tok
                aid = _decode_jwt_account_id(tok)
                if aid:
                    self.account_id = aid
                    self.account_uid = aid
        return self

    def _score(self):
        s = 0
        if self.token and self.token.startswith("eyJ") and len(self.token) > 40:
            s += 50
        if self.url and "http" in self.url:
            s += 20
        if self.region:
            s += 5
        if self.account_id and int(self.account_id) > 0:
            s += 30
        if isinstance(self.aes_ak, (bytes, bytearray)) and len(self.aes_ak) in (16, 24, 32):
            s += 25
        if isinstance(self.iv_i, (bytes, bytearray)) and len(self.iv_i) in (16, 24, 32):
            s += 25
        return s

    def _normalize(self):
        if self.account_uid and not self.account_id:
            self.account_id = self.account_uid
        if self.url and not self.server_url:
            self.server_url = self.url
        if self.server_url and not self.url:
            self.url = self.server_url
        if self.key and not self.aes_ak:
            self.aes_ak = self.key
        if self.iv and not self.iv_i:
            self.iv_i = self.iv
        if self.aes_ak and not self.key:
            self.key = self.aes_ak
        if self.iv_i and not self.iv:
            self.iv = self.iv_i
        if isinstance(self.aes_ak, (bytes, bytearray)) and 0 < len(self.aes_ak) < 16:
            self.aes_ak = b""; self.key = b""
        if isinstance(self.iv_i, (bytes, bytearray)) and 0 < len(self.iv_i) < 16:
            self.iv_i = b""; self.iv = b""

    def _parse_at(self, data, start):
        i, n = start, len(data)
        while i < n:
            tag = data[i]; i += 1
            fn, wt = tag >> 3, tag & 7
            if wt == 0:
                val, i = self._varint(data, i)
                if fn == 1:
                    self.account_uid = val; self.account_id = val
                elif fn in (18, 21):
                    self.timestamp = val; self.server_time = val
            elif wt == 2:
                ln, i = self._varint(data, i)
                if i + ln > n: break
                raw = data[i:i+ln]; i += ln
                if fn == 2:
                    self.region = raw.decode("utf-8", errors="ignore")
                elif fn == 8:
                    tok = raw.decode("utf-8", errors="ignore")
                    if tok.startswith("eyJ") and len(tok) > len(self.token or ""):
                        self.token = tok
                elif fn == 10:
                    self.url = raw.decode("utf-8", errors="ignore"); self.server_url = self.url
                elif fn in (19, 22) and len(raw) in (16, 24, 32):
                    self.key = raw; self.aes_ak = raw
                elif fn in (20, 23) and len(raw) in (16, 24, 32):
                    self.iv = raw; self.iv_i = raw
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                break

    def _varint(self, data, pos):
        result = shift = 0
        while pos < len(data):
            b = data[pos]; pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        return result, pos
