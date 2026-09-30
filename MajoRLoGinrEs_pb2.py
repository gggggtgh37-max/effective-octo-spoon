# Hand-written compatible replacement for MajoRLoGinrEs_pb2
# Field numbers aligned with Free Fire MajorLogin response (OB55)

import base64
import json


def _decode_jwt_account_id(token: str):
    """Pull account_id from JWT payload when protobuf field 1 is missing."""
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


def _find_jwt_in_bytes(data: bytes) -> str:
    """Locate eyJ... JWT anywhere in the raw response body."""
    if not data:
        return ""
    idx = data.find(b"eyJ")
    if idx < 0:
        return ""
    # JWT charset
    end = idx
    while end < len(data) and data[end] in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.":
        end += 1
    tok = data[idx:end].decode("ascii", errors="ignore")
    if tok.count(".") >= 2 and len(tok) > 40:
        return tok
    return ""


class MajorLoginRes:
    def __init__(self):
        self.account_uid = 0
        self.account_id = 0
        self.region = ""
        self.noti_region = ""
        self.ip_region = ""
        self.token = ""
        self.url = ""
        self.server_url = ""
        self.timestamp = 0
        self.server_time = 0
        self.key = b""
        self.iv = b""
        self.aes_ak = b""
        self.iv_i = b""
        self.ttl = 0
        self.emulator_score = 0
        self.kts = 0

    def ParseFromString(self, data):
        """Parse response; pick the best offset (longest JWT + real AES keys)."""
        if not data:
            return self

        # Hard reject anti-bot body
        if b"Protection Bypass" in data and b"eyJ" not in data:
            return self

        candidates = []
        max_off = min(128, len(data))
        for offset in [0] + list(range(1, max_off)):
            self._reset()
            try:
                self._parse_at(data, offset)
            except Exception:
                continue
            self._normalize()
            score = self._score()
            if score > 0:
                candidates.append((score, offset, self._snapshot()))

        # Also try JWT-only recovery from raw body
        jwt = _find_jwt_in_bytes(data)
        if jwt:
            self._reset()
            self.token = jwt
            self.account_id = _decode_jwt_account_id(jwt)
            # try to still get url/region/keys from best protobuf pass
            if candidates:
                best = max(candidates, key=lambda x: x[0])[2]
                for k, v in best.items():
                    if k == "token" and self.token:
                        continue
                    if k == "account_id" and self.account_id:
                        continue
                    setattr(self, k, v)
            self._normalize()
            if self.account_id and self.token:
                return self

        if not candidates:
            return self

        # Prefer highest score
        best = max(candidates, key=lambda x: x[0])[2]
        self._reset()
        for k, v in best.items():
            setattr(self, k, v)
        self._normalize()
        return self

    def _score(self) -> int:
        score = 0
        if self.token and self.token.startswith("eyJ") and len(self.token) > 40:
            score += 50 + min(len(self.token), 500) // 10
        if self.url and "http" in self.url:
            score += 20
        if self.region:
            score += 5
        if self.account_id and int(self.account_id) > 0:
            score += 30
        if isinstance(self.aes_ak, (bytes, bytearray)) and len(self.aes_ak) in (16, 24, 32):
            score += 25
        if isinstance(self.iv_i, (bytes, bytearray)) and len(self.iv_i) in (16, 24, 32):
            score += 25
        # penalize garbage 1-byte keys
        if isinstance(self.aes_ak, (bytes, bytearray)) and 0 < len(self.aes_ak) < 16:
            score -= 20
        if isinstance(self.iv_i, (bytes, bytearray)) and 0 < len(self.iv_i) < 16:
            score -= 20
        return score

    def _snapshot(self) -> dict:
        return {
            "account_uid": self.account_uid,
            "account_id": self.account_id,
            "region": self.region,
            "noti_region": self.noti_region,
            "ip_region": self.ip_region,
            "token": self.token,
            "url": self.url,
            "server_url": self.server_url,
            "timestamp": self.timestamp,
            "server_time": self.server_time,
            "key": self.key,
            "iv": self.iv,
            "aes_ak": self.aes_ak,
            "iv_i": self.iv_i,
            "ttl": self.ttl,
            "emulator_score": self.emulator_score,
            "kts": self.kts,
        }

    def _normalize(self):
        if self.account_uid and not self.account_id:
            self.account_id = self.account_uid
        if self.server_url and not self.url:
            self.url = self.server_url
        if self.url and not self.server_url:
            self.server_url = self.url
        if self.kts and not self.server_time:
            self.server_time = self.kts
        if self.timestamp and not self.server_time:
            self.server_time = self.timestamp
        if self.key and not self.aes_ak:
            self.aes_ak = self.key
        if self.iv and not self.iv_i:
            self.iv_i = self.iv
        if self.aes_ak and not self.key:
            self.key = self.aes_ak
        if self.iv_i and not self.iv:
            self.iv = self.iv_i
        # Drop garbage 1-byte keys so validation fails cleanly
        if isinstance(self.aes_ak, (bytes, bytearray)) and 0 < len(self.aes_ak) < 16:
            self.aes_ak = b""
            self.key = b""
        if isinstance(self.iv_i, (bytes, bytearray)) and 0 < len(self.iv_i) < 16:
            self.iv_i = b""
            self.iv = b""
        # JWT fallback for account_id
        if (not self.account_id or int(self.account_id) <= 0) and self.token:
            aid = _decode_jwt_account_id(self.token)
            if aid:
                self.account_id = aid
                self.account_uid = aid

    def _reset(self):
        self.__init__()

    def _parse_at(self, data, start):
        i = start
        n = len(data)
        while i < n:
            tag_byte = data[i]
            i += 1
            field_number = tag_byte >> 3
            wire_type = tag_byte & 0x7
            if wire_type == 0:  # varint
                val, i = self._read_varint(data, i)
                if field_number == 1:
                    self.account_uid = val
                    self.account_id = val
                elif field_number == 9:
                    self.ttl = val
                elif field_number == 11:
                    self.emulator_score = val
                elif field_number == 18:  # kts
                    self.kts = val
                    self.server_time = val
                    self.timestamp = val
                elif field_number == 21:
                    self.timestamp = val
                    if not self.server_time:
                        self.server_time = val
            elif wire_type == 2:  # length-delimited
                length, i = self._read_varint(data, i)
                if i + length > n:
                    break
                raw = data[i:i + length]
                i += length
                if field_number == 2:  # lockRegion
                    self.region = raw.decode("utf-8", errors="ignore")
                elif field_number == 3:
                    self.noti_region = raw.decode("utf-8", errors="ignore")
                    if not self.region:
                        self.region = self.noti_region
                elif field_number == 4:
                    self.ip_region = raw.decode("utf-8", errors="ignore")
                elif field_number == 8:  # token
                    tok = raw.decode("utf-8", errors="ignore")
                    if tok.startswith("eyJ") and len(tok) > len(self.token or ""):
                        self.token = tok
                elif field_number == 10:  # serverUrl
                    self.url = raw.decode("utf-8", errors="ignore")
                    self.server_url = self.url
                elif field_number == 19:  # ak
                    if len(raw) in (16, 24, 32):
                        self.key = raw
                        self.aes_ak = raw
                elif field_number == 20:  # aiv
                    if len(raw) in (16, 24, 32):
                        self.iv = raw
                        self.iv_i = raw
                elif field_number == 22:
                    if len(raw) in (16, 24, 32) and not self.key:
                        self.key = raw
                        self.aes_ak = raw
                elif field_number == 23:
                    if len(raw) in (16, 24, 32) and not self.iv:
                        self.iv = raw
                        self.iv_i = raw
            elif wire_type == 5:
                i += 4
            elif wire_type == 1:
                i += 8
            else:
                break
        return self

    def _read_varint(self, data, pos):
        result = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift > 63:
                break
        return result, pos
