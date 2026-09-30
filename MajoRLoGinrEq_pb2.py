# Hand-written compatible replacement for MajoRLoGinrEq_pb2
# Field numbers aligned with Free Fire MajorLogin request (OB55 / public schema)

class MajorLogin:
    def __init__(self):
        self._fields = {}

    def __setattr__(self, name, value):
        if name == '_fields':
            super().__setattr__(name, value)
        else:
            self._fields[name] = value

    def __getattr__(self, name):
        if name == '_fields':
            raise AttributeError(name)
        # sensible defaults so missing attrs don't explode
        if name in ('analytics_detail', 'unknown_bytes102', 'key', 'iv', 'gindetail', 'ffantidetail'):
            return b""
        int_names = {
            'platform_id', 'login_by', 'platform_sdk_id', 'login_open_id_type',
            'cpu_type', 'channel_type', 'reg_avatar', 'screen_width', 'screen_height',
            'memory', 'supported_astc_bitset', 'android_engine_init_flag', 'if_push',
            'is_vpn', 'unknown_int85', 'external_storage_total', 'external_storage_available',
            'internal_storage_total', 'internal_storage_available', 'game_disk_storage_total',
            'game_disk_storage_available', 'external_sdcard_total_storage',
            'external_sdcard_avail_storage', 'loading_time', 'zone_area_id', 'level',
            'emulator_score', 'quality', 'lock_region_time',
        }
        if name in int_names:
            return 0
        return ""

    def SerializeToString(self):
        # name -> (field_number, wire_type)
        # wire_type: 0=varint, 2=length-delimited (string/bytes), 9=alias for string
        FIELD_MAP = {
            # Core identity / session
            'event_time':              (3, 9),
            'game_name':               (4, 9),   # gameid
            'platform_id':             (5, 0),   # platid
            'zone_area_id':            (6, 0),
            'client_version':          (7, 9),
            'system_software':         (8, 9),
            'system_hardware':         (9, 9),
            'telecom_operator':        (10, 9),
            'network_type':            (11, 9),
            'screen_width':            (12, 0),
            'screen_height':           (13, 0),
            'screen_dpi':              (14, 9),
            'processor_details':       (15, 9),  # cpuhardware
            'memory':                  (16, 0),
            'gpu_renderer':            (17, 9),  # glrender
            'gpu_version':             (18, 9),  # glversion
            'unique_device_id':         (19, 9),  # deviceid
            'client_ip':               (20, 9),
            'language':                (21, 9),
            'open_id':                 (22, 9),  # openid  *** critical
            'open_id_type':            (23, 9),  # openidtype
            'device_type':             (24, 9),
            'device_model':            (25, 9),
            'region':                  (26, 9),
            'access_token':            (29, 9),  # logintoken  *** critical
            'platform_sdk_id':         (30, 0),
            'network_operator_a':      (35, 9),
            'network_type_a':          (36, 9),
            # Storage
            'external_storage_total':      (42, 0),
            'external_storage_available':  (43, 0),
            'internal_storage_total':      (44, 0),
            'internal_storage_available':  (45, 0),
            'game_disk_storage_available': (46, 0),
            'game_disk_storage_total':     (47, 0),
            'external_sdcard_avail_storage': (48, 0),
            'external_sdcard_total_storage': (49, 0),
            # Auth / client meta
            'login_by':                (50, 0),
            'reg_avatar':              (53, 0),
            'library_path':            (56, 9),  # libpath
            'library_token':           (58, 9),  # libtoken
            'channel_type':            (59, 0),
            'cpu_type':                (60, 0),
            'cpu_architecture':        (61, 9),
            'client_version_code':     (62, 9),
            'graphics_api':            (65, 9),  # systemgraphicsapi
            'supported_astc_bitset':   (66, 0),
            'login_open_id_type':      (67, 0),
            'loading_time':            (70, 0),
            'release_channel':         (71, 9),
            'analytics_detail':        (72, 2),  # gindetail (bytes)
            'android_engine_init_flag':(73, 0),
            'extra_info':              (74, 9),
            'if_push':                 (75, 0),  # bool as varint
            'is_vpn':                  (76, 0),
            'origin_platform_type':    (77, 9),  # orignplatformtype
            'primary_platform_type':   (78, 9),
            # OB55 requires explicit platform strings
            'platform_str':            (99, 9),  # platform
            'main_active_platform':    (100, 9), # mainactiveplatform
            'client_using_version':    (57, 9),
            'extra_json':              (101, 9),
            'unknown_bytes102':        (102, 2),
            'unknown_int85':           (85, 0),
        }
        out = b""
        for fname, (fnum, wtype) in FIELD_MAP.items():
            val = self._fields.get(fname)
            if val is None:
                continue
            if wtype == 0:
                if isinstance(val, bool):
                    val = 1 if val else 0
                if isinstance(val, int) and val != 0:
                    out += self._encode_varint((fnum << 3) | 0)
                    out += self._encode_varint(val & 0xFFFFFFFFFFFFFFFF)
            elif wtype in (2, 9):
                if isinstance(val, str) and val:
                    enc = val.encode('utf-8')
                    out += self._encode_varint((fnum << 3) | 2)
                    out += self._encode_varint(len(enc))
                    out += enc
                elif isinstance(val, (bytes, bytearray)) and val:
                    out += self._encode_varint((fnum << 3) | 2)
                    out += self._encode_varint(len(val))
                    out += bytes(val)
        return out

    def _encode_varint(self, value):
        value = int(value)
        result = b""
        bits = value & 0x7F
        value >>= 7
        while value:
            result += bytes([0x80 | bits])
            bits = value & 0x7F
            value >>= 7
        result += bytes([bits])
        return result
