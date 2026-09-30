# Hand-written compatible replacement for MajoRLoGinrEq_pb2
# Works with all protobuf versions — pure Python serializer

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
        return self._fields.get(name, b"" if name in ('analytics_detail','unknown_bytes102','key','iv') else ("" if name not in ('platform_id','login_by','platform_sdk_id','login_open_id_type','cpu_type','channel_type','reg_avatar','screen_width','screen_height','memory','supported_astc_bitset','android_engine_init_flag','if_push','is_vpn','unknown_int85','external_storage_total','external_storage_available','internal_storage_total','internal_storage_available','game_disk_storage_total','game_disk_storage_available','external_sdcard_total_storage','external_sdcard_avail_storage','loading_time','unknown_int85') else 0))

    def SerializeToString(self):
        # Field number -> (wire_type, value)
        FIELD_MAP = {
            'event_time': (1, 9), 'game_name': (2, 9),
            'platform_id': (3, 0), 'client_version': (4, 9),
            'system_software': (5, 9), 'system_hardware': (6, 9),
            'telecom_operator': (7, 9), 'network_type': (8, 9),
            'screen_width': (9, 0), 'screen_height': (10, 0),
            'screen_dpi': (11, 9), 'processor_details': (12, 9),
            'memory': (13, 0), 'gpu_renderer': (14, 9),
            'gpu_version': (15, 9), 'unique_device_id': (16, 9),
            'client_ip': (17, 9), 'language': (18, 9),
            'open_id': (19, 9), 'open_id_type': (20, 9),
            'device_type': (21, 9), 'device_model': (22, 9),
            'region': (23, 9), 'access_token': (24, 9),
            'platform_sdk_id': (25, 0), 'network_operator_a': (26, 9),
            'network_type_a': (27, 9), 'client_using_version': (28, 9),
            'external_storage_total': (29, 0), 'external_storage_available': (30, 0),
            'internal_storage_total': (31, 0), 'internal_storage_available': (32, 0),
            'game_disk_storage_available': (33, 0), 'game_disk_storage_total': (34, 0),
            'external_sdcard_avail_storage': (35, 0), 'external_sdcard_total_storage': (36, 0),
            'login_by': (37, 0), 'library_path': (38, 9),
            'reg_avatar': (39, 0), 'library_token': (40, 9),
            'channel_type': (41, 0), 'cpu_type': (42, 0),
            'cpu_architecture': (43, 9), 'client_version_code': (44, 9),
            'unknown_int85': (85, 0), 'graphics_api': (46, 9),
            'supported_astc_bitset': (47, 0), 'login_open_id_type': (48, 0),
            'analytics_detail': (49, 2), 'loading_time': (50, 0),
            'release_channel': (51, 9), 'extra_info': (52, 9),
            'extra_json': (53, 9), 'android_engine_init_flag': (54, 0),
            'if_push': (55, 0), 'is_vpn': (56, 0),
            'origin_platform_type': (57, 9), 'primary_platform_type': (58, 9),
            'unknown_bytes102': (102, 2),
        }
        out = b""
        for fname, (fnum, wtype) in FIELD_MAP.items():
            val = self._fields.get(fname)
            if val is None: continue
            if wtype == 0:
                if isinstance(val, int) and val != 0:
                    out += self._encode_varint((fnum << 3) | 0)
                    out += self._encode_varint(val)
            elif wtype == 9:
                if isinstance(val, str) and val:
                    enc = val.encode('utf-8')
                    out += self._encode_varint((fnum << 3) | 2)
                    out += self._encode_varint(len(enc))
                    out += enc
            elif wtype == 2:
                if isinstance(val, (bytes, bytearray)) and val:
                    out += self._encode_varint((fnum << 3) | 2)
                    out += self._encode_varint(len(val))
                    out += bytes(val)
        return out

    def _encode_varint(self, value):
        bits = value & 0x7F
        value >>= 7
        result = b""
        while value:
            result += bytes([0x80 | bits])
            bits = value & 0x7F
            value >>= 7
        result += bytes([bits])
        return result
