import base64, json, os
import random, time
import hashlib
import uuid
import pytz
import execjs
from datetime import datetime
import binascii, secrets
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from src.bda.bda_template import FunCaptchaOptions
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from curl_cffi import requests
from src.utilities.headers import Headers
from typing import Dict, Any, List

from src.config import enforcement_hash

with open("arkose.js") as file:
    gctx = execjs.compile(file.read())

with open("webgl.json") as file:
    webgls = json.loads(file.read())

class Arkose:
    @staticmethod
    def decrypt_data(data, main):
        ciphertext = base64.b64decode(data['ct'])
        iv_bytes = binascii.unhexlify(data['iv'])
        salt_bytes = binascii.unhexlify(data['s'])
        salt_words = Arkose.from_sigbytes(salt_bytes)
        key_words = Arkose.generate_other_key(main, salt_words)
        key_bytes = Utils.to_sigbytes(key_words, 32)
        iv_bytes = Utils.to_sigbytes(key_words[-4:], 16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    @staticmethod
    def encrypt_ct(text: bytes, key: bytes, iv: bytes) -> bytes:
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plain_text = padder.update(text) + padder.finalize()
        cipher_text = encryptor.update(padded_plain_text) + encryptor.finalize()
        return cipher_text

    @staticmethod
    def from_sigbytes(sigBytes: bytes) -> list:
        padded_length = (len(sigBytes) + 3) // 4 * 4
        padded_bytes = sigBytes.ljust(padded_length, b'\0')
        words = [int.from_bytes(padded_bytes[i:i + 4], byteorder='big') for i in range(0, len(padded_bytes), 4)]
        return words

    @staticmethod
    def make_encrypted_dict(data: str, useragent: str, x_ark_value: str) -> str:
        s_value = Utils.hex(Utils.uint8_array(8))
        iv_value = Utils.uint8_array(16)
        key = Arkose.generate_key(
            gctx,
            s_value,
            f"{useragent}{x_ark_value}"
        )

        result = Arkose.encrypt_ct(
            text=bytes(data.encode()),
            key=bytes(key),
            iv=bytes(iv_value)
        )

        return json.dumps({
            "ct": base64.b64encode(result).decode(),
            "s": s_value,
            "iv": Utils.hex(iv_value)
        }).replace(" ", "")

    @staticmethod
    def generate_key(ctx: execjs.compile, s_value: str, useragent: str) -> list:
        key = Utils.dict_to_list(ctx.call(
            'genkey',
            useragent,
            s_value
        ))
        return key

class Utils:
    @staticmethod
    def hex(data: str) -> str:
        return ''.join(f'{byte:02x}' for byte in data)

    @staticmethod
    def uint8_array(size: int) -> list:
        v = bytearray(size)
        for i in range(len(v)):
            v[i] = Utils.random_integer(256)
        return Utils.bytes_to_buffer(v)

    @staticmethod
    def random_integer(value: int) -> int:
        max_random_value = (2 ** 32 // value) * value
        while True:
            a = secrets.randbelow(2 ** 32)
            if a < max_random_value:
                return a % value

    @staticmethod
    def bytes_to_buffer(data: bytes) -> list:
        buffer = BytesIO(data)
        buffer.seek(0)
        content = buffer.read()
        return list(content)

    @staticmethod
    def dict_to_list(data: dict) -> list:
        result = []
        for obj in data:
            result.append(data[obj])
        return result

    @staticmethod
    def to_sigbytes(words: list, sigBytes: int) -> list:
        result = b''.join(Utils.int_to_bytes(word, 4) for word in words)
        return result[:sigBytes]

    @staticmethod
    def int_to_bytes(n: str, length: int) -> bytes:
        return n.to_bytes(length, byteorder='big', signed=True)

def md5_hash(data: str) -> str:
    md5_hash = hashlib.md5()
    md5_hash.update(data.encode('utf-8'))
    return md5_hash.hexdigest()

def process_fp(fpdata: list) -> str:
    result = []
    for item in fpdata:
        result.append(item.split(":")[1])
    return ';'.join(result)

def proccess_webgl2(data: list) -> str:
    result = []
    for item in data:
        result.append(item["key"])
        result.append(item["value"])
    return ','.join(result) + ',webgl_hash_webgl,'

def random_pixel_depth() -> int:
    pixel_depths = [24, 30]
    return random.choice(pixel_depths)

def update_fingerprint_data(
    decrypted_fingerprint: list[dict[str, str]], method: str, useragent: str
) -> list[dict[str, str]]:
    try:
        decrypted_fingerprint_dict: dict[str, str] = convert_json_to_dict(
            decrypted_fingerprint
        )
        enhanced_fingerprint_data: dict[str, str] = convert_json_to_dict(
            decrypted_fingerprint_dict["enhanced_fp"]
        )
        decrypted_fingerprint_dict["enhanced_fp"] = convert_dict_to_json(
            enhanced_fingerprint_data
        )
        decrypted_fingerprint: list[dict[str, str]] = convert_dict_to_json(
            decrypted_fingerprint_dict
        )
    except Exception as error:
        raise Exception("Unable to update fingerprint data: " + str(error))
    return decrypted_fingerprint


def prepare_fingerprint_data(fingerprint: dict) -> str:
    formatted_data = []
    for key, value in fingerprint.items():
        if isinstance(value, list):
            formatted_data.append(",".join(map(str, value)))
        else:
            formatted_data.append(str(value))
    return ";".join(formatted_data)


def prepare_fingerprint_entries(fp: dict) -> list[str]:
    formatted_entries = [f"{key}:{value}" for key, value in fp.items()]
    return formatted_entries


def parse_fingerprint_entries(fingerprint_entries: list[str]) -> dict:
    parsed_fp = {}
    for entry in fingerprint_entries:
        key, value = entry.split(":")
        parsed_fp[key] = value
    return parsed_fp


def identify_user_platform(user_agent: str) -> str:
    platform_mapping = {
        "iPhone": "iPhone",
        "Intel Mac OS": "MacIntel",
        "Windows": "Win32",
        "Android": lambda: random.choice(["Linux aarch64", "Linux armv7l"]),
        "Linux": "Linux x86_64",
    }
    return next(
        (
            (platform() if callable(platform) else platform)
            for platform_name, platform in platform_mapping.items()
            if platform_name in user_agent
        ),
        "Linux armv8",
    )

def convert_json_to_dict(json_data: list[dict[str, str]]) -> dict[str, str]:
    result_dict: dict[str, str] = {}
    for item in json_data:
        key: str = item.get("key")
        value: str = item.get("value")
        result_dict[key] = value
    return result_dict


def convert_dict_to_json(original_dict: dict[str, str]) -> list[dict[str, str]]:
    json_data: list[dict[str, str]] = [
        {"key": key, "value": value} for key, value in original_dict.items()
    ]
    return json_data

def getIpInfo(proxy: str) -> int:
    try:
        proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        
        response = requests.get(
            "https://api.ipify.org/?format=json", 
            proxies=proxy_dict, 
            timeout=10
        ).json()
        ip_address = response.get('ip', '')
        
        geo_data = requests.get(
            f"https://ipinfo.io/{ip_address}/json",
            proxies=proxy_dict,
            timeout=10
        ).json()
        
        timezone_str = geo_data.get("timezone", "America/New_York")
        
        tz = pytz.timezone(timezone_str)
        current_time = datetime.now(tz)
        utc_offset = int(current_time.utcoffset().total_seconds() / 60)
        
        return utc_offset
    except Exception:
        return 0

def generate_browser_data(
    headers: Headers, method: str = None, proxy=None, xark=None, custom_headers=None, retry_count: int = 0, referrer=None
) -> tuple[str, str, str, Dict[Any, Any]]:
    #global _cached_cfp, _last_cfp_update

    data2use = FunCaptchaOptions(method=method)
    data2use.get_options()
    shit2use = data2use.options
    
    if retry_count >= 3:
        raise Exception("Failed to generate valid browser data after 3 attempts")

    time_now = time.time()
    x_ark_value = xark if xark else str(int(time.time() / 21600) * 21600)

    headerdict = headers.headers()
    if custom_headers:
        headerdict.update(custom_headers)

    user_agent: str = headerdict["User-Agent"]
    headers.ua = user_agent

    webgl_data = random.choice(webgls)
    H = webgl_data["fe"]["H"]
    CFP = webgl_data["fe"]["CFP"]
    S = webgl_data["fe"]["S"]
    AS = webgl_data["fe"]["AS"]
    # Use cached CFP
    #CFP = _cached_cfp
    
    offet = int(getIpInfo(proxy))
    offet = -offet

    fp1 = [
        "DNT:unknown",
        f"L:en-GB",
        "D:24",
        "PR:1",
        f"S:{S}",
        f"AS:{AS}",
        f"TO:{offet}",
        "SS:true",
        "LS:true",
        "IDB:true",
        "B:false",
        "ODB:false",
        "CPUC:unknown",
        f"PK:Win32",
        f"CFP:{CFP}",
        "FR:false",
        "FOS:false",
        "FB:false",
        f"JSF:",
        f"P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF",
        "T:0,false,false",
        f"H:{H}",
        "SWF:false"
    ]

    try:
        if "enhanced_fp" in webgl_data:
            webgl = webgl_data["enhanced_fp"]
            if isinstance(webgl, list) and len(webgl) > 0 and isinstance(webgl[0], dict):
                webgl = webgl[0]
        elif "enhanced_fp" in webgl_data.get("fe", {}):
            webgl = webgl_data["fe"]["enhanced_fp"]
            if isinstance(webgl, list) and len(webgl) > 0 and isinstance(webgl[0], dict):
                webgl = webgl[0]
        else:
            webgl = {}
    except Exception as e:
        print(f"Error processing webgl_data: {str(e)}")
        webgl = {}
    enhanced_fp = []
    
    webgl_properties = [
        "webgl_extensions", "webgl_extensions_hash", "webgl_renderer",
        "webgl_vendor", "webgl_version", "webgl_shading_language_version",
        "webgl_aliased_line_width_range", "webgl_aliased_point_size_range", 
        "webgl_antialiasing", "webgl_bits", "webgl_max_params",
        "webgl_max_viewport_dims", "webgl_unmasked_vendor", "webgl_unmasked_renderer",
        "webgl_vsf_params", "webgl_vsi_params", "webgl_fsf_params", "webgl_fsi_params"
    ]
    
    for prop in webgl_properties:
        if prop in webgl:
            enhanced_fp.append({
                "key": prop,
                "value": webgl.get(prop, "")
            })

    enhanced_fp.append({
        "key": "webgl_hash_webgl",
        "value": webgl.get("webgl_hash_webgl", "")
    })

    enhanced_fp_more = [
        {
            "key": "user_agent_data_brands",
            "value": "Microsoft Edge,Not-A.Brand,Chromium"
        },
        {
            "key": "user_agent_data_mobile",
            "value": False
        },
        {
            "key": "navigator_connection_downlink",
            "value": 10
        },
        {
            "key": "navigator_connection_downlink_max",
            "value": None
        },
        {
            "key": "network_info_rtt",
            "value": 50
        },
        {
            "key": "network_info_save_data",
            "value": False
        },
        {
            "key": "network_info_rtt_type",
            "value": None
        },
        {
            "key": "screen_pixel_depth",
            "value": 24
        },
        {
            "key": "navigator_device_memory",
            "value": 8
        },
        {
            "key": "navigator_pdf_viewer_enabled",
            "value": True
        },
        {
            "key": "navigator_languages",
            "value": "en-GB,en"
        },
        {
            "key": "window_inner_width",
            "value": 0
        },
        {
            "key": "window_inner_height", 
            "value": 0
        },
        {
            "key": "window_outer_width",
            "value": int(AS.split(",")[0])
        },
        {
            "key": "window_outer_height",
            "value": int(AS.split(",")[1])
        },
        {
            "key": "browser_detection_firefox",
            "value": False
        },
        {
            "key": "browser_detection_brave",
            "value": False
        },
        {
            "key": "browser_api_checks",
            "value": [
                "permission_status: true",
                "eye_dropper: true",
                "audio_data: true",
                "writable_stream: true",
                "css_style_rule: true",
                "navigator_ua: true",
                "barcode_detector: false",
                "display_names: true",
                "contacts_manager: false",
                "svg_discard_element: false",
                "usb: defined",
                "media_device: defined",
                "playback_quality: true"
            ]
        },
        {
            "key": "browser_object_checks",
            "value": "554838a8451ac36cb977e719e9d6623c"
        },
        {
            "key": "29s83ih9",
            "value": "68934a3e9455fa72420237eb05902327⁣"
        },
        {
            "key": "audio_codecs",
            "value": "{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"
        },
        {
            "key": "audio_codecs_extended_hash",
            "value": "805036349642e2569ec299baed02315b"
        },
        {
            "key": "video_codecs",
            "value": "{\"ogg\":\"\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"
        },
        {
            "key": "video_codecs_extended_hash",
            "value": "cb2c967d0cd625019556b39c63f7d435"
        },
        {
            "key": "media_query_dark_mode",
            "value": False
        },
        {
            "key": "css_media_queries",
            "value": 1
        },
        {
            "key": "css_color_gamut",
            "value": "srgb"
        },
        {
            "key": "css_contrast",
            "value": "no-preference"
        },
        {
            "key": "css_monochrome",
            "value": False
        },
        {
            "key": "css_pointer",
            "value": "fine"
        },
        {
            "key": "css_grid_support",
            "value": False
        },
        {
            "key": "headless_browser_phantom",
            "value": False
        },
        {
            "key": "headless_browser_selenium",
            "value": False
        },
        {
            "key": "headless_browser_nightmare_js",
            "value": False
        },
        {
            "key": "headless_browser_generic",
            "value": 4
        },
        {
            "key": "1l2l5234ar2",
            "value": str(int(time_now * 1000)) + "⁣"
        },
        {
            "key": "document__referrer",
            "value": shit2use['document__referrer'] if not referrer else referrer
        },
        {
            "key": "window__ancestor_origins",
            "value": shit2use['window__ancestor_origins']
        },
        {
            "key": "window__tree_index",
            "value": shit2use['window__tree_index']
        },
        {
            "key": "window__tree_structure",
            "value": shit2use['window__tree_structure']
        },
        {
            "key": "window__location_href",
            "value": shit2use['window__location_href']
        },
        {
            "key": "client_config__sitedata_location_href",
            "value": shit2use['client_config__sitedata_location_href']
        },
        {
            "key": "client_config__language",
            "value": shit2use['client_config__language']
        },
        {
            "key": "client_config__surl",
            "value": shit2use['client_config__surl']
        },
        {
            "key": "c8480e29a",
            "value": md5_hash(shit2use['client_config__surl']) + "⁢"
        },
        {
            "key": "client_config__triggered_inline",
            "value": False
        },
        {
            "key": "mobile_sdk__is_sdk",
            "value": False
        },
        {
            "key": "audio_fingerprint",
            "value": webgl['audio_fingerprint']
        },
        {
            "key": "navigator_battery_charging",
            "value": True
        },
        {
            "key": "media_device_kinds",
            "value": [
                "audiooutput"
            ]
        },
        {
            "key": "media_devices_hash",
            "value": "eba8b0db4bf7d1f1bfb964d48f6c1784"
        },
        {
            "key": "navigator_permissions_hash", 
            "value": "67419471976a14a1430378465782c62d"
        },
        {
            "key": "math_fingerprint",
            "value": "0ce80c69b75667d69baedc0a70c82da7"
        },
        {
            "key": "supported_math_functions",
            "value": "67d1759d7e92844d98045708c0a91c2f"
        },
        {
            "key": "screen_orientation",
            "value": "landscape-primary"
        },
        {
            "key": "rtc_peer_connection",
            "value": 5
        },
        {
            "key": "4b4b269e68",
            "value": str(uuid.uuid4())
        },
        {
            "key": "6a62b2a558",
            "value": enforcement_hash
        },
        {
            "key": "is_keyless",
            "value": False
        },
        {
            "key": "c2d2015",
            "value": "29d13b1af8803cb86c2697345d7ea9eb"
        },
        {
            "key": "43f2d94",
            "value": False
        },
        {
            "key": "20c15922",
            "value": True
        },
        {
            "key": "4f59ca8",
            "value": None
        },
        {
            "key": "speech_default_voice",
            "value": "Microsoft David - English (United States) || en-US"
        },
        {
            "key": "speech_voices_hash",
            "value": "9b82b0cd905a61a38c299e683f46e162"
        },
        {
            "key": "4ca87df3d1",
            "value": "Ow=="
        },
        {
            "key": "867e25e5d4",
            "value": "Ow=="
        },
        {
            "key": "d4a306884c",
            "value": "Ow=="
        }
    ]

    for item in enhanced_fp_more:
        enhanced_fp.append(item)

    fp = [
        {
            "key": "api_type",
            "value": "js"
        },
        {
            "key": "f",
            "value": gctx.call("x64hash128", process_fp(fp1), 0)
        },
        {
            "key": "n",
            "value": base64.b64encode(str(int(time_now)).encode()).decode()
        },
        {
            "key": "wh",
            "value": f"{secrets.token_hex(16)}|cc7fecdd5c8bec57541ae802c7648eed"
        },
        {
            "key": "enhanced_fp",
            "value": enhanced_fp
        },
        {
            "key": "fe",
            "value": fp1
        },
        {
            "key": "ife_hash",
            "value": gctx.call("x64hash128", ", ".join(fp1), 38)
        },
        {
            "key": "jsbd",
            "value": "{\"HL\":2,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DMTO\":1,\"DOTO\":1}"
        }
    ]

    encrypted_data = Arkose.make_encrypted_dict(json.dumps(fp, separators=(',', ':'),
                                                         ensure_ascii=False), user_agent, x_ark_value)
    base64_encrypted_data = base64.b64encode(encrypted_data.encode()).decode()

    return (
        base64_encrypted_data,
        user_agent,
        json.dumps(fp, separators=(',', ':'), ensure_ascii=False),
        {},
    )