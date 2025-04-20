from src.config import capi_version, enforcement_hash
from typing import Optional, Dict, Any
import hashlib
import random
import time
import os
import json
import glob
import uuid
import base64


class FunCaptchaSession:
    def __init__(
        self,
        public_key: Optional[str] = None,
        service_url: Optional[str] = None,
        site_url: Optional[str] = None,
        capi_mode: str = "lightbox",
        method: Optional[str] = None,
        blob: Optional[str] = None,
    ):
        self.method: Optional[str] = method
        self.public_key: Optional[str] = public_key
        self.service_url: Optional[str] = service_url
        self.site_url: Optional[str] = site_url
        self.capi_mode: str = capi_mode
        self.blob: Optional[str] = blob

        if method:
            self.get_method()

    def get_method(self) -> None:
        if self.method == "outlook":
            self.public_key = "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"
            self.service_url = "https://client-api.arkoselabs.com"
            self.site_url = "https://iframe.arkoselabs.com"
            self.capi_mode = "inline"
            self.language = "en"
        elif self.method == "twitter":
            self.public_key = "2CB16598-CB82-4CF7-B332-5990DB66F3AB"
            self.service_url = "https://client-api.arkoselabs.com"
            self.site_url = "https://iframe.arkoselabs.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "twitter_unlock":
            self.public_key = "0152B4EB-D2DC-460A-89A1-629838B529C9"
            self.service_url = "https://client-api.arkoselabs.com"
            self.site_url = "https://iframe.arkoselabs.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "roblox_signup":
            self.public_key = "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F"
            self.service_url = "https://arkoselabs.roblox.com"
            self.site_url = "https://www.roblox.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "roblox_login":
            self.public_key = "476068BF-9607-4799-B53D-966BE98E2B81"
            self.service_url = "https://arkoselabs.roblox.com"
            self.site_url = "https://www.roblox.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "roblox_join":
            self.public_key = "63E4117F-E727-42B4-6DAA-C8448E9B137F"
            self.service_url = "https://arkoselabs.roblox.com"
            self.site_url = "https://www.roblox.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "ea":
            self.public_key = "73BEC076-3E53-30F5-B1EB-84F494D43DBA"
            self.service_url = "https://ea-api.arkoselabs.com"
            self.site_url = "https://signin.ea.com"
            self.capi_mode = "lightbox"
            self.language = None
        elif self.method == "github-signup":
            self.public_key = "747B83EC-2CA3-43AD-A7DF-701F286FBABA"
            self.service_url = "https://github-api.arkoselabs.com"
            self.site_url = "https://octocaptcha.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "demo":
            self.public_key = "DF9C4D87-CB7B-4062-9FEB-BADB6ADA61E6"
            self.service_url = "https://client-api.arkoselabs.com"
            self.site_url = "https://demo.arkoselabs.com"
            self.capi_mode = "inline"
            self.language = "en"
        elif self.method == "roblox_wall":
            self.public_key = "63E4117F-E727-42B4-6DAA-C8448E9B137F"
            self.service_url = "https://arkoselabs.roblox.com"
            self.site_url = "https://www.roblox.com"
            self.capi_mode = "inline"
            self.language = None
        elif self.method == "airbnb-register":
            self.public_key = "2F0D6CB5-ACAC-4EA9-9B2A-A5F90A2DF15E"
            self.service_url = "https://airbnb-api.arkoselabs.com"
            self.site_url = "https://www.airbnb.com"
            self.capi_mode = "inline"
            self.language = "en"
        else:
            raise Exception("Invalid method")


class FunCaptchaOptions:
    def __init__(
        self,
        options: Optional[Dict[str, Any]] = None,
        method: Optional[str] = None
    ):
        self.method: Optional[str] = method
        self.options: Optional[Dict[str, Any]] = options
        self.hashing = lambda data: hashlib.md5(
            data.encode() if isinstance(data, str) else data
        ).hexdigest()

    def _adjust_for_browser(self, useragent: str) -> None:
        is_firefox = "firefox" in useragent.lower()
        is_chrome = "chrome" in useragent.lower()
        
        if is_firefox:
            self.options["window__ancestor_origins"] = "null"
            self.options["user_agent_data_brands"] = None
            self.options["user_agent_data_mobile"] = None
        elif is_chrome:
            fingerprint = FunCaptchaOptions._profile_10
            
            # Process all fingerprint components with randomization
            for item in fingerprint:
                if item["key"] == "enhanced_fp":
                    enhanced_fp = {}
                    for fp_item in item["value"]:
                        key = fp_item["key"]
                        value = fp_item["value"]
                        
                        # Chrome 132 specific values and randomization
                        if key == "4b4b269e68":  # Random UUID
                            value = str(uuid.uuid4())
                        elif key == "audio_fingerprint":  # Random audio fingerprint
                            value = str(124.04219653179191 + random.uniform(0.001, 0.003))
                        elif key == "1l2l5234ar2":  # Random timestamp
                            value = str(int(time.time() * 1000)) + "\u2062"
                        elif key == "webgl_extensions":
                            # Chrome 132 WebGL extensions
                            value = "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_float;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"
                        elif key == "webgl_renderer":
                            value = "WebKit WebGL"
                        elif key == "webgl_vendor":
                            value = "WebKit"
                        elif key == "webgl_version":
                            value = "WebGL 1.0 (OpenGL ES 2.0 Chromium)"
                        elif key == "webgl_shading_language_version":
                            value = "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"
                        elif key == "webgl_unmasked_renderer":
                            # Use more common/stable GPU models
                            gpus = [
                                "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                                "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)",
                                "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                            ]
                            value = random.choice(gpus)
                        elif key == "webgl_unmasked_vendor":
                            # Match vendor with chosen GPU
                            if "NVIDIA" in self.options.get("webgl_unmasked_renderer", ""):
                                value = "Google Inc. (NVIDIA)"
                            elif "Intel" in self.options.get("webgl_unmasked_renderer", ""):
                                value = "Google Inc. (Intel)"
                            else:
                                value = "Google Inc. (AMD)"
                        elif key == "user_agent_data_brands":
                            value = "Chromium;Not A(Brand;Google Chrome"
                        elif key == "user_agent_data_mobile":
                            value = False
                        elif key == "navigator_connection_downlink":
                            # More stable network speeds
                            value = round(random.uniform(8, 12), 1)
                        elif key == "network_info_rtt":
                            # More stable RTT values
                            value = random.randint(50, 70)
                        elif key == "navigator_device_memory":
                            # Prefer more common memory sizes
                            value = random.choice([8, 16])
                        elif key == "window_outer_width":
                            # Stick to most common resolution
                            value = 1920
                        elif key == "window_outer_height":
                            value = 1080
                        elif key == "navigator_languages":
                            value = "en-US,en"
                        elif key == "css_color_gamut":
                            value = "srgb"  # Most common value
                        elif key == "css_contrast":
                            value = "no-preference"  # Most common value
                        elif key == "css_pointer":
                            value = "fine"  # Indicates a mouse/touchpad
                        elif key == "browser_api_checks":
                            value = [
                                "permission_status: true",
                                "eye_dropper: true",
                                "audio_data: false",
                                "writable_stream: true",
                                "css_style_rule: true",
                                "navigator_ua: true",
                                "barcode_detector: false",
                                "display_names: true",
                                "contacts_manager: false",
                                "svg_discard_element: false",
                                "usb: true",
                                "media_device: defined",
                                "playback_quality: false",
                                "bluetooth: object",
                                "managed_config: undefined",
                                "window_placement: object",
                                "app_badge: undefined"
                            ]
                        
                        enhanced_fp[key] = value
                    
                    # Update all enhanced_fp values at once
                    for key, value in enhanced_fp.items():
                        self.options[key] = value
                        
                elif item["key"] == "n":  # Base64 encoded timestamp
                    timestamp = str(int(time.time())).encode('utf-8')
                    self.options["n"] = base64.b64encode(timestamp).decode('utf-8')
                elif item["key"] == "wh":  # Window hash - randomize first part, keep second part
                    parts = item["value"].split("|")
                    new_hash = hashlib.md5(str(time.time() + random.random()).encode('utf-8')).hexdigest()
                    self.options["wh"] = f"{new_hash}|{parts[1]}"
                elif item["key"] == "f":  # Fingerprint hash
                    # Generate a new fingerprint hash based on timestamp and random value
                    new_fp = hashlib.md5(f"{time.time()}_{random.random()}".encode('utf-8')).hexdigest()
                    self.options[item["key"]] = new_fp
                else:
                    self.options[item["key"]] = item["value"]

    def _extract_chrome_version(self, useragent: str) -> str:
        try:
            return useragent.split("Chrome/")[1].split(".")[0]
        except:
            return "132"  # fallback to a common version

    def _get_browser_api_checks(self, is_firefox: bool, is_chrome: bool) -> list:
        base_checks = [
            "permission_status: true",
            "eye_dropper: false",
            "writable_stream: true",
            "css_style_rule: true",
            "barcode_detector: false",
            "display_names: true",
            "contacts_manager: false",
            "svg_discard_element: false",
            "media_device: defined",
            "ink: undefined",
            "scheduling: undefined",
            "serial: undefined",
            "compute_pressure: undefined"
        ]
        
        if is_firefox:
            base_checks.extend([
                "audio_data: true",
                "navigator_ua: false",
                "usb: NA",
                "playback_quality: true"
            ])
        elif is_chrome:
            base_checks.extend([
                "audio_data: false",
                "navigator_ua: true",
                "usb: true",
                "playback_quality: false",
                "bluetooth: object",
                "managed_config: undefined",
                "window_placement: object",
                "app_badge: undefined"
            ])
            
        return base_checks

    def _get_tree_structure(self) -> tuple[str, list]:
        structures = [
            ("[[],[[]]]", [1, 0]),  # Most common
            ("[[[]]]", [0, 0]),     # Less common
            ("[[]]", [0]),          # Rare
        ]
        weights = [0.7, 0.2, 0.1]   # Weighted choices to match real browser patterns
        return random.choices(structures, weights=weights)[0]

    def get_options(self) -> None:
        if self.method == "roblox_login":
            base_url = "https://www.roblox.com"
            service_url = "https://arkoselabs.roblox.com"
            
            self.options = {
                "document__referrer": f"{base_url}/",
                "window__ancestor_origins": [base_url, base_url],
                "window__tree_index": [1, 0],
                "window__tree_structure": "[[],[[]]]",
                "window__location_href": f"{service_url}/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": f"{base_url}/arkose/iframe",
                "client_config__language": None,
                "client_config__surl": service_url,
                "c8480e29a": str(self.hashing(service_url)) + "\u2062",
                "client_config__triggered_inline": False
            }
        elif self.method == "outlook":
            self.options = {
                "document__referrer": "https://iframe.arkoselabs.com/",
                "window__ancestor_origins": [
                    "https://iframe.arkoselabs.com",
                    "https://signup.live.com",
                ],
                "window__tree_index": [1, 0],
                "window__tree_structure": "[[[]],[[]]]",
                "window__location_href": f"https://client-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": f"https://iframe.arkoselabs.com/B7D8911C-5CC8-A9A3-35B0-554ACEE604DA/index.html",
                "client_config__language": "en",
                "client_config__surl": "https://client-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://client-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "twitter":
            self.options = {
                "document__referrer": "https://iframe.arkoselabs.com/",
                "window__ancestor_origins": [
                    "https://iframe.arkoselabs.com",
                    "https://twitter.com",
                ],
                "window__tree_index": [0, 0],
                "window__tree_structure": "[[[]]]",
                "window__location_href": f"https://client-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/2CB16598-CB82-4CF7-B332-5990DB66F3AB/index.html",
                "client_config__language": None,
                "client_config__surl": "https://client-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://client-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "twitter_unlock":
            self.options = {
                "document__referrer": "https://iframe.arkoselabs.com/",
                "window__ancestor_origins": [
                    "https://iframe.arkoselabs.com",
                    "https://twitter.com",
                ],
                "window__tree_index": [0, 0],
                "window__tree_structure": "[[[]]]",
                "window__location_href": f"https://client-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://iframe.arkoselabs.com/0152B4EB-D2DC-460A-89A1-629838B529C9/index.html",
                "client_config__language": None,
                "client_config__surl": "https://client-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://client-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "roblox_signup":
            self.options = {
                "document__referrer": "https://www.roblox.com/",
                "window__ancestor_origins": [
                    "https://www.roblox.com",
                    "https://www.roblox.com",
                ],
                "window__tree_index": [0, 0],
                "window__tree_structure": "[[[]]]",
                "window__location_href": f"https://arkoselabs.roblox.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": f"https://www.roblox.com/arkose/iframe",
                "client_config__language": None,
                "client_config__surl": "https://arkoselabs.roblox.com",
                "c8480e29a": str(self.hashing("https://arkoselabs.roblox.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "roblox_join" or self.method == "roblox_follow":
            self.options = {
                "document__referrer": "https://www.roblox.com/",
                "window__ancestor_origins": [
                    "https://www.roblox.com"
                ],
                "window__tree_index": [1],
                "window__tree_structure": "[[],[]]",
                "window__location_href": f"https://www.roblox.com/arkose/iframe",
                "client_config__sitedata_location_href": "https://www.roblox.com/arkose/iframe",
                "client_config__language": None,
                "client_config__surl": "https://arkoselabs.roblox.com",
                "c8480e29a": str(self.hashing("https://arkoselabs.roblox.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "ea":
            self.options = {
                "document__referrer": "https://signin.ea.com/",
                "window__ancestor_origins": [
                    "https://signin.ea.com",
                ],
                "window__tree_index": [0],
                "window__tree_structure": "[[]]",
                "window__location_href": f"https://ea-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://signin.ea.com/p/juno/create",
                "client_config__language": "en",
                "client_config__surl": "https://ea-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://ea-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "github-signup":
            self.options = {
                "document__referrer": "https://octocaptcha.com/",
                "window__ancestor_origins": [
                    "https://octocaptcha.com",
                    "https://github.com",
                ],
                "window__tree_index": [0, 0],
                "window__tree_structure": "[[[]],[]]",
                "window__location_href": f"https://github-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://octocaptcha.com/",
                "client_config__language": None,
                "client_config__surl": "https://github-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://github-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "demo":
            self.options = {
                "document__referrer": "https://login.microsoftonline.com/",
                "window__ancestor_origins": [
                    "https://demo.arkoselabs.com",
                ],
                "window__tree_index": [0],
                "window__tree_structure": "[[]]",
                "window__location_href": f"https://cleint-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://demo.arkoselabs.com/",
                "client_config__language": "en",
                "client_config__surl": "https://demo-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://client-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "roblox_wall":
            self.options = {
                "document__referrer": "https://www.roblox.com/",
                "window__ancestor_origins": [
                    "https://www.roblox.com",
                    "https://www.roblox.com",
                ],
                "window__tree_index": [1, 0],
                "window__tree_structure": "[[],[[]]]",
                "window__location_href": f"https://arkoselabs.roblox.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://www.roblox.com/arkose/iframe",
                "client_config__language": None,
                "client_config__surl": "https://arkoselabs.roblox.com",
                "c8480e29a": str(self.hashing("https://arkoselabs.roblox.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        elif self.method == "airbnb-register":
            self.options = {
                "document__referrer": "https://www.airbnb.com/",
                "window__ancestor_origins": [
                    "https://www.airbnb.com",
                ],
                "window__tree_index": [1],
                "window__tree_structure": "[[[]],[]]",
                "window__location_href": f"https://airbnb-api.arkoselabs.com/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "client_config__sitedata_location_href": "https://www.airbnb.com/",
                "client_config__language": "en",
                "client_config__surl": "https://airbnb-api.arkoselabs.com",
                "c8480e29a": str(self.hashing("https://airbnb-api.arkoselabs.com"))
                + "\u2062",
                "client_config__triggered_inline": False,
            }
        else:
            raise Exception("Invalid method")
