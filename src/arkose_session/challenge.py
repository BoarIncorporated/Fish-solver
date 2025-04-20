import json, random
import string, time, uuid
from datetime import datetime

from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlencode
from hashlib import sha512
import os


from curl_cffi import requests
from src.arkose_session.crypto import aes_encrypt
from src.bda.fingerprint import generate_browser_data
from src.arkose_session.game import Game
from src.utilities.headers import Headers
from src.utilities.format import construct_form_data
from src.config import capi_version, enforcement_hash

enforcement_url = f"/v2/{capi_version}/enforcement.{enforcement_hash}.html"

def sort_headers(headers: Dict[str, str]) -> Dict[str, str]:
    header_order = [
        ":authority",
        ":method",
        ":path",
        ":scheme",
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "cache-control",
        "content-length",
        "content-type",
        "cookie",
        "host",
        "origin",
        "pragma",
        "priority",
        "referer",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "user-agent",
        "x-ark-esync-value"
    ]
    return {k: v for k, v in sorted(headers.items(), key=lambda item: header_order.index(item[0]) if item[0] in header_order else len(header_order))}

EDGE_JA3_FINGERPRINTS = [
    "771,{}-{}-{}-{}-{}-{}-{}-{}-{}-{}-{},0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,{}-{}-{},0".format(
        *random.sample([4865, 4866, 4867], 3),
        *random.sample([49195, 49196, 49199, 49200], 4),
        *random.sample([52392, 52393], 2),
        *random.sample([49171, 49172], 2),
        *random.sample([23, 24, 29], 3)
    ) for _ in range(20)
]

class ChallengeSession:
    """
    Challenge Session
    """

    def __init__(
        self,
        captcha_session,
        proxy: Optional[str] = None,
        browser_data: Optional[Tuple[str, str, str, str, str]] = None,
        referrer: Optional[str] = None,
        timeout: int = 30,
    ):
        self.captcha_session = captcha_session

        self.headers = Headers(
            browser=browser_data[0],
            version=browser_data[1],
            os=browser_data[2],
            accept_language=browser_data[3],
            method=self.captcha_session.method
        )
        self.cookies = browser_data[4]
        self.referrer = referrer
        self.session = requests.Session(impersonate="edge101")
        self.session.default_headers = 0
        self.session.timeout = timeout
        self.proxy = proxy
        self.session.proxies = {"http": self.proxy, "https": self.proxy}
        self.browser_data: Optional[str] = None
        self.detailed_browser_data: Optional[str] = None

        self.arkose_token: Optional[str] = None
        self.session_token: Optional[str] = None
        self.session_id: Optional[str] = None
        self.analytics_tier: Optional[str] = None
        self.security_score: Optional[int] = None
        self.encrypted_mode: Optional[bool] = None

    def _get_timestamp(self) -> Tuple[str, str]:
        """
        Generates a timestamp string from the current time and returns it as a cookie.

        Returns:
            Tuple[str, str]: A tuple containing the cookie string and the value.
        """
        timestamp_str = str(int(time.time() * 1000))
        value = f"{timestamp_str[:7]}00{timestamp_str[7:]}"
        cookie = f"timestamp={value}"
        return cookie, value

    def _generate_challenge_task(self, xark) -> Dict[str, Any]:
        (
            self.browser_data,
            self.headers.ua,
            self.detailed_browser_data,
            additional_headers,
        ) = generate_browser_data(
            self.headers,
            method=self.captcha_session.method,
            proxy=self.proxy,
            xark=xark,
            referrer=self.referrer,
        )
        if additional_headers:
            self.headers.update(additional_headers)

        random.seed(random.randint(0, 2**64 - 1))

        task = {
            "public_key": self.captcha_session.public_key,
            "capi_version": capi_version,
            "capi_mode": self.captcha_session.capi_mode,
            "style_theme": "default",
            "rnd": random.random(),
            "bda": self.browser_data,
            "site": self.captcha_session.site_url,
            "userbrowser": self.headers.ua,
        }
        if self.captcha_session.blob:
            task["data[blob]"] = self.captcha_session.blob
        if self.captcha_session.method == "github-signup":
            task["data[origin_page]"] = "github_signup_redesign"
        return task

    def fetch_challenge_token(self) -> str:
        xark = str(int(time.time() / 21600) * 21600)

        base_headers = {
            ":authority": self.captcha_session.service_url.replace("https://", ""),
            ":method": "POST",
            ":path": f"/fc/gt2/public_key/{self.captcha_session.public_key}",
            ":scheme": "https",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-GB,en;q=0.9,en-US;q=0.8",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "cookie": "rbx-ip2=1; RBXEventTrackerV2=CreateDate=04/13/2025 09:58:57&rbxid=&browserid=1744556337882001; GuestData=UserID=-420659607; RBXSource=rbx_acquisition_time=04/13/2025 14:59:02&rbx_acquisition_referrer=https://www.roblox.com/login&rbx_medium=Social&rbx_source=www.roblox.com&rbx_campaign=&rbx_adgroup=&rbx_keyword=&rbx_matchtype=&rbx_send_info=0; _cfuvid=2Tcy_EqLJ0qhYnviOGCTm_1P9sZBMu9.hAx5FSqz2z4-1717104076479-0.0.1.1-604800000; timestamp=174455600399189",
            "origin": self.captcha_session.service_url,
            "priority": "u=1, i",
            "referer": f"{self.captcha_session.service_url}/v2/{capi_version}/enforcement.{enforcement_hash}.html",
            "sec-ch-ua": '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": self.headers.ua,
            "x-ark-esync-value": xark
        }

        task = self._generate_challenge_task(xark)
        cookie, timestamp_value = self._get_timestamp()

        self.session.headers.clear()
        self.session.headers.update(base_headers)
        
        self.session.cookies.set(
            "timestamp",
            timestamp_value,
            domain=self.captcha_session.service_url.replace("https://", ""),
        )

        if "roblox" in self.captcha_session.method:
            for name, value in self.cookies.items():
                self.session.cookies.set(name, value, domain=".roblox.com")

        self.session.headers = sort_headers(self.session.headers)
        cfuidcookies = self.session.get(f"{self.captcha_session.service_url}/v2/{self.captcha_session.public_key}/api.js")
        self.session.cookies.update(cfuidcookies.cookies)

        task_form = construct_form_data(task)
        self.session.headers["content-length"] = str(len(task_form))

        self.session.headers = sort_headers(self.session.headers)
        response = self.session.post(
            f"{self.captcha_session.service_url}/fc/gt2/public_key/{self.captcha_session.public_key}",
            data=task_form,
        )
        self.task = task
        if response.status_code == 200:
            response_json: Dict[str, Any] = response.json()
            self.arkose_token = response_json["token"]
            if response_json["pow"]:
                print("POW")
                self.pow()
            
            #if "sup=1" in self.arkose_token:
                #timestamp = int(time.time())
                #filename = f"sup/silentpass({timestamp}).txt"
                #with open(filename, "w") as f:
                    #f.write(self.browser_data)
            
            return self.arkose_token, self.browser_data
        else:
            raise Exception(f"Failed to fetch Arkose token: {response.text}")

    def fetch_challenge_game(self, arkose_token: Optional[str] = None) -> Optional[Game]:
        self.arkose_token = arkose_token if arkose_token else self.arkose_token

        def _parse_arkose_token(token: str) -> Dict[str, str]:
            token = "token=" + token
            token_data = {}
            for field in token.split("|"):
                key, value = field.partition("=")[0], field.partition("=")[-1]
                token_data[key] = value
            return token_data

        token_data = _parse_arkose_token(self.arkose_token)
        self.session_token = token_data["token"]
        self.session_id = token_data["r"]
        self.analytics_tier = token_data["at"]

        self.session.headers = self.headers.headers()
        if "sup" in token_data:
            return
        else:
            self.session.get(f"{self.captcha_session.service_url}/fc/init-load/?session_token={self.arkose_token.split('|')[0]}")

            self.session.headers.update(
                {
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
                    "Connection": "keep-alive",
                    "Host": self.captcha_session.service_url.replace("https://", ""),
                    "Referer": f"{self.captcha_session.service_url}/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                    "Sec-Fetch-Mode": "nested-navigate",
                    "Sec-Fetch-Site": "same-origin",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": self.headers.ua
                }
            )

            self.session.headers = sort_headers(self.session.headers)
            game_url = f"{self.captcha_session.service_url}/fc/assets/ec-game-core/game-core/1.27.4/standard/index.html?session={self.arkose_token.replace('|', '&')}&theme=default"
            self.session.get(game_url)

            cookie, timestamp_value = self._get_timestamp()
            self.session.cookies.set(
                "timestamp",
                timestamp_value,
                domain=self.captcha_session.service_url.replace("https://", ""),
            )

            self.session.headers.update({
                ":authority": self.captcha_session.service_url.replace("https://", ""),
                ":method": "POST", 
                ":path": "/fc/gfct/",
                ":scheme": "https",
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "en-GB,en;q=0.9,en-US;q=0.8",
                "cache-control": "no-cache",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "cookie": "GuestData=UserID=-995324538; RBXSource=rbx_acquisition_time=04/03/2025 15:55:34&rbx_acquisition_referrer=&rbx_medium=Social&rbx_source=&rbx_campaign=&rbx_adgroup=&rbx_keyword=&rbx_matchtype=&rbx_send_info=0; RBXEventTrackerV2=CreateDate=04/10/2025 17:53:01&rbxid=7527238585&browserid=1728730606958001; rbx-ip2=1; _cfuvid=2Tcy_EqLJ0qhYnviOGCTm_1P9sZBMu9.hAx5FSqz2z4-1717104076479-0.0.1.1-604800000; timestamp=174449300933146",
                "dnt": "1",
                "origin": self.captcha_session.service_url,
                "pragma": "no-cache",
                "priority": "u=1, i",
                "referer": f"{self.captcha_session.service_url}/v2/{capi_version}/enforcement.{enforcement_hash}.html",
                "sec-ch-ua": '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors", 
                "sec-fetch-site": "same-origin",
                "user-agent": self.headers.ua,
                "x-newrelic-timestamp": timestamp_value,
                "x-requested-with": "XMLHttpRequest"
            })
            
            data2 = {
                "token": self.session_token,
                "sid": self.session_id,
                "render_type": "canvas",
                "lang": '',
                "isAudioGame": False,
                "is_compatibility_mode": False,
                "apiBreakerVersion": "green",
                "analytics_tier": self.analytics_tier
            }
            self.session.headers = sort_headers(self.session.headers)
            response = self.session.post(
                f"{self.captcha_session.service_url}/fc/gfct/", data=data2
            )
            if response.status_code == 200:
                game = Game(self.captcha_session, self, response.json())
            else:
                raise Exception(f"Failed to fetch game: {response.text}")

            game_token = game.challenge_id

            cookie, timestamp_value = self._get_timestamp()
            requested_id = aes_encrypt(
                json.dumps({"sc": [190, 253]}), f"REQUESTED{self.session_token}ID"
            )
            self.session.cookies.set(
                "timestamp",
                timestamp_value,
                domain=self.captcha_session.service_url.replace("https://", ""),
            )
            self.session.headers.update(
                {
                    "X-Newrelic-Timestamp": timestamp_value,
                    "X-Requested-ID": requested_id,
                    "X-Requested-With": "XMLHttpRequest",
                }
            )

            url_a = f"{self.captcha_session.service_url}/fc/a/"
            cookie, timestamp_value = self._get_timestamp()
            self.session.cookies.set(
                "timestamp",
                timestamp_value,
                domain=self.captcha_session.service_url.replace("https://", ""),
            )
            self.session.headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": self.captcha_session.service_url,
                    "X-Newrelic-Timestamp": timestamp_value,
                    "X-Requested-With": "XMLHttpRequest",
                }
            )
            data1 = {
                "sid": self.session_id,
                "session_token": self.session_token,
                "analytics_tier": self.analytics_tier,
                "disableCookies": False,
                "render_type": "canvas",
                "is_compatibility_mode": False,
                "category": "Site URL",
                "action": f"{self.captcha_session.service_url}{enforcement_url}",
            }
            data1 = urlencode(data1)
            self.session.headers = sort_headers(self.session.headers)
            response = self.session.post(url_a, data=data1)

            data3 = {
                "sid": self.session_id,
                "session_token": self.session_token,
                "analytics_tier": self.analytics_tier,
                "disableCookies": False,
                "game_token": game_token,
                "game_type": game.type,
                "render_type": "canvas",
                "is_compatibility_mode": False,
                "category": "begin app",
                "action": "user clicked verify",
            }
            data3 = urlencode(data3)
            self.session.headers = sort_headers(self.session.headers)
            response = self.session.post(url_a, data=data3)

            return game


    def send_enforcement_callback(self):
        url1: str = f"{self.captcha_session.service_url}/v2/{capi_version}/enforcement.{enforcement_hash}.html"
        url2: str = f"{self.captcha_session.service_url}/v2/{capi_version}/enforcement.{enforcement_hash}.js"
        self.session.headers = sort_headers(self.session.headers)
        for url in [url1, url2]:
            self.session.get(url)


    def pow(self):
        def pows(powSeed, powLeadingZeroCount):
            interactions = 0
            # More realistic start time range
            start = random.randint(3500, 5000)
            
            # Add initial delay to simulate human behavior
            time.sleep(random.uniform(0.2, 0.5))
            
            while True:
                interactions += 1
                # More realistic random string length
                randomString = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(12, 18)))
                hash = sha512((powSeed + randomString).encode()).hexdigest()
                if hash[:powLeadingZeroCount] == "0" * powLeadingZeroCount:
                    # More realistic execution time calculation
                    execTime = start - random.randint(800, 1200)
                    # Add small delay before returning
                    time.sleep(random.uniform(0.1, 0.3))
                    return {
                        "result": randomString,
                        "execution_time": round(execTime),
                        "iteration_count": interactions,
                        "hash_rate": round(interactions / execTime, 4)  # Round to 4 decimal places
                    }
                
                # Add small delay between iterations
                if interactions % 100 == 0:
                    time.sleep(random.uniform(0.01, 0.02))
        
        headers = {
            'Accept': '*/*',
            'Accept-Language': "en-GB,en;q=0.9",
            "Origin": self.captcha_session.service_url,
            'Referer': self.captcha_session.service_url + enforcement_url,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': self.session.headers.get("User-Agent", self.headers.ua)
        }

        self.session.headers.update(headers)

        params = {
            "session_token": self.arkose_token.split("|")[0],
        }

        self.session.headers = sort_headers(self.session.headers)
        url = f"{self.captcha_session.service_url}/pows/setup"
        response = self.session.get(url, params=params)
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch pow setup: {response.text}")

        powjson = response.json()
        powSeed = powjson["seed"]
        powLeadingZeroCount = powjson["leading_zero_count"]
        token = powjson["pow_token"]

        
        powsolve = pows(powSeed, powLeadingZeroCount)

        powdata = {
            "session_token": str(self.arkose_token.split("|")[0]),
            "pow_token": str(token),
            "result": str(powsolve["result"]),
            "execution_time": powsolve["execution_time"],
            "iteration_count": powsolve["iteration_count"],
            "hash_rate": powsolve["hash_rate"]
        }

        self.session.headers["Content-Type"] = "text/plain;charset=UTF-8"

        self.session.headers = sort_headers(self.session.headers)
        url = f"{self.captcha_session.service_url}/pows/check"
        response = self.session.post(url, json=powdata, headers=headers)

        if response.status_code != 200:
            raise Exception(f"Failed to verify pow: {response.text}")

        rfjson = response.json()
        if rfjson.get("action", None) == None:
            raise Exception("POW failed")