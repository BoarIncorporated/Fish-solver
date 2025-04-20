import base64, hashlib, json, os, random, re, string, time
import execjs
import aiohttp
import asyncio

from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Union
from PIL import Image
from src.image.botmasterlabs import XEvil
from urllib.parse import urlencode

from src.arkose_session.bio import DataGenerator
from src.arkose_session.crypto import aes_encrypt, aes_decrypt


def remove_all_html_tags(text: str) -> str:
    pattern = re.compile(r"<[^>]+>")
    return pattern.sub("", text)


def calculate_coordinates(
    answer_index: int, layouts: Dict[str, Any]
) -> Dict[str, float]:
    columns = layouts["columns"]
    rows = layouts["rows"]
    tile_width = layouts["tile_width"]
    tile_height = layouts["tile_height"]
    if not 0 <= answer_index < columns * rows:
        raise ValueError(f"The answer should be between 0 and {columns * rows}")
    x = (answer_index % columns) * tile_width
    y = (answer_index // columns) * tile_height
    px = round(random.uniform(0, tile_width), 2)
    py = round(random.uniform(0, tile_height), 2)
    return {"px": px, "py": py, "x": x, "y": y}


def flagged(data: list) -> bool:
    if not data or not isinstance(data, list):
        return False
    values = [value for d in data for value in d.values()]
    if not values:
        return False

    def ends_with_uppercase(value):
        return value and value[-1] in string.ascii_uppercase

    return all(ends_with_uppercase(value) for value in values)


def pguesses(guesses: list, token: str) -> list:
    sess: str
    ion: str

    sess, ion = token.split(".")
    answers: list = []

    for guess in guesses:
        if "index" in guess:
            answers.append({"index": guess["index"], sess: ion})
        else:
            guess: dict = json.loads(guess)
            answers.append(
                {
                    "px": guess["px"],
                    "py": guess["py"],
                    "x": guess["x"],
                    "y": guess["y"],
                    sess: ion,
                }
            )

    return answers


def process(dapib_code: str, answers: list) -> list:
    tries = 0
    while True:
        tries += 1
        try:
            ctx = execjs.compile(
                """
            function runCode(dapibCode, answers) {
                window = {};
                window.parent = {};
                window.parent.ae = {"answer": answers};
                window.parent.ae["dapibRecei" + "ve"] = function(data) {
                    response = JSON.stringify(data);
                };
                
                eval(dapibCode);
                return response;
            }
            """
            )

            result: str = ctx.call("runCode", dapib_code, answers)
            result: dict = json.loads(result)

            if flagged(result["tanswer"]):
                for array in result["tanswer"]:
                    for item in array:
                        array[item] = (
                            array[item][:-1] if isinstance(array[item], str) else array[item]
                        )

            return result["tanswer"]
        
        except Exception as e:
            if tries > 5:
                raise Exception("Failed to process tguess answers: " + str(e))
            continue

def main(dapib_code: str, token: str, guesses: list) -> list:
    try:
        answers: list = pguesses(guesses, token)
        result: list = process(dapib_code, answers)

    except Exception as e:
        raise Exception("Failed to process tguess answers: " + str(e))

    return result


class Game:
    def __init__(
        self,
        captcha_session: Any,
        challenge_session: Any,
        response_session: Dict[str, Any],
    ) -> None:
        self.captcha_session = captcha_session
        self.challenge_session = challenge_session

        self.session_token: str = response_session["session_token"]
        self.challenge_id: str = response_session["challengeID"]
        self.challenge_url: str = response_session["challengeURL"]

        self.dapib_url: Optional[str] = response_session.get("dapib_url")

        self.data: Dict[str, Any] = response_session["game_data"]
        self.type: int = self.data["gameType"]
        self.waves: int = self.data["waves"]
        self.difficulty: Optional[str] = (
            self.data.get("game_difficulty") if self.type == 4 else None
        )

        self.encrypted_mode: Union[bool, int] = self.data["customGUI"].get(
            "encrypted_mode", False
        )
        self.ekey: str = None

        self.game_variant: str = (
            self.data.get("instruction_string")
            if self.type == 4
            else self.data["game_variant"]
        )

        if not self.game_variant:
            self.game_variant = "3d_rollball_animalss"
        self.customGUI: Dict[str, Any] = self.data["customGUI"]
        self.layouts: Optional[Dict[str, Any]] = (
            self.customGUI.get("_challenge_layouts") if self.type == 3 else None
        )

        self.image_urls: List[str] = self.customGUI["_challenge_imgs"]
        self.image_bytes: List[bytes] = []
        if self.game_variant == "3d_rollball_animalss":
            self.prompt: str = response_session["string_table"].get(
                f"{self.type}.instructions_{self.game_variant}", ""
            )

        else:
            self.prompt: str = response_session["string_table"].get(
                f"{self.type}.instructions-{self.game_variant}", ""
            )

        self.guess: List[Dict[str, Any]] = []
        self.tguess: List[Any] = []
        self.prompt_en: str = remove_all_html_tags(self.prompt)

    def pre_get_image(self) -> None:

        image_headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd", 
            "Accept-Language": "en-GB,en;q=0.9,en-US;q=0.8",
            "Cache-Control": "no-cache",
            "Cookie": "GuestData=UserID=-995324538; RBXSource=rbx_acquisition_time=04/03/2025 15:55:34&rbx_acquisition_referrer=&rbx_medium=Social&rbx_source=&rbx_campaign=&rbx_adgroup=&rbx_keyword=&rbx_matchtype=&rbx_send_info=0; RBXEventTrackerV2=CreateDate=04/10/2025 17:53:01&rbxid=7527238585&browserid=1728730606958001; rbx-ip2=1; _cfuvid=2Tcy_EqLJ0qhYnviOGCTm_1P9sZBMu9.hAx5FSqz2z4-1717104076479-0.0.1.1-604800000; timestamp=174449300934155",
            "DNT": "1",
            "Host": self.captcha_session.service_url.replace("https://", ""),
            "Pragma": "no-cache",
            "Priority": "u=1, i",
            "Referer": f"{self.captcha_session.service_url}/fc/assets/ec-game-core/game-core/1.27.4/standard/index.html?session={self.challenge_session.arkose_token.replace('|', '&')}&theme=default",
            "Sec-Ch-Ua": '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors", 
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.challenge_session.headers.ua
        }

        if self.encrypted_mode == 1:
            payload: Dict[str, str] = {
                "session_token": self.session_token,
                "game_token": self.challenge_id,
                "sid": self.challenge_session.session_id,
            }

            ekeyurl = f"{self.captcha_session.service_url}/fc/ekey/"
            ekey = self.challenge_session.session.post(ekeyurl, data=payload)

            if ekey.status_code == 200:
                self.ekey = ekey.json()["decryption_key"]
            else:
                raise Exception("Failed to get ekey: " + ekey.text)

        for i, url in enumerate(self.image_urls):
            response = self.challenge_session.session.get(url, headers=image_headers)
            if response.status_code == 200:
                imgbytes: bytes = None
                if self.encrypted_mode == 1:
                    rjson: Dict[str, str] = response.json()
                    imgbytes = aes_decrypt(rjson, self.ekey)
                else:
                    imgbytes = response.content
                self.image_bytes.append(imgbytes)
            else:
                raise Exception("Failed to get image: " + response.text)

    def process_all_images(self) -> List[Tuple[int, str, str]]:
        """
        Process all images in batch and return answers
        """
        if len(self.image_bytes) == 0:
            self.pre_get_image()

        images_base64 = []
        image_md5s = []

        # Prepare all images
        for image_bytes in self.image_bytes:
            image_base64 = base64.b64encode(image_bytes).decode("utf-8")
            image_md5 = hashlib.md5(image_bytes).hexdigest()
            images_base64.append(image_base64)
            image_md5s.append(image_md5)

        if self.game_variant in ["waterIconCup", "bowling", "pathfinder", "Matchship"]:
            answers = []
            for image_base64 in images_base64:
                answer = XEvil.solveImage(image_base64, self.game_variant)
                answers.append(answer)
        else:
            # Solve all images in batch for standard variants
            variants = [self.game_variant] * len(images_base64)
            answers = XEvil.solve_batch_sync(images_base64, variants)

        return list(zip(answers, image_md5s, image_md5s))

    def get_image(
        self, number: int, show: bool = False, download: bool = False
    ) -> Tuple[str, str, str]:
        """Get a specific image's data"""
        if len(self.image_bytes) == 0:
            raise Exception("Images not downloaded yet. Call pre_get_image first.")
            
        image_bytes = self.image_bytes[number]
        if show:
            image = Image.open(BytesIO(image_bytes))
            image.show()

        image_base64 = base64.b64encode(image_bytes).decode("utf-8")
        image_md5 = hashlib.md5(image_bytes).hexdigest()

        return image_base64, image_md5, image_md5

    def solve_challenge(self) -> Dict[str, Any]:
        """
        Ultra-fast challenge solving with minimal delays
        """
            
        # Process all images at once
        results = self.process_all_images()
        
        # Prepare all answers first
        for wave_index, (answer_index, _, _) in enumerate(results):
            if self.type == 4:
                answer = {"index": answer_index}
            elif self.type == 3:
                answer = calculate_coordinates(answer_index, self.layouts[wave_index])
            
            self.guess.append(answer)
        
        return self.submit_final_answer()

    def submit_final_answer(self) -> Dict[str, Any]:
        """Submit all answers at once"""
        guess_crypt = aes_encrypt(json.dumps(self.guess), self.session_token)
        answer_url = f"{self.captcha_session.service_url}/fc/ca/"
        
        self.challenge_session.session.headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"{self.captcha_session.service_url}/fc/assets/ec-game-core/game-core/1.27.4/standard/index.html?session={self.challenge_session.arkose_token.replace('|', '&')}",
        })
        
        bio_data = DataGenerator().generate()
        
        answer_data = {
            "session_token": self.session_token,
            "game_token": self.challenge_id,
            "sid": self.challenge_session.session_id,
            "guess": guess_crypt,
            "render_type": "canvas",
            "analytics_tier": self.challenge_session.analytics_tier,
            "bio": bio_data,
            "is_compatibility_mode": "false",
        }

        if self.dapib_url:
            tguess_crypt = self.get_tguess_crypt()
            answer_data["tguess"] = tguess_crypt

        timestamp_cookie, timestamp_value = self.challenge_session._get_timestamp()
        requested_id = aes_encrypt(
            json.dumps({"sc": [random.randint(1, 200), random.randint(1, 200)]}),
            f"REQUESTED{self.session_token}ID",
        )
        
        self.challenge_session.session.cookies.set(
            "timestamp",
            timestamp_value,
            domain=self.captcha_session.service_url.replace("https://", ""),
        )
        
        self.challenge_session.session.headers.update({
            "X-Newrelic-Timestamp": timestamp_value,
            "X-Requested-ID": requested_id,
            "X-Requested-With": "XMLHttpRequest",
        })

        response = self.challenge_session.session.post(answer_url, data=urlencode(answer_data))
        if response.status_code == 200:
            try:
                self.ekey = response.json().get("decryption_key", False)
            except Exception:
                self.ekey = False
            return response.json()
        else:
            raise Exception(
                f"Failed to put answer: {str(response.status_code)} {response.text}"
            )

    def get_tguess_crypt(self) -> str:
        response = ""
        try:
            data: Dict[str, Any] = {
                "guess": self.guess,
                "dapib_url": self.dapib_url,
                "session_token": self.session_token,
            }

            dapi_code = self.challenge_session.session.post(self.dapib_url).text
            response = main(
                dapi_code,
                data["session_token"],
                data["guess"],
            )

            tguess_crypt: str = aes_encrypt(json.dumps(response), self.session_token)
            return tguess_crypt
        except Exception as e:
            raise Exception("Failed to get tguess: " + str(e))

    def put_answer(self, num: int, answer_index: int) -> Dict[str, Any]:
        # Add human-like delay before submitting answer
        time.sleep(random.uniform(0.8, 1.5))
        
        if self.type == 4:
            answer: Dict[str, Any] = {"index": answer_index}
        elif self.type == 3:
            answer = calculate_coordinates(answer_index, self.layouts[num])
        self.guess.append(answer)
        
        # Add small delay after adding guess
        time.sleep(random.uniform(0.2, 0.4))
        
        guess_crypt: str = aes_encrypt(json.dumps(self.guess), self.session_token)

        answer_url: str = f"{self.captcha_session.service_url}/fc/ca/"

        if num + 1 == self.waves:
            # Add longer delay before final submission
            time.sleep(random.uniform(0.5, 0.8))
            
            self.challenge_session.session.headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": f"{self.captcha_session.service_url}/fc/assets/ec-game-core/game-core/1.27.4/standard/index.html?session={self.challenge_session.arkose_token.replace('|', '&')}",
                }
            )
            
            # Generate more realistic bio data
            bio_data = DataGenerator().generate()
            
            answer_data: Dict[str, Any] = {
                "session_token": self.session_token,
                "game_token": self.challenge_id,
                "sid": self.challenge_session.session_id,
                "guess": guess_crypt,
                "render_type": "canvas",
                "analytics_tier": self.challenge_session.analytics_tier,
                "bio": bio_data,
                "is_compatibility_mode": False
            }

            if self.dapib_url:
                tguess_crypt: str = self.get_tguess_crypt()
                answer_data["tguess"] = tguess_crypt

            timestamp_cookie, timestamp_value = self.challenge_session._get_timestamp()
            requested_id: str = aes_encrypt(
                json.dumps({"sc": [random.randint(1, 200), random.randint(1, 200)]}),
                f"REQUESTED{self.session_token}ID",
            )
            self.challenge_session.session.cookies.set(
                "timestamp",
                timestamp_value,
                domain=self.captcha_session.service_url.replace("https://", ""),
            )
            self.challenge_session.session.headers.update(
                {
                    "X-Newrelic-Timestamp": timestamp_value,
                    "X-Requested-ID": requested_id,
                    "X-Requested-With": "XMLHttpRequest",
                }
            )
            response = self.challenge_session.session.post(
                answer_url, data=urlencode(answer_data)
            )
            if response.status_code == 200:
                try:
                    self.ekey = response.json().get("decryption_key", False)
                except Exception:
                    self.ekey = False
                return response.json()
            else:
                raise Exception(
                    f"Failed to put answer: {str(response.status_code)} {str(response.text)}"
                )
