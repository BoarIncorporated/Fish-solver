import random, string, json, ua_generator
from typing import Dict, Optional, List, Tuple

class Headers:
    """
    An enhanced class to generate HTTP headers with customizable fields and
    randomization for specific values like User-Agent and Accept-Language.
    """

    def __init__(
        self,
        browser: Optional[str] = None,
        version: Optional[str] = None,
        os: Optional[str] = None,
        accept: str = "*/*",
        accept_encoding: str = "gzip, deflate, br",
        accept_language: Optional[str] = None,
        sec_ch_ua: Optional[str] = None,
        sec_ch_ua_platform: Optional[str] = None,
        sec_fetch_dest: str = "empty",
        sec_fetch_mode: str = "cors",
        sec_fetch_site: str = "same-origin",
        upgrade_insecure_requests: Optional[str] = None,
        user_agent: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        method: Optional[str] = None,
    ) -> None:
        """
        Initializes header attributes, with improvements for realism and evasion.
        """
        # Store the method parameter
        self.method: Optional[str] = method
        
        self.browser, self.version, self.os = (
            self._choose_browser_os_version()
            if browser and version and os is None
            else (browser, version, os)
        )
        self.user_agent: str = user_agent or self._choose_user_agent()
        # Add ua as an alias for user_agent for compatibility
        self.ua: str = self.user_agent
        self.accept: str = accept
        self.accept_encoding: str = accept_encoding
        self.accept_language: str = accept_language or self._generate_accept_language()
        self.sec_ch_ua: str = sec_ch_ua or self._choose_sec_ch_ua()
        self.sec_ch_ua_mobile: str = "0?"
        self.sec_ch_ua_platform: str = (
            sec_ch_ua_platform or self._choose_sec_ch_ua_platform()
        )
        self.sec_fetch_dest: str = sec_fetch_dest
        self.sec_fetch_mode: str = sec_fetch_mode
        self.sec_fetch_site: str = sec_fetch_site
        self.upgrade_insecure_requests: Optional[str] = (
            upgrade_insecure_requests if random.uniform(0, 0.81) > 0.8 else None
        )
        self.custom_headers: Dict[str, str] = custom_headers or {}

    def headers(self) -> Dict[str, str]:
        """
        Returns a dictionary of HTTP headers.
        """
        headers: Dict[str, str] = {
            "Accept": self.accept,
            "Accept-Encoding": self.accept_encoding,
            "Accept-Language": self.accept_language,
            "Sec-Fetch-Dest": self.sec_fetch_dest,
            "Sec-Fetch-Mode": self.sec_fetch_mode,
            "Sec-Fetch-Site": self.sec_fetch_site,
            "User-Agent": self.user_agent,
        }
        if "firefox" in self.user_agent.lower():
            headers["TE"] = "trailers"
        if self.upgrade_insecure_requests:
            headers["Upgrade-Insecure-Requests"] = self.upgrade_insecure_requests

        headers.update(self.custom_headers)

        return headers

    def update(self, headers: str) -> None:
        """
        Updates header attributes based on the input string representation of a dictionary.
        """
        try:
            headers_dict: Dict[str, str] = json.loads(headers)
            for key, value in headers_dict.items():
                setattr(self, key.lower().replace("-", "_"), value)
            
            # Keep ua in sync with user_agent if user_agent was updated
            if "User-Agent" in headers_dict or "user-agent" in headers_dict:
                self.ua = self.user_agent
                
            # If method is updated, update the user agent accordingly
            if "method" in headers_dict:
                self.method = headers_dict["method"]
                # Update user agent if method has changed
                self.user_agent = self._choose_user_agent()
                self.ua = self.user_agent
                
            self.custom_headers.update(
                {k: v for k, v in headers_dict.items() if k not in self.__dict__}
            )
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid header format: {e}")

    def _choose_browser_os_version(self) -> Tuple[str, int, str]:
        """
        Randomly choose a browser, version, and OS for more realistic User-Agent strings.
        """
        browsers: List[Tuple[str, str, str]] = [
            ("chrome", 134, "Windows NT 10.0; Win64; x64"),
            ("chrome mac", 132, "Macintosh; Intel Mac OS X 14_3_1"), 
            ("chrome linux", 132, "Linux x86_64"),
            ("chrome android", 133, "Linux; Android 10; K"),
            ("edge", 132, "Windows NT 10.0; Win64; x64"),
            ("safari", 16.2, "iPhone; CPU iPhone OS 16_2 like Mac OS X"),
        ]
        # Use the same browser/version combination for the entire session
        if not hasattr(self, '_browser_choice'):
            self._browser_choice = random.choice(browsers)
        return self._browser_choice

    def _choose_user_agent(self) -> str:
        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"
    
    def _choose_sec_ch_ua(self) -> str:
        """
        Generates the Sec-CH-UA header based on the User-Agent.
        """

        if "Edg" in self.user_agent:
            return f'"Chromium";v="132", "Not:A-Brand";v="24", "Microsoft Edge";v="132"'
        elif "Mobile" in self.user_agent and "Chrome" in self.user_agent:
            return f'"Google Chrome";v="{self.version}", "Not)A;Brand";v="8", "Chromium";v="{self.version}"'
        elif "Chrome" in self.user_agent:
            return f'"Chromium";v="{self.version}", "Google Chrome";v="{self.version}", "Not;A=Brand";v="24"'
        elif "Firefox" in self.user_agent:
            return None
        elif "Safari" in self.user_agent:
            return None
        elif "opr" in self.user_agent.lower():
            return f'"Chromium";v="{self.version}", "Opera GX";v="{self.version}", "Not;A=Brand";v="99"'
        else:
            return f'"Chromium";v="{self.version}", "Not;A=Brand";v="99"'

    def _choose_sec_ch_ua_platform(self) -> str:
        """
        Choose a platform that matches the selected operating system.
        """
        if "Macintosh" in self.os:
            return '"macOS"'
        elif "Windows" in self.os:
            return '"Windows"'
        elif "Linux" in self.os:
            return '"Linux"'
        elif "Android" in self.os:
            return '"Android"'
        return '"Unknown"'

    def _generate_accept_language(self, max_lang: int = random.randint(0, 3)) -> str:
        """
        Generates the Accept-Language header mimicking real-world browser behavior.
        """
        languages = [
            "en-US"
        ]

        base_lang = "en-US"
        shuffled_langs = random.sample(languages, k=max_lang)
        chosen_langs = [base_lang] + shuffled_langs

        q_values = [round(0.9 - 0.1 * i, 1) for i in range(len(chosen_langs))]
        lang_with_q = [f"{lang};q={q}" for lang, q in zip(chosen_langs, q_values)]

        if "-" in base_lang:
            base_lang_code = base_lang.split("-")[0]
            lang_with_q[0] = f"{base_lang},{base_lang_code};q={q_values[0]}"

        return ",".join(lang_with_q)

    def to_json(self) -> str:
        """
        Returns a JSON string representation of the headers.
        """
        return json.dumps(self.headers(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "Headers":
        """
        Creates a Headers instance from a JSON string.
        """
        data = json.loads(json_str)
        # If method exists in the data, extract it to pass during initialization
        method = data.get("method", None)
        headers = cls(method=method)
        headers.update(json.dumps(data))
        return headers

    def randomize(self) -> None:
        """
        Randomizes all header values.
        """
        # Save the method before re-initializing
        method = self.method
        self.__init__(method=method)


if __name__ == "__main__":
    headers = Headers()
    print(headers.to_json())
