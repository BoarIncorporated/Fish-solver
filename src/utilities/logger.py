from datetime import datetime
from threading import Lock
from typing import Final


LOCK: Final[Lock] = Lock()


class Logger:
    def __init__(self, show_time: bool = True) -> None:
        self.show_time = show_time
        self.console = Console()

    def log(self, message, **kwargs):
        args = []
        for key, value in kwargs.items():
            args.append(
                f"\033[90m{key}=\033[0m\033[97m{value}\033[0m"
            )
        message = f"\033[97m{message} {' '.join(args)}"
        if self.show_time:
            message = f"\033[90m[\033[97m{datetime.now().strftime('%H:%M:%S')}\033[90m] {message}"
        with LOCK:
            print(message)

    def solved_captcha(self, token=None, waves=None, variant=None, game_type=None):
        self.console._print_success(
            token=token if token else "N/A",
            waves=waves if waves else "N/A",
            game_type=game_type if game_type else "N/A",
            variant=variant if variant else "N/A"
        )

    def log_info(self, message, **kwargs):
        self.log(
            f"\033[94mINFO      \033[97m{message}", **kwargs
        )

    def log_error(self, message, **kwargs):
        self.log(f"\033[91mERROR     \033[97m{message}", **kwargs)

    def log_debug(self, message, **kwargs):
        self.log(
            f"\033[93mDEBUG     \033[97m{message}",
            **kwargs,
        )


class Console:
    def __init__(self) -> None:
        pass

    def _print_success(
        self, token: str, waves: str, game_type: str, variant: str
    ) -> None:
        with LOCK:
            print(
                f"\033[96mTunaCap\033[0m | \033[91m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m | \033[92mSolved\033[0m | \033[94mTOKEN\033[0m\033[90m[\033[0m{token}\033[90m]\033[0m :: \033[94mWAVES\033[0m\033[90m[\033[0m{waves}\033[90m]\033[0m :: \033[94mGAME-TYPE\033[0m\033[90m[\033[0m{game_type}\033[90m]\033[0m :: \033[94mVARIANT\033[0m\033[90m[\033[0m{variant}\033[90m]\033[0m"
            )

    def _print_failed(
        self, token: str, waves: str, game_type: str, variant: str
    ) -> None:
        with LOCK:
            print(
                f"\033[96mTunaCap\033[0m | \033[91m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m | \033[91mFailed\033[0m | \033[94mTOKEN\033[0m\033[90m[\033[0m{token}\033[90m]\033[0m :: \033[94mWAVES\033[0m\033[90m[\033[0m{waves}\033[90m]\033[0m :: \033[94mGAME-TYPE\033[0m\033[90m[\033[0m{game_type}\033[90m]\033[0m :: \033[94mVARIANT\033[0m\033[90m[\033[0m{variant}\033[90m]\033[0m"
            )

    def _print_challenge(
        self, token: str, waves: str, game_type: str, variant: str
    ) -> None:
        with LOCK:
            print(
                f"\033[96mTunaCap\033[0m | \033[91m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m | \033[38;2;255;165;0mChallenge\033[0m | \033[94mTOKEN\033[0m\033[90m[\033[0m{token}\033[90m]\033[0m :: \033[94mWAVES\033[0m\033[90m[\033[0m{waves}\033[90m]\033[0m :: \033[94mGAME-TYPE\033[0m\033[90m[\033[0m{game_type}\033[90m]\033[0m :: \033[94mVARIANT\033[0m\033[90m[\033[0m{variant}\033[90m]\033[0m"
            )


log = Logger()
