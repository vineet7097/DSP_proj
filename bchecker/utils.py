import math
import re
import sys
from json import dump
from os import get_terminal_size
from os.path import exists
from time import time


class Colors:
    GREEN = "\033[38;5;121m"
    BGREEN = "\033[38;5;82m"
    WHITE = "\033[38;5;231m"
    LBLUE = "\033[38;5;117m"
    BYELLOW = "\033[38;5;226m"
    LYELLOW = "\033[38;5;228m"
    LPURPLE = "\033[38;5;141m"
    CYAN = "\033[38;5;51m"
    RED = "\033[38;5;196m"
    GRAY = "\033[38;5;244m"
    BOLD = "\033[1m"
    END = "\033[0m"


class Banner:
    @staticmethod
    def __get_spaces(text: str) -> int:
        try:
            col = get_terminal_size().columns
        except OSError:
            col = 80
        ntext = max(len(line.strip()) for line in text.splitlines())
        return max(0, (col - ntext) // 2)

    @classmethod
    def center(cls, text: str) -> str:
        spaces = cls.__get_spaces(text=text)
        return "\n".join(f"{' ' * spaces}{line}" for line in text.splitlines())


class SecurityMetrics:
    """Mathematical calculations for Data Security and Information Theory."""

    @staticmethod
    def calculate_shannon_entropy(password: str) -> dict:
        """
        Calculates Shannon Entropy: H = L * log2(R)
        L = password length
        R = character pool size
        """
        length = len(password)
        if length == 0:
            return {"entropy": 0.0, "pool_size": 0, "length": 0, "rating": "Empty", "crack_time": "Instant", "color": Colors.RED}

        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digits = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digits:
            pool_size += 10
        if has_special:
            pool_size += 33

        entropy = round(length * math.log2(pool_size), 2) if pool_size > 0 else 0.0

        if entropy < 28:
            rating = "Very Weak (Instant dictionary attack)"
            color = Colors.RED
        elif entropy < 45:
            rating = "Weak (Fast GPU brute-force feasible)"
            color = Colors.BYELLOW
        elif entropy < 65:
            rating = "Moderate (Acceptable for standard accounts)"
            color = Colors.LBLUE
        elif entropy < 85:
            rating = "Strong (Computationally expensive to attack)"
            color = Colors.GREEN
        else:
            rating = "Very Strong / Cryptographically Robust"
            color = Colors.BGREEN

        guesses = 2**entropy
        seconds = guesses / 1e11
        crack_time = SecurityMetrics._format_crack_time(seconds)

        return {
            "entropy": entropy,
            "pool_size": pool_size,
            "length": length,
            "rating": rating,
            "color": color,
            "crack_time": crack_time,
        }

    @staticmethod
    def _format_crack_time(seconds: float) -> str:
        if seconds < 1:
            return "Instant (< 1 sec)"
        elif seconds < 60:
            return f"{round(seconds, 2)} seconds"
        elif seconds < 3600:
            return f"{round(seconds / 60, 2)} minutes"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 2)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400, 2)} days"
        elif seconds < 3153600000:
            return f"{round(seconds / 31536000, 2)} years"
        else:
            return "Centuries / Computationally Infeasible"

    @staticmethod
    def check_leetspeak_and_patterns(password: str) -> list:
        warnings = []
        leet_map = {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "7": "t"}
        normalized = "".join(leet_map.get(c, c).lower() for c in password)

        common_bases = ["password", "admin", "welcome", "qwerty", "login", "secret", "vineet"]
        for base in common_bases:
            if base in normalized:
                warnings.append(f"Contains predictable root word '{base}' with trivial substitution")

        if re.search(r"(.)\1\1", password):
            warnings.append("Three or more consecutive repeated characters detected")

        return warnings


class UserInput:
    @staticmethod
    def get_input(prompt: str) -> str:
        return input(prompt)


class Config:
    @staticmethod
    def load_file(filename: str) -> list:
        if not exists(filename):
            print(f'\n{Colors.RED}File not found: "{filename}"{Colors.END}\n')
            sys.exit()
        with open(filename, "r") as file:
            return [line.strip() for line in file if line.strip()]

    @staticmethod
    def save_results(results, config_file: str) -> None:
        with open(config_file, "a", encoding="utf8") as file:
            dump(results, file, indent=4, ensure_ascii=False)
            file.write("\n\n")
        print(f'\n{Colors.BYELLOW}Results appended to{Colors.END} "{Colors.LPURPLE}{config_file}{Colors.END}"')

    @staticmethod
    def time_taken(started_time: float) -> str:
        elapsed = round((time() - started_time), 2)
        if elapsed < 60:
            return f"{elapsed} seconds" if elapsed >= 1 else f"{round(elapsed * 1000)} ms"
        minutes, seconds = divmod(int(elapsed), 60)
        return f"{minutes} min {seconds} sec"