import asyncio
import sys
from hashlib import sha1
from json import dumps
from time import time

import httpx

from .utils import Colors, Config, SecurityMetrics, UserInput


class PassChecker(Colors, Config, UserInput):
    PASS_URL = "https://api.pwnedpasswords.com/range"

    @classmethod
    async def __make_request(
        cls, client: httpx.AsyncClient, head: str
    ) -> httpx.Response:
        return await client.get(f"{cls.PASS_URL}/{head}")

    @staticmethod
    def __leaks_count(response: httpx.Response, tail: str) -> tuple:
        """Parses the k-anonymity response bucket from the server."""
        lines = response.text.splitlines()
        hashes = {
            line.split(":")[0]: int(line.split(":")[1])
            for line in lines
            if ":" in line
        }
        return hashes.get(tail, 0), len(hashes)

    @staticmethod
    def __hashes_password(password: str) -> tuple:
        sha1password = sha1(bytes(password, "utf-8")).hexdigest().upper()
        head, tail = sha1password[:5], sha1password[5:]
        return head, tail, sha1password

    @classmethod
    def display_audit_report(
        cls,
        password: str,
        metrics: dict,
        patterns: list,
        head: str,
        tail: str,
        full_hash: str,
        leaks: int,
        bucket_size: int,
    ) -> None:
        """Detailed academic evaluation output for Data Security and Privacy."""
        border = f"{cls.CYAN}{'=' * 68}{cls.END}"
        print(f"\n{border}")
        print(f"{cls.BOLD}             CREDENTIAL SECURITY & PRIVACY AUDIT REPORT{cls.END}")
        print(border)

        # 1. Security Pillar: Information Theory
        print(f"{cls.LPURPLE}[+] PILLAR 1: DATA SECURITY (Information Theory & Complexity){cls.END}")
        print(f"    • Evaluated String          : {cls.BYELLOW}{password}{cls.END}")
        print(f"    • Password Length (L)       : {cls.WHITE}{metrics['length']}{cls.END} characters")
        print(f"    • Character Pool Size (R)   : {cls.WHITE}{metrics['pool_size']}{cls.END} symbols")
        print(
            f"    • Shannon Entropy (H)       : {metrics['color']}{metrics['entropy']} bits{cls.END}"
        )
        print(f"    • Brute-Force Crack Time    : {cls.WHITE}{metrics['crack_time']}{cls.END} (@ 100 GH/s)")
        print(f"    • Cryptographic Rating      : {metrics['color']}{metrics['rating']}{cls.END}")

        if patterns:
            print(f"\n    {cls.RED}Pattern Vulnerabilities Detected:{cls.END}")
            for p in patterns:
                print(f"      - {p}")

        # 2. Privacy Pillar: k-Anonymity
        print(f"\n{cls.LPURPLE}[+] PILLAR 2: DATA PRIVACY (k-Anonymity Leak Detection){cls.END}")
        print(f"    • Full Client SHA-1 Hash    : {cls.GRAY}{full_hash}{cls.END}")
        print(f"    • Sent Routing Prefix       : {cls.BYELLOW}{head}{cls.END} (Only 5 hex characters sent to server)")
        print(f"    • Protected Client Suffix   : {cls.CYAN}{tail}{cls.END} (Kept local, never disclosed)")
        print(f"    • k-Anonymity Bucket Size   : {cls.WHITE}{bucket_size}{cls.END} candidate hashes returned")

        # Verdict
        print(f"\n{cls.BOLD}[+] FINAL VERDICT:{cls.END}")
        if leaks > 0:
            print(
                f"    {cls.RED}[!] COMPROMISED:{cls.END} Found {cls.WHITE}{leaks:,}{cls.END} times across exposed data breaches."
            )
            print(f"    {cls.RED}[!] STATUS:{cls.END} High Risk. Invalidate and re-hash immediately.")
        else:
            print(
                f"    {cls.BGREEN}[✓] CLEAN:{cls.END} 0 occurrences detected in verified breach records."
            )
        print(f"{border}\n")

    @classmethod
    async def __single_pass(cls, client: httpx.AsyncClient, password: str) -> None:
        while True:
            password = password or cls.get_input("Enter password to audit: ")
            if password == "!s":
                sys.exit()

            metrics = SecurityMetrics.calculate_shannon_entropy(password)
            patterns = SecurityMetrics.check_leetspeak_and_patterns(password)

            head, tail, full_hash = cls.__hashes_password(password)
            try:
                response = await cls.__make_request(client, head)
                leaks, bucket_size = cls.__leaks_count(response, tail)
            except Exception as e:
                print(f"{cls.RED}[!] Connection Error:{cls.END} {e}")
                password = None
                continue

            cls.display_audit_report(
                password=password,
                metrics=metrics,
                patterns=patterns,
                head=head,
                tail=tail,
                full_hash=full_hash,
                leaks=leaks,
                bucket_size=bucket_size,
            )

            password = None

    @classmethod
    async def __mass_pass(cls, client: httpx.AsyncClient, filename: str) -> dict:
        result = {}
        passwords = cls.load_file(filename)
        hash_tuples = [cls.__hashes_password(p) for p in passwords]
        heads = [item[0] for item in hash_tuples]
        tails = [item[1] for item in hash_tuples]

        tasks = [cls.__make_request(client, head) for head in heads]
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)

        for index, response in enumerate(completed_tasks):
            pwd = passwords[index]
            metrics = SecurityMetrics.calculate_shannon_entropy(pwd)
            if isinstance(response, Exception):
                result[pwd] = {"error": str(response)}
                continue

            leaks, _ = cls.__leaks_count(response, tails[index])
            result[pwd] = {
                "length": metrics["length"],
                "shannon_entropy_bits": metrics["entropy"],
                "strength_rating": metrics["rating"],
                "breach_occurrences": leaks,
                "status": "COMPROMISED" if leaks > 0 else "SECURE",
            }

        return result

    @classmethod
    async def run_pass(
        cls,
        client: httpx.AsyncClient,
        filename: str = None,
        password: str = None,
        task_type: str = None,
    ) -> None:
        while True:
            task_type = task_type or cls.get_input(
                f"Choose audit mode ({cls.BYELLOW}1. Single Password{cls.END} or {cls.BYELLOW}2. Batch File Audit{cls.END}): "
            )
            if task_type == "!s":
                sys.exit()

            if task_type == "1":
                await cls.__single_pass(client, password)
            elif task_type == "2":
                filename = filename or cls.get_input("Enter filename (e.g., massp.txt): ")
                started_mass = time()
                result = await cls.__mass_pass(client, filename)
                print(dumps(result, indent=4, ensure_ascii=False))
                print(f"\nBatch completed in: {cls.time_taken(started_mass)}")
                cls.save_results(result, "passleaks.json")

            task_type, filename = None, None