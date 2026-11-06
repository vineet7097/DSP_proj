import asyncio
import sys
from argparse import ArgumentParser
from os import name, system

from .api import PassChecker
from .http_client import HttpClient
from .utils import Banner, Colors


class CredentialAuditor(Banner, PassChecker):
    BANNER = r"""
  ██████╗  ███████╗██████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ██╔══██╗ ██╔════╝██╔══██╗   ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██║  ██║ ███████╗██████╔╝   ███████║██║   ██║██║  ██║██║   ██║   
  ██║  ██║ ╚════██║██╔═══╝    ██╔══██║██║   ██║██║  ██║██║   ██║   
  ██████╔╝ ███████║██║        ██║  ██║╚██████╔╝██████╔╝██║   ██║   
  ╚═════╝  ╚══════╝╚═╝        ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   
    """

    @classmethod
    def display_header(cls):
        print(f"{cls.CYAN}{cls.BANNER}{cls.END}")
        print(cls.center(f"{cls.BOLD}DATA SECURITY & PRIVACY (DSP) CREDENTIAL AUDITOR{cls.END}"))
        print(cls.center(f"{cls.GRAY}Shannon Entropy Analysis & k-Anonymity Leak Verification{cls.END}"))
        print(f"\n{cls.RED}>> {cls.LPURPLE}Type {cls.BYELLOW}!s{cls.LPURPLE} anytime to EXIT{cls.END}\n")

    @classmethod
    async def start_program(cls) -> None:
        parser = ArgumentParser(
            description="DSP Mini Project: Password Entropy and k-Anonymity Breach Auditor"
        )
        parser.add_argument(
            "-pu",
            "--proxy_url",
            default=None,
            type=str,
            help="Proxy URL (optional)",
        )
        parser.add_argument(
            "-t",
            "--task_type",
            default=None,
            type=str,
            choices=["1", "2"],
            help="(1) Single Credential Audit (2) Mass Batch File Audit",
        )
        parser.add_argument(
            "-p",
            "--password",
            default=None,
            type=str,
            help="Password to audit directly",
        )
        parser.add_argument(
            "-f",
            "--filename",
            default=None,
            type=str,
            help="Path to password text file for batch mode",
        )

        args = parser.parse_args()
        cls.display_header()

        async with HttpClient(args.proxy_url) as client:
            await cls.run_pass(
                client=client,
                filename=args.filename,
                password=args.password,
                task_type=args.task_type,
            )


if __name__ == "__main__":
    system("cls" if name == "nt" else "clear")
    asyncio.run(CredentialAuditor.start_program())