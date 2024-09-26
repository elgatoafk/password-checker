"""
Password Strength Checker Script

This script evaluates the strength of a user's password based on several
criteria, including length, character variety, and whether the password has
been compromised in known data breaches. It can be run from the command line
with optional arguments.

Usage:
    python password_checker.py [password]

If no password is provided as an argument, the script will prompt the user
to enter one interactively.
"""

import argparse
import hashlib
import requests
import re


def parse_arguments() -> str | None:
    """
    Parse command-line arguments provided by the user.

    Returns:
        str: The password provided via command line or None.
    """
    parser = argparse.ArgumentParser(
        description='Password Strength Checker'
    )
    parser.add_argument(
        'password',
        type=str,
        nargs='?',
        help='Password to check'
    )
    args = parser.parse_args()
    return args.password
