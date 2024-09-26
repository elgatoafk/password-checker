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


def check_strength(password) -> tuple[int, list[str]]:
    """
    Evaluate the strength of the given password.

    The function checks for minimum length, presence of uppercase and
    lowercase letters, digits, and special characters.

    Args:
        password (str): The password to evaluate.

    Returns:
        tuple: A tuple containing the score (int) and a list of
               recommendations (list of str).
    """
    score = 0
    recommendations = []

    # Check password length
    if len(password) < 8:
        recommendations.append(
            "Please use a password at least 8 characters long."
        )
    else:
        score += 1

    # If the password is short and lacks other attributes
    if len(password) < 8:
        if not any(char.isupper() for char in password) and \
                not any(char.islower() for char in password) and \
                not any(char.isdigit() for char in password) and \
                not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            # Only length recommendation is needed
            return score, recommendations

    # Uppercase letter check
    if not any(char.isupper() for char in password):
        recommendations.append(
            "Include at least one uppercase letter."
        )
    else:
        score += 1

    # Lowercase letter check
    if not any(char.islower() for char in password):
        recommendations.append(
            "Include at least one lowercase letter."
        )
    else:
        score += 1

    # Digit check
    if not any(char.isdigit() for char in password):
        recommendations.append(
            "Include at least one number."
        )
    else:
        score += 1

    # Special character check
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        recommendations.append(
            "Include at least one special character."
        )
    else:
        score += 1

    return score, recommendations


def check_password_leak(password) -> int:
    """
    Check if the password has been compromised in a data breach.

    Uses the Have I Been Pwned API to check if the password exists
    in known data breaches without compromising user privacy.

    Args:
        password (str): The password to check.

    Returns:
        int: The number of times the password was found in data breaches.
    """
    # Hash the password using SHA-1
    sha1pwd = hashlib.sha1(
        password.encode('utf-8')
    ).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]

    # Query the API with the hash prefix
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(url, timeout=20)
    if response.status_code != 200:
        raise RuntimeError(
            f'Error fetching data: {response.status_code}'
        )

    # Check if the hash suffix is in the response
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

