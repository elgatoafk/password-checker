"""
Password Strength Checker Script

This script evaluates the strength of a user's password based on several
criteria, including length, character variety, sequences, and whether the password
has been compromised in known data breaches. It can be run from the command line
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
from colorama import init, Fore, Style
init(autoreset=True)
# length requirement for password to pass the check
LENGTH_REQUIREMENT = 16

# Maximum score achievable
MAX_SCORE = 10

# Common keyboard patterns
KEYBOARD_PATTERNS = [
    'qwerty', 'asdfgh', 'zxcvbn', '12345', 'qazwsx', '1qaz2wsx',
    'password', 'admin', 'letmein', 'iloveyou', 'welcome'
]


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


def has_consecutive_letters(password) -> bool:
    """
    Check if the password contains three or more consecutive letters.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if consecutive letters are found, False otherwise.
    """
    count = 0
    for char in password:
        if char.isalpha():
            count += 1
            if count >= 3:
                return True
        else:
            count = 0
    return False


def has_consecutive_numbers(password) -> bool:
    """
    Check if the password contains three or more consecutive numbers.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if consecutive numbers are found, False otherwise.
    """
    count = 0
    for char in password:
        if char.isdigit():
            count += 1
            if count >= 3:
                return True
        else:
            count = 0
    return False


def has_keyboard_pattern(password) -> bool:
    """
    Check if the password contains common keyboard patterns.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if a keyboard pattern is found, False otherwise.
    """
    password_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            return True
    return False


def has_repeated_substring(password) -> bool:
    """
    Check if the password contains repeated substrings.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if a repeated substring is found, False otherwise.
    """
    for i in range(1, len(password) // 2 + 1):
        substr = password[:i]
        repetitions = len(password) // len(substr)
        if substr * repetitions == password[:repetitions * len(substr)]:
            return True
    return False


def check_strength(password) -> tuple[int, list[str]]:
    """
    Evaluate the strength of the given password.

    The function checks for minimum length, presence of uppercase and
    lowercase letters, digits, special characters, and sequences.

    Args:
        password (str): The password to evaluate.

    Returns:
        tuple: A tuple containing the score (int) and a list of
               recommendations (list of str).
    """
    score = 0
    recommendations = []

    # Check password length (minimum 12 characters)
    if len(password) < 12:
        recommendations.append(
            "Please use a password at least 12 characters long."
        )
    else:
        score += 1

    # If the password is too short and lacks other attributes
    if len(password) < 12 and not any([
        any(char.isupper() for char in password),
        any(char.islower() for char in password),
        any(char.isdigit() for char in password),
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    ]):
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

        # Consecutive letters check
    if has_consecutive_letters(password):
        recommendations.append(
            "Avoid using three or more consecutive letters."
        )
    else:
        score += 1

        # Consecutive numbers check
    if has_consecutive_numbers(password):
        recommendations.append(
            "Avoid using three or more consecutive numbers."
        )
    else:
        score += 1

    # Keyboard pattern check
    if has_keyboard_pattern(password):
        recommendations.append(
            "Avoid using common keyboard patterns."
        )
    else:
        score += 1

    # Repeated substring check
    if has_repeated_substring(password):
        recommendations.append(
            "Avoid using repeated words or patterns."
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


def main():
    """
    The main function that orchestrates the password checking process.

    It handles user input, calls the strength and leak check functions,
    and outputs the final results to the user.
    """
    password = parse_arguments()
    if not password:
        import getpass
        password = getpass.getpass("Enter your password: ")

    score = 0
    recommendations = []

    # Strength Checks
    strength_score, strength_recommendations = check_strength(password)
    score += strength_score
    recommendations.extend(strength_recommendations)

    # Leaked Password Check
    password_leaked = False
    try:
        leak_count = check_password_leak(password)
        if leak_count:
            password_leaked = True
            recommendations.append(
                f"Your password has been found {leak_count} times "
                "in data breaches. Avoid using compromised passwords."
            )
        else:
            score += 1  # Increment score if password not found in leaks
    except Exception as e:
        recommendations.append(
            f"An error occurred while checking password leak: {e}"
        )

    # Final Output
    if score >= 7:
        print(Fore.GREEN + f"\nPassword Score: {score}/{MAX_SCORE}")
    elif score >= 4:
        print(Fore.YELLOW + f"\nPassword Score: {score}/{MAX_SCORE}")
    else:
        print(Fore.RED + f"\nPassword Score: {score}/{MAX_SCORE}")

    if recommendations:
        # Print recommendations with appropriate colors
        print(Fore.YELLOW + "Recommendations:")
        for rec in recommendations:
            if "data breaches" in rec:
                # Highlight leak warning in red
                print(Fore.RED + f"- {rec}")
            else:
                print(Fore.YELLOW + f"- {rec}")
    else:
        print(Fore.GREEN + "Your password is strong!")

if __name__ == '__main__':
    main()
