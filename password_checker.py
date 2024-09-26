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
import string

# length requirement for password to pass the check
LENGTH_REQUIREMENT = 16

# Maximum score achievable
MAX_SCORE = 9

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


def has_sequential_chars(password, sequence_length=4):
    """
    Check if the password contains sequential characters.

    Args:
        password (str): The password to check.
        sequence_length (int): The minimum length of the sequence to check for.

    Returns:
        bool: True if a sequence is found, False otherwise.
    """
    sequences = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
    ]

    # Check for increasing sequences
    for seq in sequences:
        for i in range(len(seq) - sequence_length + 1):
            sub_seq = seq[i:i + sequence_length]
            if sub_seq in password:
                return True

    # Check for decreasing sequences
    for seq in sequences:
        reversed_seq = seq[::-1]
        for i in range(len(reversed_seq) - sequence_length + 1):
            sub_seq = reversed_seq[i:i + sequence_length]
            if sub_seq in password:
                return True

    return False


def has_keyboard_pattern(password):
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


def has_repeated_substring(password):
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


def check_strength(password):
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

    # Sequential characters check
    if has_sequential_chars(password):
        recommendations.append(
            "Avoid using sequential letters or numbers."
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
    try:
        leak_count = check_password_leak(password)
        if leak_count:
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
    print(f"\nPassword Score: {score}/{MAX_SCORE}")
    if recommendations:
        print("Recommendations:")
        for rec in recommendations:
            print(f"- {rec}")
    else:
        print("Your password is strong!")


if __name__ == '__main__':
    main()
