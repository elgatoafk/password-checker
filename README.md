# Password Strength Checker

## Overview

The **Password Strength Checker** is a Python tool that evaluates the strength of a password based on several criteria. It checks the length, complexity, presence of common patterns, and verifies whether the password has been compromised in known data breaches.

The tool can be used as a standalone script with command-line arguments, or as part of a larger system like a web app or API.

## Features

- **Length Check**: Ensures the password meets a minimum length.
- **Uppercase, Lowercase, Digits, and Special Characters**: Ensures the password contains a variety of character types.
- **No Consecutive Characters**: Avoids passwords with three or more consecutive letters (e.g., `"abc"`) or numbers (e.g., `"123"`).
- **Avoids Common Patterns**: Detects common keyboard patterns like `"qwerty"` or `"password"`.
- **No Repeated Substrings**: Identifies passwords with repeated substrings (e.g., `"abcabcabc"`).
- **Data Breach Check**: Integrates with the [Have I Been Pwned API](https://haveibeenpwned.com/API/v3#PwnedPasswords) to check if the password has been compromised in a data breach.
- **Colorful Output**: Uses `colorama` for colored feedback on password strength.

## Requirements

- **Python 3.6+**
- **Dependencies**: Listed in `requirements.txt`

### Dependencies

- `requests`
- `colorama`

Install the required packages with:

```bash
pip install -r requirements.txt
```

## Usage

You can run the Password Strength Checker directly from the command line.

### Running with Command Line Arguments

```bash
python password_checker.py [password]
```

If no password is provided as an argument, the script will prompt the user to enter one interactively.

### Example Usage:

```bash
python password_checker.py MyStr0ngP@ssw0rd!
```

### Sample Output:

```bash
Password Score: 6/7
Recommendations:
- Avoid using consecutive letters/numbers, common patterns, or repeated words.
```

If the password has been compromised in a known data breach, the output will warn you:

```bash
Password Score: 0/7
Your password has been found 500 times in data breaches. Avoid using compromised passwords.
```

## How It Works

### Password Strength Scoring

The password strength is evaluated across multiple criteria:
1. **Length**: A password must be at least 12 characters long.
2. **Character Variety**: A mix of uppercase letters, lowercase letters, digits, and special characters is required.
3. **Consecutive Characters**: Avoids three or more consecutive letters or numbers.
4. **Common Patterns**: Passwords like `"password"`, `"qwerty"`, and other keyboard patterns are flagged.
5. **Repeated Substrings**: Repeated patterns within the password, like `"abcabcabc"`, reduce its strength.
6. **Data Breach Check**: If the password has been compromised in a known breach, its score is set to 0.

### Password Compromise Check

The script uses the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) API to check if a password has been found in known data breaches. This does not send the password directly but hashes it using the SHA-1 algorithm and checks for matching prefixes in the leaked password database.

## License

This project is licensed under the MIT License.
