import re

def _luhn(digits: str) -> bool:
    digit_list = [int(char) for char in reversed(digits)]
    total = sum(
        digit if index % 2 == 0 else (digit * 2 - 9 if digit * 2 > 9 else digit * 2)
        for index, digit in enumerate(digit_list)
    )
    return total % 10 == 0


# Email Pattern Detection
email_pattern = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

def detect_emails(text):
    return [(match.start(), match.end(), 'EMAIL', match.group()) for match in email_pattern.finditer(text)]


# Phone Pattern Detection
phone_pattern = re.compile(
    r'(?<![A-Za-z\d])\+91[\s\-]?\d{2,5}[\s\-]?\d{4,9}(?![A-Za-z\d])'
)

def detect_phones(text):
    spans = []
    for match in phone_pattern.finditer(text):
        if len(re.sub(r'\D', '', match.group())) == 12:
            spans.append((match.start(), match.end(), 'PHONE', match.group()))
    return spans


# SSN Pattern Detection
ssn_pattern = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

def detect_ssns(text):
    return [(match.start(), match.end(), 'SSN', match.group()) for match in ssn_pattern.finditer(text)]


# Credit Card Pattern Detection
credit_card_pattern = re.compile(r'(?<![A-Za-z\d])\d(?:[ \-]?\d){12,18}(?![A-Za-z\d])')

def detect_credit_cards(text):
    spans = []
    for match in credit_card_pattern.finditer(text):
        digits = re.sub(r'\D', '', match.group())
        if 13 <= len(digits) <= 19 and _luhn(digits):
            spans.append((match.start(), match.end(), 'CREDIT_CARD', match.group()))
    return spans


# IP Pattern Detection
ip_pattern = re.compile(r'(?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)')

def detect_ips(text):
    spans = []
    for match in ip_pattern.finditer(text):
        if all(0 <= int(octet) <= 255 for octet in match.group().split('.')):
            spans.append((match.start(), match.end(), 'IP', match.group()))
    return spans


# DOB Pattern Detection
month_pattern = (
    r'Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?'
    r'|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?'
)
date_pattern = re.compile(
    r'\b(?:'
    r'\d{1,2}\s+(?:' + month_pattern + r')\s+\d{4}'
    r'|(?:' + month_pattern + r')\s+\d{1,2},?\s+\d{4}'
    r'|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}'
    r'|\d{4}[/\-]\d{1,2}[/\-]\d{1,2}'
    r')\b',
    re.IGNORECASE,
)
dob_context_pattern = re.compile(
    r'\b(?:born|date\s+of\s+birth|dob|birth\s+date)\b', re.IGNORECASE
)

def detect_dob(text):
    spans = []
    for date_match in date_pattern.finditer(text):
        window = text[max(0, date_match.start() - 60):date_match.start()]
        if dob_context_pattern.search(window):
            spans.append((date_match.start(), date_match.end(), 'DOB', date_match.group()))
    return spans


if __name__ == "__main__":
    all_detectors = [detect_emails, detect_phones, detect_ssns,
                     detect_credit_cards, detect_ips, detect_dob]

    tests = [
        ("Email", "Contact: john.doe@kshintl.co.in for queries."),
        ("Phone STD", "Landline: +91 20 45053237"),
        ("Phone mobile", "Mobile: +91 81081 14949"),
        ("SSN", "Her SSN is 123-45-6789."),
        ("Credit card", "Card number: 4111 1111 1111 1111"),
        ("IP address", "Server IP: 203.0.113.42"),
        ("DOB gated", "Director was born on 12 March 1990 in Mumbai."),
        ("DOB gated alt", "Date of Birth: 15/08/1985"),
        ("CIN", "CIN: U28129PN1979PLC141032"),
        ("DIN", "DIN: 00135070"),
        ("PIN", "Pune - 411 001"),
        ("SEBI reg", "SEBI reg. INM000013004"),
        ("Corp date", "resolution dated May 6, 2025"),
        ("Bare date", "incorporated on 15 March 2003"),
    ]

    for label, text in tests:
        hits = [hit for detector_func in all_detectors for hit in detector_func(text)]
        print(label)
        for hit in hits:
            print(f"  {hit[2]}: {hit[3]!r}")

