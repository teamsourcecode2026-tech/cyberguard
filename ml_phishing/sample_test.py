from model import analyze_phishing

test_messages = [
    "URGENT: Your account will be suspended! Verify now: http://fake-bank-login.com",
    "Hey, are we still on for lunch tomorrow?",
    "Click here immediately to claim your prize: bit.ly/xyz123",
    "Your Amazon order has shipped and will arrive Friday.",
    "Dear user, your password has expired, click here to reset: http://secure-login-update.com",
    "Team meeting moved to 3pm today.",
    "Congratulations! You've won $1000, click to claim: tinyurl.com/abcd",
    "Please review the attached invoice for last month.",
    "Your bank account has been suspended due to suspicious activity. Verify immediately.",
    "Don't forget to submit the report by end of day."
]

for msg in test_messages:
    result = analyze_phishing(msg)
    print(msg[:50], "->", result)