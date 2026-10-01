from sms_detector import analyze_sms_phishing

test_messages = [
    "Your OTP is 834521. Do not share this code with anyone.",
    "Hey, running 10 mins late for dinner!",
    "Your package delivery failed. Pay a small customs fee to redeliver: bit.ly/redeliver-now",
    "Reminder: your dentist appointment is tomorrow at 10am.",
    "URGENT: Your bank account is locked. Verify your identity here: tinyurl.com/verify-acc",
    "Mom, can you pick me up from school at 4?"
]

for msg in test_messages:
    result = analyze_sms_phishing(msg)
    print(f"\n{msg[:50]} -> {result}")