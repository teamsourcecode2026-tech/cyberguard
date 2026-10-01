from social_media_detector import analyze_social_media_phishing

test_messages = [
    "Hey girl, loved your last post! Keep it up 🔥",
    "Congratulations! You've been selected for our giveaway. Claim your prize now!",
    "Your account will be disabled in 24 hours due to violating community guidelines. Confirm your account here.",
    "Hi, I'm interested in your product. Can we discuss pricing?",
    "I've made huge profits with crypto trading. Let me show you how, message me on WhatsApp.",
    "Hello, this is Instagram Support. Your account was flagged. Verify now to avoid suspension.",
    "I feel like we have a real connection. I'm lonely and would love to talk more, here's my number."
]

for msg in test_messages:
    result = analyze_social_media_phishing(msg)
    print(f"\n{msg[:55]} -> {result}")