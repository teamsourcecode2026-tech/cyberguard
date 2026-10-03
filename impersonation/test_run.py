from detector import analyze_impersonation

# Test 1: suspicious profile
result1 = analyze_impersonation(profile={
    "name": "Narendra Modii",
    "claimed_title": "Prime Minister",
    "bio": "Official PM account",
    "verified": False,
    "account_age_days": 5,
    "follower_count": 42,
})
print("Profile test:", result1)

# Test 2: scam message
result2 = analyze_impersonation(message={
    "text": "This is the Income Tax Department. You have a pending fine. Pay immediately to avoid arrest warrant.",
    "sender_name": "IT Department",
    "sender_email": "officer123@gmail.com",
})
print("Message test:", result2)

# Test 3: legitimate-looking message
result3 = analyze_impersonation(message={
    "text": "Reminder: your appointment is scheduled for tomorrow at 10 AM.",
    "sender_email": "office@gov.in",
})
print("Legit test:", result3)
# Test 4: CEO fraud attempt
result4 = analyze_impersonation(message={
    "text": "Hi, I'm in a meeting and can't talk right now. I need you to buy gift cards urgently and send me the codes. Keep this confidential, don't tell anyone.",
    "sender_name": "CEO Office",
})
print("CEO fraud test:", result4)