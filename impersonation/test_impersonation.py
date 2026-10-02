from impersonation_detector import analyze_impersonation

tests = [
    "This is Income Tax Department. You have unpaid dues, pay immediately or legal action will be taken.",
    "Hi, are we still meeting for coffee tomorrow?",
    "This is CBI officer calling. There is an arrest warrant against you, call back immediately.",
    "Your Amazon order has shipped.",
    "Hi, this is your CEO. I need you to buy gift cards urgently, don't tell anyone about this.",
    "Reminder: team lunch is at 1pm today.",
    "This is Controller of Examinations. Pay the pending fee immediately or your result will be withheld.",
    "Class is rescheduled to 2pm tomorrow.",
    "This is HDFC Bank. Your KYC update required, share your OTP immediately or your card will be blocked.",
    "Your electricity bill payment was successful.",
    "This is DTDC. Your parcel is on hold, pay customs duty immediately to release it.",
    "Your Swiggy order will arrive in 20 minutes.",
    "Hi it's me, your son. This is my new number, my phone is damaged. Can you send some money right now?",
    "Hey, can you send me the notes from today's class?",
]

for t in tests:
    print(t[:50], "->", analyze_impersonation(t))