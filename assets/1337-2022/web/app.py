from flask import Flask, request, send_file, render_template_string
from secrets import token_hex
from uuid import uuid4
import adminbot

app = Flask(__name__)
secure_cookie = token_hex(64)
pages = {}

template = """
<!DOCTYPE html>
<html>
<head>
  <title>cool stats</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width"/>
</head>
<body>
  <p>{{ message }}</p>
  <p>u have clicked {{ count | safe }} times!</p>
</body>
</html>
"""


def generate(count: str) -> str:
    message = ""
    number = 0

    try:
        number = int(count)
    except Exception:
        number = -1

    if number > 20000:
        message = "incredible! ur a SUPER clickr!"
    elif number > 500:
        message = "hey, that's pretty good! but can u do better..."
    elif number > 50:
        message = "lame... i can outclick u any day of the week..."
    else:
        message = ""

    return render_template_string(template, message=message, count=count)


@app.route("/")
def index():
    return send_file("static/index.html")


@app.route("/secrets")
def secrets():
    if request.cookies.get("secure_cookie") == secure_cookie:
        return send_file("static/secrets.html")
    else:
        return send_file("static/401.html")


@app.route("/stats")
def stats():
    webpage = generate(request.cookies.get("count", 0))
    unique_id = str(uuid4())
    pages[unique_id] = webpage
    adminbot.visit(f"http://127.0.0.1:31337/view?id={unique_id}", secure_cookie)
    return webpage


@app.route("/view")
def view_stats_page():
    if request.cookies.get("secure_cookie") == secure_cookie:
        unique_id = request.args.get("id", "")
        page = pages.get(unique_id)
        if page:
            pages[unique_id] = None
            return page

        return send_file("static/404.html")

    return send_file("static/401.html")


@app.errorhandler(404)
def page_not_found(err):
    return send_file("static/404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=31337, debug=False)