from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def home():

    logs = []

    total_threats = 0
    blocked_ips = 0

    try:
        with open("logs/firewall.log", "r") as file:

            logs = file.readlines()[-50:]

            for line in logs:

                if "Suspicious" in line:
                    total_threats += 1

                if "Blocked IP" in line:
                    blocked_ips += 1

    except:
        logs = ["No logs found"]

    return render_template(
        "index.html",
        logs=logs,
        threats=total_threats,
        blocked=blocked_ips
    )

if __name__ == "__main__":
    app.run(debug=True)