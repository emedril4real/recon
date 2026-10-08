from __future__ import annotations

from flask import Flask, render_template, request

from recon_tool import run_recon, summarize_recon

app = Flask(__name__)
app.config["SECRET_KEY"] = "recon-demo-secret"


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    target = ""

    if request.method == "POST":
        target = (request.form.get("target") or "").strip()
        if target:
            try:
                report = run_recon(target)
                report["summary"] = summarize_recon(report)
            except ValueError:
                report = {"error": "Please enter a valid URL or domain."}

    return render_template("index.html", report=report, target=target)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
