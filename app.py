from flask import Flask, render_template, request

from url_analyzer import analyze_url


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    url = ""

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:
            result = analyze_url(url)

            # Decide the visual style of the result
            if result.get("trusted"):
                result["risk_class"] = "trusted"

            elif result.get("risk_level") == "Low Risk":
                result["risk_class"] = "low"

            elif result.get("risk_level") == "Medium Risk":
                result["risk_class"] = "medium"

            elif result.get("risk_level") == "High Risk":
                result["risk_class"] = "high"

    return render_template(
        "index.html",
        result=result,
        url=url
    )


if __name__ == "__main__":
    app.run(debug=True)