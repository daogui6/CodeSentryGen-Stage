from flask import Flask, jsonify


app = Flask(__name__)


@app.get("/")
def index():
    return jsonify({
        "message": "Hello, World!",
        "status": "ok",
    })


@app.get("/health")
def health_check():
    return jsonify({
        "healthy": True,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
