from flask import Flask, request, jsonify
from flask_cors import CORS
import requests, os, time, json
from functools import wraps

os.environ.setdefault('PORT', '5000')  # Default port for local testing

# ─── NEW: load variables from .env if present ────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()            # silently does nothing if no .env file exists
except ModuleNotFoundError:
    # python-dotenv not installed – script still works if ENV vars are set
    pass
# ─────────────────────────────────────────────────────────────────────────────

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")  # now populated by .env
CACHE_TTL = 300  # seconds

app = Flask(__name__)
CORS(app)

# ─── simple in-memory cache decorator ────────────────────────────────────────
_cache = {}
def cache_response(ttl=CACHE_TTL):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            key = str(hash(str(request.get_json())))
            now = time.time()
            if key in _cache:
                data, ts = _cache[key]
                if now - ts < ttl:
                    return data
            result = f(*args, **kwargs)
            _cache[key] = (result, now)
            # prune expired
            expired = [k for k, (_, ts) in _cache.items() if now - ts >= ttl]
            for k in expired:
                _cache.pop(k, None)
            return result
        return wrapped
    return decorator
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/ask", methods=["POST"])
@cache_response(ttl=180)               # 3-minute cache
def ask_question():
    try:
        data          = request.json or {}
        question      = data.get("question", "").strip()
        property_data = data.get("propertyData", {})

        if not question or not property_data:
            return jsonify({"answer": "Please provide a valid question."}), 400

        prompt = f"""
You are a helpful real estate AI assistant. A potential buyer is asking about a property.

Property Details:
- Title       : {property_data.get('title', 'N/A')}
- Description : {property_data.get('description', 'N/A')[:300]}…
- Price       : ₹{property_data.get('price', 'N/A'):,}
- Address     : {property_data.get('address', 'N/A')}
- Location    : lat {property_data.get('location', {}).get('latitude', 'N/A')}, \
lng {property_data.get('location', {}).get('longitude', 'N/A')}

Customer Question: {question}

Please respond concisely (≤150 words):
1. Directly answer the question
2. Highlight key benefits
3. Encourage consideration
4. Keep tone engaging and professional
"""

        if GEMINI_API_KEY:
            ai_answer = call_gemini_api(prompt)
            if ai_answer:
                return jsonify({"answer": ai_answer})

        return jsonify({"answer": fallback_answer(question, property_data)})
    except Exception as e:
        print("ask_question error:", e)
        return jsonify({"answer": "Sorry, something went wrong."}), 500

# ─── Gemini API helper ───────────────────────────────────────────────────────
def call_gemini_api(prompt: str):
    try:
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               "gemini-2.0-flash:generateContent")
        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": GEMINI_API_KEY
        }
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": 3000,
                "temperature": 0.7,
                "topK": 40,
                "topP": 0.8
            }
        }
        res = requests.post(url, headers=headers, json=payload, timeout=15)
        if res.status_code == 200:
            body = res.json()
            parts = (body.get("candidates") or [{}])[0] \
                        .get("content", {}) \
                        .get("parts", [])
            if parts and isinstance(parts[0], dict):
                return parts[0].get("text", "").strip()
        else:
            print("Gemini error:", res.status_code, res.text[:200])
    except requests.exceptions.Timeout:
        print("Gemini API timeout")
    except Exception as e:
        print("Gemini call failed:", e)
    return None
# ─────────────────────────────────────────────────────────────────────────────

# ─── fallback answer generator (unchanged) ───────────────────────────────────
def fallback_answer(q: str, p: dict) -> str:
    title   = p.get("title", "this property")
    price   = p.get("price", 0)
    address = p.get("address", "a great location")
    desc    = p.get("description", "")

    q_low = q.lower()
    if any(k in q_low for k in ("price", "cost", "expensive")):
        return (f"The asking price for {title} is ${price:,}. Considering its "
                f"prime location at {address}, this is excellent value.")
    if any(k in q_low for k in ("location", "area", "neighborhood")):
        return (f"{title} is situated at {address}, offering convenient access "
                "to daily amenities and transport.")
    if any(k in q_low for k in ("size", "space", "room")):
        return (f"{title} provides generous living space. {desc[:120]}…")
    if any(k in q_low for k in ("investment", "value")):
        return (f"At ${price:,}, {title} presents a strong investment "
                "opportunity given local appreciation trends.")
    if any(k in q_low for k in ("amenities", "features")):
        return (f"{title} boasts modern amenities and thoughtful design. "
                f"{desc[:140]}…")
    return (f"Thanks for your interest in {title}! Priced at ${price:,} "
            f"and located at {address}. Let me know if you need any more "
            "details.")

# ─── utility endpoints (unchanged) ───────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "healthy", "cache_entries": len(_cache)})

@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    _cache.clear()
    return jsonify({"message": "Cache cleared"})


# ─── main ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True, debug=False)
