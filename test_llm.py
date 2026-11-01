from pathlib import Path
from dotenv import dotenv_values
from google import genai

env_path = Path(__file__).parent / ".env"
key = dotenv_values(env_path).get("GEMINI_API_KEY")
print("Key length:", len(key) if key else 0)
if not key:
    raise SystemExit("No key found. Check your .env file.")

client = genai.Client(api_key=key)
MODEL = "gemini-3.5-flash"

try:
    reply = client.models.generate_content(
        model=MODEL,
        contents="In one sentence, what is a SOC alert?",
    )
    print("WORKS:", reply.text)
except Exception as e:
    print("ERROR:", e)
    print("Models your key can use:")
    for m in client.models.list():
        print(" -", m.name)