"""Shared settings: where the API key comes from and which model to use."""
from pathlib import Path
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
MODEL = "gemini-3.8-flash"   # change here if your key needs a different model


def get_api_key() -> str:
    """Read GEMINI_API_KEY from the .env file in the project folder."""
    key = dotenv_values(ROOT / ".env").get("GEMINI_API_KEY")
    if not key:
        raise SystemExit("No GEMINI_API_KEY found in .env")
    return key
