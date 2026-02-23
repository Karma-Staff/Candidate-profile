import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

with open('available_models.txt', 'w') as f:
    try:
        f.write("Listing all available models:\n")
        for m in genai.list_models():
            f.write(f"- {m.name} (Methods: {m.supported_generation_methods})\n")
    except Exception as e:
        f.write(f"Error listing models: {e}\n")
