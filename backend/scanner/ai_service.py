import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

# Setup Gemini API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Use gemini-2.5-flash as the default model
MODEL_NAME = "gemini-2.5-flash"

async def ask_ai(prompt: str, user_message: str) -> str:
    """
    Sends the system prompt (context) and the user message to Gemini.
    """
    if not GEMINI_API_KEY:
        return "AI Assistant is currently unavailable (API Key not configured)."
        
    try:
        # Create generative model instance
        model = genai.GenerativeModel(MODEL_NAME)
        
        # Combine the system prompt (context) with the user message
        full_prompt = f"{prompt}\n\nUser Question:\n{user_message}"
        
        # Call the API synchronously
        response = model.generate_content(full_prompt)
        return response.text
    except Exception as e:
        # Log the error but don't expose it to the user
        print(f"Gemini API Error: {str(e)}")
        return "The AI Assistant encountered an error while processing your request. Please try again later."
