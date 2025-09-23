import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
API_KEY = os.getenv("KRUTRIM_API_KEY")

# Krutrim API endpoint (latest as of now)
API_URL = "https://cloud.olakrutrim.com/v1/chat/completions"

def chat_with_krutrim(prompt):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "Krutrim-spectre-v2",  # example model (update if needed)
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 512,
        "temperature": 0.7
    }

    response = requests.post(API_URL, headers=headers, json=payload)

    if response.status_code == 200:
        data = response.json()
        return data["choices"][0]["message"]["content"]
    else:
        return f"Error: {response.status_code}, {response.text}"

if __name__ == "__main__":
    print("🤖 Krutrim Chatbot (type 'exit' to quit)\n")
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            print("Chatbot: Goodbye! 👋")
            break
        reply = chat_with_krutrim(user_input)
        print("Chatbot:", reply)
