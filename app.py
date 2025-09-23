import os
import requests
from dotenv import load_dotenv
import streamlit as st

# Load API key
load_dotenv()
API_KEY = os.getenv("KRUTRIM_API_KEY")

API_URL = "https://cloud.olakrutrim.com/v1/chat/completions"

# Function to call Krutrim API
def chat_with_krutrim(prompt):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "Krutrim-spectre-v2",  # adjust if needed
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 512,
        "temperature": 0.7
    }

    response = requests.post(API_URL, headers=headers, json=payload)

    if response.status_code == 200:
        data = response.json()
        return data["choices"][0]["message"]["content"]
    else:
        return f"❌ Error: {response.status_code}, {response.text}"

# Streamlit UI
st.set_page_config(page_title="Krutrim Chatbot", page_icon="🤖", layout="centered")

st.title("🤖 Krutrim Chatbot")
st.write("Chat with Krutrim AI below:")

if "messages" not in st.session_state:
    st.session_state.messages = []

# Show chat history
for role, text in st.session_state.messages:
    if role == "user":
        st.chat_message("user").markdown(text)
    else:
        st.chat_message("assistant").markdown(text)

# Chat input
if prompt := st.chat_input("Type your message..."):
    st.session_state.messages.append(("user", prompt))
    st.chat_message("user").markdown(prompt)

    with st.spinner("Thinking..."):
        reply = chat_with_krutrim(prompt)

    st.session_state.messages.append(("assistant", reply))
    st.chat_message("assistant").markdown(reply)
