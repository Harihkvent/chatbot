import os
import streamlit as st
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import requests
import bcrypt
from urllib.parse import quote_plus

# ----------------- Load environment -----------------
load_dotenv()
DEFAULT_API_KEY = os.getenv("KRUTRIM_API_KEY")
API_URL = "https://cloud.olakrutrim.com/v1/chat/completions"

# ----------------- MongoDB -----------------
password = quote_plus(os.getenv("MONGO_PASS"))
dbname = os.getenv("MONGO_DB")
password = quote_plus(password)
MONGO_URI = f"mongodb+srv://chatbot:{password}@cluster0.57nirib.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
db = client[dbname]
users_col = db.users
chats_col = db.chats

# ----------------- Authentication -----------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def register_user(email, password):
    if users_col.find_one({"email": email}):
        return False, "User already exists!"
    hashed = hash_password(password)
    users_col.insert_one({
        "email": email,
        "password_hash": hashed,
        "api_key": None,
        "tokens_used_today": 0,
        "last_reset": datetime.now(timezone.utc)
    })
    return True, "Registered successfully!"

def login_user(email, password):
    user = users_col.find_one({"email": email})
    if not user:
        return False, "User not found."
    if check_password(password, user["password_hash"]):
        return True, user
    return False, "Incorrect password."

# ----------------- Rate Limiting -----------------
def can_use_tokens(user, tokens_needed):
    last_reset = user.get("last_reset")

    if not isinstance(last_reset, datetime):
        last_reset = datetime.now(timezone.utc)
    else:
        # If stored as naive, make it UTC aware
        if last_reset.tzinfo is None:
            last_reset = last_reset.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) - last_reset > timedelta(days=1):
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"tokens_used_today": 0, "last_reset": datetime.now(timezone.utc)}}
        )
        user["tokens_used_today"] = 0

    return user["tokens_used_today"] + tokens_needed <= 2000

def increment_tokens(user, tokens):
    users_col.update_one({"_id": user["_id"]}, {"$inc": {"tokens_used_today": tokens}})

# ----------------- Krutrim Chat -----------------
def chat_with_krutrim(messages, api_key=None):
    key_to_use = api_key if api_key else DEFAULT_API_KEY
    headers = {"Authorization": f"Bearer {key_to_use}", "Content-Type": "application/json"}
    payload = {"model": "Krutrim-spectre-v2", "messages": messages, "max_tokens": 512, "temperature": 0.7}
    resp = requests.post(API_URL, headers=headers, json=payload)
    if resp.status_code == 200:
        data = resp.json()
        return data["choices"][0]["message"]["content"], payload["max_tokens"]
    return f"❌ Error: {resp.status_code}, {resp.text}", 0

# ----------------- Streamlit UI -----------------
st.set_page_config(page_title="Krutrim Chatbot", page_icon="🤖", layout="centered")

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user" not in st.session_state:
    st.session_state.user = None
if "messages" not in st.session_state:
    st.session_state.messages = []

# ----------------- Login / Registration -----------------
if not st.session_state.authenticated:
    st.title("Login / Register")
    choice = st.radio("Login method:", ["Email/Password", "Google"])

    if choice == "Email/Password":
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.button("Register"):
            success, msg = register_user(email, password)
            st.success(msg) if success else st.error(msg)
        if st.button("Login"):
            success, user_or_msg = login_user(email, password)
            if success:
                st.session_state.authenticated = True
                st.session_state.user = user_or_msg
                st.session_state.messages = []  # Reset chat messages
                st.experimental_rerun = lambda: None  # Dummy to avoid error
            else:
                st.error(user_or_msg)

    elif choice == "Google":
        st.info("Google OAuth not fully supported in local Streamlit. Deploy with HTTPS or use backend.")

# ----------------- Chat interface -----------------
else:
    user = st.session_state.user
    st.title(f"🤖 Krutrim Chatbot ({user['email']})")
    
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.user = None
        st.session_state.messages = []
        st.experimental_rerun = lambda: None  # dummy

    # Optional: custom API key
    api_key_input = st.text_input("Custom API Key (optional)", value=user.get("api_key") or "")
    if api_key_input != user.get("api_key"):
        users_col.update_one({"_id": user["_id"]}, {"$set": {"api_key": api_key_input}})
        user["api_key"] = api_key_input

    # Load chat history
    if not st.session_state.messages:
        history = list(chats_col.find({"user_id": user["_id"]}).sort("timestamp", 1))
        st.session_state.messages = [(m["role"], m["content"]) for m in history]

    # Display chat
    for role, text in st.session_state.messages:
        st.chat_message(role).markdown(text)

    # Chat input
    if prompt := st.chat_input("Type your message..."):
        tokens_needed = 512
        if not can_use_tokens(user, tokens_needed) and not user.get("api_key"):
            st.warning("⚠️ Daily limit reached (2000). Add your own API key to continue.")
        else:
            st.session_state.messages.append(("user", prompt))
            st.chat_message("user").markdown(prompt)

            # Maintain context
            messages_payload = [{"role": r, "content": c} for r, c in st.session_state.messages]
            reply, used_tokens = chat_with_krutrim(messages_payload, user.get("api_key"))

            st.session_state.messages.append(("assistant", reply))
            st.chat_message("assistant").markdown(reply)

            # Save chat
            chats_col.insert_many([
                {"user_id": user["_id"], "role": "user", "content": prompt, "timestamp": datetime.now(timezone.utc)},
                {"user_id": user["_id"], "role": "assistant", "content": reply, "timestamp": datetime.now(timezone.utc)}
            ])

            increment_tokens(user, used_tokens)
