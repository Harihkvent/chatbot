import os
import streamlit as st
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import requests
import bcrypt
from urllib.parse import quote_plus
import certifi  # ensures proper SSL certificates

# ----------------- Load environment -----------------
load_dotenv()
DEFAULT_API_KEY = os.getenv("KRUTRIM_API_KEY")
API_URL = "https://cloud.olakrutrim.com/v1/chat/completions"

# ----------------- MongoDB -----------------
username = quote_plus("chatbot")  # or use env variable
password = quote_plus(os.getenv("MONGO_PASS"))
dbname = os.getenv("MONGO_DB")

MONGO_URI = (
    f"mongodb+srv://{username}:{password}@cluster0.57nirib.mongodb.net/{dbname}"
    "?retryWrites=true&w=majority&tls=true"
)

client = MongoClient(
    MONGO_URI,
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=10000
)

# Test connection
try:
    client.admin.command("ping")
    print("MongoDB connected!")
except Exception as e:
    print("MongoDB connection failed:", e)
# ----------------- Collections -----------------
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

# Initialize session state variables
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_email" not in st.session_state:
    st.session_state.user_email = None
if "user" not in st.session_state:
    st.session_state.user = None
if "messages" not in st.session_state:
    st.session_state.messages = []

# Fixed Navigation Bar
st.markdown("""
    <style>
    .navbar {
        position: fixed;
        top: 0; left: 0; right: 0;
        background: #222;
        color: #fff;
        padding: 0.7rem 2rem;
        z-index: 1000;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .navbar-title {
        font-size: 1.3rem;
        font-weight: bold;
        letter-spacing: 1px;
    }
    .navbar-link {
        color: #fff;
        text-decoration: none;
        margin-left: 2rem;
        font-size: 1rem;
    }
    .stApp { padding-top: 60px; }
    </style>
    <div class="navbar">
        <span class="navbar-title">🤖 Krutrim Chatbot</span>
        <span>
            <a class="navbar-link" href="#chat">Chat</a>
            <a class="navbar-link" href="#profile">Profile</a>
        </span>
    </div>
""", unsafe_allow_html=True)

# ----------------- Login / Registration -----------------
if not st.session_state.authenticated:
    st.markdown("## Welcome to Krutrim Chatbot")
    st.markdown("#### Please login or register to continue")
    choice = st.radio("Choose an option:", ["Login", "Register"], horizontal=True)

    with st.form("login_register_form"):
        st.markdown("### " + ("Login" if choice == "Login" else "Register"))
        email = st.text_input("Email", placeholder="Enter your email")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        col1, col2 = st.columns([1,1])
        login_btn = col1.form_submit_button("Login", use_container_width=True)
        register_btn = col2.form_submit_button("Register", use_container_width=True)

        if choice == "Register" and register_btn:
            success, msg = register_user(email, password)
            if success:
                st.success(msg)
            else:
                st.error(msg)

        if choice == "Login" and login_btn:
            success, user_or_msg = login_user(email, password)
            if success:
                st.session_state.authenticated = True
                st.session_state.user_email = email
                st.session_state.user = user_or_msg
                st.session_state.messages = []
                st.rerun()
            else:
                st.error(user_or_msg)

    st.markdown("""
        <style>
        .stTextInput>div>input { border-radius: 8px; border: 1px solid #aaa; }
        .stPasswordInput>div>input { border-radius: 8px; border: 1px solid #aaa; }
        .stButton>button { border-radius: 8px; background: #222; color: #fff; }
        </style>
    """, unsafe_allow_html=True)

# ----------------- Chat interface -----------------
else:
    user = st.session_state.user
    st.markdown('<a name="chat"></a>', unsafe_allow_html=True)

    # Sidebar for profile/settings
    with st.sidebar:
        st.markdown("### Profile & Settings")
        st.write(f"**Email:** {user['email']}")
        st.write(f"**Tokens used today:** {user.get('tokens_used_today', 0)} / 2000")
        
        # Hide API key input, add Save/Delete
        api_key_input = st.text_input(
            "Custom API Key (optional)", 
            value=user.get("api_key") or "", 
            type="password", 
            key="api_key_input"
        )
        col_api1, col_api2 = st.columns([1, 1])
        if col_api1.button("Save API Key"):
            users_col.update_one({"_id": user["_id"]}, {"$set": {"api_key": api_key_input}})
            user["api_key"] = api_key_input
            st.success("API Key saved!")
        if col_api2.button("Delete API Key"):
            users_col.update_one({"_id": user["_id"]}, {"$set": {"api_key": None}})
            user["api_key"] = None
            st.success("API Key deleted!")

        if st.button("Logout", key="logout_btn"):
            st.session_state.authenticated = False
            st.session_state.user_email = None
            st.session_state.user = None
            st.session_state.messages = []
            st.rerun()

    st.markdown("""
        <style>
        .chat-container {
            max-width: 700px;
            margin: 0 auto;
            padding: 1.5rem 0 6rem 0;
        }
        .chat-bubble-user {
            background: #222;
            color: #fff;
            border-radius: 12px;
            padding: 12px 18px;
            margin-bottom: 10px;
            margin-left: 80px;
            margin-right: 0;
            text-align: left;
            width: fit-content;
            max-width: 80%;
        }
        .chat-bubble-bot {
            background: #f3f3f3;
            color: #222;
            border-radius: 12px;
            padding: 12px 18px;
            margin-bottom: 10px;
            margin-right: 80px;
            margin-left: 0;
            text-align: left;
            width: fit-content;
            max-width: 80%;
        }
        .chat-input-box input {
            border-radius: 8px;
            border: 1px solid #aaa;
            padding: 10px;
            font-size: 1.1rem;
        }
        .stApp { background: #fafbfc; }
        </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="chat-container">', unsafe_allow_html=True)
    for role, text in st.session_state.messages:
        if role == "user":
            st.markdown(f'<div class="chat-bubble-user">🧑‍💻 {text}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="chat-bubble-bot">🤖 {text}</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # Scroll to bottom button using HTML/JS
    st.markdown("""
        <button onclick="window.scrollTo(0, document.body.scrollHeight);" style="position:fixed;bottom:30px;right:30px;z-index:999;background:#222;color:#fff;border:none;padding:10px 18px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.15);cursor:pointer;">
            ⬇️ Scroll to Bottom
        </button>
        """, unsafe_allow_html=True)

    # Chat input
    prompt = st.chat_input("Type your message...")
    if prompt:
        tokens_needed = 512
        if not can_use_tokens(user, tokens_needed) and not user.get("api_key"):
            st.warning("⚠️ Daily limit reached (2000). Add your own API key to continue.")
        else:
            st.session_state.messages.append(("user", prompt))
            st.markdown(f'<div class="chat-bubble-user">🧑‍💻 {prompt}</div>', unsafe_allow_html=True)

            messages_payload = [{"role": r, "content": c} for r, c in st.session_state.messages]
            reply, used_tokens = chat_with_krutrim(messages_payload, user.get("api_key"))

            st.session_state.messages.append(("assistant", reply))
            st.markdown(f'<div class="chat-bubble-bot">🤖 {reply}</div>', unsafe_allow_html=True)

            chats_col.insert_many([
                {"user_id": user["_id"], "role": "user", "content": prompt, "timestamp": datetime.now(timezone.utc)},
                {"user_id": user["_id"], "role": "assistant", "content": reply, "timestamp": datetime.now(timezone.utc)}
            ])

            increment_tokens(user, used_tokens)
            user = users_col.find_one({"_id": user["_id"]})
            st.session_state.user = user
            st.rerun()

    if st.button("🔄 Refresh Chat", key="refresh_chat_btn"):
        user = users_col.find_one({"_id": user["_id"]})
        st.session_state.user = user
        st.rerun()
