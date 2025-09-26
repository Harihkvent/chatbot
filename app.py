import os
import streamlit as st
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import requests
import bcrypt
from urllib.parse import quote_plus
import certifi  # ensures proper SSL certificates
import logging
from prometheus_client import Counter, Histogram, start_http_server, REGISTRY

# ----------------- Logging Setup -----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("chatbot")

def get_metric(name, metric_type, *args, **kwargs):
    # Helper to get or create a metric
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    else:
        return metric_type(name, *args, **kwargs)

# ----------------- Prometheus Metrics -----------------
REQUEST_COUNT = get_metric('chatbot_requests_total', Counter, 'Total requests')
LOGIN_COUNT = get_metric('chatbot_logins_total', Counter, 'Total logins')
REGISTER_COUNT = get_metric('chatbot_registers_total', Counter, 'Total registrations')
CHAT_COUNT = get_metric('chatbot_chats_total', Counter, 'Total chat messages')
ERROR_COUNT = get_metric('chatbot_errors_total', Counter, 'Total errors')
CHAT_LATENCY = get_metric('chatbot_chat_latency_seconds', Histogram, 'Chat response latency')

if not hasattr(st, "prometheus_metrics_server_started"):
    try:
        start_http_server(8000)
        logger.info("Prometheus metrics server started on port 8000")
    except Exception as e:
        logger.warning(f"Prometheus metrics server could not start: {e}")
    st.prometheus_metrics_server_started = True

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

logger.info("Connecting to MongoDB...")
client = MongoClient(
    MONGO_URI,
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=10000
)

# Test connection
try:
    client.admin.command("ping")
    logger.info("MongoDB connected!")
except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")
# ----------------- Collections -----------------
db = client[dbname]
users_col = db.users
chats_col = db.chats

# ----------------- Authentication -----------------
def hash_password(password):
    logger.info("Hashing password")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    logger.info("Checking password")
    return bcrypt.checkpw(password.encode(), hashed)

def register_user(email, password):
    logger.info(f"Registering user: {email}")
    REGISTER_COUNT.inc()
    if users_col.find_one({"email": email}):
        logger.warning(f"User already exists: {email}")
        return False, "User already exists!"
    hashed = hash_password(password)
    users_col.insert_one({
        "email": email,
        "password_hash": hashed,
        "api_key": None,
        "tokens_used_today": 0,
        "last_reset": datetime.now(timezone.utc)
    })
    logger.info(f"User registered: {email}")
    return True, "Registered successfully!"

def login_user(email, password):
    logger.info(f"Login attempt: {email}")
    user = users_col.find_one({"email": email})
    if not user:
        logger.warning(f"User not found: {email}")
        ERROR_COUNT.inc()
        return False, "User not found."
    if check_password(password, user["password_hash"]):
        LOGIN_COUNT.inc()
        logger.info(f"Login successful: {email}")
        return True, user
    logger.warning(f"Incorrect password for user: {email}")
    ERROR_COUNT.inc()
    return False, "Incorrect password."

# ----------------- Rate Limiting -----------------
def can_use_tokens(user, tokens_needed):
    logger.info(f"Checking token usage for user: {user['email']}")
    last_reset = user.get("last_reset")

    if not isinstance(last_reset, datetime):
        last_reset = datetime.now(timezone.utc)
    else:
        if last_reset.tzinfo is None:
            last_reset = last_reset.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) - last_reset > timedelta(days=1):
        logger.info(f"Resetting tokens for user: {user['email']}")
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"tokens_used_today": 0, "last_reset": datetime.now(timezone.utc)}}
        )
        user["tokens_used_today"] = 0

    allowed = user["tokens_used_today"] + tokens_needed <= 1000
    logger.info(f"Token allowed: {allowed} for user: {user['email']}")
    return allowed

def increment_tokens(user, tokens):
    logger.info(f"Incrementing tokens by {tokens} for user: {user['email']}")
    users_col.update_one({"_id": user["_id"]}, {"$inc": {"tokens_used_today": tokens}})

# ----------------- Krutrim Chat -----------------
def chat_with_krutrim(messages, api_key=None):
    logger.info("Sending chat request to Krutrim API")
    key_to_use = api_key if api_key else DEFAULT_API_KEY
    headers = {"Authorization": f"Bearer {key_to_use}", "Content-Type": "application/json"}
    payload = {"model": "Krutrim-spectre-v2", "messages": messages, "max_tokens": 512, "temperature": 0.7}
    try:
        with CHAT_LATENCY.time():
            resp = requests.post(API_URL, headers=headers, json=payload)
        REQUEST_COUNT.inc()
        if resp.status_code == 200:
            data = resp.json()
            logger.info("Received response from Krutrim API")
            return data["choices"][0]["message"]["content"], payload["max_tokens"]
        logger.error(f"Krutrim API error: {resp.status_code}, {resp.text}")
        ERROR_COUNT.inc()
        return f"❌ Error: {resp.status_code}, {resp.text}", 0
    except Exception as e:
        logger.error(f"Exception during chat API call: {e}")
        ERROR_COUNT.inc()
        return f"❌ Exception: {str(e)}", 0

# ----------------- Streamlit UI -----------------
st.set_page_config(page_title="Krutrim Chatbot", page_icon="🤖", layout="centered")

# Initialize session state variables
if "authenticated" not in st.session_state:
    logger.info("Initializing session state: authenticated")
    st.session_state.authenticated = False
if "user_email" not in st.session_state:
    logger.info("Initializing session state: user_email")
    st.session_state.user_email = None
if "user" not in st.session_state:
    logger.info("Initializing session state: user")
    st.session_state.user = None
if "messages" not in st.session_state:
    logger.info("Initializing session state: messages")
    st.session_state.messages = []

st.markdown("""
    <style>
    /* Navbar */
    .navbar {
        position: fixed;
        top: 0; left: 0; right: 0;
        background: #18181b;
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
    .stApp { padding-top: 60px; background: #101014; }
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #18181b;
        color: #fff;
    }
    /* Sidebar buttons */
    .stButton>button {
        background: #23272f;
        color: #fff;
        border-radius: 8px;
        border: none;
        margin: 4px 0;
        
        padding: 0.5rem 1.2rem;
        font-size: 1rem;
        transition: background 0.2s;
    }
    .stButton>button:hover {
        background: #2563eb;
        color: #fff;
    }
    /* API key input */
    input[type="password"] {
        background: #23272f;
        color: #fff;
        border-radius: 8px;
        border: 1px solid #444;
        padding: 0.5rem;
        font-size: 1rem;
    }
    /* Chat container */
    .chat-container {
        max-width: 700px;
        margin: 0 auto;
        padding: 2rem 0 7rem 0;
        min-height: 70vh;
    }
    /* Chat bubbles */
    .chat-bubble-user {
        background: #2563eb;
        color: #fff;
        border-radius: 16px 16px 0 16px;
        padding: 14px 20px;
        margin-bottom: 12px;
        margin-left: 120px;
        margin-right: 0;
        text-align: left;
        width: fit-content;
        max-width: 80%;
        box-shadow: 0 2px 8px rgba(37,99,235,0.08);
        font-size: 1.08rem;
    }
    .chat-bubble-bot {
        background: #23272f;
        color: #fff;
        border-radius: 16px 16px 16px 0;
        padding: 14px 20px;
        margin-bottom: 12px;
        margin-right: 120px;
        margin-left: 0;
        text-align: left;
        width: fit-content;
        max-width: 80%;
        box-shadow: 0 2px 8px rgba(0,0,0,0.12);
        font-size: 1.08rem;
    }
    /* Chat input box */
    .stChatInput>div>input {
        border-radius: 12px;
        border: 1px solid #444;
        background: #18181b;
        color: #fff;
        font-size: 1.1rem;
        padding: 0.7rem;
    }
    /* Scroll button */
    .scroll-btn {
        position:fixed;
        bottom:30px;
        right:30px;
        z-index:999;
        background:#2563eb;
        color:#fff;
        border:none;
        padding:10px 18px;
        border-radius:8px;
        box-shadow:0 2px 8px rgba(0,0,0,0.15);
        cursor:pointer;
        font-size:1rem;
        transition: background 0.2s;
    }
    .scroll-btn:hover {
        background: #1e40af;
    }
    /* Refresh button */
    .refresh-btn {
        background: #23272f;
        color: #fff;
        border-radius: 8px;
        border: 2px solid #2563eb;
        padding: 0.5rem 1.2rem;
        font-size: 1rem;
        margin: 1rem auto;
        display: block;
        transition: background 0.2s;
    }
    .refresh-btn:hover {
        background: #2563eb;
        color: #fff;
    }
    </style>
""", unsafe_allow_html=True)

st.markdown("""
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
    logger.info("Rendering login/register UI")
    st.title("Krutrim Chatbot")
    st.subheader("Login or Register to continue")
    choice = st.radio("Choose an option:", ["Login", "Register"], horizontal=True)

    with st.form("login_register_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        col1, col2 = st.columns(2)
        login_btn = col1.form_submit_button("Login")
        register_btn = col2.form_submit_button("Register")

        if choice == "Register" and register_btn:
            logger.info("Register button clicked")
            success, msg = register_user(email, password)
            if success:
                st.success(msg)
            else:
                st.error(msg)

        if choice == "Login" and login_btn:
            logger.info("Login button clicked")
            success, user_or_msg = login_user(email, password)
            if success:
                st.session_state.authenticated = True
                st.session_state.user_email = email
                st.session_state.user = user_or_msg
                st.session_state.messages = []
                logger.info(f"User logged in: {email}")
                st.rerun()
            else:
                st.error(user_or_msg)

else:
    user = st.session_state.user
    logger.info(f"Rendering chat UI for user: {user['email']}")

    # Sidebar for profile/settings
    with st.sidebar:
        st.header("Profile & Settings")
        st.write(f"**Email:** {user['email']}")
        st.write(f"**Tokens used today:** {user.get('tokens_used_today', 0)} / 2000")
        api_key_input = st.text_input("Custom API Key (optional)", value=user.get("api_key") or "", type="password")
        col_api1, col_api2 = st.columns(2)
        if col_api1.button("Save API Key"):
            logger.info("Save API Key button clicked")
            users_col.update_one({"_id": user["_id"]}, {"$set": {"api_key": api_key_input}})
            user["api_key"] = api_key_input
            st.success("API Key saved!")
        if col_api2.button("Delete API Key"):
            logger.info("Delete API Key button clicked")
            users_col.update_one({"_id": user["_id"]}, {"$set": {"api_key": None}})
            user["api_key"] = None
            st.success("API Key deleted!")
        st.divider()
        if st.button("Logout"):
            logger.info(f"User logged out: {user['email']}")
            st.session_state.authenticated = False
            st.session_state.user_email = None
            st.session_state.user = None
            st.session_state.messages = []
            st.rerun()

    st.title("🤖 Krutrim Chatbot")
    st.caption("ChatGPT-like experience. Your messages are private.")

    # Show chat history
    logger.info("Rendering chat history")
    for role, text in st.session_state.messages:
        with st.chat_message(role):
            st.write(text)

    # Refresh chat button
    if st.button("🔄 Refresh Chat"):
        logger.info("Refresh Chat button clicked")
        user = users_col.find_one({"_id": user["_id"]})
        st.session_state.user = user
        st.rerun()

    # Chat input
    prompt = st.chat_input("Type your message...")
    if prompt:
        logger.info(f"User sent message: {prompt}")
        tokens_needed = 512
        if not can_use_tokens(user, tokens_needed) and not user.get("api_key"):
            logger.warning("Token limit reached for user")
            st.warning("⚠️ Daily limit reached (2000). Add your own API key to continue.")
        else:
            st.session_state.messages.append(("user", prompt))
            with st.chat_message("user"):
                st.write(prompt)

            messages_payload = [{"role": r, "content": c} for r, c in st.session_state.messages]
            reply, used_tokens = chat_with_krutrim(messages_payload, user.get("api_key"))

            st.session_state.messages.append(("assistant", reply))
            with st.chat_message("assistant"):
                st.write(reply)

            logger.info("Saving chat messages to database")
            chats_col.insert_many([
                {"user_id": user["_id"], "role": "user", "content": prompt, "timestamp": datetime.now(timezone.utc)},
                {"user_id": user["_id"], "role": "assistant", "content": reply, "timestamp": datetime.now(timezone.utc)}
            ])

            increment_tokens(user, used_tokens)
            user = users_col.find_one({"_id": user["_id"]})
            st.session_state.user = user
            CHAT_COUNT.inc()
            st.rerun()
