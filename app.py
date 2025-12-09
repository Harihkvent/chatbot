import os
import streamlit as st
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import requests
import json
from google_auth_oauthlib.flow import Flow
import bcrypt
from urllib.parse import quote_plus, urlencode
import certifi  # ensures proper SSL certificates
import logging
import secrets
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
        logger.warning(f"Prometheus metrics server could not start : {e}")
    st.prometheus_metrics_server_started = True

# ----------------- Load environment -----------------
load_dotenv()
DEFAULT_API_KEY = os.getenv("KRUTRIM_API_KEY")
API_URL = "https://cloud.olakrutrim.com/v1/chat/completions"

# ----------------- Google OAuth -----------------
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

def get_google_oauth_url():
    """Generate Google OAuth authorization URL"""
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    if not client_id:
        logger.error("Google Client ID not configured")
        return None
    
    # Generate a random state parameter for security
    state = secrets.token_urlsafe(32)
    st.session_state.oauth_state = state
    
    redirect_uri = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:8501")
    
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(SCOPES),
        "response_type": "code",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account"
    }
    
    oauth_url = "https://accounts.google.com/o/oauth2/auth?" + urlencode(params)
    return oauth_url

def exchange_code_for_token(code, state):
    """Exchange authorization code for access token and get user info"""
    # Verify state parameter
    if state != st.session_state.get("oauth_state"):
        logger.error("OAuth state mismatch - possible CSRF attack")
        return None
    
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:8501")
    
    if not client_id or not client_secret:
        logger.error("Google OAuth credentials not configured")
        return None
    
    # Exchange code for token
    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri
    }
    
    try:
        # Get access token
        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data=token_data
        )
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.status_code} {token_response.text}")
            return None
        
        token_info = token_response.json()
        access_token = token_info.get("access_token")
        
        if not access_token:
            logger.error("No access token received")
            return None
        
        # Get user info
        user_response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if user_response.status_code != 200:
            logger.error(f"Failed to fetch user info: {user_response.status_code} {user_response.text}")
            return None
        
        user_info = user_response.json()
        logger.info(f"Successfully retrieved user info for: {user_info.get('email')}")
        return user_info
        
    except Exception as e:
        logger.error(f"OAuth token exchange failed: {e}")
        return None

def create_or_update_google_user(user_info):
    """Create or update user in database with Google profile info"""
    google_id = user_info.get("id")
    email = user_info.get("email")
    name = user_info.get("name")
    picture = user_info.get("picture")
    
    if not email or not google_id:
        logger.error("Missing required user info from Google")
        return None
    
    # Look up existing user by google_id or email
    user = users_col.find_one({"$or": [{"google_id": google_id}, {"email": email}]})
    
    if user:
        # Update existing user
        logger.info(f"Updating existing user: {email}")
        update_data = {
            "google_id": google_id,
            "name": name,
            "picture": picture,
            "last_login": datetime.now(timezone.utc)
        }
        users_col.update_one({"_id": user["_id"]}, {"$set": update_data})
        user = users_col.find_one({"_id": user["_id"]})
    else:
        # Create new user
        logger.info(f"Creating new Google user: {email}")
        new_user = {
            "email": email,
            "google_id": google_id,
            "name": name,
            "picture": picture,
            "api_key": None,
            "tokens_used_today": 0,
            "last_reset": datetime.now(timezone.utc),
            "created_at": datetime.now(timezone.utc),
            "last_login": datetime.now(timezone.utc),
            "auth_method": "google"
        }
        result = users_col.insert_one(new_user)
        user = users_col.find_one({"_id": result.inserted_id})
        REGISTER_COUNT.inc()
    
    return user

# ----------------- Chat Management Functions -----------------
def create_new_chat(user_id):
    """Create a new chat session"""
    try:
        chat_metadata_col = db.chat_metadata
        
        chat_doc = {
            "user_id": user_id,
            "title": "New Chat",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "message_count": 0
        }
        result = chat_metadata_col.insert_one(chat_doc)
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error creating new chat: {e}")
        return None

def get_user_chats(user_id):
    """Get all chats for a user"""
    try:
        # First, let's create a separate collection for chat metadata
        chat_metadata_col = db.chat_metadata
        
        chats = list(chat_metadata_col.find(
            {"user_id": user_id},
            {"title": 1, "created_at": 1, "updated_at": 1, "message_count": 1}
        ).sort("updated_at", -1))
        
        # If no chats found, return empty list
        return chats
    except Exception as e:
        logger.error(f"Error getting user chats: {e}")
        return []

def get_chat_messages(chat_id):
    """Get messages for a specific chat"""
    try:
        messages = list(chats_col.find(
            {"chat_id": ObjectId(chat_id)},
            {"role": 1, "content": 1, "timestamp": 1}
        ).sort("timestamp", 1))
        return [(msg["role"], msg["content"]) for msg in messages]
    except:
        return []

def save_chat_message(user_id, chat_id, role, content):
    """Save a message to a specific chat"""
    try:
        # Save message to messages collection
        message_doc = {
            "user_id": user_id,
            "chat_id": ObjectId(chat_id),
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc)
        }
        chats_col.insert_one(message_doc)
        
        # Update chat metadata
        chat_metadata_col = db.chat_metadata
        
        if role == "user" and len(content) > 0:
            title = content[:50] + "..." if len(content) > 50 else content
            
            # Update or create chat metadata
            chat_metadata_col.update_one(
                {"_id": ObjectId(chat_id)},
                {
                    "$set": {"title": title, "updated_at": datetime.now(timezone.utc)},
                    "$inc": {"message_count": 1}
                },
                upsert=True
            )
        else:
            # Just update the timestamp for assistant messages
            chat_metadata_col.update_one(
                {"_id": ObjectId(chat_id)},
                {"$set": {"updated_at": datetime.now(timezone.utc)}},
                upsert=True
            )
    except Exception as e:
        logger.error(f"Error saving chat message: {e}")

def delete_chat(chat_id):
    """Delete a chat and all its messages"""
    try:
        chat_metadata_col = db.chat_metadata
        
        # Delete all messages in the chat
        chats_col.delete_many({"chat_id": ObjectId(chat_id)})
        # Delete the chat metadata document
        chat_metadata_col.delete_one({"_id": ObjectId(chat_id)})
        return True
    except Exception as e:
        logger.error(f"Error deleting chat: {e}")
        return False

# ----------------- MongoDB -----------------
@st.cache_resource
def get_mongo_client():
    """Initializes and returns a cached MongoDB client."""
    logger.info("Connecting to MongoDB...")
    username = quote_plus("chatbot")
    password = quote_plus(os.getenv("MONGO_PASS"))
    dbname = os.getenv("MONGO_DB")
    mongo_uri = f"mongodb+srv://{username}:{password}@cluster0.57nirib.mongodb.net/{dbname}?retryWrites=true&w=majority&tls=true"
    
    client = MongoClient(mongo_uri, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=10000)
    
    # Test connection
    try:
        client.admin.command("ping")
        logger.info("MongoDB connected!")
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        # The app will likely fail later, but we log the initial error.
    return client

client = get_mongo_client()
db = client[os.getenv("MONGO_DB")]
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
        "last_reset": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
        "auth_method": "email"
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
    
    # Check if user was created via Google OAuth (no password hash)
    if not user.get("password_hash"):
        logger.warning(f"User {email} was created via Google OAuth, cannot login with password")
        ERROR_COUNT.inc()
        return False, "This account was created with Google. Please use 'Sign in with Google'."
    
    if check_password(password, user["password_hash"]):
        LOGIN_COUNT.inc()
        logger.info(f"Login successful: {email}")
        # Update last login time
        users_col.update_one({"_id": user["_id"]}, {"$set": {"last_login": datetime.now(timezone.utc)}})
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

    allowed = user["tokens_used_today"] + tokens_needed <= 2000
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
st.set_page_config(
    page_title="Krutrim Chatbot", 
    page_icon="🤖", 
    layout="wide",
    initial_sidebar_state="expanded"
)

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
if "oauth_state" not in st.session_state:
    st.session_state.oauth_state = None
if "is_generating" not in st.session_state:
    st.session_state.is_generating = False
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None
if "show_profile" not in st.session_state:
    st.session_state.show_profile = False
if "chat_history" not in st.session_state:
    st.session_state.chat_history = {}# Handle OAuth callback
query_params = st.query_params
if "code" in query_params and "state" in query_params and not st.session_state.authenticated:
    logger.info("Processing OAuth callback")
    code = query_params.get("code")
    state = query_params.get("state")
    
    user_info = exchange_code_for_token(code, state)
    if user_info:
        user = create_or_update_google_user(user_info)
        if user:
            st.session_state.authenticated = True
            st.session_state.user_email = user.get("email")
            st.session_state.user = user
            st.session_state.messages = []
            LOGIN_COUNT.inc()
            logger.info(f"Google user successfully logged in: {user.get('email')}")
            
            # Clear query parameters and redirect
            st.query_params.clear()
            st.rerun()
        else:
            st.error("Failed to create or update user account")
    else:
        st.error("Failed to process Google sign-in")
        # Clear query parameters on error
        st.query_params.clear()

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Global Styles */
    .stApp {
        background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
        font-family: 'Inter', sans-serif;
    }
    
    /* Login Container */
    .login-container {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 20px;
        padding: 2.5rem;
        margin: 2rem auto;
        max-width: 450px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    }
    
    /* Navbar */
    .navbar {
        position: fixed;
        top: 0; left: 0; right: 0;
        background: rgba(15, 15, 35, 0.9);
        backdrop-filter: blur(20px);
        color: #fff;
        padding: 1rem 2rem;
        z-index: 1000;
        box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    .navbar-title {
        font-size: 1.4rem;
        font-weight: 700;
        letter-spacing: 1px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    .navbar-link {
        color: rgba(255, 255, 255, 0.8);
        text-decoration: none;
        margin-left: 2rem;
        font-size: 1rem;
        font-weight: 500;
        transition: color 0.3s ease;
    }
    .navbar-link:hover {
        color: #667eea;
    }
    
    /* Main app padding */
    .main .block-container {
        padding-top: 5rem;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: rgba(15, 15, 35, 0.9);
        backdrop-filter: blur(20px);
        border-right: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .sidebar .sidebar-content {
        background: transparent;
    }
    
    /* Profile Card in Sidebar */
    .profile-card {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1rem 0;
        border: 1px solid rgba(255, 255, 255, 0.1);
        text-align: center;
    }
    
    .profile-avatar {
        border-radius: 50%;
        border: 3px solid rgba(102, 126, 234, 0.3);
        margin: 0 auto 1rem;
        display: block;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: #fff;
        border: none;
        border-radius: 12px;
        padding: 0.7rem 1.5rem;
        font-size: 1rem;
        font-weight: 500;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.2);
        width: 100%;
        margin: 0.25rem 0;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
    }
    
    .stButton > button:active {
        transform: translateY(0);
    }
    
    /* Google Sign-in Button */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #4285f4 0%, #34a853 50%, #ea4335 100%);
    }
    
    /* Form Elements */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    input[type="password"],
    input[type="email"] {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        color: #fff;
        padding: 0.8rem 1rem;
        font-size: 1rem;
        transition: all 0.3s ease;
    }
    
    .stTextInput > div > div > input:focus,
    input[type="password"]:focus,
    input[type="email"]:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.2);
        outline: none;
    }
    
    /* Chat Input - ChatGPT Style */
    .stChatInput {
        position: sticky;
        bottom: 0;
        background: rgba(15, 15, 35, 0.95);
        backdrop-filter: blur(20px);
        padding: 20px 0;
        margin-top: 20px;
        border-top: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .stChatInput > div {
        max-width: 900px;
        margin: 0 auto;
    }
    
    .stChatInput > div > div {
        background: rgba(64, 65, 79, 0.3);
        border-radius: 26px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        transition: all 0.3s ease;
    }
    
    .stChatInput > div > div:focus-within {
        border-color: rgba(102, 126, 234, 0.5);
        box-shadow: 0 4px 30px rgba(102, 126, 234, 0.2);
        background: rgba(64, 65, 79, 0.5);
    }
    
    .stChatInput > div > div > input {
        background: transparent !important;
        border: none !important;
        color: #ffffff !important;
        padding: 16px 24px !important;
        font-size: 16px !important;
        line-height: 1.5 !important;
        min-height: 24px !important;
    }
    
    .stChatInput > div > div > input::placeholder {
        color: rgba(255, 255, 255, 0.5) !important;
    }
    
    /* Send Button Styling */
    .stChatInput button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        border: none !important;
        border-radius: 50% !important;
        width: 36px !important;
        height: 36px !important;
        margin: 6px !important;
        box-shadow: 0 2px 8px rgba(102, 126, 234, 0.3) !important;
        transition: all 0.2s ease !important;
    }
    
    .stChatInput button:hover {
        transform: scale(1.05) !important;
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4) !important;
    }
    
    /* Radio buttons */
    .stRadio > div {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 12px;
        padding: 1rem;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Success/Error Messages */
    .stSuccess {
        background: rgba(52, 168, 83, 0.1);
        border: 1px solid rgba(52, 168, 83, 0.3);
        border-radius: 12px;
    }
    
    .stError {
        background: rgba(234, 67, 53, 0.1);
        border: 1px solid rgba(234, 67, 53, 0.3);
        border-radius: 12px;
    }
    
    .stInfo {
        background: rgba(66, 133, 244, 0.1);
        border: 1px solid rgba(66, 133, 244, 0.3);
        border-radius: 12px;
    }
    
    /* Chat Messages - ChatGPT/Claude Style */
    .stChatMessage {
        background: transparent;
        border: none;
        margin: 0;
        padding: 0;
    }
    
    /* User Message Styling */
    .stChatMessage[data-testid="user-message"] {
        background: transparent;
    }
    
    .user-message {
        background: #2f2f2f;
        color: #ffffff;
        border-radius: 18px;
        padding: 12px 16px;
        margin: 8px 0 16px auto;
        max-width: 80%;
        word-wrap: break-word;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Assistant Message Styling */
    .assistant-message {
        background: rgba(247, 247, 248, 0.05);
        color: #ffffff;
        border-radius: 18px;
        padding: 16px 20px;
        margin: 8px auto 16px 0;
        max-width: 85%;
        word-wrap: break-word;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.08);
        line-height: 1.6;
    }
    
    /* Message Container */
    .message-container {
        display: flex;
        align-items: flex-start;
        margin: 12px 0;
        gap: 12px;
    }
    
    .user-container {
        justify-content: flex-end;
    }
    
    .assistant-container {
        justify-content: flex-start;
    }
    
    /* Avatar Styling */
    .message-avatar {
        width: 32px;
        height: 32px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 14px;
        flex-shrink: 0;
        margin-top: 4px;
    }
    
    .user-avatar {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        order: 2;
    }
    
    .assistant-avatar {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
    }
    
    /* Chat Container */
    .chat-container {
        max-width: 900px;
        margin: 0 auto;
        padding: 20px;
        min-height: 60vh;
    }
    
    /* Typing Indicator */
    .typing-indicator {
        display: flex;
        align-items: center;
        gap: 8px;
        color: rgba(255, 255, 255, 0.6);
        font-style: italic;
        padding: 12px 16px;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 18px;
        margin: 8px auto 16px 0;
        max-width: fit-content;
    }
    
    .typing-dots {
        display: flex;
        gap: 3px;
    }
    
    .typing-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.4);
        animation: typing 1.4s infinite;
    }
    
    .typing-dot:nth-child(2) { animation-delay: 0.2s; }
    .typing-dot:nth-child(3) { animation-delay: 0.4s; }
    
    @keyframes typing {
        0%, 60%, 100% { opacity: 0.3; transform: scale(0.8); }
        30% { opacity: 1; transform: scale(1); }
    }
    
    /* Title Styling */
    h1, h2, h3 {
        color: #fff;
        font-weight: 600;
    }
    
    h1 {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    /* Custom Animations */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .fade-in {
        animation: fadeIn 0.6s ease-out;
    }
    
    /* Loading Animation */
    .loading-dots {
        display: inline-block;
    }
    
    .loading-dots::after {
        content: '.';
        animation: dots 1.5s steps(5, end) infinite;
    }
    
    @keyframes dots {
        0%, 20% { color: rgba(255,255,255,0); text-shadow: .25em 0 0 rgba(255,255,255,0), .5em 0 0 rgba(255,255,255,0); }
        40% { color: white; text-shadow: .25em 0 0 rgba(255,255,255,0), .5em 0 0 rgba(255,255,255,0); }
        60% { text-shadow: .25em 0 0 white, .5em 0 0 rgba(255,255,255,0); }
        80%, 100% { text-shadow: .25em 0 0 white, .5em 0 0 white; }
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(255, 255, 255, 0.05);
    }
    
    ::-webkit-scrollbar-thumb {
        background: rgba(102, 126, 234, 0.5);
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(102, 126, 234, 0.8);
    }
    
    /* Stats Cards */
    .stats-card {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 1rem;
        margin: 0.5rem 0;
        border: 1px solid rgba(255, 255, 255, 0.1);
        text-align: center;
    }
    
    .stats-number {
        font-size: 1.5rem;
        font-weight: 700;
        color: #667eea;
    }
    
    .stats-label {
        font-size: 0.9rem;
        color: rgba(255, 255, 255, 0.7);
        margin-top: 0.25rem;
    }
    </style>
""", unsafe_allow_html=True)

# Navigation bar with integrated buttons
if st.session_state.authenticated:
    # Add custom CSS for fixed header with navigation buttons
    st.markdown("""
        <style>
        .fixed-header {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 1000;
            background: rgba(15, 15, 35, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255,255,255,0.1);
            padding: 0.8rem 2rem;
        }
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
        }
        .header-title {
            font-size: 1.4rem;
            font-weight: 700;
            color: #667eea;
        }
        .header-buttons {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        .header-spacer {
            height: 70px;
        }
        
        /* Fix button alignment and spacing */
        .stButton > button {
            width: 100%;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.1);
            color: white;
            transition: all 0.2s ease;
        }
        
        .stButton > button:hover {
            background: rgba(255, 255, 255, 0.2);
            border-color: rgba(102, 126, 234, 0.5);
        }
        
        /* Fix form layout */
        .login-container {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 20px;
            padding: 2rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
        }
        </style>
        <div class="fixed-header">
            <div class="header-content">
                <div class="header-title">🤖 Krutrim AI</div>
                <div class="header-buttons">
                    <div id="profile-btn-container"></div>
                    <div id="logout-btn-container"></div>
                </div>
            </div>
        </div>
        <div class="header-spacer"></div>
    """, unsafe_allow_html=True)
    
    # Create columns for the navigation buttons in a more compact way
    col1, col2, col3 = st.columns([8, 1, 1])
    
    with col1:
        pass  # Spacer
    
    with col2:
        if st.button("👤 Profile", help="View profile settings", key="nav_profile"):
            st.session_state.show_profile = not st.session_state.show_profile
            st.rerun()
    
    with col3:
        if st.button("🚪 Logout", help="Sign out", key="nav_logout"):
            logger.info(f"User logged out: {st.session_state.user['email']}")
            st.session_state.authenticated = False
            st.session_state.user_email = None
            st.session_state.user = None
            st.session_state.messages = []
            st.session_state.current_chat_id = None
            st.session_state.show_profile = False
            st.rerun()
else:
    # Clean header for non-authenticated users
    pass  # No duplicate header needed

# ----------------- Login / Registration -----------------
if not st.session_state.authenticated:
    logger.info("Rendering login/register UI")
    
    # Center the login form
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown('<div class="login-container fade-in">', unsafe_allow_html=True)
        
        # Welcome message with gradient text
        st.markdown("""
            <h1 style="text-align: center; margin-bottom: 2rem; font-size: 2.5rem;">
                🤖 Welcome to YAHANAR AI
            </h1>
            <p style="text-align: center; color: rgba(255,255,255,0.7); font-size: 1.1rem; margin-bottom: 2rem;">
                Your intelligent assistant powered by advanced AI
            </p>
        """, unsafe_allow_html=True)
        
        choice = st.radio(
            "Choose an option:", 
            ["🔐 Login", "📝 Register"], 
            horizontal=True,
            key="auth_choice"
        )

        with st.form("login_register_form", clear_on_submit=False):
            email = st.text_input(
                "📧 Email Address", 
                placeholder="Enter your email address",
                key="email_input"
            )
            password = st.text_input(
                "🔒 Password", 
                type="password", 
                placeholder="Enter your password",
                key="password_input"
            )
            
            st.markdown("<div style='margin: 1.5rem 0;'></div>", unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            if "🔐 Login" in choice:
                login_btn = col1.form_submit_button("🚀 Login", use_container_width=True)
                register_btn = False
            else:
                register_btn = col1.form_submit_button("📝 Create Account", use_container_width=True)
                login_btn = False
                
            # Google Sign-In button (full width)
            st.markdown("<div style='margin: 1rem 0;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='text-align: center; color: rgba(255,255,255,0.5); margin: 1rem 0;'>── or ──</div>", unsafe_allow_html=True)
            google_signin = st.form_submit_button(
                "🌟 Continue with Google", 
                use_container_width=True
            )
        
    # Handle Google Sign-In outside the form to avoid conflicts
    if google_signin:
        logger.info("Google sign-in initiated")
        oauth_url = get_google_oauth_url()
        if oauth_url:
            st.markdown("""
                <div style="text-align: center; padding: 2rem; background: rgba(66, 133, 244, 0.1); border-radius: 12px; margin: 1rem 0;">
                    <div class="loading-dots" style="font-size: 1.2rem; color: #4285f4; margin-bottom: 1rem;">
                        🌟 Redirecting to Google
                    </div>
                    <p style="color: rgba(255,255,255,0.7);">Please wait while we redirect you to Google for secure authentication...</p>
                </div>
            """, unsafe_allow_html=True)
            st.markdown(f'<meta http-equiv="refresh" content="1; url={oauth_url}">', unsafe_allow_html=True)
            st.link_button("🔗 Click here if redirect doesn't work automatically", oauth_url, use_container_width=True)
        else:
            st.error("❌ Failed to generate Google OAuth URL. Please check your configuration.")

        # Close login container div
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Handle email/password authentication outside the columns
    if register_btn:
        logger.info("Register button clicked")
        if not email or not password:
            st.error("⚠️ Please enter both email and password.")
        elif len(password) < 6:
            st.error("⚠️ Password must be at least 6 characters long.")
        elif "@" not in email or "." not in email:
            st.error("⚠️ Please enter a valid email address.")
        else:
            with st.spinner("Creating your account..."):
                success, msg = register_user(email, password)
                if success:
                    st.success(f"🎉 {msg} Please login with your credentials.")
                else:
                    st.error(f"❌ {msg}")

    if login_btn:
        logger.info("Login button clicked")
        if not email or not password:
            st.error("⚠️ Please enter both email and password.")
        else:
            with st.spinner("Signing you in..."):
                success, user_or_msg = login_user(email, password)
                if success:
                    st.session_state.authenticated = True
                    st.session_state.user_email = email
                    st.session_state.user = user_or_msg
                    st.session_state.messages = []
                    logger.info(f"User logged in: {email}")
                    st.success("✅ Login successful! Redirecting...")
                    st.rerun()
                else:
                    st.error(f"❌ {user_or_msg}")

else:
    user = st.session_state.user
    logger.info(f"Rendering chat UI for user: {user['email']}")

    # No more modal popup - profile will be shown in sidebar instead
    show_profile_in_sidebar = st.session_state.show_profile
    
    # Sidebar content - either chat history or profile
    with st.sidebar:
        if show_profile_in_sidebar:
            # Profile section in sidebar
            st.markdown("### 👤 Profile & Settings")
            
            # Back to chats button
            if st.button("← Back to Chats", use_container_width=True):
                st.session_state.show_profile = False
                st.rerun()
            
            st.markdown("---")
            
            # Profile information
            if user.get("picture"):
                st.image(user["picture"], width=80)
            
            if user.get("name"):
                st.write(f"**Name:** {user['name']}")
            
            st.write(f"**Email:** {user['email']}")
            
            if user.get("auth_method"):
                auth_icon = "🌟" if user['auth_method'] == 'google' else "📧"
                st.write(f"**Sign-in method:** {auth_icon} {user['auth_method'].title()}")
            
            st.markdown("---")
            
            # Token usage
            tokens_used = user.get('tokens_used_today', 0)
            tokens_remaining = 2000 - tokens_used
            progress_percent = min(tokens_used / 2000, 1.0)
            
            st.markdown("#### 📊 Usage Statistics")
            st.metric("Tokens Used Today", f"{tokens_used:,}", f"{tokens_remaining:,} remaining")
            st.progress(progress_percent)
            
            st.markdown("---")
            
            # API Key management
            st.markdown("#### 🔑 API Key")
            api_key_input = st.text_input(
                "Custom API Key (optional)", 
                value=user.get("api_key") or "", 
                type="password",
                key="profile_api_key"
            )
            
            col_api1, col_api2 = st.columns(2)
            if col_api1.button("💾 Save", use_container_width=True, key="save_api_profile"):
                users_col.update_one({"_id": user["_id"]}, {"$set": {"api_key": api_key_input}})
                user["api_key"] = api_key_input
                st.success("API Key saved!")
            
            if col_api2.button("🗑️ Delete", use_container_width=True, key="delete_api_profile"):
                users_col.update_one({"_id": user["_id"]}, {"$set": {"api_key": None}})
                user["api_key"] = None
                st.success("API Key deleted!")
        
        else:
            # Chat history section in sidebar
            st.markdown("### 💬 Chat History")
            
            # New chat button
            if st.button("➕ New Chat", use_container_width=True, key="new_chat_sidebar"):
                new_chat_id = create_new_chat(user["_id"])
                if new_chat_id:
                    st.session_state.current_chat_id = new_chat_id
                    st.session_state.messages = []
                    st.success("Started new chat!")
                    st.rerun()
                else:
                    st.error("Failed to create new chat. Please try again.")
            
            st.markdown("---")
            
            # Load user's chat history
            user_chats = get_user_chats(user["_id"])
            
            if user_chats:
                for chat in user_chats:
                    chat_id = str(chat["_id"])
                    is_current = chat_id == st.session_state.current_chat_id
                    
                    col1, col2 = st.columns([4, 1])
                    
                    with col1:
                        # Safe access to chat fields with defaults
                        chat_title = chat.get('title', 'Untitled Chat')
                        message_count = chat.get('message_count', 0)
                        created_at = chat.get('created_at', datetime.now(timezone.utc))
                        
                        # Format creation date safely
                        try:
                            date_str = created_at.strftime('%Y-%m-%d %H:%M')
                        except:
                            date_str = 'Unknown'
                        
                        # Apply different styling for current chat
                        if st.button(
                            f"💬 {chat_title[:25]}{'...' if len(chat_title) > 25 else ''}",
                            key=f"chat_{chat_id}",
                            help=f"Messages: {message_count}\nCreated: {date_str}",
                            use_container_width=True
                        ):
                            st.session_state.current_chat_id = chat_id
                            st.session_state.messages = get_chat_messages(chat_id)
                            st.rerun()
                    
                    with col2:
                        if st.button("🗑️", key=f"delete_{chat_id}", help="Delete chat"):
                            if delete_chat(chat_id):
                                if chat_id == st.session_state.current_chat_id:
                                    st.session_state.current_chat_id = None
                                    st.session_state.messages = []
                                st.success("Chat deleted!")
                                st.rerun()
            else:
                st.info("No chat history yet. Start a new conversation!")
            
            # Quick stats
            st.markdown("---")
            st.markdown(f"**Total Chats:** {len(user_chats)}")
            if st.session_state.messages:
                user_msg_count = len([m for m in st.session_state.messages if m[0] == 'user'])
                st.markdown(f"**Current Chat:** {user_msg_count} messages")

    # Main chat interface with fixed ChatGPT-like layout
    # Create a container with proper margins for the chat area
    chat_container = st.container()
    
    with chat_container:
        # Use columns to create proper chat width like ChatGPT
        col1, col2, col3 = st.columns([1, 6, 1])
        
        with col2:
            # Show header only for empty conversations
            if not st.session_state.messages:
                # Main welcome section
                st.markdown('<div style="text-align: center; margin: 3rem 0 4rem 0; opacity: 0.9;">', unsafe_allow_html=True)
        
                # AI Icon and Title
                st.markdown('<div style="font-size: 3rem; margin-bottom: 1rem;">🤖</div>', unsafe_allow_html=True)
                st.markdown('<h1 style="font-size: 2.2rem; margin-bottom: 1rem; font-weight: 600; color: #fff;">YAHANAR AI</h1>', unsafe_allow_html=True)
                st.markdown('<p style="color: rgba(255,255,255,0.7); font-size: 1.1rem; margin-bottom: 2rem;">How can I help you today?</p>', unsafe_allow_html=True)
        
                # Feature cards using Streamlit columns
                col1, col2, col3, col4 = st.columns(4)
        
                with col1:
                    st.markdown("""
                        <div style="background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; text-align: left; border: 1px solid rgba(255,255,255,0.1); height: 120px;">
                            <div style="font-size: 1.5rem; margin-bottom: 8px;">💡</div>
                            <h3 style="margin: 0 0 8px 0; font-size: 1rem; color: #fff;">Creative Writing</h3>
                            <p style="margin: 0; color: rgba(255,255,255,0.6); font-size: 0.85rem;">Stories, essays, and creative content</p>
                        </div>
                    """, unsafe_allow_html=True)
                    
                with col2:
                    st.markdown("""
                        <div style="background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; text-align: left; border: 1px solid rgba(255,255,255,0.1); height: 120px;">
                            <div style="font-size: 1.5rem; margin-bottom: 8px;">💻</div>
                            <h3 style="margin: 0 0 8px 0; font-size: 1rem; color: #fff;">Programming</h3>
                            <p style="margin: 0; color: rgba(255,255,255,0.6); font-size: 0.85rem;">Debug code and learn programming</p>
                        </div>
                    """, unsafe_allow_html=True)
                    
                with col3:
                    st.markdown("""
                        <div style="background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; text-align: left; border: 1px solid rgba(255,255,255,0.1); height: 120px;">
                            <div style="font-size: 1.5rem; margin-bottom: 8px;">🔍</div>
                            <h3 style="margin: 0 0 8px 0; font-size: 1rem; color: #fff;">Research</h3>
                            <p style="margin: 0; color: rgba(255,255,255,0.6); font-size: 0.85rem;">Deep dive into topics and analysis</p>
                        </div>
                    """, unsafe_allow_html=True)
                    
                with col4:
                    st.markdown("""
                        <div style="background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; text-align: left; border: 1px solid rgba(255,255,255,0.1); height: 120px;">
                            <div style="font-size: 1.5rem; margin-bottom: 8px;">🎨</div>
                            <h3 style="margin: 0 0 8px 0; font-size: 1rem; color: #fff;">Creative Ideas</h3>
                            <p style="margin: 0; color: rgba(255,255,255,0.6); font-size: 0.85rem;">Brainstorm innovative solutions</p>
                        </div>
                    """, unsafe_allow_html=True)
        
                st.markdown('</div>', unsafe_allow_html=True)  # Close welcome section

            # Display chat messages with ChatGPT/Claude style
            logger.info("Rendering chat history")
            
            for i, (role, text) in enumerate(st.session_state.messages):
                if role == "user":
                    st.markdown(f"""
                        <div class="message-container user-container fade-in">
                            <div class="user-message">
                                {text}
                            </div>
                            <div class="message-avatar user-avatar">
                                👤
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    # Format assistant message with simpler styling
                    st.markdown(f'''
                        <div class="message-container assistant-container slide-in">
                            <div class="message-avatar assistant-avatar">🤖</div>
                            <div class="assistant-message">
                                <div class="message-content">{text}</div>
                            </div>
                        </div>
                    ''', unsafe_allow_html=True)
            
            # Add some spacing after messages
            if st.session_state.messages:
                st.markdown('<div style="margin-bottom: 2rem;"></div>', unsafe_allow_html=True)

    # Chat input with ChatGPT-style design (outside the column layout)
    prompt = st.chat_input(
        "Message Krutrim AI...", 
        key="chat_input"
    )
        
    if prompt:
        logger.info(f"User sent message: {prompt}")
        tokens_needed = 512
        
        # Check token limits with better UX
        if not can_use_tokens(user, tokens_needed) and not user.get("api_key"):
            logger.warning("Token limit reached for user")
            st.error("""
                🚫 **Daily Token Limit Reached**
                
                You've used all 2,000 free tokens for today. To continue:
                
                • 🔑 Add your Krutrim API key in the sidebar
                • ⏰ Wait for tomorrow's reset (tokens refresh daily)
            """, icon="⚠️")
        else:
            # Add user message
            st.session_state.messages.append(("user", prompt))
            
            # Show temporary typing indicator and generate response
            with st.status("✨ Generating response...", expanded=False) as status:
                try:
                    messages_payload = [{"role": r, "content": c} for r, c in st.session_state.messages]
                    reply, used_tokens = chat_with_krutrim(messages_payload, user.get("api_key"))
                    
                    # Add assistant response
                    st.session_state.messages.append(("assistant", reply))
                    
                    # Save to database
                    logger.info("Saving chat messages to database")
                    try:
                        # Create new chat if none exists
                        if not st.session_state.current_chat_id:
                            new_chat_id = create_new_chat(user["_id"])
                            if new_chat_id:
                                st.session_state.current_chat_id = new_chat_id
                            else:
                                st.error("Failed to create chat. Please try again.")
                                st.stop()
                        
                        # Save messages to current chat
                        save_chat_message(user["_id"], st.session_state.current_chat_id, "user", prompt)
                        save_chat_message(user["_id"], st.session_state.current_chat_id, "assistant", reply)
                    except Exception as e:
                        logger.error(f"Failed to save chat to database: {e}")
                    
                    # Update token usage
                    increment_tokens(user, used_tokens)
                    user = users_col.find_one({"_id": user["_id"]})
                    st.session_state.user = user
                    CHAT_COUNT.inc()
                    
                    status.update(label="✅ Response generated!", state="complete")
                    
                except Exception as e:
                    logger.error(f"Error generating response: {e}")
                    st.session_state.messages.append(("assistant", "❌ Sorry, I encountered an error while processing your request. Please try again."))
                    status.update(label="❌ Error occurred", state="error")
            
            st.rerun()
    
    # Auto-scroll to bottom for new messages and add keyboard shortcuts
    if st.session_state.messages:
        st.markdown("""
            <script>
                // Auto scroll to bottom
                setTimeout(function() {
                    window.scrollTo({
                        top: document.body.scrollHeight,
                        behavior: 'smooth'
                    });
                }, 100);
                
                // Keyboard shortcuts
                document.addEventListener('keydown', function(e) {
                    // Ctrl/Cmd + K to start new chat
                    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                        e.preventDefault();
                        const newChatBtn = document.querySelector('[title="Start a new conversation"]');
                        if (newChatBtn) newChatBtn.click();
                    }
                    
                    // Focus chat input on any key (except special keys)
                    if (!e.ctrlKey && !e.metaKey && !e.altKey && e.key.length === 1) {
                        const chatInput = document.querySelector('.stChatInput input');
                        if (chatInput && document.activeElement !== chatInput) {
                            chatInput.focus();
                        }
                    }
                });
            </script>
        """, unsafe_allow_html=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
        <div style="text-align: center; color: rgba(255,255,255,0.5); padding: 2rem 0;">
            <p>🤖 Powered by <strong>Krutrim AI</strong> | 🔒 Your privacy is protected</p>
            <p style="font-size: 0.8rem;">Built with ❤️ using Streamlit | 📊 <a href="http://localhost:8000" style="color: #667eea;">Metrics Dashboard</a></p>
        </div>
    """, unsafe_allow_html=True)
