# Krutrim Chatbot

A modern, ChatGPT-like chatbot web app built with Streamlit, MongoDB, and Krutrim API.  
It supports user authentication, token limits, custom API keys, metrics, and logging.

---

**Access the bot online:**  
👉 [https://yahanar.streamlit.app/](https://yahanar.streamlit.app/)

---

## Features

- **User Authentication:** Register and login securely with hashed passwords or Google OAuth.
- **Google Sign-In:** One-click authentication with Google accounts.
- **Chat Interface:** ChatGPT-style UI using Streamlit components.
- **Token Usage:** Daily token limit per user, shown in the sidebar.
- **Custom API Key:** Users can save or delete their own API key (hidden input).
- **Profile & Settings:** Sidebar shows user info, profile picture, token usage, and API key management.
- **User Database:** Stores user profiles with Google profile information (name, picture, email).
- **Logging:** All major actions are logged for debugging and monitoring.
- **Metrics:** Prometheus metrics for requests, logins, registrations, errors, and chat latency.
- **MongoDB Storage:** Stores users and chat history.
- **Easy Refresh:** Refresh chat history without logging out.
- **Dark Mode:** Clean, modern look using Streamlit's built-in theming.

## Getting Started

### 1. Clone the repository

```sh
git clone <your-repo-url>
cd chatbot
```

### 2. Create and activate a virtual environment

```sh
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```sh
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root with your API keys and credentials:

```env
# Krutrim API Configuration
KRUTRIM_API_KEY=your_krutrim_api_key_here

# MongoDB Configuration
MONGO_PASS=your_mongodb_password_here
MONGO_DB=your_database_name_here

# Google OAuth Configuration (for Google Sign-In)
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
OAUTH_REDIRECT_URI=http://localhost:8501
```

**For Google Sign-In setup, see [GOOGLE_OAUTH_SETUP.md](GOOGLE_OAUTH_SETUP.md)**

### 5. Run the app

```sh
streamlit run app.py
```

The Prometheus metrics server will start on port 8000 by default.

## Usage

- Register or login with your email and password.
- Start chatting with the bot.
- View your token usage and profile in the sidebar.
- Save or delete your custom API key.
- Refresh chat history with the refresh button.
- Monitor metrics at `http://localhost:8000/metrics`.

## Contributing

Contributions are welcome!  
If you have ideas, bug fixes, or improvements, please:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Submit a pull request with a clear description.

Please follow [PEP8](https://peps.python.org/pep-0008/) coding style and add logging for new features.

## License

MIT

---

**Contact:**  
For questions or support, open an issue or contact the maintainer.


taskkill /IM msedge.exe /F