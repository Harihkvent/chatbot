# Krutrim Chatbot

A modern, ChatGPT-like chatbot web app built with Streamlit, MongoDB, and Krutrim API.  
It supports user authentication, token limits, custom API keys, metrics, and logging.

## Features

- **User Authentication:** Register and login securely with hashed passwords.
- **Chat Interface:** ChatGPT-style UI using Streamlit components.
- **Token Usage:** Daily token limit per user, shown in the sidebar.
- **Custom API Key:** Users can save or delete their own API key (hidden input).
- **Profile & Settings:** Sidebar shows user info, token usage, and API key management.
- **Logging:** All major actions are logged for debugging and monitoring.
- **Metrics:** Prometheus metrics for requests, logins, registrations, errors, and chat latency.
- **MongoDB Storage:** Stores users and chat history.
- **Easy Refresh:** Refresh chat history without logging out.
- **Dark Mode:** Clean, modern look using Streamlit’s built-in theming.

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

### 4. Configure secrets

Edit `.streamlit/secrets.toml` with your API keys and MongoDB credentials:

```toml
KRUTRIM_API_KEY="your_krutrim_api_key"
MONGO_USER="your_mongo_user"
MONGO_PASS="your_mongo_password"
MONGO_CLUSTER="your_mongo_cluster_url"
MONGO_DB="your_db_name"
```

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
