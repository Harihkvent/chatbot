# Google OAuth Setup Guide

## Steps to Configure Google OAuth for your Chatbot

### 1. Create Google Cloud Project and OAuth Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API:
   - Go to "APIs & Services" > "Library"
   - Search for "Google+ API" and enable it
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Choose "Web application"
   - Add authorized redirect URIs:
     - For local development: `http://localhost:8501`
     - For production: your actual domain URL
   - Note down the Client ID and Client Secret

### 2. Configure Environment Variables

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Fill in your credentials in `.env`:
   ```
   GOOGLE_CLIENT_ID=your_actual_client_id_here
   GOOGLE_CLIENT_SECRET=your_actual_client_secret_here
   OAUTH_REDIRECT_URI=http://localhost:8501
   ```

### 3. Update Client Secrets File (Optional)

The `client_secret_*.json` file should contain your Google OAuth configuration:

```json
{
  "web": {
    "client_id": "your_client_id_here",
    "project_id": "your_project_id_here",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "your_client_secret_here",
    "redirect_uris": ["http://localhost:8501"]
  }
}
```

### 4. Test the Setup

1. Start your Streamlit app:
   ```bash
   streamlit run app.py
   ```

2. Click "Sign in with Google"
3. You should be redirected to Google's OAuth page
4. After authorization, you should be redirected back to your app

### Troubleshooting

- **Empty client secrets file**: Make sure your JSON file contains the proper OAuth configuration
- **Redirect URI mismatch**: Ensure the redirect URI in Google Cloud Console matches your `.env` file
- **Port conflicts**: Make sure port 8501 is available for Streamlit
- **Missing scopes**: The app requests email and profile information - make sure these are enabled in Google Cloud Console

### Security Notes

- Never commit your `.env` file or actual credentials to version control
- For production, use HTTPS redirect URIs
- Consider implementing proper session management and CSRF protection