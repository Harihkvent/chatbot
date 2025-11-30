#!/usr/bin/env python3
"""
Test script to verify Google OAuth configuration and setup
"""
import os
from dotenv import load_dotenv

def test_oauth_config():
    """Test Google OAuth configuration"""
    load_dotenv()
    
    print("🔍 Testing Google OAuth Configuration...")
    print("=" * 50)
    
    # Check environment variables
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:8501")
    
    if not client_id:
        print("❌ GOOGLE_CLIENT_ID not found in .env file")
        return False
    else:
        print(f"✅ GOOGLE_CLIENT_ID: {client_id[:10]}...")
    
    if not client_secret:
        print("❌ GOOGLE_CLIENT_SECRET not found in .env file")
        return False
    else:
        print(f"✅ GOOGLE_CLIENT_SECRET: {client_secret[:10]}...")
    
    print(f"✅ OAUTH_REDIRECT_URI: {redirect_uri}")
    
    # Test OAuth URL generation
    from urllib.parse import urlencode
    import secrets
    
    state = secrets.token_urlsafe(32)
    scopes = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ]
    
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "response_type": "code",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account"
    }
    
    oauth_url = "https://accounts.google.com/o/oauth2/auth?" + urlencode(params)
    
    print("\n🌐 Generated OAuth URL:")
    print(oauth_url[:100] + "..." if len(oauth_url) > 100 else oauth_url)
    
    # Check required packages
    try:
        import google_auth_oauthlib
        print("✅ google-auth-oauthlib package available")
    except ImportError:
        print("❌ google-auth-oauthlib package not installed")
        print("   Run: pip install google-auth-oauthlib")
        return False
    
    try:
        import prometheus_client
        print("✅ prometheus-client package available")
    except ImportError:
        print("❌ prometheus-client package not installed")
        print("   Run: pip install prometheus-client")
        return False
    
    print("\n✅ Configuration looks good!")
    print("\nNext steps:")
    print("1. Make sure your .env file has the correct Google OAuth credentials")
    print("2. In Google Cloud Console, add http://localhost:8501 as an authorized redirect URI")
    print("3. Run: streamlit run app.py")
    print("4. Test Google sign-in functionality")
    
    return True

if __name__ == "__main__":
    test_oauth_config()