#!/usr/bin/env python3
"""
Debug script to check database connection and user authentication
"""
import os
from pymongo import MongoClient
from urllib.parse import quote_plus
from dotenv import load_dotenv
import bcrypt
import certifi

def test_database_and_auth():
    """Test database connection and authentication functions"""
    load_dotenv()
    
    print("🔍 Testing Database Connection and Authentication...")
    print("=" * 60)
    
    # MongoDB connection
    username = quote_plus("chatbot")
    password = quote_plus(os.getenv("MONGO_PASS"))
    dbname = os.getenv("MONGO_DB")
    
    if not password or not dbname:
        print("❌ MongoDB credentials not found in .env file")
        return False
    
    MONGO_URI = (
        f"mongodb+srv://{username}:{password}@cluster0.57nirib.mongodb.net/{dbname}"
        "?retryWrites=true&w=majority&tls=true"
    )
    
    try:
        client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=10000)
        client.admin.command("ping")
        print("✅ MongoDB connection successful")
        
        db = client[dbname]
        users_col = db.users
        
        # Check existing users
        user_count = users_col.count_documents({})
        print(f"📊 Total users in database: {user_count}")
        
        if user_count > 0:
            print("\n👥 Sample users:")
            for user in users_col.find({}).limit(3):
                print(f"   Email: {user.get('email')}")
                print(f"   Auth method: {user.get('auth_method', 'unknown')}")
                print(f"   Has password hash: {'Yes' if user.get('password_hash') else 'No'}")
                print(f"   Google ID: {'Yes' if user.get('google_id') else 'No'}")
                print("   ---")
        
        # Test authentication functions
        def hash_password(password):
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        def check_password(password, hashed):
            return bcrypt.checkpw(password.encode(), hashed)
        
        # Test password hashing
        test_password = "test123"
        hashed = hash_password(test_password)
        
        if check_password(test_password, hashed):
            print("✅ Password hashing and verification working correctly")
        else:
            print("❌ Password hashing/verification failed")
            
        print("\n🧪 Test creating a sample user...")
        test_email = "test@example.com"
        
        # Remove test user if exists
        users_col.delete_one({"email": test_email})
        
        # Create test user
        from datetime import datetime, timezone
        test_user = {
            "email": test_email,
            "password_hash": hashed,
            "api_key": None,
            "tokens_used_today": 0,
            "last_reset": datetime.now(timezone.utc),
            "created_at": datetime.now(timezone.utc),
            "auth_method": "email"
        }
        
        result = users_col.insert_one(test_user)
        print(f"✅ Test user created with ID: {result.inserted_id}")
        
        # Test login
        user = users_col.find_one({"email": test_email})
        if user and check_password(test_password, user["password_hash"]):
            print("✅ Test login successful")
        else:
            print("❌ Test login failed")
        
        # Clean up test user
        users_col.delete_one({"email": test_email})
        print("🧹 Test user cleaned up")
        
        print("\n✅ All tests passed! Email/password authentication should work.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    test_database_and_auth()