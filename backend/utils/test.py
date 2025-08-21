import urllib.parse

business_id = 1  # example business/user ID
redirect_uri = "https://zentry1.onrender.com/instagram/callback"

# Fix: Format state parameter to match what callback expects
state = f"business_id={business_id}"

# URL encode the state parameter to handle special characters safely
encoded_state = urllib.parse.quote(state)

url = (
    f"https://www.instagram.com/oauth/authorize"
    f"?client_id=797715939467119"
    f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
    f"&scope=instagram_business_basic,"
    f"instagram_business_manage_messages,"
    f"instagram_business_manage_comments,"
    f"instagram_business_content_publish,"
    f"instagram_business_manage_insights"
    f"&response_type=code"
    f"&state={encoded_state}"
)
print("OAuth URL:")
print(url)
print("\nState parameter being sent:", state)