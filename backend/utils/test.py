business_id = 1  # example business/user ID
redirect_uri = "https://zentry1.onrender.com/instagram/callback"

url = (
    f"https://www.instagram.com/oauth/authorize?"
    f"force_reauth=true&client_id=797715939467119"
    f"&redirect_uri={redirect_uri}"
    f"&response_type=code"
    f"&scope=instagram_business_basic,"
    f"instagram_business_manage_messages,"
    f"instagram_business_manage_comments,"
    f"instagram_business_content_publish,"
    f"instagram_business_manage_insights"
    f"&state=business_id={business_id}"
)

print(url)
