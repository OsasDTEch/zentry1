business_id = 1  # example business/user ID
redirect_uri = "https://zentry1.onrender.com/instagram/callback"
state = str(business_id)

url = (
    f"https://www.instagram.com/oauth/authorize"
    f"?client_id=797715939467119"
    f"&redirect_uri={redirect_uri}"
    f"&scope=instagram_business_basic,"
    f"instagram_business_manage_messages,"
    f"instagram_business_manage_comments,"
    f"instagram_business_content_publish,"
    f"instagram_business_manage_insights"
    f"&response_type=code"
    f"&state={state}"
)
print(url)