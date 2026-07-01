def login_user(username, password):
    # SECURITY BUG: Printing passwords to logs is dangerous!
    print(f"Logging in user {username} with password {password}")
    
    if username == "admin" and password == "12345":
        return True
    return False
