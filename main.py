import streamlit as st
import sqlite3
from sqlite3 import Error
from streamlit_option_menu import option_menu

# Database connection
def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('fintree_suggestion_box.db')
        create_table(conn)  # Create tables if they don't exist
    except Error as e:
        st.error(e)
    return conn

# Create tables for users and suggestions
def create_table(conn):
    try:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                contact_number TEXT NOT NULL,
                suggestion_access INTEGER NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                suggestion TEXT NOT NULL
            )
        ''')
        conn.commit()
    except Error as e:
        st.error(e)

# Helper functions for database operations
def get_user(conn, username):
    try:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        return c.fetchone()
    except Error as e:
        st.error(e)
        return None

def get_all_users(conn):
    try:
        c = conn.cursor()
        c.execute('SELECT username, suggestion_access FROM users')
        return c.fetchall()
    except Error as e:
        st.error(e)
        return []

def add_user(conn, username, password, contact_number):
    try:
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, contact_number, suggestion_access) VALUES (?, ?, ?, ?)', (username, password, contact_number, 0))
        conn.commit()
    except Error as e:
        st.error(e)

def update_password(conn, username, new_password):
    try:
        c = conn.cursor()
        c.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
        conn.commit()
    except Error as e:
        st.error(e)

def update_user_access(conn, username, access):
    try:
        c = conn.cursor()
        c.execute('UPDATE users SET suggestion_access = ? WHERE username = ?', (access, username))
        conn.commit()
    except Error as e:
        st.error(e)

def admin_login(username, password):
    return username == "omadmin" and password == "ompass"

def add_suggestion(conn, username, suggestion):
    try:
        c = conn.cursor()
        c.execute('INSERT INTO suggestions (username, suggestion) VALUES (?, ?)', (username, suggestion))
        conn.commit()
    except Error as e:
        st.error(e)

def get_suggestions(conn, username=None):
    try:
        c = conn.cursor()
        if username:
            c.execute('SELECT id, username, suggestion FROM suggestions WHERE username = ?', (username,))
        else:
            c.execute('SELECT id, username, suggestion FROM suggestions')
        return c.fetchall()
    except Error as e:
        st.error(e)
        return []

def delete_suggestion(conn, suggestion_id):
    try:
        c = conn.cursor()
        c.execute('DELETE FROM suggestions WHERE id = ?', (suggestion_id,))
        conn.commit()
    except Error as e:
        st.error(e)

def delete_all_suggestions(conn):
    try:
        c = conn.cursor()
        c.execute('DELETE FROM suggestions')
        conn.commit()
    except Error as e:
        st.error(e)

def add_reply(conn, username, suggestion_id, reply):
    try:
        c = conn.cursor()
        c.execute('INSERT INTO suggestions (username, suggestion) VALUES (?, ?)', (username, f"Reply to {suggestion_id}: {reply}"))
        conn.commit()
    except Error as e:
        st.error(e)

def rerun():
    st.experimental_set_query_params(rerun="true")

# Streamlit Login Page
def login_page():
    st.title("📮 Fintree Suggestion Box - Login")
    
    # Database connection
    conn = create_connection()

    # Check if user is logged in
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.is_admin = False

    # Check if user is verified for password reset
    if 'verified' not in st.session_state:
        st.session_state.verified = False

    # Function to handle user login
    def user_login(username, is_admin=False):
        st.session_state.logged_in = True
        st.session_state.username = username
        st.session_state.is_admin = is_admin

    # Create tabs for login functionalities
    tab1, tab2, tab3, tab4 = st.tabs(["Login", "Register", "Forgot Password", "Admin Login"])

    # Login Tab
    with tab1:
        st.subheader("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login", key="login_button"):
            user = get_user(conn, username)
            if user and user[2] == password:  # user[2] is the password
                st.success(f"Welcome {username} 🎉")
                user_login(username)
                rerun()  # Force a rerun to update the state
            else:
                st.error("Invalid Username or Password")

    # Register Tab
    with tab2:
        st.subheader("Register 📝")
        new_username = st.text_input("New Username", key="register_username")
        new_password = st.text_input("New Password", type="password", key="register_password")
        contact_number = st.text_input("Contact Number", key="register_contact")
        if st.button("Register", key="register_button"):
            if not new_username or not new_password or not contact_number:
                st.error("Please fill all fields")
            elif len(contact_number) != 10:
                st.error("Contact Number must be 10 digits")
            else:
                existing_user = get_user(conn, new_username)
                if existing_user:
                    st.error("Username already exists. Please choose a different username.")
                else:
                    add_user(conn, new_username, new_password, contact_number)
                    st.success("You have successfully registered!")
                    user_login(new_username)
                    rerun()  # Force a rerun to update the state

    # Forgot Password Tab
    with tab3:
        st.subheader("Forgot Password")
        username = st.text_input("Username", key="forgot_username")
        contact_number = st.text_input("Contact Number", key="forgot_contact")
        if st.button("Verify", key="verify_button"):
            user = get_user(conn, username)
            if user and user[3] == contact_number:  # user[3] is the contact_number
                st.success("Verification successful. Please enter your new password.")
                st.session_state.verified = True
                st.session_state.username = username
                rerun()  # Force a rerun to update the state
            else:
                st.error("Invalid Username or Contact Number")
        
        if st.session_state.verified:
            new_password = st.text_input("New Password", type="password", key="forgot_new_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="forgot_confirm_password")
            if st.button("Reset Password", key="reset_password_button"):
                if new_password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    update_password(conn, st.session_state.username, new_password)
                    st.success("Password has been reset")
                    st.session_state.verified = False  # Reset the verification state
                    st.session_state.username = ""
                    rerun()  # Force a rerun to update the state

    # Admin Login Tab
    with tab4:
        st.subheader("Admin Login")
        admin_username = st.text_input("Admin Username", key="admin_username")
        admin_password = st.text_input("Admin Password", type="password", key="admin_password")
        if st.button("Admin Login", key="admin_login_button"):
            if admin_login(admin_username, admin_password):
                st.success("Welcome Admin 🎉")
                user_login("omadmin", is_admin=True)
                rerun()  # Force a rerun to update the state
            else:
                st.error("Invalid Admin Username or Password")

# Suggestion Box Page for Normal Users
def suggestion_box_page():
    st.title("📬 Suggestion Box")

    # Database connection
    conn = create_connection()

    # Display welcome message
    st.subheader(f"Welcome, {st.session_state.username}!")

    # Check suggestion access for normal users
    user = get_user(conn, st.session_state.username)
    if user and user[4] == 0:  # user[4] is the suggestion_access
        st.warning("You do not have access to the suggestion box yet. Please contact the admin.")
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.is_admin = False
            rerun()  # Force a rerun to update the state
        return

    # Create tabs for Suggestion Box and Suggestion List
    tab1, tab2 = st.tabs(["Submit Suggestion", "View Suggestions"])

    # Submit Suggestion Tab
    with tab1:
        st.subheader("Submit a Suggestion")
        with st.form(key='suggestion_form'):
            suggestion = st.text_area("Your Suggestion", key="suggestion_text")
            submit_button = st.form_submit_button(label="Submit Suggestion")
        if submit_button:
            if suggestion.strip() == "":
                st.error("Suggestion cannot be empty")
            else:
                add_suggestion(conn, st.session_state.username, suggestion)
                st.success("Your suggestion has been submitted!")

    # View Suggestions Tab
    with tab2:
        st.subheader("All Suggestions")
        all_suggestions = get_suggestions(conn)
        suggestion_map = {}
        
        # First loop to organize replies under their corresponding suggestions
        for sugg_id, sugg_user, suggestion in all_suggestions:
            if suggestion.startswith("Reply to"):
                # Extract the suggestion ID this reply belongs to
                reply_to_id = int(suggestion.split(":")[0].split(" ")[-1])
                if reply_to_id in suggestion_map:
                    suggestion_map[reply_to_id].append((sugg_id, sugg_user, suggestion))
                else:
                    suggestion_map[reply_to_id] = [(sugg_id, sugg_user, suggestion)]
            else:
                # Add normal suggestions
                suggestion_map[sugg_id] = [(sugg_id, sugg_user, suggestion)]

        # Second loop to display suggestions and their replies
        for main_sugg_id, suggestions in suggestion_map.items():
            for sugg_id, sugg_user, suggestion in suggestions:
                user_type = 'Admin' if sugg_user == 'omadmin' else 'User'
                with st.form(key=f'suggestion_form_{sugg_id}'):
                    st.write(f"User: {user_type}")
                    st.write(f"Suggestion: {suggestion}")
                    # Only show buttons if the suggestion is not a reply and belongs to the user
                    if sugg_id == main_sugg_id and sugg_user == st.session_state.username:
                        delete_button = st.form_submit_button(label='Delete 🗑️')
                        if delete_button:
                            delete_suggestion(conn, sugg_id)
                            rerun()  # Force a rerun to update the suggestion list

        else:
            st.info("There are no suggestions yet.")

    # Logout button
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.is_admin = False
        rerun()  # Force a rerun to update the state

# Admin Panel with Option Menu
def admin_panel():
    st.title("👨‍💼 Admin Panel")

    # Database connection
    conn = create_connection()

    # Sidebar option menu for admin
    with st.sidebar:
        selected = option_menu(
            "Menu",
            ["Admin Suggestion", "View All Suggestions", "User Control"],
            icons=["pencil-square", "list-ul", "people-fill"],
            menu_icon="cast",
            default_index=0,
            orientation="vertical",
        )

    # Admin Suggestion Tab
    if selected == "Admin Suggestion":
        st.subheader("Submit an Admin Suggestion")
        with st.form(key='admin_suggestion_form'):
            admin_suggestion = st.text_area("Your Suggestion", key="admin_suggestion_text")
            admin_submit_button = st.form_submit_button(label="Submit Admin Suggestion")
        if admin_submit_button:
            if admin_suggestion.strip() == "":
                st.error("Suggestion cannot be empty")
            else:
                add_suggestion(conn, st.session_state.username, admin_suggestion)
                st.success("Your suggestion has been submitted!")

    # View All Suggestions Tab
    if selected == "View All Suggestions":
        st.subheader("All Suggestions")
        all_suggestions = get_suggestions(conn)
        suggestion_map = {}
        
        # First loop to organize replies under their corresponding suggestions
        for sugg_id, sugg_user, suggestion in all_suggestions:
            if suggestion.startswith("Reply to"):
                # Extract the suggestion ID this reply belongs to
                reply_to_id = int(suggestion.split(":")[0].split(" ")[-1])
                if reply_to_id in suggestion_map:
                    suggestion_map[reply_to_id].append((sugg_id, sugg_user, suggestion))
                else:
                    suggestion_map[reply_to_id] = [(sugg_id, sugg_user, suggestion)]
            else:
                # Add normal suggestions
                suggestion_map[sugg_id] = [(sugg_id, sugg_user, suggestion)]

        # Second loop to display suggestions and their replies
        for main_sugg_id, suggestions in suggestion_map.items():
            for sugg_id, sugg_user, suggestion in suggestions:
                user_type = 'Admin' if sugg_user == 'omadmin' else 'User'
                
                # Display suggestion with form only for main suggestions
                if sugg_id == main_sugg_id:
                    with st.form(key=f'suggestion_form_admin_{sugg_id}'):
                        st.write(f"User: {user_type}")
                        st.write(f"Suggestion: {suggestion}")
                        delete_button = st.form_submit_button(label='Delete 🗑️')
                        reply_button = st.form_submit_button(label='Reply 💬')
                        if delete_button:
                            delete_suggestion(conn, sugg_id)
                            rerun()  # Force a rerun to update the suggestion list
                        if reply_button and sugg_user != 'omadmin':
                            st.session_state.reply_to = sugg_id
                            rerun()  # Force a rerun to update the state
                else:
                    # For replies, just display them without any form
                    st.write(f"User: {user_type}")
                    st.write(f"Suggestion: {suggestion}")
                    st.markdown("<hr>", unsafe_allow_html=True)

                # Display reply box if needed (outside form)
                if 'reply_to' in st.session_state and st.session_state.reply_to == main_sugg_id:
                    reply = st.text_area("Your Reply", key=f"reply_text_admin_{sugg_id}")
                    if st.button(label="Submit Reply", key=f"submit_reply_admin_{sugg_id}"):
                        if reply.strip():
                            add_reply(conn, "omadmin", main_sugg_id, reply)
                            st.success("Reply submitted")
                            del st.session_state.reply_to  # Reset reply state
                            rerun()
                        else:
                            st.error("Reply cannot be empty")
        
        # Button to delete all suggestions
        if st.button("Delete All Suggestions", key="delete_all_suggestions"):
            delete_all_suggestions(conn)
            st.success("All suggestions have been deleted.")
            rerun()

    # User Control Tab
    if selected == "User Control":
        st.subheader("User Access Control")
        users = get_all_users(conn)
        if users:
            for user, access in users:
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**{user}** - {'Access Granted' if access else 'No Access'}")
                with col2:
                    if access:
                        if st.button("Revoke Access", key=f"revoke_{user}"):
                            update_user_access(conn, user, 0)
                            st.warning(f"Access has been taken from {user}.")
                            rerun()
                    else:
                        if st.button("Grant Access", key=f"grant_{user}"):
                            update_user_access(conn, user, 1)
                            st.success(f"Access has been granted to {user}.")
                            rerun()
        else:
            st.info("There are no users to display.")

    # Logout button
    if st.button("Logout", key="admin_logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.is_admin = False
        rerun()  # Force a rerun to update the state

# Main function
if __name__ == "__main__":
    if st.session_state.get("logged_in", False):
        if st.session_state.is_admin:
            admin_panel()
        else:
            suggestion_box_page()
    else:
        login_page()
