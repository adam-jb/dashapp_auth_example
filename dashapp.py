from dotenv import load_dotenv
import os
from functools import wraps
from flask import Flask, request, redirect, make_response, session as flask_session
from workos import WorkOSClient
import dash
from dash import html, dcc
from dash.exceptions import PreventUpdate
from dash.dependencies import Input, Output, State
import base64
import secrets


## Edit this
ALLOWED_USERS = [
    'adambricknell7@gmail.com',
]


# Load environment variables and setup
load_dotenv()
server = Flask(__name__)
server.secret_key = os.urandom(24)  # Required for flask session

# Configure WorkOS
workos = WorkOSClient(
    api_key=os.getenv("WORKOS_API_KEY"),
    client_id=os.getenv("WORKOS_CLIENT_ID")
)

# Generate a valid Fernet key if not provided
cookie_password = os.getenv("WORKOS_COOKIE_PASSWORD")
if not cookie_password:
    cookie_password = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()

def check_auth():
    """Helper function to check authentication status"""
    try:
        session = workos.user_management.load_sealed_session(
            sealed_session=request.cookies.get("wos_session"),
            cookie_password=cookie_password,
        )
        auth_response = session.authenticate()
        return auth_response.authenticated
    except:
        return False

def protect_dashviews(f):
    """Decorator to protect dash views"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_auth():
            return html.Div([
                html.H1("Please Log In"),
                html.P("You must log in before accessing the Dash app."),
                html.A("Login", href="/login")
            ])
        return f(*args, **kwargs)
    return decorated

# Flask routes remain the same as before
@server.route("/login")
def login():
    authorization_url = workos.user_management.get_authorization_url(
        provider="authkit",
        redirect_uri=os.getenv("WORKOS_REDIRECT_URI")
    )
    return redirect(authorization_url)

@server.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        print("No code provided")
        return redirect("/login")
        
    try:
        auth_response = workos.user_management.authenticate_with_code(
            code=code,
            session={"seal_session": True, "cookie_password": cookie_password},
        )
        
        base_url = request.host_url.rstrip('/')
        response = make_response(redirect(f"{base_url}/"))
        response.set_cookie(
            "wos_session",
            auth_response.sealed_session,
            secure=True,
            httponly=True,
            samesite="Lax",
            domain=request.host.split(':')[0],
            path='/'
        )
        return response
        
    except Exception as e:
        print(f"Authentication error: {e}")
        return redirect("/login")
    except Exception as e:
        print("Error authenticating with code", e)
        return redirect("/login")

@server.route("/logout")
def logout():
    session = workos.user_management.load_sealed_session(
        sealed_session=request.cookies.get("wos_session"),
        cookie_password=cookie_password,
    )
    url = session.get_logout_url()
    response = make_response(redirect(url))
    response.delete_cookie("wos_session")
    return response

# Create Dash app
app = dash.Dash(__name__, server=server, routes_pathname_prefix="/")

# ASCII art
ascii_art = r"""
_    _      _ _                __                            _           _     
| |  | |    | | |              / _|                          | |         | |    
| |__| | ___| | | ___    ___  | |_ _ __ ___  _ __ ___     __| | __ _ ___| |__  
|  __  |/ _ \ | |/ _ \  / _ \ |  _| '__/ _ \| '_ ` _ \   / _` |/ _` / __| '_ \ 
| |  | |  __/ | | (_) |( (_) )| | | | | (_) | | | | | | | (_| | (_| \__ \ | | |
|_|  |_|\___|_|_|\___/  \___/ |_| |_|  \___/|_| |_| |_|  \__,_|\__,_|___/_| |_|
"""

def get_user():
    """Get current user data from WorkOS session"""
    try:
        session = workos.user_management.load_sealed_session(
            sealed_session=request.cookies.get("wos_session"),
            cookie_password=cookie_password,
        )
        auth_response = session.authenticate()
        if auth_response.authenticated:
            return auth_response.user
        return None
    except:
        return None

@protect_dashviews
def serve_layout():
    """Protected layout function"""
    user = get_user()
    if user.email in ALLOWED_USERS:
        return html.Div([
            html.H1(f"Welcome {user.email if user else ''}!"),
            html.Pre(ascii_art),
            html.P("You are logged in. Enjoy the app!"),
            html.A("Logout", href="/logout")
        ])
    else:
        return html.Div([
            html.H1(f"Apologies, you dont have permission to view this app!"),
        ])

app.layout = serve_layout

if __name__ == "__main__":
    server.run(debug=True, port=3001)