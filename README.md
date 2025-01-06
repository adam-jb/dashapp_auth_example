Dash integration example using AuthKit


## To add users

Edit the list of ALLOWED_USERS in `dashapp.py`

A better way: sync a list csv of users from Sharepoint or a database somewhere


## To set up

Go to WorkOS dashboard and:
- Set up Authkit
- Get your client ID and API key from the main WorkOS dashboard
- Set up a redirect URL in the Authkit settings, which should reflect the public URL (the Azure container URL, or ngrok if debugging locally)

Make and populate the `.env` file with your WorkOS API key and client ID.
```
WORKOS_API_KEY=[get from workos dashboard]
WORKOS_CLIENT_ID=[get from workos dashboard]
WORKOS_REDIRECT_URI=[ngrok or other public app url]/callback
WORKOS_COOKIE_PASSWORD=[32-bit pwd. Make in py with: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()]
```


