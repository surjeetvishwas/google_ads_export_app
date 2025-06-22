import os
import time
import flask
from flask import Flask, redirect, session, url_for, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
#from googleads import google_ads_client  # alias import path if needed
from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.errors import GoogleAdsException

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret")

# Env vars
GOOGLE_CLIENT_ID     = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
DEVELOPER_TOKEN      = os.environ["DEVELOPER_TOKEN"]
REDIRECT_URI         = os.environ["REDIRECT_URI"]

SCOPES = [
    "https://www.googleapis.com/auth/adwords",
    "https://www.googleapis.com/auth/spreadsheets",
    "openid", "email", "profile"
]

@app.route("/")
def index():
    return render_template("index.html", authorized=("credentials" in session))

@app.route("/login")
def login():
    flow = Flow.from_client_config({
        "web": {
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri":      "https://accounts.google.com/o/oauth2/auth",
            "token_uri":     "https://oauth2.googleapis.com/token",
            "redirect_uris":[REDIRECT_URI]
        }
    }, scopes=SCOPES, redirect_uri=REDIRECT_URI)

    auth_url, state = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true"
    )
    session['state'] = state  # Use the state returned by authorization_url()
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_config({
        "web": {
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri":      "https://accounts.google.com/o/oauth2/auth",
            "token_uri":     "https://oauth2.googleapis.com/token",
            "redirect_uris":[REDIRECT_URI]
        }
    }, scopes=SCOPES, state=session.get('state'), redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=flask.request.url)

    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    session.pop('sheet_id', None)  # clear any old sheet
    return redirect(url_for("index"))

@app.route("/export-to-sheets")
def export_to_sheets():
    if 'credentials' not in session:
        return redirect(url_for('index'))

    # Rebuild credentials for Sheets & Ads
    info = session['credentials']
    creds = Credentials(
        token=info['token'],
        refresh_token=info['refresh_token'],
        token_uri=info['token_uri'],
        client_id=info['client_id'],
        client_secret=info['client_secret'],
        scopes=info['scopes']
    )
    sheets = build('sheets', 'v4', credentials=creds)

    # Create or reuse spreadsheet
    sheet_id = session.get('sheet_id')
    if not sheet_id:
        resp = sheets.spreadsheets().create(
            body={'properties': {'title': 'Ads Change History'}}
        ).execute()
        sheet_id = resp['spreadsheetId']
        session['sheet_id'] = sheet_id

    # Prepare Google Ads client
    ads_config = {
        'developer_token': DEVELOPER_TOKEN,
        'client_id':       GOOGLE_CLIENT_ID,
        'client_secret':   GOOGLE_CLIENT_SECRET,
        'refresh_token':   creds.refresh_token,
    }
    base_client = GoogleAdsClient.load_from_dict(ads_config)
    cust_svc = base_client.get_service('CustomerService')

    # 1️⃣ Get all customer resource names
    resources = cust_svc.list_accessible_customers().resource_names

    # 2️⃣ Identify manager + children
    manager_id = None
    child_ids = []
    for r in resources:
        cust = cust_svc.get_customer(resource_name=r)
        cid = r.split('/')[-1]
        if cust.manager:
            manager_id = cid
        else:
            child_ids.append(cid)
    if not manager_id and child_ids:
        # fallback if none flagged manager
        manager_id = child_ids.pop(0)

    # 3️⃣ Query change history for each child
    # Rebuild Ads client with login_customer_id set
    ads_config['login_customer_id'] = manager_id
    ads_client = GoogleAdsClient.load_from_dict(ads_config)
    ga_svc = ads_client.get_service('GoogleAdsService')

    query = """
      SELECT change_status.resource_name,
             change_status.last_change_date_time,
             change_status.resource_type,
             change_status.resource_status
      FROM change_status
      WHERE change_status.last_change_date_time DURING LAST_30_DAYS
    """

    rows = [[
        'manager_customer','child_customer',
        'resource_name','last_change_time',
        'resource_type','resource_status'
    ]]

    for cid in child_ids:
        time.sleep(1)
        try:
            stream = ga_svc.search_stream(customer_id=cid, query=query)
            for batch in stream:
                for row in batch.results:
                    cs = row.change_status
                    rows.append([
                        manager_id, cid,
                        cs.resource_name,
                        cs.last_change_date_time,
                        cs.resource_type,
                        cs.resource_status
                    ])
        except GoogleAdsException as e:
            rows.append([manager_id, cid, 'ERROR', str(e.error.code()), e.error.message])

    # 4️⃣ Write back to Sheet
    sheets.spreadsheets().values().clear(
        spreadsheetId=sheet_id, range='Sheet1'
    ).execute()
    sheets.spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range='Sheet1!A1',
        valueInputOption='RAW',
        body={'values': rows}
    ).execute()

    link = f"https://docs.google.com/spreadsheets/d/{sheet_id}"
    return f'<h2>✅ Export complete! View your data <a href="{link}" target="_blank">here</a>.</h2>'

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
