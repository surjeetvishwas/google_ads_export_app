import os
import time
import flask
from flask import Flask, redirect, session, url_for, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.errors import GoogleAdsException

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret")

GOOGLE_CLIENT_ID     = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
DEVELOPER_TOKEN      = os.environ["DEVELOPER_TOKEN"]
REDIRECT_URI         = os.environ["REDIRECT_URI"]

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/adwords",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]

@app.route("/")
def index():
    authorized = bool(session.get("credentials"))
    return render_template("index.html", authorized=authorized)

@app.route("/login")
def login():
    session.clear()
    flow = Flow.from_client_config({
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI]
        }
    }, scopes=SCOPES, redirect_uri=REDIRECT_URI)

    auth_url, state = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes=False
    )
    session['state'] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    try:
        state = session.get('state')
        flow = Flow.from_client_config({
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        }, scopes=SCOPES, state=state, redirect_uri=REDIRECT_URI)

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
        session.pop('sheet_id', None)
        return redirect(url_for("index"))

    except Exception as e:
        return f"<h3>❌ OAuth error: {str(e)}</h3><p>Try <a href='/login'>logging in again</a>.</p>", 500

@app.route("/export-to-sheets")
def export_to_sheets():
    if 'credentials' not in session:
        return redirect(url_for('index'))

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

    sheet_id = session.get('sheet_id')
    if not sheet_id:
        resp = sheets.spreadsheets().create(
            body={'properties': {'title': 'Ads Change History'}}
        ).execute()
        sheet_id = resp['spreadsheetId']
        session['sheet_id'] = sheet_id

    base_ads_cfg = {
        'developer_token': DEVELOPER_TOKEN,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'refresh_token': creds.refresh_token,
        'use_proto_plus': True
    }

    try:
        client = GoogleAdsClient.load_from_dict(base_ads_cfg)
        cust_svc = client.get_service('CustomerService')

        resources = cust_svc.list_accessible_customers().resource_names
        manager_id = None
        child_ids = []

        for r in resources:
            cid = r.split('/')[-1]
            # Query to check if this customer is a manager
            query = """
                SELECT customer.manager
                FROM customer
                WHERE customer.resource_name = '{}'
            """.format(r)
            ga_svc = client.get_service('GoogleAdsService')
            response = ga_svc.search(customer_id=cid, query=query)
            is_manager = False
            for row in response:
                is_manager = row.customer.manager
            if is_manager:
                manager_id = cid
            else:
                child_ids.append(cid)
        if not manager_id and child_ids:
            manager_id = child_ids.pop(0)

        ads_cfg = dict(base_ads_cfg)
        # Only set login_customer_id if you are using a manager account
        if manager_id:
            ads_cfg["login_customer_id"] = str(manager_id)
        client = GoogleAdsClient.load_from_dict(ads_cfg)
        ga_svc = client.get_service('GoogleAdsService')

        query = """
          SELECT change_status.resource_name,
                 change_status.last_change_date_time,
                 change_status.resource_type,
                 change_status.resource_status
          FROM change_status
          WHERE change_status.last_change_date_time DURING LAST_30_DAYS
        """

        rows = [[
            'manager_customer', 'child_customer',
            'resource_name', 'last_change_time',
            'resource_type', 'resource_status'
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

    except Exception as e:
        return f"<h3>❌ Export failed: {str(e)}</h3><p>Check logs for details.</p>", 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
