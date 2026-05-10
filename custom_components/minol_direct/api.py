import logging, re, urllib.parse
from datetime import datetime
from aiohttp import ClientSession

_LOGGER = logging.getLogger(__name__)

SAP_HOST = "https://webservices.minol.com"
B2C_HOST = "https://minolauth.b2clogin.com"
B2C_POLICY = "B2C_1A_Signup_Signin_Groups_SAML"

INIT_URL = f"{SAP_HOST}/minol.com~kundenportal~login~saml/?logonTargetUrl=https%3A%2F%2Fwebservices.minol.com%2F%3Fredirect2%3Dtrue&saml2idp=B2C-Minol-Tenant"
SELF_ASSERTED_URL = f"{B2C_HOST}/minolauth.onmicrosoft.com/{B2C_POLICY}/SelfAsserted"
CONFIRMED_URL = f"{B2C_HOST}/minolauth.onmicrosoft.com/{B2C_POLICY}/api/CombinedSigninAndSignup/confirmed"
ACS_URL = f"{SAP_HOST}/saml2/sp/acs"
APP_LOGIN_URL = f"{SAP_HOST}/minol.com~kundenportal~login~saml/?logonTargetUrl=https%3A%2F%2Fwebservices.minol.com%2F%3Fredirect2%3Dtrue&saml2idp=B2C-Minol-Tenant"

TENANTS_URL = f"{SAP_HOST}/minol.com~kundenportal~em~web/rest/EMData/getUserTenants"
READ_DATA_URL = f"{SAP_HOST}/minol.com~kundenportal~em~web/rest/EMData/readData"

# Standard-Browser-Header, um Firewall-Blocks zu vermeiden
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
}

class MinolAuthError(Exception): pass
class MinolConnectionError(Exception): pass

class MinolOnlineClient:
    def __init__(self, username, password, session: ClientSession):
        self._username = username
        self._password = password
        self._session = session
        self._is_authenticated = False

    async def async_get_user_tenants(self):
        if not self._is_authenticated:
            await self._authenticate()
            
        headers = {
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "X-Requested-With": "XMLHttpRequest", 
            "Accept": "application/json", 
            "Content-Type": "application/json; charset=UTF-8"
        }
        async with self._session.get(TENANTS_URL, headers=headers) as resp:
            if resp.status == 200:
                try:
                    return await resp.json()
                except Exception as e:
                    _LOGGER.error("Konnte Tenant-JSON nicht parsen: %s", e)
            else:
                _LOGGER.error("Fehler beim Abruf der Tenants: HTTP %s", resp.status)
        return []

    async def async_fetch_data(self):
        if not self._is_authenticated:
            await self._authenticate()
            
        tenants = await self.async_get_user_tenants()
        if not tenants:
            await self._authenticate()
            tenants = await self.async_get_user_tenants()
            if not tenants:
                raise MinolConnectionError("Keine Nutzeinheiten gefunden.")

        all_meters = []
        for tenant in tenants:
            user_num = tenant.get("userNumber")
            if not user_num: continue
            
            meters = await self._fetch_all_mediums(user_num, tenant)
            if meters:
                all_meters.extend(meters)

        return {"meters": all_meters, "fetched_at": datetime.now().isoformat()}

    async def _fetch_all_mediums(self, user_num, tenant_info):
        all_meters = []
        now = datetime.now()
        start_date = f"{now.year - 1}01"
        end_date = now.strftime("%Y%m")
        cons_types = ["HZKWH", "WW", "KW"] 

        headers = {
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "X-Requested-With": "XMLHttpRequest", 
            "Accept": "application/json, text/javascript, */*; q=0.01", 
            "Content-Type": "application/json; charset=UTF-8"
        }

        for c_type in cons_types:
            payload = {
                "userNum": user_num, "layer": "NE", "scale": "CALMONTH", "chartRefUnit": "ABS",
                "refObject": "DIN_AVG", "consType": c_type, "dashBoardKey": "PE",
                "timelineStart": start_date, "timelineStartTxt": "", "timelineEnd": end_date,
                "timelineEndTxt": "", "valuesInKWH": True, "dlgKey": "100KWH"
            }

            try:
                async with self._session.post(READ_DATA_URL, json=payload, headers=headers) as resp:
                    if resp.status == 403 or "application/json" not in resp.headers.get("Content-Type", ""):
                        continue 
                        
                    json_resp = await resp.json()
                    if "table" in json_resp:
                        for row in json_resp["table"]:
                            row["_ha_medium_type"] = c_type
                            row["_tenant_info"] = tenant_info
                            all_meters.append(row)
            except Exception as e:
                _LOGGER.error("Fehler beim Abruf für Typ %s (userNum %s): %s", c_type, user_num, e)
                
        return all_meters

    async def _authenticate(self):
        url = INIT_URL
        method = "GET"
        data = None
        
        csrf_token = None
        tx_token = None

        # 1. Init URL abrufen & SAML Auto-Submit Formulare wie ein Browser auflösen
        for step in range(5):
            if method == "GET":
                async with self._session.get(url, headers=BROWSER_HEADERS) as resp:
                    html = await resp.text()
            else:
                async with self._session.post(url, data=data, headers=BROWSER_HEADERS) as resp:
                    html = await resp.text()

            # Prüfen, ob wir auf der Zielseite mit den Token angekommen sind
            csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
            tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', html)
            if csrf_match and tx_match:
                csrf_token = csrf_match.group(1)
                tx_token = tx_match.group(1)
                break
                
            # Falls nicht: Prüfen ob Azure B2C ein Auto-Submit-Formular verlangt
            action_match = re.search(r'(?is)<form[^>]+action=[\'"]([^\'"]+)[\'"]', html)
            saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
            
            if action_match and saml_match:
                url = action_match.group(1)
                relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
                
                data = {
                    "SAMLResponse": saml_match.group(1),
                    "RelayState": relay_match.group(1) if relay_match else ""
                }
                method = "POST"
                _LOGGER.debug(f"SAML Auto-Submit erkannt. Leite weiter an: {url}")
                continue
            
            # Weder Token noch Weiterleitung gefunden
            _LOGGER.error(f"SAML-Flow abgebrochen! HTTP Status: {resp.status} | Ziel-URL: {resp.url}")
            _LOGGER.error(f"HTML Auszug:\n{html[:800]}")
            raise MinolAuthError("CSRF/TX nicht gefunden und keine automatische Weiterleitung erkannt.")
            
        if not csrf_token or not tx_token:
            raise MinolAuthError("Konnte Login-Seite nach mehreren Weiterleitungen nicht erreichen.")

        # 2. Anmeldedaten posten
        auth_params = {"tx": tx_token, "p": B2C_POLICY}
        auth_data = f"request_type=RESPONSE&signInName={urllib.parse.quote(self._username)}&password={urllib.parse.quote(self._password)}"
        auth_headers = {
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "X-CSRF-TOKEN": csrf_token, 
            "X-Requested-With": "XMLHttpRequest", 
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        }

        async with self._session.post(SELF_ASSERTED_URL, params=auth_params, data=auth_data, headers=auth_headers) as resp:
            resp_text = await resp.text()
            if '"status":"400"' in resp_text:
                _LOGGER.error(f"Step 2 Fehlgeschlagen: Login von Minol/Azure abgelehnt! Server Antwort: {resp_text}")
                raise MinolAuthError(f"Login abgelehnt (Falsches Passwort?). API sagt: {resp_text}")

        # 3. SAML Token abholen
        conf_url = f"{CONFIRMED_URL}?rememberMe=false&csrf_token={csrf_token}&tx={tx_token}&p={B2C_POLICY}"
        async with self._session.get(conf_url, headers=BROWSER_HEADERS) as resp:
            conf_html = await resp.text()

        saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
        if not saml_match: 
            _LOGGER.error(f"Step 3 Fehlgeschlagen: SAML Response Token fehlt! HTML:\n{conf_html[:800]}")
            raise MinolAuthError("SAMLResponse fehlt.")
        saml_response = saml_match.group(1)
        
        relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
        relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"

        # 4. SAP ACS Auth
        acs_headers = {"User-Agent": BROWSER_HEADERS["User-Agent"]}
        await self._session.post(ACS_URL, data={"SAMLResponse": saml_response, "RelayState": relay_state}, headers=acs_headers)
        await self._session.post(APP_LOGIN_URL, data={"SAMLResponse": saml_response, "RelayState": relay_state, "saml2post": "false"}, headers=acs_headers)
        
        self._is_authenticated = True
