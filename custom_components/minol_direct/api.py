import logging, re, urllib.parse, json, asyncio, random
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

TENANTS_URL = f"{SAP_HOST}/minol.com~kundenportal~em~web/rest/EMData/getUserTenants"
READ_DATA_URL = f"{SAP_HOST}/minol.com~kundenportal~em~web/rest/EMData/readData"

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
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
            
        await asyncio.sleep(random.uniform(0.3, 0.7))
            
        headers = {
            "User-Agent": BROWSER_HEADERS["User-Agent"], 
            "X-Requested-With": "XMLHttpRequest", 
            "Accept": "application/json"
        }
        
        async with self._session.get(TENANTS_URL, headers=headers) as resp:
            text = await resp.text()
            if resp.status == 200:
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    _LOGGER.error(f"API lieferte kein gültiges JSON für Tenants. URL: {resp.url} | Status: {resp.status}")
                    _LOGGER.error(f"KOMPLETTER HTML QUELLTEXT DER ANTWORT:\n{text}")
            else:
                _LOGGER.error(f"Fehler beim Abruf der Tenants: HTTP {resp.status}.")
                _LOGGER.error(f"KOMPLETTER HTML QUELLTEXT DER ANTWORT:\n{text}")
        return []

    async def async_fetch_data(self):
        if not self._is_authenticated:
            await self._authenticate()
            
        tenants = await self.async_get_user_tenants()
        if not tenants:
            # Token möglicherweise abgelaufen -> Re-Auth
            self._is_authenticated = False
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
            await asyncio.sleep(random.uniform(0.2, 0.6))
            payload = {
                "userNum": user_num, "layer": "NE", "scale": "CALMONTH", "chartRefUnit": "ABS",
                "refObject": "DIN_AVG", "consType": c_type, "dashBoardKey": "PE",
                "timelineStart": start_date, "timelineStartTxt": "", "timelineEnd": end_date,
                "timelineEndTxt": "", "valuesInKWH": True, "dlgKey": "100KWH"
            }
            try:
                async with self._session.post(READ_DATA_URL, json=payload, headers=headers) as resp:
                    text = await resp.text()
                    if resp.status == 403: continue 
                    try:
                        json_resp = json.loads(text)
                        if "table" in json_resp:
                            for row in json_resp["table"]:
                                row["_ha_medium_type"] = c_type
                                row["_tenant_info"] = tenant_info
                                all_meters.append(row)
                    except json.JSONDecodeError:
                        _LOGGER.error(f"Kein gültiges JSON für Typ {c_type} (userNum {user_num}). Kompletter Text:\n{text}")
            except Exception as e:
                _LOGGER.error(f"Fehler beim Abruf für Typ {c_type} (userNum {user_num}): {e}")
                
        return all_meters

    async def _authenticate(self):
        # 1. Start URL abrufen
        async with self._session.get(INIT_URL, headers=BROWSER_HEADERS) as resp:
            html = await resp.text()

        saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        
        if saml_match:
            _LOGGER.debug("Auto-Submit Formular erkannt! Überspringe Azure Login.")
            saml_response = saml_match.group(1)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"
            
        else:
            # 2. Azure B2C Login
            csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
            tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', html)
            
            if not csrf_match or not tx_match: 
                raise MinolAuthError("SAML Flow fehlgeschlagen: CSRF/TX nicht gefunden.")
            
            csrf_token, tx_token = csrf_match.group(1), tx_match.group(1)
            await asyncio.sleep(random.uniform(0.8, 1.8))

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
                    raise MinolAuthError("Login abgelehnt (Falsches Passwort).")

            await asyncio.sleep(random.uniform(0.2, 0.6))
            conf_url = f"{CONFIRMED_URL}?rememberMe=false&csrf_token={csrf_token}&tx={tx_token}&p={B2C_POLICY}"
            async with self._session.get(conf_url, headers=BROWSER_HEADERS) as resp:
                conf_html = await resp.text()

            saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            if not saml_match: 
                raise MinolAuthError("SAMLResponse fehlt im Confirmed-Endpoint.")
            
            saml_response = saml_match.group(1)
            relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"

        # 3. SAP Login-Sequenz simulieren
        await asyncio.sleep(random.uniform(0.1, 0.3))
        acs_headers = {"User-Agent": BROWSER_HEADERS["User-Agent"]}
        
        # Sende Ticket an ACS. SAP antwortet hier meist mit einem Formular, das an die App weiterleitet.
        async with self._session.post(ACS_URL, data={"SAMLResponse": saml_response, "RelayState": relay_state}, headers=acs_headers) as resp:
            acs_html = await resp.text()
            
        app_action_match = re.search(r'(?is)<form[^>]+action=[\'"]([^\'"]+)[\'"]', acs_html)
        if app_action_match:
            app_url = app_action_match.group(1)
            if app_url.startswith("/"): app_url = SAP_HOST + app_url
            
            # Formularfelder extrahieren
            app_data = {}
            for field in ["SAMLResponse", "RelayState", "saml2post"]:
                f_match = re.search(rf'(?is)name=[\'"]{field}[\'"].*?value=[\'"]([^\'"]+)[\'"]', acs_html)
                if f_match: app_data[field] = f_match.group(1)
                
            await asyncio.sleep(random.uniform(0.2, 0.5))
            # Ticket an finale App senden
            async with self._session.post(app_url, data=app_data, headers=acs_headers) as app_resp:
                app_html = await app_resp.text()
                
                # PRÜFUNG AUF META-REFRESH (Hier war vorher der Hänger!)
                refresh_match = re.search(r'(?is)content=[\'"]\d+;\s*url=([^\'"]+)[\'"]', app_html, re.IGNORECASE)
                if refresh_match:
                    next_url = refresh_match.group(1).replace("&#x3d;", "=").replace("&amp;", "&")
                    if next_url.startswith("/"): next_url = SAP_HOST + next_url
                    _LOGGER.debug(f"Folge HTML Meta-Refresh zu: {next_url}")
                    await asyncio.sleep(random.uniform(0.2, 0.5))
                    await self._session.get(next_url, headers=BROWSER_HEADERS)

        # Überprüfe, ob SAP uns den ersehnten Session-Cookie ausgestellt hat
        cookies = self._session.cookie_jar.filter_cookies(SAP_HOST)
        if "MYSAPSSO2" in cookies:
            _LOGGER.debug("SAML Login erfolgreich, SAP Session-Cookie (MYSAPSSO2) wurde gesetzt.")
        else:
            _LOGGER.warning("WARNUNG: MYSAPSSO2 Cookie fehlt nach dem SAML Login. API Aufrufe könnten fehlschlagen!")

        self._is_authenticated = True
