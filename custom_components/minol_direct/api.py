import logging, re, urllib.parse, json
from datetime import datetime
from aiohttp import ClientSession
from yarl import URL

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
            
        headers = {
            "User-Agent": BROWSER_HEADERS["User-Agent"], 
            "X-Requested-With": "XMLHttpRequest", 
            "Accept": "application/json, text/javascript, */*; q=0.01"
        }
        
        async with self._session.get(TENANTS_URL, headers=headers) as resp:
            text = await resp.text()
            if resp.status == 200:
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    _LOGGER.error(f"API lieferte kein gültiges JSON für Tenants. Status: {resp.status}")
                    _LOGGER.debug(f"HTML Antwort:\n{text[:1000]}")
            else:
                _LOGGER.error(f"Fehler beim Abruf der Tenants: HTTP {resp.status}")
        return []

    async def async_fetch_data(self):
        if not self._is_authenticated:
            await self._authenticate()
            
        tenants = await self.async_get_user_tenants()
        if not tenants:
            _LOGGER.debug("Re-Auth Versuch, da keine Tenants gefunden wurden.")
            self._is_authenticated = False
            await self._authenticate()
            tenants = await self.async_get_user_tenants()
            if not tenants:
                raise MinolConnectionError("Keine Nutzeinheiten (Tenants) gefunden.")

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
                    if resp.status == 403: continue 
                    text = await resp.text()
                    try:
                        json_resp = json.loads(text)
                        if "table" in json_resp:
                            for row in json_resp["table"]:
                                row["_ha_medium_type"] = c_type
                                row["_tenant_info"] = tenant_info
                                all_meters.append(row)
                    except json.JSONDecodeError:
                        _LOGGER.error(f"Kein gültiges JSON für Typ {c_type}.")
            except Exception as e:
                _LOGGER.error(f"Fehler beim Abruf für Typ {c_type}: {e}")
                
        return all_meters

    def _extract_and_set_sap_cookie(self, html):
        """Sucht im HTML nach dem versteckten SAP Cookie und setzt es manuell im CookieJar."""
        match = re.search(r'(?i)name=[\'"]MYSAPSSO2[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        if match:
            cookie_value = match.group(1)
            # Cookie manuell in die aiohttp Session injizieren!
            self._session.cookie_jar.update_cookies({"MYSAPSSO2": cookie_value}, URL(SAP_HOST))
            _LOGGER.debug("Erfolg! MYSAPSSO2 Cookie manuell aus HTML extrahiert und gesetzt.")
            return True
        return False

    async def _authenticate(self):
        _LOGGER.debug("Schritt 1: Initialisiere SAML Flow...")
        async with self._session.get(INIT_URL, headers=BROWSER_HEADERS) as resp:
            html = await resp.text()

        saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        
        if saml_match:
            saml_response = saml_match.group(1)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"
        else:
            csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
            tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', html)
            
            if not csrf_match or not tx_match: 
                raise MinolAuthError("Fehler: Konnte CSRF-Token oder TX-State nicht finden.")
            
            csrf_token, tx_token = csrf_match.group(1), tx_match.group(1)

            _LOGGER.debug("Schritt 2: Sende Credentials an Azure B2C...")
            auth_params = {"tx": tx_token, "p": B2C_POLICY}
            
            auth_data = {
                "request_type": "RESPONSE",
                "signInName": self._username,
                "password": self._password
            }
            auth_headers = {
                "X-CSRF-TOKEN": csrf_token, 
                "X-Requested-With": "XMLHttpRequest"
            }

            async with self._session.post(SELF_ASSERTED_URL, params=auth_params, data=auth_data, headers=auth_headers) as resp:
                resp_text = await resp.text()
                if '"status":"400"' in resp_text or '"status": "400"' in resp_text:
                    raise MinolAuthError("Login fehlgeschlagen! E-Mail oder Passwort falsch.")

            _LOGGER.debug("Schritt 3: Hole SAML-Ticket ab...")
            conf_url = f"{CONFIRMED_URL}?rememberMe=false&csrf_token={csrf_token}&tx={tx_token}&p={B2C_POLICY}"
            async with self._session.get(conf_url, headers=BROWSER_HEADERS) as resp:
                conf_html = await resp.text()

            saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            if not saml_match: 
                raise MinolAuthError("Fehler: Konnte SAMLResponse nicht aus dem HTML extrahieren.")
            
            saml_response = saml_match.group(1)
            relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"

        _LOGGER.debug("Schritt 4: Übergebe SAML-Ticket an SAP (ACS & APP LOGIN)...")
        
        acs_data = {"SAMLResponse": saml_response, "RelayState": relay_state}
        async with self._session.post(ACS_URL, data=acs_data, headers=BROWSER_HEADERS) as resp:
            acs_html = await resp.text()
            self._extract_and_set_sap_cookie(acs_html)
            
        app_data = {"SAMLResponse": saml_response, "saml2post": "false", "RelayState": relay_state}
        async with self._session.post(APP_LOGIN_URL, data=app_data, headers=BROWSER_HEADERS) as resp:
            app_html = await resp.text()
            self._extract_and_set_sap_cookie(app_html)

        _LOGGER.debug("Login Flow abgeschlossen. Session bereit für API Calls.")
        self._is_authenticated = True
