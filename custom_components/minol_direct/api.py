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

#Tenant-API
TENANTS_URL = f"{SAP_HOST}/minol.com~kundenportal~em~web/rest/EMData/getUserTenants"
READ_DATA_URL = f"{SAP_HOST}/minol.com~kundenportal~em~web/rest/EMData/readData"

class MinolAuthError(Exception): pass
class MinolConnectionError(Exception): pass

class MinolOnlineClient:
    def __init__(self, username, password, session: ClientSession):
        self._username = username
        self._password = password
        self._session = session
        self._is_authenticated = False

    async def async_get_user_tenants(self):
        """Authentifiziert und holt die Liste aller Nutzeinheiten/Wohnungen des Benutzers."""
        if not self._is_authenticated:
            await self._authenticate()
            
        headers = {
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
        """Holt die Zählerstände für alle gefundenen Wohnungen."""
        if not self._is_authenticated:
            await self._authenticate()
            
        tenants = await self.async_get_user_tenants()
        if not tenants:
            # Fallback: Erneuter Auth-Versuch bei Cookie-Ablauf
            await self._authenticate()
            tenants = await self.async_get_user_tenants()
            if not tenants:
                raise MinolConnectionError("Datenabruf fehlgeschlagen. Keine Nutzeinheiten (Wohnungen) gefunden.")

        all_meters = []
        for tenant in tenants:
            user_num = tenant.get("userNumber")
            if not user_num:
                continue
            
            meters = await self._fetch_all_mediums(user_num, tenant)
            if meters:
                all_meters.extend(meters)

        return {"meters": all_meters, "fetched_at": datetime.now().isoformat()}

    async def _fetch_all_mediums(self, user_num, tenant_info):
        """Holt die Zählerdaten (Heizung, WW, KW) für eine spezifische Kundennummer."""
        all_meters = []
        now = datetime.now()
        start_date = f"{now.year - 1}01"
        end_date = now.strftime("%Y%m")
        cons_types = ["HZKWH", "WW", "KW"] 

        headers = {
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
                            row["_tenant_info"] = tenant_info # Wohnungsdaten für Sensor-Attribute anhängen
                            all_meters.append(row)
            except Exception as e:
                _LOGGER.error("Fehler beim Abruf für Typ %s (userNum %s): %s", c_type, user_num, e)
                
        return all_meters

    async def _authenticate(self):
        async with self._session.get(INIT_URL) as resp:
            html = await resp.text()

        csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
        tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', html)
        if not csrf_match or not tx_match: 
            raise MinolAuthError("CSRF/TX nicht gefunden.")
        
        csrf_token, tx_token = csrf_match.group(1), tx_match.group(1)

        auth_params = {"tx": tx_token, "p": B2C_POLICY}
        auth_data = f"request_type=RESPONSE&signInName={urllib.parse.quote(self._username)}&password={urllib.parse.quote(self._password)}"
        auth_headers = {
            "X-CSRF-TOKEN": csrf_token, 
            "X-Requested-With": "XMLHttpRequest", 
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        }

        async with self._session.post(SELF_ASSERTED_URL, params=auth_params, data=auth_data, headers=auth_headers) as resp:
            if '"status":"400"' in await resp.text(): 
                raise MinolAuthError("Login abgelehnt.")

        conf_url = f"{CONFIRMED_URL}?rememberMe=false&csrf_token={csrf_token}&tx={tx_token}&p={B2C_POLICY}"
        async with self._session.get(conf_url) as resp:
            conf_html = await resp.text()

        saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
        if not saml_match: 
            raise MinolAuthError("SAMLResponse fehlt.")
        saml_response = saml_match.group(1)
        
        relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
        relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"

        await self._session.post(ACS_URL, data={"SAMLResponse": saml_response, "RelayState": relay_state})
        await self._session.post(APP_LOGIN_URL, data={"SAMLResponse": saml_response, "RelayState": relay_state, "saml2post": "false"})
        self._is_authenticated = True
