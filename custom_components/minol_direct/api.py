import logging, re, json
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

# Der entscheidende, bisher fehlende Endpunkt aus der HAR-Datei!
SEND_COOKIE_URL = f"{SAP_HOST}/irj/servlet/prt/portal/prtroot/com.sap.portal.usermanagement.admin.mdc"

TENANTS_URL = f"{SAP_HOST}/minol.com~kundenportal~em~web/rest/EMData/getUserTenants"
READ_DATA_URL = f"{SAP_HOST}/minol.com~kundenportal~em~web/rest/EMData/readData"

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
}

class MinolAuthError(Exception): pass
class MinolConnectionError(Exception): pass


class MinolOnlineClient:
    def __init__(self, username: str, password: str, session: ClientSession) -> None:
        self._username = username
        self._password = password
        self._session = session
        self._is_authenticated = False

    def _log_cookies(self, label: str = "") -> None:
        """Loggt den aktuellen Inhalt des Cookie-Jars für die SAP-Domain."""
        cookies = self._session.cookie_jar.filter_cookies(URL(SAP_HOST))
        names = list(cookies.keys())
        _LOGGER.debug(f"[COOKIES {label}]: {names if names else 'LEER'}")

    async def async_get_user_tenants(self) -> list[dict]:
        if not self._is_authenticated:
            await self._authenticate()

        headers = {
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        async with self._session.get(TENANTS_URL, headers=headers) as resp:
            text = await resp.text()
            _LOGGER.debug(f"[TENANTS] HTTP {resp.status} von {resp.url}")
            if resp.status == 200:
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    _LOGGER.error("[TENANTS] Kein JSON empfangen. Erster Zeileninhalt: %s", text.splitlines()[0] if text else "LEER")
            else:
                _LOGGER.error(f"[TENANTS] HTTP Fehler: {resp.status}")
        return []

    async def async_fetch_data(self) -> dict:
        if not self._is_authenticated:
            await self._authenticate()

        tenants = await self.async_get_user_tenants()
        if not tenants:
            _LOGGER.warning("Keine Tenants. Führe Re-Auth durch...")
            self._is_authenticated = False
            await self._authenticate()
            tenants = await self.async_get_user_tenants()
            if not tenants:
                raise MinolConnectionError("Keine Nutzeinheiten gefunden.")

        all_meters: list[dict] = []
        for tenant in tenants:
            user_num = tenant.get("userNumber")
            if not user_num:
                continue
            meters = await self._fetch_all_mediums(user_num, tenant)
            all_meters.extend(meters)

        return {"meters": all_meters, "fetched_at": datetime.now().isoformat()}

    async def _fetch_all_mediums(self, user_num: str, tenant_info: dict) -> list[dict]:
        all_meters: list[dict] = []
        now = datetime.now()
        start_date = f"{now.year - 1}01"
        end_date = now.strftime("%Y%m")
        cons_types = ["HZKWH", "WW", "KW"]

        headers = {
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json; charset=UTF-8",
        }

        for c_type in cons_types:
            payload = {
                "userNum": user_num, "layer": "NE", "scale": "CALMONTH",
                "chartRefUnit": "ABS", "refObject": "DIN_AVG", "consType": c_type,
                "dashBoardKey": "PE", "timelineStart": start_date, "timelineStartTxt": "",
                "timelineEnd": end_date, "timelineEndTxt": "", "valuesInKWH": True,
                "dlgKey": "100KWH",
            }
            try:
                async with self._session.post(READ_DATA_URL, json=payload, headers=headers) as resp:
                    if resp.status == 403:
                        continue
                    text = await resp.text()
                    json_resp = json.loads(text)
                    for row in json_resp.get("table", []):
                        row["_ha_medium_type"] = c_type
                        row["_tenant_info"] = tenant_info
                        all_meters.append(row)
            except Exception as e:
                _LOGGER.error(f"[readData] Fehler für Typ {c_type}: {e}")

        return all_meters

    async def _authenticate(self) -> None:
        """
        Führt den vollständigen SAML-Authentifizierungsfluss durch.
        Basiert 1:1 auf dem analysierten HAR-Traffic:
        1. Azure B2C Login-Seite abrufen
        2. Credentials senden
        3. SAMLResponse abholen
        4. SAMLResponse an SAP ACS senden
        5. Ergebnis-HTML an SAP APP_LOGIN_URL senden
        6. MDC sendCookie-Endpunkt aufrufen (DER FEHLENDE SCHRITT!)
        """
        # --- Schritt 1: Azure B2C Login-Seite ---
        _LOGGER.debug("[AUTH S1] GET %s", INIT_URL)
        async with self._session.get(INIT_URL, headers=BROWSER_HEADERS) as resp:
            html = await resp.text()
            _LOGGER.debug("[AUTH S1] HTTP %s | Set-Cookie: %s", resp.status, resp.headers.getall("Set-Cookie", []))

        # Prüfen ob Session noch aktiv (SAMLResponse direkt da)
        saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)

        if saml_match:
            _LOGGER.debug("[AUTH S1] SAMLResponse direkt erhalten (Session noch aktiv).")
            saml_response = saml_match.group(1)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"
        else:
            # --- Schritt 2: Credentials senden ---
            csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
            tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', html)
            if not csrf_match or not tx_match:
                raise MinolAuthError("CSRF/TX Token nicht gefunden.")

            csrf_token = csrf_match.group(1)
            tx_token = tx_match.group(1)
            _LOGGER.debug("[AUTH S2] CSRF: %s... TX: %s...", csrf_token[:15], tx_token[:15])
            _LOGGER.debug("[AUTH S2] POST %s", SELF_ASSERTED_URL)

            async with self._session.post(
                SELF_ASSERTED_URL,
                params={"tx": tx_token, "p": B2C_POLICY},
                data={"request_type": "RESPONSE", "signInName": self._username, "password": self._password},
                headers={"X-CSRF-TOKEN": csrf_token, "X-Requested-With": "XMLHttpRequest"},
            ) as resp:
                resp_text = await resp.text()
                _LOGGER.debug("[AUTH S2] HTTP %s", resp.status)
                if '"status":"400"' in resp_text:
                    raise MinolAuthError("Login abgelehnt (E-Mail oder Passwort falsch).")

            # --- Schritt 3: SAMLResponse abholen ---
            conf_url = f"{CONFIRMED_URL}?rememberMe=false&csrf_token={csrf_token}&tx={tx_token}&p={B2C_POLICY}"
            _LOGGER.debug("[AUTH S3] GET %s", conf_url)
            async with self._session.get(conf_url, headers=BROWSER_HEADERS) as resp:
                conf_html = await resp.text()
                _LOGGER.debug("[AUTH S3] HTTP %s", resp.status)

            saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            if not saml_match:
                raise MinolAuthError("SAMLResponse nicht gefunden.")

            saml_response = saml_match.group(1)
            relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"
            _LOGGER.debug("[AUTH S3] SAMLResponse Länge: %d | RelayState: %s", len(saml_response), relay_state)

        # --- Schritt 4: SAMLResponse an SAP ACS senden ---
        _LOGGER.debug("[AUTH S4] POST %s", ACS_URL)
        async with self._session.post(
            ACS_URL,
            data={"SAMLResponse": saml_response, "RelayState": relay_state},
            headers=BROWSER_HEADERS,
        ) as resp:
            acs_html = await resp.text()
            _LOGGER.debug("[AUTH S4] HTTP %s | Ziel-URL: %s", resp.status, resp.url)
            _LOGGER.debug("[AUTH S4] Set-Cookie: %s", resp.headers.getall("Set-Cookie", []))

        # --- Schritt 5: Ergebnis-HTML an SAP APP_LOGIN_URL senden ---
        _LOGGER.debug("[AUTH S5] POST %s", APP_LOGIN_URL)
        async with self._session.post(
            APP_LOGIN_URL,
            data={"SAMLResponse": saml_response, "saml2post": "false", "RelayState": relay_state},
            headers=BROWSER_HEADERS,
        ) as resp:
            app_html = await resp.text()
            _LOGGER.debug("[AUTH S5] HTTP %s | Ziel-URL: %s", resp.status, resp.url)
            _LOGGER.debug("[AUTH S5] Set-Cookie: %s", resp.headers.getall("Set-Cookie", []))

        # --- Schritt 6: MDC sendCookie-Endpunkt (DER FEHLENDE SCHRITT!) ---
        # SAP verteilt das MYSAPSSO2-Cookie über ein MDC-Formular im HTML.
        # Der Cookie-Wert steckt als hidden input im HTML von Schritt 5.
        # Wir extrahieren ihn und senden ihn explizit an den sendCookie-Endpunkt.
        mysap_match = re.search(r'(?i)name=[\'"]MYSAPSSO2[\'"].*?value=[\'"]([^\'"]+)[\'"]', app_html)
        if mysap_match:
            mysapsso2_value = mysap_match.group(1)
            _LOGGER.debug("[AUTH S6] MYSAPSSO2 aus HTML extrahiert (Länge: %d). Sende an sendCookie...", len(mysapsso2_value))
            _LOGGER.debug("[AUTH S6] POST %s", SEND_COOKIE_URL)

            async with self._session.post(
                SEND_COOKIE_URL,
                data={"com.sap.portal.mdc.action": "sendCookie", "MYSAPSSO2": mysapsso2_value},
                headers=BROWSER_HEADERS,
            ) as resp:
                _LOGGER.debug("[AUTH S6] HTTP %s | Ziel-URL: %s", resp.status, resp.url)
                _LOGGER.debug("[AUTH S6] Set-Cookie: %s", resp.headers.getall("Set-Cookie", []))
        else:
            _LOGGER.warning("[AUTH S6] MYSAPSSO2 nicht im App-Login HTML gefunden! Cookie wurde möglicherweise via Set-Cookie Header gesetzt.")

        self._log_cookies(label="NACH LOGIN")

        # Finale Prüfung
        cookies = self._session.cookie_jar.filter_cookies(URL(SAP_HOST))
        if "MYSAPSSO2" not in cookies:
            _LOGGER.warning("[AUTH] MYSAPSSO2 Cookie fehlt nach komplettem Login-Flow!")
        else:
            _LOGGER.debug("[AUTH] Login erfolgreich! MYSAPSSO2 Cookie vorhanden.")

        self._is_authenticated = True
