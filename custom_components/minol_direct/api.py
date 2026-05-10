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

    def _dump_cookie_jar(self, label: str) -> None:
        """Gibt den KOMPLETTEN Inhalt des Cookie-Jars aus."""
        all_cookies = list(self._session.cookie_jar)
        if not all_cookies:
            _LOGGER.debug("[COOKIES %s] Cookie-Jar ist LEER", label)
            return
        _LOGGER.debug("[COOKIES %s] Alle %d Cookies im Jar:", label, len(all_cookies))
        for cookie in all_cookies:
            _LOGGER.debug(
                "  -> Name: %-20s | Domain: %-35s | Pfad: %s",
                cookie.key,
                cookie.get("domain", "?"),
                cookie.get("path", "/"),
            )

    async def _request(self, method: str, url: str, label: str, **kwargs) -> tuple[int, dict, str]:
        """
        Führt einen HTTP-Request OHNE automatischen Redirect aus.
        Gibt (status, headers, body) zurück.
        """
        kwargs["allow_redirects"] = False
        _LOGGER.debug("[%s] %s %s", label, method.upper(), url)
        if "data" in kwargs:
            safe = {k: ("***" if k.lower() == "password" else v) for k, v in kwargs["data"].items()}
            _LOGGER.debug("[%s] Payload: %s", label, safe)
        if "headers" in kwargs:
            _LOGGER.debug("[%s] Extra-Header: %s", label, kwargs["headers"])

        async with self._session.request(method, url, **kwargs) as resp:
            body = await resp.text()
            set_cookies = resp.headers.getall("Set-Cookie", [])
            location = resp.headers.get("Location", "")
            _LOGGER.debug(
                "[%s] → HTTP %s | Location: %s | Set-Cookie Count: %d",
                label, resp.status, location or "–", len(set_cookies),
            )
            for sc in set_cookies:
                _LOGGER.debug("[%s] Set-Cookie: %s", label, sc)
            return resp.status, dict(resp.headers), body

    async def _follow_redirects(self, start_url: str, method: str, label: str, **kwargs) -> str:
        """
        Folgt einer Redirect-Kette manuell, Schritt für Schritt.
        Protokolliert jeden Zwischenschritt inkl. Set-Cookie Header.
        Gibt den finalen HTML-Body zurück.
        """
        url = start_url
        current_method = method
        current_kwargs = kwargs
        max_hops = 10

        for hop in range(max_hops):
            status, headers, body = await self._request(current_method, url, f"{label} Hop{hop+1}", **current_kwargs)

            if status in (301, 302, 303, 307, 308):
                location = headers.get("Location", "")
                if not location:
                    _LOGGER.warning("[%s] Redirect ohne Location-Header!", label)
                    return body
                # Relative URLs auflösen
                if location.startswith("/"):
                    location = SAP_HOST + location
                _LOGGER.debug("[%s] Redirect %s → %s", label, status, location)
                # 302/303 erzwingen GET (wie Browser es tun)
                if status in (302, 303):
                    current_method = "GET"
                    current_kwargs = {"headers": BROWSER_HEADERS}
                url = location
                continue
            else:
                # Kein Redirect mehr → fertig
                return body

        _LOGGER.warning("[%s] Maximale Redirect-Tiefe erreicht!", label)
        return body

    async def async_get_user_tenants(self) -> list[dict]:
        if not self._is_authenticated:
            await self._authenticate()

        headers = {
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        _LOGGER.debug("[TENANTS] GET %s", TENANTS_URL)
        self._dump_cookie_jar("VOR TENANTS-CALL")

        # Tenants-API nutzt allow_redirects=True (normaler GET-Call)
        async with self._session.get(TENANTS_URL, headers=headers) as resp:
            text = await resp.text()
            _LOGGER.debug("[TENANTS] HTTP %s | Content-Type: %s", resp.status, resp.headers.get("Content-Type", "?"))
            if resp.status == 200:
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    _LOGGER.error("[TENANTS] Kein JSON empfangen!")
                    _LOGGER.debug("[TENANTS] Erste 500 Zeichen der Antwort:\n%s", text[:500])
            else:
                _LOGGER.error("[TENANTS] HTTP Fehler: %s", resp.status)
        return []

    async def async_fetch_data(self) -> dict:
        if not self._is_authenticated:
            await self._authenticate()

        tenants = await self.async_get_user_tenants()
        if not tenants:
            _LOGGER.warning("[FETCH] Keine Tenants. Re-Auth...")
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
                "userNum": user_num, "layer": "NE", "scale": "CALMONTH", "chartRefUnit": "ABS",
                "refObject": "DIN_AVG", "consType": c_type, "dashBoardKey": "PE",
                "timelineStart": start_date, "timelineStartTxt": "", "timelineEnd": end_date,
                "timelineEndTxt": "", "valuesInKWH": True, "dlgKey": "100KWH",
            }
            try:
                async with self._session.post(READ_DATA_URL, json=payload, headers=headers) as resp:
                    if resp.status == 403:
                        continue
                    text = await resp.text()
                    for row in json.loads(text).get("table", []):
                        row["_ha_medium_type"] = c_type
                        row["_tenant_info"] = tenant_info
                        all_meters.append(row)
            except Exception as e:
                _LOGGER.error("[readData] Fehler für Typ %s: %s", c_type, e)
        return all_meters

    async def _authenticate(self) -> None:
        _LOGGER.debug("=" * 60)
        _LOGGER.debug("=== STARTE AUTHENTICATION FLOW ===")
        _LOGGER.debug("=" * 60)

        # === SCHRITT 1: Azure B2C Login-Seite ===
        status, headers, html = await self._request("GET", INIT_URL, "S1-INIT", headers=BROWSER_HEADERS)
        self._dump_cookie_jar("NACH S1")

        saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)

        if saml_match:
            _LOGGER.debug("[S1-INIT] SAMLResponse direkt da (Session noch aktiv).")
            saml_response = saml_match.group(1)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"
        else:
            csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
            tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', html)
            if not csrf_match or not tx_match:
                _LOGGER.error("[S1-INIT] HTML (erste 500 Zeichen):\n%s", html[:500])
                raise MinolAuthError("CSRF/TX Token nicht gefunden.")
            csrf_token, tx_token = csrf_match.group(1), tx_match.group(1)
            _LOGGER.debug("[S1-INIT] CSRF: %s... TX: %s...", csrf_token[:15], tx_token[:15])

            # === SCHRITT 2: Credentials senden ===
            status, headers, body = await self._request(
                "POST",
                SELF_ASSERTED_URL,
                "S2-LOGIN",
                params={"tx": tx_token, "p": B2C_POLICY},
                data={"request_type": "RESPONSE", "signInName": self._username, "password": self._password},
                headers={"X-CSRF-TOKEN": csrf_token, "X-Requested-With": "XMLHttpRequest"},
            )
            self._dump_cookie_jar("NACH S2")
            if '"status":"400"' in body:
                raise MinolAuthError("Login abgelehnt (E-Mail oder Passwort falsch).")

            # === SCHRITT 3: SAMLResponse abholen ===
            conf_url = f"{CONFIRMED_URL}?rememberMe=false&csrf_token={csrf_token}&tx={tx_token}&p={B2C_POLICY}"
            status, headers, conf_html = await self._request("GET", conf_url, "S3-CONFIRMED", headers=BROWSER_HEADERS)
            self._dump_cookie_jar("NACH S3")

            saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            if not saml_match:
                _LOGGER.error("[S3-CONFIRMED] SAMLResponse fehlt. HTML:\n%s", conf_html[:800])
                raise MinolAuthError("SAMLResponse fehlt.")
            saml_response = saml_match.group(1)
            relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"
            _LOGGER.debug("[S3-CONFIRMED] SAMLResponse: %d Zeichen | RelayState: %s", len(saml_response), relay_state)

        # === SCHRITT 4: SAMLResponse an SAP ACS senden (MANUELLER REDIRECT) ===
        _LOGGER.debug("--- Starte manuelle Redirect-Kette ab ACS ---")
        acs_body = await self._follow_redirects(
            ACS_URL,
            "POST",
            "S4-ACS",
            data={"SAMLResponse": saml_response, "RelayState": relay_state},
            headers=BROWSER_HEADERS,
        )
        self._dump_cookie_jar("NACH S4 (nach allen Redirects)")

        # Prüfen ob SAP das SAMLResponse nochmal weiterleiten will
        form_action_match = re.search(r'(?is)<form[^>]+action=[\'"]([^\'"]+)[\'"]', acs_body)
        inner_saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', acs_body)
        if form_action_match and inner_saml_match:
            next_action = form_action_match.group(1)
            if next_action.startswith("/"): next_action = SAP_HOST + next_action
            next_saml = inner_saml_match.group(1)
            next_relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', acs_body)
            next_relay = next_relay_match.group(1) if next_relay_match else relay_state
            _LOGGER.debug("[S4-ACS] SAP will weiteres Formular senden an: %s", next_action)

            # === SCHRITT 5: App-Login (MANUELLER REDIRECT) ===
            app_body = await self._follow_redirects(
                next_action,
                "POST",
                "S5-APPLOGIN",
                data={"SAMLResponse": next_saml, "RelayState": next_relay, "saml2post": "false"},
                headers=BROWSER_HEADERS,
            )
            self._dump_cookie_jar("NACH S5 (nach allen Redirects)")
        else:
            _LOGGER.debug("[S4-ACS] Kein weiteres SAP-Formular im ACS-Body. Body-Auszug:\n%s", acs_body[:300])

        _LOGGER.debug("=" * 60)
        _LOGGER.debug("=== AUTHENTICATION FLOW ABGESCHLOSSEN ===")
        self._dump_cookie_jar("FINAL")

        # Prüfung auf MYSAPSSO2
        all_cookies = {c.key for c in self._session.cookie_jar}
        if "MYSAPSSO2" in all_cookies:
            _LOGGER.debug("[AUTH] MYSAPSSO2 Cookie erfolgreich gesetzt!")
        else:
            _LOGGER.warning("[AUTH] MYSAPSSO2 Cookie fehlt. API-Calls werden wahrscheinlich fehlschlagen.")

        self._is_authenticated = True
