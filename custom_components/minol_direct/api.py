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
        all_cookies = list(self._session.cookie_jar)
        if not all_cookies:
            _LOGGER.debug("[COOKIES %s] Cookie-Jar ist LEER", label)
            return
        _LOGGER.debug("[COOKIES %s] %d Cookies im Jar:", label, len(all_cookies))
        for cookie in all_cookies:
            _LOGGER.debug(
                "  -> %-20s | Domain: %-35s | Pfad: %s",
                cookie.key,
                cookie.get("domain", "?"),
                cookie.get("path", "/"),
            )

    async def _post_no_redirect(self, url: str, label: str, **kwargs) -> tuple[int, dict, str]:
        """POST ohne automatischen Redirect - gibt (status, headers, body) zurück."""
        _LOGGER.debug("[%s] POST %s", label, url)
        if "data" in kwargs:
            safe = {k: ("***" if k.lower() == "password" else v) for k, v in kwargs["data"].items()}
            _LOGGER.debug("[%s] Payload: %s", label, safe)

        async with self._session.post(url, allow_redirects=False, **kwargs) as resp:
            body = await resp.text()
            location = resp.headers.get("Location", "")
            set_cookies = resp.headers.getall("Set-Cookie", [])
            _LOGGER.debug(
                "[%s] → HTTP %s | Location: %s | Set-Cookie Count: %d",
                label, resp.status, location or "–", len(set_cookies),
            )
            for sc in set_cookies:
                _LOGGER.debug("[%s] Set-Cookie: %s", label, sc)
            return resp.status, dict(resp.headers), body

    async def _follow_redirects_from_post(self, start_url: str, label: str, post_data: dict) -> str:
        """
        Führt einen POST aus, folgt dann allen Redirects manuell
        und gibt den finalen HTML-Body zurück.
        """
        # Erster Request: POST
        status, headers, body = await self._post_no_redirect(
            start_url, f"{label} POST",
            data=post_data,
            headers=BROWSER_HEADERS,
        )

        url = headers.get("Location", "")
        hop = 0
        max_hops = 10

        while url and status in (301, 302, 303, 307, 308) and hop < max_hops:
            hop += 1
            # Relative URLs auflösen
            if url.startswith("/"):
                url = SAP_HOST + url

            _LOGGER.debug("[%s Hop%d] GET %s", label, hop, url)
            async with self._session.get(url, headers=BROWSER_HEADERS, allow_redirects=False) as resp:
                body = await resp.text()
                status = resp.status
                set_cookies = resp.headers.getall("Set-Cookie", [])
                url = resp.headers.get("Location", "")
                _LOGGER.debug(
                    "[%s Hop%d] → HTTP %s | Next-Location: %s | Set-Cookie Count: %d",
                    label, hop, status, url or "–", len(set_cookies),
                )
                for sc in set_cookies:
                    _LOGGER.debug("[%s Hop%d] Set-Cookie: %s", label, hop, sc)

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
        self._dump_cookie_jar("VOR TENANTS")

        async with self._session.get(TENANTS_URL, headers=headers) as resp:
            text = await resp.text()
            _LOGGER.debug("[TENANTS] HTTP %s | Content-Type: %s", resp.status, resp.headers.get("Content-Type", "?"))
            if resp.status == 200:
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    _LOGGER.error("[TENANTS] Kein JSON empfangen!")
                    _LOGGER.debug("[TENANTS] Erste 300 Zeichen:\n%s", text[:300])
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

        # === SCHRITT 1: INIT_URL abrufen MIT automatischem Redirect ===
        # SAP leitet via 302 nach Azure B2C weiter.
        # allow_redirects=True folgt dieser Weiterleitung automatisch!
        _LOGGER.debug("[S1-INIT] GET %s (allow_redirects=True)", INIT_URL)
        async with self._session.get(INIT_URL, headers=BROWSER_HEADERS, allow_redirects=True) as resp:
            html = await resp.text()
            _LOGGER.debug("[S1-INIT] Final-URL: %s | HTTP %s", resp.url, resp.status)
            _LOGGER.debug("[S1-INIT] Set-Cookie: %s", resp.headers.getall("Set-Cookie", []))
        self._dump_cookie_jar("NACH S1")

        # Prüfen ob Session noch aktiv (SAMLResponse direkt da)
        saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)

        if saml_match:
            _LOGGER.debug("[S1-INIT] SAMLResponse direkt da (Session noch aktiv).")
            saml_response = saml_match.group(1)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"

        else:
            # === SCHRITT 2: CSRF + TX aus Azure B2C Login-Seite extrahieren ===
            csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
            tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', html)

            if not csrf_match or not tx_match:
                _LOGGER.error("[S2] CSRF/TX nicht gefunden. HTML (erste 500 Zeichen):\n%s", html[:500])
                raise MinolAuthError("CSRF/TX Token nicht gefunden.")

            csrf_token = csrf_match.group(1)
            tx_token = tx_match.group(1)
            _LOGGER.debug("[S2] CSRF: %s... | TX: %s...", csrf_token[:15], tx_token[:15])

            # === SCHRITT 2: Credentials an Azure B2C senden ===
            _LOGGER.debug("[S2-LOGIN] POST %s", SELF_ASSERTED_URL)
            async with self._session.post(
                SELF_ASSERTED_URL,
                params={"tx": tx_token, "p": B2C_POLICY},
                data={"request_type": "RESPONSE", "signInName": self._username, "password": self._password},
                headers={"X-CSRF-TOKEN": csrf_token, "X-Requested-With": "XMLHttpRequest"},
                allow_redirects=False,
            ) as resp:
                body = await resp.text()
                _LOGGER.debug("[S2-LOGIN] HTTP %s", resp.status)
                if '"status":"400"' in body:
                    _LOGGER.error("[S2-LOGIN] Login abgelehnt! Azure Antwort: %s", body)
                    raise MinolAuthError("Login abgelehnt (E-Mail oder Passwort falsch).")
            self._dump_cookie_jar("NACH S2")

            # === SCHRITT 3: SAMLResponse vom Confirmed-Endpoint ===
            conf_url = (
                f"{CONFIRMED_URL}?rememberMe=false"
                f"&csrf_token={csrf_token}&tx={tx_token}&p={B2C_POLICY}"
            )
            _LOGGER.debug("[S3-CONFIRMED] GET %s", conf_url)
            async with self._session.get(conf_url, headers=BROWSER_HEADERS, allow_redirects=True) as resp:
                conf_html = await resp.text()
                _LOGGER.debug("[S3-CONFIRMED] HTTP %s | Final-URL: %s", resp.status, resp.url)
            self._dump_cookie_jar("NACH S3")

            saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            if not saml_match:
                _LOGGER.error("[S3-CONFIRMED] SAMLResponse fehlt. HTML:\n%s", conf_html[:800])
                raise MinolAuthError("SAMLResponse fehlt.")

            saml_response = saml_match.group(1)
            relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', conf_html)
            relay_state = relay_match.group(1) if relay_match else "ouccprfhrffau"
            _LOGGER.debug("[S3-CONFIRMED] SAMLResponse: %d Zeichen | RelayState: %s", len(saml_response), relay_state)

        # === SCHRITT 4: SAMLResponse an SAP ACS - MANUELLE REDIRECTS ===
        _LOGGER.debug("[S4-ACS] Starte POST + manuelle Redirect-Kette...")
        acs_body = await self._follow_redirects_from_post(
            ACS_URL,
            "S4-ACS",
            post_data={"SAMLResponse": saml_response, "RelayState": relay_state},
        )
        self._dump_cookie_jar("NACH S4")

        # Prüfen ob SAP nochmals ein Formular mit SAMLResponse liefert
        form_action_match = re.search(r'(?is)<form[^>]+action=[\'"]([^\'"]+)[\'"]', acs_body)
        inner_saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', acs_body)

        if form_action_match and inner_saml_match:
            next_action = form_action_match.group(1)
            if next_action.startswith("/"):
                next_action = SAP_HOST + next_action
            next_saml = inner_saml_match.group(1)
            next_relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', acs_body)
            next_relay = next_relay_match.group(1) if next_relay_match else relay_state
            saml2post_match = re.search(r'(?is)name=[\'"]saml2post[\'"].*?value=[\'"]([^\'"]+)[\'"]', acs_body)
            saml2post = saml2post_match.group(1) if saml2post_match else "false"

            _LOGGER.debug("[S5-APPLOGIN] SAP will weiteres Formular an: %s", next_action)

            # === SCHRITT 5: App-Login - MANUELLE REDIRECTS ===
            app_body = await self._follow_redirects_from_post(
                next_action,
                "S5-APPLOGIN",
                post_data={"SAMLResponse": next_saml, "RelayState": next_relay, "saml2post": saml2post},
            )
            self._dump_cookie_jar("NACH S5")
        else:
            _LOGGER.debug("[S4-ACS] Kein weiteres SAP-Formular im ACS-Body.")

        _LOGGER.debug("=" * 60)
        _LOGGER.debug("=== AUTHENTICATION FLOW ABGESCHLOSSEN ===")
        self._dump_cookie_jar("FINAL")

        all_cookie_names = {c.key for c in self._session.cookie_jar}
        if "MYSAPSSO2" in all_cookie_names:
            _LOGGER.debug("[AUTH] MYSAPSSO2 Cookie erfolgreich gesetzt!")
        else:
            _LOGGER.warning("[AUTH] MYSAPSSO2 Cookie fehlt nach Login!")

        self._is_authenticated = True
