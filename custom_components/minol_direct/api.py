"""Minol Online API Client für Home Assistant.

Nutzt requests.Session (statt aiohttp) weil aiohttp bei Azure B2C SelfAsserted POSTs
einen HTTP 400 produziert, während requests problemlos funktioniert.
Alle HTTP-Calls werden via asyncio.to_thread() ausgeführt für HA-Kompatibilität.
"""
import asyncio, logging, re, json, base64, urllib.parse, requests
from datetime import datetime

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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
}


class MinolAuthError(Exception):
    pass


class MinolConnectionError(Exception):
    pass


class MinolOnlineClient:
    """Async-kompatibler Minol API Client (nutzt requests intern via asyncio.to_thread)."""

    def __init__(self, username: str, password: str, session: requests.Session | None = None) -> None:
        self._username = username
        self._password = password
        self._session = session or requests.Session()
        self._session.headers.update(BROWSER_HEADERS)
        self._is_authenticated = False

    def _dump_cookies(self, label: str) -> None:
        """Gibt alle Cookies der Session aus."""
        cookies = self._session.cookies
        if not cookies:
            _LOGGER.debug("[COOKIES %s] Leer", label)
            return
        _LOGGER.debug("[COOKIES %s] %d Cookies:", label, len(cookies))
        for c in cookies:
            _LOGGER.debug(
                "  -> %-20s | Domain: %-35s | Pfad: %s",
                c.name, c.domain or "?", c.path or "/",
            )

    def _is_saml_success(self, saml_response_b64: str) -> bool:
        """Prüft ob eine Base64-kodierte SAMLResponse erfolgreich ist."""
        try:
            xml = base64.b64decode(saml_response_b64 + "==").decode("utf-8", errors="ignore")
            if "status:Success" in xml:
                return True
            if "status:Requester" in xml or "status:Responder" in xml or "Invalid" in xml:
                _LOGGER.warning("[SAML] SAMLResponse enthält Fehler-Status!")
                msg_match = re.search(r"<[^>]*StatusMessage[^>]*>([^<]+)<", xml)
                if msg_match:
                    _LOGGER.warning("[SAML] StatusMessage: %s", msg_match.group(1))
                return False
        except Exception as e:
            _LOGGER.debug("[SAML] Konnte SAMLResponse nicht dekodieren: %s", e)
        return False

    def _follow_redirects_from_post(self, start_url: str, label: str, post_data: dict) -> str:
        """POST ausführen und manuell allen Redirects folgen. Gibt finalen HTML-Body zurück."""
        _LOGGER.debug("[%s-POST] POST %s", label, start_url)
        resp = self._session.post(
            start_url, data=post_data, headers=BROWSER_HEADERS,
            allow_redirects=False,
        )
        _LOGGER.debug("[%s-POST] → HTTP %s | Location: %s", label, resp.status_code, resp.headers.get("Location", "–"))

        redirect_url = resp.headers.get("Location", "")
        hop = 0
        max_hops = 10
        body = resp.text

        while redirect_url and resp.status_code in (301, 302, 303, 307, 308) and hop < max_hops:
            hop += 1
            if redirect_url.startswith("/"):
                redirect_url = SAP_HOST + redirect_url

            _LOGGER.debug("[%s Hop%d] GET %s", label, hop, redirect_url)
            resp = self._session.get(
                redirect_url, headers=BROWSER_HEADERS, allow_redirects=False,
            )
            body = resp.text
            redirect_url = resp.headers.get("Location", "")
            _LOGGER.debug(
                "[%s Hop%d] → HTTP %s | Next: %s",
                label, hop, resp.status_code, redirect_url or "–",
            )

        return body

    # ── Async Public API (für Home Assistant) ──────────────────────────

    async def async_get_user_tenants(self) -> list[dict]:
        if not self._is_authenticated:
            await self._authenticate()

        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        _LOGGER.debug("[TENANTS] GET %s", TENANTS_URL)

        def _do():
            return self._session.get(TENANTS_URL, headers=headers)

        resp = await asyncio.to_thread(_do)
        text = resp.text
        _LOGGER.debug("[TENANTS] HTTP %s | Content-Type: %s", resp.status_code, resp.headers.get("Content-Type", "?"))
        if resp.status_code == 200:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                _LOGGER.error("[TENANTS] Kein JSON empfangen!")
                _LOGGER.debug("[TENANTS] Erste 300 Zeichen:\n%s", text[:300])
        else:
            _LOGGER.error("[TENANTS] HTTP Fehler: %s", resp.status_code)
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
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json; charset=UTF-8",
        }
        for c_type in ["HZKWH", "WW", "KW"]:
            payload = {
                "userNum": user_num, "layer": "NE", "scale": "CALMONTH",
                "chartRefUnit": "ABS", "refObject": "DIN_AVG", "consType": c_type,
                "dashBoardKey": "PE", "timelineStart": start_date, "timelineStartTxt": "",
                "timelineEnd": end_date, "timelineEndTxt": "",
                "valuesInKWH": True, "dlgKey": "100KWH",
            }

            def _do():
                return self._session.post(READ_DATA_URL, json=payload, headers=headers)

            try:
                resp = await asyncio.to_thread(_do)
                if resp.status_code == 403:
                    continue
                text = resp.text
                for row in json.loads(text).get("table", []):
                    row["_ha_medium_type"] = c_type
                    row["_tenant_info"] = tenant_info
                    all_meters.append(row)
            except Exception as e:
                _LOGGER.error("[readData] Fehler für Typ %s: %s", c_type, e)
        return all_meters

    # ── Authentication Flow ────────────────────────────────────────────

    async def _authenticate(self) -> None:
        _LOGGER.debug("=" * 60)
        _LOGGER.debug("=== STARTE AUTHENTICATION FLOW ===")

        # === SCHRITT 1a: INIT_URL - OHNE automatischen Redirect ===
        _LOGGER.debug("[S1a] GET %s (allow_redirects=False)", INIT_URL)

        def _s1a():
            return self._session.get(INIT_URL, allow_redirects=False)

        resp = await asyncio.to_thread(_s1a)
        sap_redirect_url = resp.headers.get("Location", "")
        _LOGGER.debug("[S1a] HTTP %s | Redirect: %s...", resp.status_code, sap_redirect_url[:80])

        if not sap_redirect_url:
            raise MinolAuthError("SAP sendete keinen Redirect zu Azure B2C!")

        # === SCHRITT 1b: Azure B2C aufrufen ===
        _LOGGER.debug("[S1b] GET Azure B2C URL (allow_redirects=True)")

        def _s1b():
            return self._session.get(sap_redirect_url, allow_redirects=True)

        resp = await asyncio.to_thread(_s1b)
        html = resp.text
        azure_final_url = resp.url
        _LOGGER.debug("[S1b] Final-URL: %s | HTTP %s", azure_final_url, resp.status_code)
        self._dump_cookies("NACH S1")

        # Prüfung: Ist bereits eine VALIDE SAMLResponse da?
        saml_match = re.search(r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)
        relay_match = re.search(r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]', html)

        saml_response = None
        relay_state = "ouccprfhrffau"

        if saml_match and self._is_saml_success(saml_match.group(1)):
            _LOGGER.debug("[S1b] Gültige SAMLResponse direkt da (Session noch aktiv).")
            saml_response = saml_match.group(1)
            relay_state = relay_match.group(1) if relay_match else relay_state

        else:
            if saml_match:
                _LOGGER.debug("[S1b] SAMLResponse gefunden, aber FEHLER-Response. Führe normalen Login durch.")

            # === SCHRITT 2: CSRF + TX aus Azure B2C Seite extrahieren ===
            csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
            tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', html)

            if not csrf_match or not tx_match:
                _LOGGER.error("[S2] CSRF/TX nicht gefunden. HTML:\n%s", html[:500])
                raise MinolAuthError("CSRF/TX Token nicht gefunden.")

            csrf_token = csrf_match.group(1)
            tx_token = tx_match.group(1)
            _LOGGER.debug("[S2] CSRF: %s... | TX: %s...", csrf_token[:15], tx_token[:15])

            # === SCHRITT 2: Credentials an Azure B2C senden ===
            auth_body = (
                f"request_type=RESPONSE"
                f"&signInName={urllib.parse.quote(self._username, safe='')}"
                f"&password={urllib.parse.quote(self._password, safe='')}"
            )

            _LOGGER.debug("[S2] POST SelfAsserted | signInName: %s | password: ***", self._username)

            auth_headers = {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": BROWSER_HEADERS["Accept-Language"],
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": B2C_HOST,
                "Referer": azure_final_url,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "X-CSRF-TOKEN": csrf_token,
                "X-Requested-With": "XMLHttpRequest",
            }

            auth_url = f"{SELF_ASSERTED_URL}?tx={tx_token}&p={B2C_POLICY}"
            _LOGGER.debug("[S2] URL: %s", auth_url)
            _LOGGER.debug("[S2] Body: %s", auth_body)

            def _s2():
                return self._session.post(
                    auth_url, data=auth_body, headers=auth_headers, allow_redirects=False,
                )

            resp = await asyncio.to_thread(_s2)
            body = resp.text
            _LOGGER.debug("[S2] HTTP %s | Response: %s", resp.status_code, body[:300])

            if resp.status_code == 400:
                _LOGGER.error("[S2] HTTP 400 von Azure B2C! Body:\n%s", body)
                raise MinolAuthError(
                    f"Azure B2C lehnt Authentifizierungsanfrage ab (HTTP 400). "
                    f"Mögliche Ursache: CSRF-Problem oder fehlende Header. Body: {body[:200]}"
                )

            if '"status":"400"' in body or '"status": "400"' in body:
                _LOGGER.error("[S2] Zugangsdaten abgelehnt! Azure Antwort: %s", body)
                raise MinolAuthError("Login abgelehnt (E-Mail oder Passwort falsch).")

            _LOGGER.debug("[S2] Login von Azure akzeptiert.")
            self._dump_cookies("NACH S2")

            # === SCHRITT 3: SAMLResponse vom Confirmed-Endpoint ===
            conf_url = f"{CONFIRMED_URL}?rememberMe=false&csrf_token={csrf_token}&tx={tx_token}&p={B2C_POLICY}"
            _LOGGER.debug("[S3] GET Confirmed: %s", conf_url)

            def _s3():
                return self._session.get(conf_url, headers=BROWSER_HEADERS, allow_redirects=True)

            resp = await asyncio.to_thread(_s3)
            conf_html = resp.text
            _LOGGER.debug("[S3] HTTP %s | Final-URL: %s", resp.status_code, resp.url)
            self._dump_cookies("NACH S3")

            saml_match = re.search(
                r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]',
                conf_html,
            )
            if not saml_match:
                _LOGGER.error("[S3] SAMLResponse fehlt! HTML:\n%s", conf_html[:500])
                raise MinolAuthError("SAMLResponse fehlt nach Login.")

            saml_response = saml_match.group(1)
            relay_match = re.search(
                r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]',
                conf_html,
            )
            relay_state = relay_match.group(1) if relay_match else relay_state
            _LOGGER.debug("[S3] SAMLResponse: %d Zeichen | RelayState: %s", len(saml_response), relay_state)

            if not self._is_saml_success(saml_response):
                raise MinolAuthError("SAMLResponse nach Login enthält Fehler-Status!")

        # === SCHRITT 4: SAMLResponse an SAP ACS senden (manuelle Redirects) ===
        _LOGGER.debug("[S4] Sende SAMLResponse an SAP ACS (manuelle Redirect-Kette)...")

        def _s4():
            return self._follow_redirects_from_post(
                ACS_URL, "S4-ACS",
                post_data={"SAMLResponse": saml_response, "RelayState": relay_state},
            )

        acs_body = await asyncio.to_thread(_s4)
        self._dump_cookies("NACH S4")

        # Prüfen ob SAP ein weiteres Formular erwartet
        form_action_match = re.search(r'(?is)<form[^>]+action=[\'"]([^\'"]+)[\'"]', acs_body)
        inner_saml_match = re.search(
            r'(?is)name=[\'"]SAMLResponse[\'"].*?value=[\'"]([^\'"]+)[\'"]',
            acs_body,
        )

        if form_action_match and inner_saml_match:
            next_action = form_action_match.group(1)
            if next_action.startswith("/"):
                next_action = SAP_HOST + next_action

            next_saml = inner_saml_match.group(1)
            next_relay_m = re.search(
                r'(?is)name=[\'"]RelayState[\'"].*?value=[\'"]([^\'"]+)[\'"]',
                acs_body,
            )
            next_relay = next_relay_m.group(1) if next_relay_m else relay_state
            _LOGGER.debug("[S5] SAP erwartet weiteres Formular an: %s", next_action)

            def _s5():
                return self._follow_redirects_from_post(
                    next_action, "S5-APP",
                    post_data={
                        "SAMLResponse": next_saml,
                        "RelayState": next_relay,
                        "saml2post": "false",
                    },
                )

            await asyncio.to_thread(_s5)
            self._dump_cookies("NACH S5")
        else:
            _LOGGER.debug("[S4] Kein weiteres SAP-Formular im ACS-Body erkannt.")

        _LOGGER.debug("=" * 60)
        _LOGGER.debug("=== AUTH ABGESCHLOSSEN ===")
        self._dump_cookies("FINAL")

        if "MYSAPSSO2" in {c.name for c in self._session.cookies}:
            _LOGGER.debug("[AUTH] MYSAPSSO2 Cookie erfolgreich gesetzt!")
        else:
            _LOGGER.warning("[AUTH] MYSAPSSO2 Cookie fehlt nach Login!")

        self._is_authenticated = True

