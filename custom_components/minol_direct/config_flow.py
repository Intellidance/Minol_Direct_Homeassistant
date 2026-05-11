import logging
import voluptuous as vol
from homeassistant import config_entries

from .api import MinolAuthError, MinolConnectionError, MinolOnlineClient
from .const import CONF_PASSWORD, CONF_USERNAME, DOMAIN

_LOGGER = logging.getLogger(__name__)

class MinolOnlineConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            username = user_input[CONF_USERNAME].strip()
            password = user_input[CONF_PASSWORD]

            await self.async_set_unique_id(username.lower())
            self._abort_if_unique_id_configured()

            client = MinolOnlineClient(username, password)
            try:
                # Login durchführen und Wohnungen abrufen
                tenants = await client.async_get_user_tenants()

                if not tenants:
                    errors["base"] = "no_tenants"
                else:
                    # Ermittle einen schönen Titel für die Integration
                    t = tenants[0]
                    street = t.get("addrStreet", "")
                    house = t.get("addrHouseNum", "")
                    title = f"Minol {street} {house}".strip()

                    if len(tenants) > 1:
                        title += f" (+{len(tenants)-1})"
                    if not title:
                        title = f"Minol ({username})"

                    return self.async_create_entry(
                        title=title,
                        data={CONF_USERNAME: username, CONF_PASSWORD: password},
                    )
            except MinolAuthError:
                errors["base"] = "auth"
            except Exception as err:
                _LOGGER.error("Verbindungsfehler im Config Flow: %s", err)
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
            }),
            errors=errors,
        )
