import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import MinolAuthError, MinolOnlineClient
from .const import CONF_PASSWORD, CONF_USERNAME, DOMAIN, PLATFORMS, SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    client = MinolOnlineClient(entry.data[CONF_USERNAME], entry.data[CONF_PASSWORD])
    coordinator = MinolDataCoordinator(hass, client)

    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
        if coordinator and coordinator.client._session:
            coordinator.client._session.close()
    return unload_ok

class MinolDataCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, client: MinolOnlineClient) -> None:
        self.client = client
        super().__init__(hass, logger=_LOGGER, name=DOMAIN, update_interval=SCAN_INTERVAL)

    async def _async_update_data(self):
        try:
            return await self.client.async_fetch_data()
        except Exception as err:
            raise UpdateFailed(f"Fehler beim Aktualisieren der Minol Daten: {err}") from err
