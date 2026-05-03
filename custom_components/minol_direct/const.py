from datetime import timedelta
from homeassistant.const import Platform

DOMAIN = "minol_direct"
PLATFORMS: list[Platform] = [Platform.SENSOR]

CONF_USERNAME = "username"
CONF_PASSWORD = "password"

SCAN_INTERVAL = timedelta(hours=24)
