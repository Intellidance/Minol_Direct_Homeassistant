from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [MinolMeterSensor(coordinator, row) for row in coordinator.data.get("meters", []) if "gerNr" in row]
    async_add_entities(entities)

class MinolMeterSensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    def __init__(self, coordinator, row_data):
        super().__init__(coordinator)
        
        self._serial = str(row_data.get("gerNr", ""))
        self._internal_key = str(row_data.get("internalKey", self._serial))
        
        # Hänge UserNum an Unique ID an, falls Nutzer Zähler tauscht/umzieht
        tenant_info = row_data.get("_tenant_info", {})
        user_num = tenant_info.get("userNumber", "000")
        self._attr_unique_id = f"{DOMAIN}_{user_num}_{self._internal_key}"
        
        self._placement = str(row_data.get("raum", "Unbekannt"))
        self._ha_type = row_data.get("_ha_medium_type", "")
        self._raw_unit = str(row_data.get("unit", "")).upper()

        # Extrahiere Adressdaten für schönen Namen / Attribute
        street = tenant_info.get("addrStreet", "")
        house = tenant_info.get("addrHouseNum", "")
        city = tenant_info.get("addrCity", "")
        self._address = f"{street} {house}, {city}".strip(" ,")
        self._geschoss = tenant_info.get("geschossText", "")
        self._lage = tenant_info.get("lageText", "")

        # Einheiten Logik
        if self._raw_unit == "KWH" or self._ha_type == "HZKWH":
            self._attr_device_class = SensorDeviceClass.ENERGY
            self._attr_native_unit_of_measurement = "kWh"
            medium_name = "Heizung"
        elif self._raw_unit in ["M3", "M³"] or self._ha_type in ["WW", "KW"]:
            self._attr_device_class = SensorDeviceClass.WATER
            self._attr_native_unit_of_measurement = "m³"
            medium_name = "Warmwasser" if self._ha_type == "WW" else "Kaltwasser"
        else:
            self._attr_native_unit_of_measurement = self._raw_unit
            medium_name = "Zähler"

        self._attr_name = f"{medium_name} Zählerstand"
        
        # Name in HA z.B.: Heizung - Flur
        if self._address:
            self._device_name = f"{medium_name} - {self._placement} ({self._address})"
        else:
            self._device_name = f"{medium_name} - {self._placement}"

    @property
    def native_value(self):
        for row in self.coordinator.data.get("meters", []):
            if row.get("internalKey") == self._internal_key and row.get("ablesung") is not None:
                return float(row.get("ablesung"))
        return None

    @property
    def extra_state_attributes(self):
        attributes = {}
        for row in self.coordinator.data.get("meters", []):
            if row.get("internalKey") == self._internal_key:
                attributes = {
                    "raum": row.get("raum"), 
                    "seriennummer": row.get("gerNr"), 
                    "letzter_verbrauch": row.get("consumption")
                }
                break
                
        if self._address:
            attributes["adresse"] = self._address
        if self._geschoss:
            attributes["geschoss"] = self._geschoss
        if self._lage:
            attributes["lage"] = self._lage
            
        return attributes

    @property
    def device_info(self):
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            manufacturer="Minol Direct",
            name=self._device_name,
            serial_number=self._serial,
            suggested_area=self._placement
        )
