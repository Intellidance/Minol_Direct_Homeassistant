# Minol Direct HACS Integration for HomeAssistant
   ![Minol Logo](assets/Minol_Direct.svg)

> [!WARNING]
> We are aware that there are issues in the codebase.
> This is a hobby project maintained in spare time.
> Fixes and improvements are implemented when time allows.
> Do not deploy in production without proper validation.

`minol_direct` is a Home Assistant custom integration that authenticates against Minol Online and creates water and heating meter sensors from `webservices.minol.com`.

---

> [!IMPORTANT]
> Home Assistant should be treated as the Source of Truth for automations and dashboards.
> This integration is read-only and only syncs data from Minol to Home Assistant.

---

## Features

- **Easy Config-Flow Setup:** Set up directly in the Home Assistant UI (only Email & Password required).
- **Multi-Tenant Support:** Automatically detects all apartments/tenants associated with your account.
- **Per-meter sensors:**
  - Heating (`kWh`)
  - Hot Water (`m³`)
  - Cold Water (`m³`)
- **Energy Dashboard Ready:** Sensors use the `total_increasing` state class and proper device classes, making them natively compatible with the Home Assistant Energy & Water dashboard.
- **Rich Attributes:** Includes serial numbers, rooms, and address data directly in the sensor attributes.
- **Efficient Polling:** Updates every 24 hours (Minol typically updates data only once a month).

> [!NOTE]
> Sync direction is strictly one-way: Minol -> Home Assistant.
> No write operations are performed against your meters.

---

## Quick Start

### 1. Install with HACS

1. Open **HACS** in Home Assistant.
2. Go to **Integrations**.
3. Click menu (three dots) -> **Custom repositories**.
4. Add repository URL:
   - `https://github.com/Intellidance/Minol_Direct_Homeassistant`
5. Select category: **Integration**.
6. Install **Minol_Direct_Homeassistant**.
7. Restart Home Assistant.

---

### 2. Add integration

1. Go to **Settings** -> **Devices & Services**.
2. Click **Add Integration**.
3. Search for **Minol Direct**.
4. Enter your Minol Direct Email and Password.

---

### 3. Add to Energy Dashboard

In Home Assistant:

`Settings -> Dashboards -> Energy`

- **Water Consumption:** Add your Cold Water and Hot Water sensors to the water section.
- **Heating:** Add your Heating sensors (`kWh`) to the gas/heating section.

> [!IMPORTANT]
> Because the integration uses the `total_increasing` state class, Home Assistant will automatically calculate your daily, weekly, and monthly consumption based on the raw meter readings.

---

## Connectivity Requirements

Home Assistant must be able to reach the following endpoints to authenticate and fetch data:

- `https://webservices.minol.com`
- `https://minolauth.b2clogin.com`

---

## Troubleshooting

1. **Cannot connect / timeout**
   - Confirm DNS and outbound HTTPS from your Home Assistant host/container.
   - Check Home Assistant logs for `TimeoutError` or connection issues.

2. **Credentials rejected in HA, but browser works**
   - Ensure you are using the correct Minol Direct credentials.
   - The integration uses a SP-Initiated SAML Flow. If Minol changes their Azure B2C policy (`B2C_1A_Signup_Signin_Groups_SAML`), the authentication might need an update.

3. **No daily updates**
   - This is normal. Minol usually reads the meters via radio once a month and updates the portal between the 1st and 7th of the following month. The integration checks every 24 hours for new data. Do not decrease the scan interval to avoid rate limits.
