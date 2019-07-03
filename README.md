# Symantec Threat Explorer for Alfred
This workflow shows Symantec Threat Intelligence about URL's by using the Symantec Threat Explorer API. A valid API key is needed for this workflow to function.

1. Install the workflow (download is available in releases)

2. Type the **te** keyword in Aflred
![te](https://raw.githubusercontent.com/coolhva/alfred-symantec-threat-explorer/master/screenshots/te.png)

3. Install the API key with the **tesetkey api-key** command
![tesetkey](https://raw.githubusercontent.com/coolhva/alfred-symantec-threat-explorer/master/screenshots/te_set_key.png)
After hitting enter the api key will be saved and you will be notified
![tekeyst](https://github.com/coolhva/alfred-symantec-threat-explorer/blob/master/screenshots/te_api_key_saved.png)

4. Query a domain name (**te symantec.com**)
![te_symantec_com](https://raw.githubusercontent.com/coolhva/alfred-symantec-threat-explorer/master/screenshots/te_symantec_com.png)

5. Query a malicious domain (**te hxxp://vorota-v-rb.ru/manager/3**, replaced http with hxxp for security reasons)
![te_malicious](https://raw.githubusercontent.com/coolhva/alfred-symantec-threat-explorer/master/screenshots/te_malicious.png)

If the API key is not valid an error will be shown.
![te_wrong_api_key](https://github.com/coolhva/alfred-symantec-threat-explorer/blob/master/screenshots/te_invalid_api_key.png)

When a new update is available it will be shown and with **Enter** a new version will be installed.
![te_update](https://github.com/coolhva/alfred-symantec-threat-explorer/blob/master/screenshots/te_update.png)
