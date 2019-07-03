# encoding: utf-8
import sys
import argparse
import os
from workflow import Workflow, ICON_NOTE, ICON_ERROR, ICON_INFO, ICON_WEB, ICON_WARNING, ICON_BURN, ICON_NETWORK, web, PasswordNotFound

log = None

class Category:
    def __init__(self, name, lastUpdate):
        self.name = name
        self.lastUpdate = lastUpdate

class URL:
    def __init__(self, url, firstObserved, lastObserved, topSiteRank):
        self.url = url
        self.firstObserved = firstObserved
        self.lastObserved = lastObserved
        self.topSiteRank = topSiteRank

class RiskLevel:
    def __init__(self, riskLevel, lastUpdate):
        self.riskLevel = riskLevel
        self.lastUpdate = lastUpdate

class GeoLocation:
    def __init__(self, countryCode, countryName):
        self.countryCode = countryCode
        self.countryName = countryName

class IpAddress:
    def __init__(self,geolocation,ipAddress):
        self.geoLocation = geolocation
        self.ipAddress = ipAddress

class ThreatIntel:
    url = None
    categories = []
    riskLevel = None
    ipAddresses = []

def xstr(s):
    return '' if s is None else str(s)

def get_threat_intel(query, api_key):
    """Retrieve threat intel from Stmantec Threat Explorer

    Returns intelligence about the requested URL

    """
    url = 'https://threatexplorer.symantec.com/api/v1/url'
    params = dict(level='ADVANCED', url=query)
    headers = dict(Authorization=api_key)
    r = web.get(url, params, headers)

    # throw an error if request failed
    # Workflow will catch this and show it to the user
    r.raise_for_status()

    # Parse the JSON returned by the API and extract the intel
    result = r.json()

    # Create new intel object and extract the results
    intel = ThreatIntel
    intel.url = URL(query,xstr(result['firstObserved']),xstr(result['lastObserved']),xstr(result['topSiteRank']))

    # Append categories
    categories = result['categorization']['categories']
    for category in categories:
        intel.categories.append(Category(category['name'],xstr(result['categorization']['lastUpdated'])))
    
    # set risk level
    intel.riskLevel = RiskLevel(str(result['threatRiskLevel']['level']), xstr(result['threatRiskLevel']['lastUpdated']))

    # Appeend IP addresses

    ipaddresses = result["currentResolvedIps"]
    for ipaddress in ipaddresses:
        intel.ipAddresses.append(
            IpAddress(
                GeoLocation(ipaddress['geolocation']['countryCode']
                           ,ipaddress['geolocation']['countryName'])
                ,ipaddress['ipAddress']))

    return intel

def main(wf):

    log.debug('Started')

    if wf.update_available:
        wf.add_item('New version available',
                    'Install the update',
                    autocomplete='workflow:update',
                    icon=ICON_INFO)

    import validators

    # build argument parser to parse script args and collect their values
    parser = argparse.ArgumentParser()

    # add an optional (nargs='?') --setkey argument and save its
	# value to 'apikey' (dest).

    parser.add_argument('--setkey', dest='apikey', nargs='?', default=None)
	# add an optional query and save it to 'query'
    parser.add_argument('query', nargs='?', default=None)
	# parse the script's arguments
    args = parser.parse_args(wf.args)

	####################################################################
	# Save the provided API key
	####################################################################

	# decide what to do based on arguments
    if args.apikey:  # Script was passed an API key
	    # save the key
        wf.save_password('threatexplorer_api_key', args.apikey)
        return 0  # 0 means script exited cleanly

	####################################################################
	# Check that we have an API key saved
	####################################################################

    try:
        api_key = wf.get_password('threatexplorer_api_key')
    except PasswordNotFound: # API key has not yet been set
	    wf.add_item('No API key set',
	                'Please use tesetkey to set your Threat Explorer API key',
	                valid=False,
	                icon=ICON_WARNING)
	    wf.send_feedback()
	    return 0

    query = args.query
	
    # TODO: Caching is not working (yet)
    # def wrapper():
    #     """ cached_data can only cache no args functions """
    #     return get_threat_intel(query, api_key)

    # intel = wf.cached_data('intel', wrapper, max_age=600)

    # validate input
    valid = False
    if validators.domain(query):
        valid = True
    if validators.url(query):
        valid = True
    if validators.ipv4(query):
        valid = True
    if validators.ipv6(query):
        valid = True
    
    if not valid:
        wf.add_item('Enter valid URL, domain or IP',
                    '',
                    valid=False,
                    icon=ICON_WARNING)
        wf.send_feedback()
        return 0

    intel = get_threat_intel(query, api_key)

    wf.add_item(title=intel.url.url,
                subtitle='First seen: ' + intel.url.firstObserved + 
                        ' Last seen: ' + intel.url.lastObserved +
                        ' Topsite Rank: ' + intel.url.topSiteRank,
                arg=query,
                valid=True,
                icon=ICON_INFO)

    
    # Loop through the categories
    for category in intel.categories:
        wf.add_item(title='Category: ' + category.name, 
                    subtitle='Last updated: ' + category.lastUpdate,
                    arg=query,
                    valid=True,
                    icon=ICON_WEB)

    # Add risk level
    riskIcon = ICON_NOTE
    if int(intel.riskLevel.riskLevel) > 4 and int(intel.riskLevel.riskLevel) < 7:
        riskIcon = ICON_WARNING
    if int(intel.riskLevel.riskLevel) > 6 and int(intel.riskLevel.riskLevel) < 8:
        riskIcon = ICON_ERROR
    if int(intel.riskLevel.riskLevel) > 7:
        riskIcon = ICON_BURN

    wf.add_item(title='Risklevel: ' + intel.riskLevel.riskLevel, 
                    subtitle='Last updated: ' + str(intel.riskLevel.lastUpdate),
                    arg=query,
                    valid=True,
                    icon=riskIcon)
    
     # Loop through the ip addresses
    for ipaddress in intel.ipAddresses:
        countryIcon = ICON_NETWORK

        if os.path.isfile('./flags/' + ipaddress.geoLocation.countryName.replace(" ", "_").lower() + '.png'):
            countryIcon = './flags/' + ipaddress.geoLocation.countryName.replace(" ", "_").lower() + '.png'

        wf.add_item(title='IP: ' + ipaddress.ipAddress, 
                    subtitle=ipaddress.geoLocation.countryCode + ': ' + ipaddress.geoLocation.countryName,
                    arg=query,
                    valid=True,
                    icon=countryIcon)

    # Send the results to Alfred as XML
    wf.send_feedback()

if __name__ == u"__main__":
    wf = Workflow(libraries=['./lib'])
    wf = Workflow(update_settings={'github_slug': 'coolhva/alfred-symantec-threat-explorer'})
    log = wf.logger
    sys.exit(wf.run(main))