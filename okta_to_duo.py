import base64, email, hmac, hashlib, urllib, ConfigParser, requests

def sign(method, host, path, params, skey, ikey):
    """
    Return HTTP Basic Authentication ("Authorization" and "Date") headers.
    method, host, path: strings from request
    params: dict of request parameters
    skey: secret key
    ikey: integration key
    HMAC: https://en.wikipedia.org/wiki/HMAC
    """

    # create canonical string
    now = email.Utils.formatdate()
    canon = [now, method.upper(), host.lower(), path]
    args = []
    for key in sorted(params.keys()):
        val = params[key]
        if isinstance(val, unicode):
            val = val.encode("utf-8")
        args.append(
            '%s=%s' % (urllib.quote(key, '~'), urllib.quote(val, '~')))
    canon.append('&'.join(args))
    canon = '\n'.join(canon)

    # sign canonical string
    sig = hmac.new(skey, canon, hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())

    # return headers
    return {'Date': now, 'Authorization': 'Basic %s' % base64.b64encode(auth)}

# Initialize ConfigParser to read .cfg file.
config = ConfigParser.ConfigParser()

# Check if config file exists and set parameters
if config.read('okta.cfg'):
    okta_url = config.get('OKTA', 'URL', 0)              # -> "https://dev-XXXXXX-admin.oktapreview.com/api/v1/users?limit=1000; rel='next'"
    okta_api_token = config.get('OKTA', 'API_TOKEN', 0)  # -> "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    okta_headers = {
        'Accept': 'application/json', 
        'Content-Type': 'application/json', 
        'Authorization': 'SSWS' + okta_api_token
    }

    duo_skey = config.get('DUO', 'SECRET_KEY', 0)       # -> "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXV"
    duo_ikey = config.get('DUO', 'INTEGRATION_KEY', 0)  # -> "DIXXXXXXXXXXXXXXXX"
    duo_host = config.get('DUO', 'API_HOSTNAME', 0)     # -> "api-XXXXXXXX.duosecurity.com"
else:
    exit('Config file not found.')

# Find if "rel=next" exists, if -1, does not exist
x = 0

while x > -1:
    users = requests.get(okta_url, headers=okta_headers)    # Get first page of users
    users_json = users.json()                               # Variable containing users in .json format
    users_headers = str(users.headers)                      # Variable containing headers

    # print(users_json)
    # print("Next user set")
    
    # Initialize loop
    i = 0
    params = {}
    sign_params = {}

    # Loop through list of users from Okta and process to Duo
    while i < len(users_json):

        # Check status of Okta user - https://support.okta.com/help/s/article/58335656-What-are-the-different-user-statuses-in-the-Okta-Password-Health-Check-Report
        # PROVISIONED - New user is added in Okta but not activated yet
        # RECOVERY - Existing user, activated previously, is in password reset mode
        # ACTIVE - Active status
        # DEPROVISIONED - Deactivated in Okta - API DOES NOT RETURN THESE USERS.
        # PASSWORD EXPIRED - User password is expired
        # STAGED - New users created through the API and not activated yet
        if users_json[i]['status'] == 'ACTIVE':
            print('User: ' + users_json[i]['profile']['email'] + ' status is: ' + users_json[i]['status'] + '. Syncing to Duo')
            params = {'username': users_json[i]['profile']['email']}
            user_duo_sign = sign("GET", duo_host, "/admin/v1/users", params, duo_skey, duo_ikey)
            user_status = requests.get(("https://" + duo_host +"/admin/v1/users"), headers={'username': duo_ikey, 'Authorization': user_duo_sign["Authorization"], 'date': user_duo_sign["Date"]}, params={'username': users_json[i]['profile']['email']})
            user_status = user_status.json()
            if len(user_status['response']) == 0:
                
                # print user_status['response']
                print('User not found. Syncing to Duo')

                # using 'email' as username and a combination of 'firstName' and 'lastName' for realname
                # Could leverage parameters for active/inactive and additional parameters
                params = {
                    'email': (users_json[i]['profile']['email']), 
                    'realname': ((users_json[i]['profile']['firstName']) + " " + (users_json[i]['profile']['lastName'])), 
                    'username': (users_json[i]['profile']['email'])
                }

                # POST end users gathered from Okta up into Duo
                sign_params = sign("POST", duo_host, "/admin/v1/users", params, duo_skey, duo_ikey)
                request = requests.post(("https://" + duo_host + "/admin/v1/users"), headers={'username': duo_ikey, 'Authorization': sign_params["Authorization"], 'date': sign_params["Date"]}, params=params)
                print(request.json())
            else:
                print('User: ' + user_status['response'][0]['username'] + ' exists in Duo. Skipping.')
            # params = {}
        elif users_json[i]['status'] == 'SUSPENDED':
            print('User: ' + users_json[i]['profile']['email'] + ' status is: ' + users_json[i]['status'] + '. Checking status in Duo.')

            # Get Duo User status
            params = {'username': users_json[i]['profile']['email']}
            user_duo_sign = sign("GET", duo_host, "/admin/v1/users", params, duo_skey, duo_ikey)
            user_status = requests.get(("https://" + duo_host +"/admin/v1/users"), headers={'username': duo_ikey, 'Authorization': user_duo_sign["Authorization"], 'date': user_duo_sign["Date"]}, params={'username': users_json[i]['profile']['email']})
            user_status = user_status.json()
            user_id = str(user_status['response'][0]['user_id'])

            if len(user_status['response']) == 0:
                # Do nothing if user is not found in Duo
                print('User not found. Skipping.')

            elif user_status['response'][0]['status'] == 'disabled':
                # If user is already 'disabled' in Duo... Do Nothing
                print('User is disabled. Nothing to do.')

            elif user_status['response'][0]['status'] == 'active':
                # Change user status to 'disabled' in Duo
                print('Setting user: ' + users_json[i]['profile']['email'] + ' in Duo to disabled status.')
                disabled_user_params = {'user_id': user_id, 'status': 'disabled'}
                disabled_user_sign = sign('POST', duo_host, ('/admin/v1/users/' + user_id), disabled_user_params, duo_skey, duo_ikey)
                modify_user = requests.post(('https://' + duo_host + '/admin/v1/users/' + user_id), headers={'username': duo_ikey, 'Authorization': disabled_user_sign['Authorization'], 'date': disabled_user_sign['Date']}, params=disabled_user_params)
                modify_user = modify_user.json()
                print('User (' + modify_user['response']['username'] + ') status has been set to: ' + modify_user['response']['status'])
            else:
                print('User resonse is: ' + user_status['response'][0]['status'])
                # print(user_status)

        else:
            print('User: ' + users_json[i]['profile']['email'] + ' status is: ' + users_json[i]['status'] + '. skipping.')

        # Clear params for next iteration
        params = {}
        sign_params = {}

        # Increment interval
        i += 1

    # Get headers to find if next list exists -- returns -1 if cannot find 'rel="next' in headers
    x = users_headers.find('rel="next"')

    if x > -1:
        # Parse link
        links = users.headers['Link']
        links = links.split(', <')
        links = str(links[1]).split('>;')
        okta_url = links[0]
        print(okta_url)
        
    else:
        break   # When there is no next page
