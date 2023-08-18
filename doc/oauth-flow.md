# Debugging Dashboard OAuth Logins

DevOps dashboard logins use the [assisted token flow](https://curity.io/docs/idsvr/latest/developer-guide/oauth-service/web-clients/assisted-token-javascript.html) via a popup window.\
This includes use of framing, so configuration settings must be set correctly, to prevent browser errors.

## HTTP Schemes

First, ensure that the same HTTP or HTTPS scheme is used by admin and runtime nodes.\
Avoid running the Admin UI on HTTPS and runtime nodes on HTTP, or vice versa.

## Client Settings

These settings at these Admin UI locations affect the browser permissions needed during dashboard logins.\
In the example setup, these all begin with `http://localhost:6749`:

- System / Zones / Allowed Origins for CORS
- Profiles / Token Service / Clients / devops_dashboard_restconf_client / Allowed Origins
- Profiles / Token Service / Clients / devops_dashboard_restconf_client / Redirect URI
- Profiles / Token Service / Clients / devops_dashboard_restconf_client / Allowed Post Logout Redirect URIs

## Debug Dashboard Logins

If a user is denied access to the DevOps dashboard, it is typically caused by a missing or incorrect `groups`` claim.\
To debug this, first navigate to the dashboard login screen:

```text
http://localhost:6749/admin/dashboard/#/login
```

Then use browser tools to capture tokens returned to the dashboard UI after login:

![Browser Tools Login](browser-tools-login.png)

If required, also view other messages, including the OpenID Connect authentication request:

```
http://localhost:8443/oauth/v2/oauth-authorize?
scope=openid+urn%3Ase%3Acurity%3Ascopes%3Aadmin%3Aapi
&state=kbUl3F1lokSEH6xF8bfaCxCFfaCTSf4BBkvfNpPSb4slKpADf13UvohwGMvrke4r
&nonce=6P0kOAdJ3CpcaKLbBWlShZEmBIJvQ17TkHMZjh5GMcaDQvk4reD7v2coRV87U5wt
&client_id=devops_dashboard_restconf_client
&response_type=code
&code_challenge=Nh78q8z9VTWlZhU5YXJqQHMk5P9pl_bWg0d-byJF85o
&code_challenge_method=S256
&redirect_uri=http%3A%2F%2Flocalhost%3A6749%2Fadmin%2Fdashboard%2Fassisted.html
&for_origin=http%3A%2F%2Flocalhost%3A6749
```

## Capture Tokens

You can copy tokens returned to browser tools, which will look similar to this:

```json
{
    "id_token":"eyJraWQiOiItMTkzMDI1NTI4NCIsI ...",
    "token_type":"bearer",
    "access_token":"_0XBPWQQ_d18ee5e3-464a-4a86-bb7f-152364daa54e",
    "scope":"openid urn:se:curity:scopes:admin:api",
    "claims":"urn:se:curity:claims:admin:groups",
    "expires_in":299
}
```

## View Access Token Claims

Introspect the access token to view its claims, using the following command:

```bash
ACCESS_TOKEN='_0XBPWQQ_d18ee5e3-464a-4a86-bb7f-152364daa54e'
echo $(curl -k -s -X POST http://localhost:8443/oauth/v2/oauth-introspect \
    -u "introspect-client:Password1" \
    -H "Accept: application/json" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=$ACCESS_TOKEN") | jq
```

A correct access token should look like this. where the user is a member of the `developers` group:

```json
{
  "sub": "janedoe",
  "purpose": "access_token",
  "iss": "http://localhost:8443/oauth/v2/oauth-anonymous",
  "groups": [
    "developers"
  ],
  "active": true,
  "token_type": "bearer",
  "client_id": "devops_dashboard_restconf_client",
  "aud": [
    "urn:se:curity:audiences:admin:api",
    "devops_dashboard_restconf_client"
  ],
  "nbf": 1671128075,
  "scope": "openid urn:se:curity:scopes:admin:api",
  
  "exp": 1671128375,
  "delegationId": "c6e216b3-1cd7-4ac0-9a7d-df81c331530a",
  "iat": 1671128075
}
```
