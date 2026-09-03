Note: This README serves as the lab report and documentation for the LearningSteps Lockdown exercise (Days 1-4). If you're looking to deploy the application itself, see Base Deployment instead - this file focuses on the security hardening process, findings, and analysis, not the initial setup steps.

# LearningSteps Lockdown

**Student Name:** Lee Gal

**Date:** 01.09.26

**Module Name:** Module3. Cloud

**Exercise:** LearningSteps Lockdown

---
# **1. Summary of Findings**

Day 1 (Locking Down Management Access) & Day 2 (Encryption and a Web Application Firewall)

This exercise hardened the LearningSteps environment (a FastAPI application backed by PostgreSQL, deployed on Azure via Terraform) across its first two attack surfaces: management access (SSH) and public web access (HTTP/TLS/WAF). Day 1 replaced a wide-open, key-based SSH configuration with identity-based login via Microsoft Entra ID, and restricted network access to a single trusted IP address. Day 2 stood up the application's first public entry point, closed a plaintext HTTP gap with a real Let's Encrypt TLS certificate, and enabled a Web Application Firewall (CrowdSec, running the OWASP Core Rule Set) to block SQL injection and cross-site scripting (XSS) attempts.

The key result was not just completing the prescribed steps, but discovering two real, unplanned security findings along the way. First, a WAF bypass: a SQL injection payload using '+' to encode spaces (id=1+UNION+SELECT...) passed through the WAF undetected in real time, while the logically identical payload using proper percent-encoding (%20) was correctly blocked - demonstrating that signature-based WAFs are encoding-sensitive and do not guarantee protection against all representations of the same attack. Second, unsolicited internet-scanning traffic was observed hitting the VM from an unrelated IP address (Contabo GmbH, France) within hours of the environment becoming public, using a spoofed, over a decade old browser User-Agent string - direct evidence that any publicly reachable service is found and probed by automated actors almost immediately, independent of anything the operator does.

Day 3 (Identity-Based API Access)

Day 3 deployed oauth2-proxy behind NPMplus to require a valid Entra ID token before any request reaches the app, replacing anonymous access entirely.
Nearly every step surfaced a real bug rather than a scripted one: a misleading "insufficient privileges" error was actually a tenant display-name collision; a successful Microsoft login still failed with a 500 due to a missing email claim on the classroom account; and saving one NPMplus setting failed because the WAF was blocking its own admin traffic. The key confirming result: the same SQLi payload now returns 302 (redirect to login) when unauthenticated but 403 when sent from a logged-in session - proof identity and the WAF are complementary layers, not redundant ones.

Day 4 (Data Isolation)

Day 4 migrated the PostgreSQL database off the public internet entirely, moving it onto Azure VNet Integration so it's reachable only from inside the virtual network - following a genuine backup-first migration, not a reversible toggle, since networking mode can only be set at server creation.

The most useful finding was operational rather than conceptual: the local Windows psql client was silently blocked by Windows Smart App Control, with no reliable unblock path short of a full OS reset - resolved by running the backup and verification steps from Azure Cloud Shell instead, which still proved external reachability without depending on one machine's security posture. The migration itself went cleanly: the database was destroyed and recreated inside a private subnet, the backup was restored via the VM (the only resource with network access to the now-private database), and the application recovered with zero data loss - confirming the VM's connection string was built to survive the underlying server being replaced. A direct connection attempt from outside the VNet afterward failed to even resolve the hostname, a stronger and cleaner isolation result than a mere connection refusal.

---
# **2. Tools & Environment**

- **Operating System (client):** Windows 11
- **Cloud Provider:** Microsoft Azure
- **Infrastructure as Code:** Terraform
- **CLI Tools:** Azure CLI (az), PowerShell, OpenSSH for Windows, curl.exe
- **Target VM:** Ubuntu 22.04 LTS (vm-lee), Azure Linux Virtual Machine
- **Identity:** Microsoft Entra ID (Azure AD), Virtual Machine Administrator Login role
- **Reverse Proxy / Certificate Management:** NPMplus (Nginx Proxy Manager, extended build)
- **TLS Certificate Authority:** Let's Encrypt
- **Web Application Firewall:** CrowdSec (OWASP Core Rule Set, AppSec component)
- **Database:** Azure Database for PostgreSQL Flexible Server (psql-lee)
- **Version Control:** Git / GitHub Desktop

# **3. Execution & Procedures**

## Day 1 - Locking Down Management Access

Goal: replace static SSH key authentication with identity-based login via Entra ID, and restrict the network path to SSH to a single trusted IP address.

### Step 1: Grant Entra ID VM Login Role and Authenticate

The VM was already provisioned with a system-assigned managed identity and the AADSSHLoginForLinux extension by Terraform. The remaining prerequisite - granting the account the 'Virtual Machine Administrator Login' RBAC role scoped to the VM resource - is not automated and had to be applied manually, since Owner/Contributor rights on the subscription do not by themselves permit OS-level login.

![RBAC role assignment confirmation](./screenshots/01-RBAC-confirmation.png)

Confirmation that the Virtual Machine Administrator Login role assignment landed correctly, scoped to vm-lee.
Login was then performed using the Entra ID identity directly, with no SSH key file involved:
```powershell
az ssh vm --resource-group rg-lee --name vm-lee
```
![Entra ID SSH login](./screenshots/02-EntraID-SSH-login.png)

Successful SSH login to vm-lee authenticated via Entra ID identity rather than a static key.
### Step 2: Restrict SSH to a Trusted IP
The NSG's 'allow-ssh' rule initially permitted SSH (port 22) from any IP address ('"*"'), identified in 'network.tf' as the root cause of unrestricted management-plane exposure.

![NSG rule before](./screenshots/03-source_address_prefix-before.png)

network.tf before the change: source_address_prefix set to "" - SSH reachable from any IP on the internet.*
The public IP was obtained and the rule updated to allow only that single address:
```powershell
curl.exe -s -4 ifconfig.me
# -> e.g. 79.196.253.208

# network.tf
source_address_prefix = "79.196.253.208/32"
```
![NSG rule after](./screenshots/04-source_address_prefix-after.png)

network.tf after the change: source_address_prefix restricted to a single /32 address.
```powershell
terraform apply
```
![Terraform plan](./screenshots/05-terraform-apply-to-change.png)

Terraform plan showing only the NSG rule being modified in place.
![Terraform apply complete](./screenshots/06-terraform-apply-done.png)

Terraform apply completed successfully; the NSG rule is now restricted.
> **Note:** the dynamic public IP changed between sessions (ISP-assigned), causing a connection timeout on a later day. This was diagnosed by re-running the 'ifconfig.me' check, comparing it against the currently allowed NSG rule, and re-applying with the new IP - a realistic operational consequence of IP-based allow-listing.
---
Day 2 - Encryption and a Web Application Firewall
Goal: expose the application publicly for the first time, close the plaintext HTTP gap with real TLS, and add a Web Application Firewall to block known attack patterns before they reach the application.
### Step 1: Confirm the App Is Alive, But Not Yet Exposed
Using the identity-verified SSH channel from Day 1, a local tunnel confirmed the FastAPI application was running correctly on the VM, without exposing it publicly:
```powershell
az ssh config --resource-group rg-lee --name vm-lee --file azssh_config
ssh -F azssh_config -L 8000:localhost:8000 <vm-ip>
```
![SSH tunnel](./screenshots/07-tunnel.png)

SSH tunnel established from the local machine to the app's internal port (8000) on vm-lee.
```powershell
curl.exe http://localhost:8000/entries
```
![App entries via tunnel](./screenshots/08-entries-http.png)

Seeded journal entries returned as JSON, confirming the application itself is healthy while still unreachable from the public internet.
### Step 2: Create the Public Proxy Host
A Proxy Host was created in NPMplus mapping the VM's public FQDN to the application's internal address, with TLS deliberately left disabled at this stage:
Domain: 'lee.westeurope.cloudapp.azure.com'
Forward Hostname/IP: '127.0.0.1'
Forward Port: '8000'
![Proxy Host config](./screenshots/09-Proxy-Host-config.png)

Proxy Host configuration in NPMplus routing the public domain to the internal FastAPI application.
### Step 3: Confirm the Plaintext Gap
```powershell
curl.exe -i "http://lee.westeurope.cloudapp.azure.com/entries"
```
![Plain HTTP 200](./screenshots/10-HTTP-request-before-200.png)

200 OK returned over unencrypted HTTP - full JSON response readable by anything on the network path.
### Step 4: Enable Real TLS
A Let's Encrypt certificate was requested directly through the NPMplus TLS tab, with Force HTTPS enabled to redirect all plaintext traffic:
![TLS setup](./screenshots/12-TLS-setup.png)

NPMplus TLS tab: requesting a new Let's Encrypt certificate with Force HTTPS enabled.
```powershell
curl.exe -i https://lee.westeurope.cloudapp.azure.com/entries
curl.exe -i "http://lee.westeurope.cloudapp.azure.com/entries"
```
![HTTP redirect 301](./screenshots/11-HTTP-request-after-301.png)

301 Moved Permanently returned for the plain HTTP request, redirecting to HTTPS.
![HTTPS 200 and HTTP 301 pair](./screenshots/13-after-TLS-200-301.png)

Side-by-side confirmation: HTTPS returns 200 OK with a valid certificate; HTTP now redirects (301) instead of serving content directly.
### Step 5: Enable the Web Application Firewall
Before enabling the WAF, two known attack payloads were sent to confirm they passed through unobstructed:
```powershell
curl.exe -i "https://lee.westeurope.cloudapp.azure.com/entries?id=1+UNION+SELECT+*+FROM+users"
curl.exe -i "https://lee.westeurope.cloudapp.azure.com/entries?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```
![SQLi and XSS before WAF](./screenshots/14-SQL-injection-XSS-before-WAF.png)

Both a SQL injection payload and an XSS payload return 200 OK with no WAF active - the gap being demonstrated.
CrowdSec's bouncer was registered against the NPMplus proxy:
```bash
sudo docker exec crowdsec cscli bouncers add npmplus
```
![CrowdSec bouncer enable](./screenshots/15-CrowdSec-bouncer-enable.png)

CrowdSec bouncer registration, producing a one-time API key (redacted) used to authorize NPMplus to query CrowdSec's decision engine.
The generated API key was inserted into the CrowdSec configuration, and the container restarted to apply it:
```bash
sudo nano /opt/npmplus/crowdsec/crowdsec.conf
#   ENABLED=true
#   API_URL=http://127.0.0.1:8080
#   APPSEC_URL=http://127.0.0.1:7422
#   API_KEY=<redacted>

cd /opt/npmplus && sudo docker compose restart npmplus
```
![crowdsec.conf before](./screenshots/16-crowdsec-before.png)

crowdsec.conf prior to editing - ENABLED and API_KEY fields still at their default/placeholder state.
![crowdsec.conf edited](./screenshots/17-crowdsec-edited.png)

crowdsec.conf after editing - ENABLED=true and API_KEY populated with the bouncer's key.
### Step 6: Investigate an Inconsistent Block Result
Re-sending the original two payloads after enabling the WAF produced an unexpected, inconsistent result: the XSS payload was blocked ('403 Forbidden'), but the SQL injection payload still returned '200 OK', despite CrowdSec's own alert log showing both had been detected with an identical anomaly score of 40.
```bash
sudo docker exec crowdsec cscli alerts list
```
![CrowdSec alert list](./screenshots/18-CrowdSec-alert-list.png)

CrowdSec alert log showing both attacks detected (anomaly score 40) but with no active "decisions" recorded for either - the first clue that detection and enforcement were not yet aligned.
WAF signature matching is encoding-sensitive; + -encoded payloads bypassed detection while percent-encoded equivalents were blocked – a reminder that WAFs provide pattern-based defense, not a guarantee against all encodings of the same attack

![SQL not blocked, XSS blocked](./screenshots/19-sql-notblocked-xxs-blocked.png)

Re-test after enabling the WAF: the XSS payload returns 403 Forbidden, while the SQL injection payload still returns 200 OK.
To diagnose this, the AppSec configuration files inside the CrowdSec container were inspected, to check whether SQL injection detection was running out-of-band (log-only) rather than in-band (blocking):
```bash
sudo docker exec crowdsec cat /etc/crowdsec/appsec-configs/crs-inband.yaml
sudo docker exec crowdsec cat /etc/crowdsec/appsec-configs/crs.yaml
```
![crs-inband local config](./screenshots/20-crs-inband-local.png)

Both the in-band (blocking) and out-of-band (alert-only) AppSec configs reference the same crowdsecurity/crs ruleset - ruling out a pipeline/routing misconfiguration.
![Investigating the ruleset](./screenshots/21-looking-for-ruleset-mistake.png)

Investigation into the CRS ruleset behavior to isolate why one payload type was blocked and the other was not.
### Step 7: Root Cause - Encoding-Sensitive Rule Matching
The two original payloads differed in how they encoded spaces: the SQL injection payload used literal '+' characters, while the XSS payload used standard percent-encoding throughout. Re-sending the SQL injection payload with proper percent-encoding ('%20') instead of '+' resulted in an immediate block:
```powershell
curl.exe -i "https://lee.westeurope.cloudapp.azure.com/entries?id=1%20UNION%20SELECT%20*%20FROM%20users"
```
![SQL and XSS now 403](./screenshots/22-sql-xxs-403-forbidden.png)

The percent-encoded SQL injection payload is now blocked with 403 Forbidden, confirming the root cause was encoding-sensitive signature matching rather than a configuration fault.


Written explanation of the finding: '+' is a valid alternate encoding for a space in a URL query string and is decoded identically by the application, but the WAF's pattern-matching rule for this attack signature did not recognize the '+' form in real time, allowing a logically identical attack to bypass detection while its percent-encoded equivalent was blocked.
```bash
sudo docker exec crowdsec cscli alerts list
```
![All logged and blocked](./screenshots/24-all-logged-and-blocked.png)

Final alert list showing all four requests logged: the original '+'-encoded payloads (detected, not blocked) alongside the percent-encoded equivalents (detected and blocked).

### Step 8: Unplanned Finding - Real Internet Scan Traffic
While reviewing the alert log, a fifth, unprompted entry was found originating from 194.163.190.65 (Contabo GmbH, France)-an IP address not used at any point during this exercise. Inspection revealed a generic reconnaissance probe aimed at the root URI (/) with a low anomaly score of 5. The request utilized a User-Agent string identifying itself as Firefox 3.6.11 (a browser released in 2010), strongly indicating an automated scanning tool rather than a legitimate visitor. Within hours of the VM going public, automated internet scanners independently discovered the exposed endpoint with this decade-old spoofed User-Agent. This confirms that the WAF is actively capturing real-world threat traffic, rather than just the controlled test payloads sent during testing.
```bash
sudo docker exec crowdsec cscli alerts inspect 4
```
![Blocked FR scan investigation](./screenshots/25-blocked-FR-investigation.png)

Detailed inspection of the unsolicited scan: an unrelated IP hosted by Contabo GmbH probed the application's root path within hours of it becoming public, using a spoofed, obsolete User-Agent string.
> This was not a simulated test - it is unprompted traffic from the open internet, and stands as direct evidence that a publicly reachable endpoint is discovered and probed by automated actors almost immediately after exposure, independent of any action taken by the operator.
### Step 9: Reviewing CrowdSec's Data-Sharing Default
Before closing out Day 2, CrowdSec's community threat-intel sharing setting was checked, since it is enabled by default and shares detected attack signals with CrowdSec's central network:
```bash
sudo docker exec crowdsec cscli console status
```
![Console status](./screenshots/27-console-status.png)

Checking whether community threat-intel sharing is active, and making a deliberate decision on whether to keep it enabled for this environment.

---
### Day 3 - Identity-Based API Access

**Goal:** require a valid Entra ID identity token before any request reaches the application, replacing anonymous access to the API, and confirm that identity enforcement and the WAF are complementary rather than redundant.

#### Step 1: Register an Entra ID Application

The first attempt to register an application failed with `ERROR: Insufficient privileges to complete the operation`:

```powershell
$APP_ID = az ad app create --display-name learningsteps-oauth2-proxy `
    --sign-in-audience AzureADMyOrg `
    --query appId -o tsv
```

![Insufficient privileges error](./screenshots/28-app-registration-INSUFFICIENT-PRIVILEGES.png)

*Initial app registration attempt fails with an "Insufficient privileges" error.*

Root cause investigation showed this was **not** a missing Entra ID role, but a **display-name collision** in a shared classroom tenant: `az ad app create` found an existing application with the same display name and attempted to patch it instead of creating a new one. Ownership checks on both existing `learningsteps-oauth2-proxy` apps confirmed neither belonged to this account - one was orphaned (no owner at all), the other belonged to a classmate:

```powershell
az ad app list --display-name learningsteps-oauth2-proxy --query "[].{DisplayName:displayName, AppId:appId, ObjectId:id}" -o table
az ad app owner list --id <ObjectId> --query "[].userPrincipalName" -o tsv
```

![Ownership check root cause](./screenshots/28b-ownership-check-root-cause.png)

![Ownership check root cause continued](./screenshots/28c-ownership-check-root-cause.png)

*Listing all apps with the colliding display name and checking ownership confirms neither existing app belongs to this account - the true root cause of the "insufficient privileges" error.*

The fix was to use a unique display name, which registered cleanly:

```powershell
$APP_ID = az ad app create --display-name learningsteps-oauth2-proxy-lee `
    --sign-in-audience AzureADMyOrg `
    --query appId -o tsv
az ad app update --id $APP_ID --identifier-uris "api://$APP_ID"
az ad sp create --id $APP_ID
$SECRET = az ad app credential reset --id $APP_ID --query password -o tsv
$TENANT_ID = az account show --query tenantId -o tsv
```

![App registration created](./screenshots/28d-app-registration-created.png)

*Service Principal successfully created under a unique display name, avoiding the tenant-wide naming collision.*

![Confirm IDs](./screenshots/28e-confirm-id.png)

*Confirming $APP_ID, $TENANT_ID, and $SECRET all resolved to real, non-empty values before proceeding.*

Two required follow-up configuration steps - forcing v2.0-format access tokens, and exposing an API scope with a registered reply URL - both initially failed with `Bad Request` errors from Microsoft Graph due to a missing `Content-Type` header, which `az rest` does not always set automatically on Windows/PowerShell:

```powershell
az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" `
  --headers "Content-Type=application/json" `
  --body '{"api":{"requestedAccessTokenVersion":2}}'
```

![Token version set to v2](./screenshots/29-token-version-v2-set.png)

*Forcing v2.0-format access tokens, once the Content-Type header was explicitly specified.*

The reply URL PATCH additionally failed even with the header fix, due to a payload-parsing issue specific to `az ad app update`'s inline JSON handling on Windows; writing the JSON body to a file and referencing it with `@filename` resolved it:

```powershell
$redirectBody | Out-File -FilePath redirect.json -Encoding utf8 -NoNewline
az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" `
  --headers "Content-Type=application/json" `
  --body "@redirect.json"
```

![Scope PATCH](./screenshots/30a-scope-patch.png)

*Exposing the oauth2PermissionScopes API scope required for token requests.*

![Redirect URI PATCH](./screenshots/30b-redirect-uri-patch.png)

*Registering the HTTPS reply URL after working around the inline-JSON parsing issue via a file-based request body.*

#### Step 2: Configure and Start oauth2-proxy

oauth2-proxy was confirmed pre-installed but idle before configuration:

```bash
systemctl is-active oauth2-proxy
```

![oauth2-proxy inactive before configuration](./screenshots/31-oauth2proxy-inactive-before.png)

*oauth2-proxy service present but correctly inactive prior to receiving real credentials.*

Real credentials from Step 1 were inserted into the service's environment file, and the redirect URL was set:

```bash
sudo sed -i \
  -e "s#^OAUTH2_PROXY_CLIENT_ID=.*#OAUTH2_PROXY_CLIENT_ID=<app-id>#" \
  -e "s#^OAUTH2_PROXY_CLIENT_SECRET=.*#OAUTH2_PROXY_CLIENT_SECRET=<client-secret>#" \
  -e "s#^OAUTH2_PROXY_OIDC_ISSUER_URL=.*#OAUTH2_PROXY_OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant-id>/v2.0#" \
  -e "s#^OAUTH2_PROXY_OIDC_EXTRA_AUDIENCES=.*#OAUTH2_PROXY_OIDC_EXTRA_AUDIENCES=api://<app-id>#" \
  /etc/oauth2-proxy/oauth2-proxy.env

sudo sed -i "s#REPLACE_WITH_DOMAIN#lee.westeurope.cloudapp.azure.com#" /etc/systemd/system/oauth2-proxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now oauth2-proxy
```

![oauth2-proxy env configured](./screenshots/32-oauth2proxy-env-configured.png)

*Environment file populated with real Entra ID credentials (secret value redacted).*

![oauth2-proxy active](./screenshots/33-oauth2proxy-active.png)

*oauth2-proxy running and active with real credentials applied.*

> **Note:** an initial credential-reset value was only viewed (`echo $SECRET`) but never actually inserted into the VM's config before the service was started, leaving it running with a stale/invalid secret. This was caught before testing by explicitly `grep`-checking the deployed config value rather than assuming the `systemctl enable --now` success meant the credentials were correct - a useful verification habit: **a service reporting "active" only confirms it started, not that its configuration is correct.**

#### Step 3: Wire Identity Enforcement into NPMplus

Setting the Auth Request field to `oauth2proxy` initially failed to save, returning a raw HTML error instead of a JSON response:

![Auth Request attempt](./screenshots/34a-Auth-request.png)

*Setting the Proxy Host's Auth Request field to oauth2proxy.*

![Auth Request save error](./screenshots/34b-Auth-request-error.png)

*Save fails with "Unexpected token '<'... is not valid JSON" - the frontend received an HTML page instead of the expected API response.*

An `Auth Request Upstream` field (not mentioned in the handbook, likely specific to this NPMplus build) was confirmed safe to leave empty, since the upstream address is already supplied via container environment variable:

```bash
sudo docker exec npmplus env | grep -i AUTH_REQUEST
```

![Confirming the upstream env var](./screenshots/34c-Confirm-env-var.png)

*AUTH_REQUEST_OAUTH2PROXY_UPSTREAM already correctly set on the NPMplus container.*

NPMplus's own logs revealed the actual cause: CrowdSec's WAF was blocking NPMplus's **own** admin API request, since the SSH tunnel's traffic reaches NPMplus as `127.0.0.1`, which had been banned by an earlier appsec decision - the exact failure mode the Day 2 handbook had warned could recur:

```bash
sudo docker logs npmplus --tail 30
```

![NPMplus logs showing CrowdSec blocking its own request](./screenshots/34d-NPMplus-logs.png)

*Log line `[Crowdsec] denied '127.0.0.1' with 'ban' (by appsec)` on the exact PUT request attempting to save the Auth Request setting - the WAF was blocking its own management traffic.*

The documented workaround (temporarily disabling CrowdSec, saving the change, then re-enabling it) resolved this:

```bash
sudo sed -i 's/^ENABLED=.*/ENABLED=false/' /opt/npmplus/crowdsec/crowdsec.conf
cd /opt/npmplus && sudo docker compose restart npmplus
# ... save the Auth Request setting here ...
sudo sed -i 's/^ENABLED=.*/ENABLED=true/' /opt/npmplus/crowdsec/crowdsec.conf
cd /opt/npmplus && sudo docker compose restart npmplus
```

![Temporary WAF disable](./screenshots/34e-temp-fix.png)

*Temporarily disabling CrowdSec to allow the admin change to save.*

![WAF re-enabled](./screenshots/34f-enable-WAF.png)

*Re-enabling CrowdSec once the Auth Request configuration was saved successfully.*

#### Step 4: Test the Identity Gate

Unauthenticated requests, both with no token and with a garbage bearer token, were correctly redirected to Microsoft sign-in rather than reaching the application:

```powershell
curl.exe -i https://lee.westeurope.cloudapp.azure.com/
curl.exe -i -H "Authorization: Bearer garbage" https://lee.westeurope.cloudapp.azure.com/
```

![Unauthenticated request redirected to login](./screenshots/35-unauth-redirect-to-login.png)

*Both an unauthenticated request and one with an invalid bearer token return an identical 302 redirect to /oauth2/sign_in - a malformed token receives no special treatment.*

A real browser login initially failed with a `500 Internal Server Error` immediately after Microsoft authentication succeeded:

![Browser login attempt](./screenshots/37a-browser-login.png)

![500 error after login](./screenshots/37b-error.png)

*Microsoft authentication succeeds, but oauth2-proxy fails to complete the session with a 500 error.*

`journalctl` logs identified the exact cause: `neither the id_token nor the profileURL set an email` - the classroom Entra ID account's token did not populate a standard `email` claim, which oauth2-proxy required by default to identify the user:

```bash
sudo journalctl -u oauth2-proxy -n 50 --no-pager
```

![Log showing missing email claim](./screenshots/37c-log.png)

*Root cause identified: oauth2-proxy could not extract an email claim from this account's ID token.*

The fix mapped identity to the `preferred_username` claim instead (reliably populated for this account type) and allowed it to be treated as unverified:

```bash
sudo bash -c 'cat >> /etc/oauth2-proxy/oauth2-proxy.env << EOF
OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username
OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL=true
OAUTH2_PROXY_WHITELIST_DOMAIN=lee.westeurope.cloudapp.azure.com
EOF'
sudo systemctl restart oauth2-proxy
```

![Fixing the empty claim fields](./screenshots/37d-fix-empty-fields.png)

*Adding the missing claim-mapping and whitelist-domain settings.*

A fresh login attempt then completed successfully:

![Browser login success](./screenshots/37e-browser-login-success.png)

*Real Entra ID login completes and the application loads normally under the identity gate.*

#### Step 5: Re-test Day 2's WAF Now That Identity Is Layered On

The same SQL injection payload from Day 2 was sent unauthenticated, and then again from the already-authenticated browser session:

```powershell
curl.exe -i "https://lee.westeurope.cloudapp.azure.com/entries?id=1+UNION+SELECT+*+FROM+users"
```

![Unauthenticated retest returns 302, not 403](./screenshots/38-waf-retest-302-not-403.png)

*The same payload that returned 403 on Day 2 now returns 302 (redirect to login) - the Auth Request check runs before the WAF on this location, so an unauthenticated attacker never reaches the WAF at all.*

```
https://lee.westeurope.cloudapp.azure.com/entries?id=1+UNION+SELECT+*+FROM+users
```
*(pasted directly into the already-logged-in browser tab)*

![Authenticated retest still blocked by WAF](./screenshots/39-waf-retest-authenticated-403.png)

*With a valid session, the request passes the identity gate and reaches the WAF, which still correctly blocks it with 403 Forbidden.*

This confirms the core lesson of the day: **identity verifies who is making a request; the WAF verifies how the request behaves.** They operate at different layers and only see traffic that passed the layer in front of them - an anonymous attacker is stopped before ever reaching the WAF, while an attacker with a valid (or stolen) session is still caught by it. Removing either layer leaves a distinct, unrelated gap; neither one is redundant given the other.

---

### Day 4 - Data Isolation

**Goal:** migrate the database off the public internet onto Azure VNet Integration - reachable only from inside the virtual network - and practice a real, backup-first migration while doing it.

**Baseline:** the database was public from the very first deployment - `postgresql.tf` originally provisioned it with a wide-open firewall rule (`0.0.0.0`–`255.255.255.255`).

#### Step 1: Confirm the Database Is Public

A direct connection was attempted straight from a client machine - no VM, no tunnel:

```bash
psql "host=psql-lee.postgres.database.azure.com user=psqladmin dbname=learning_journal sslmode=require"
```

> **Note:** the local Windows machine's `psql` client was blocked from launching by Windows Smart App Control (a stricter, newer Windows security feature), with no clear unblock path available and no way to safely disable it (disabling Smart App Control is one-way and requires a full Windows reset). **Azure Cloud Shell** was used instead - a legitimate substitute here, since the point of this test is proving the database is reachable from *outside* the private network being built in Step 3, not specifically that the request comes from this physical laptop.

![DB public - confirmed reachable and listable](./screenshots/40-db-public-confirmed.png)

*Direct connection from outside the VNet (Azure Cloud Shell) succeeds and lists tables - confirming the database is fully public.*

#### Step 2: Back Up the Database

Client/server version compatibility was confirmed before dumping (Cloud Shell ships a compatible `pg_dump` by default):

```bash
pg_dump --version
```

![pg_dump version check](./screenshots/41-pgdump-version-check.png)

*Confirming a compatible pg_dump client version before attempting the dump.*

```bash
pg_dump "postgresql://psqladmin@psql-lee.postgres.database.azure.com/learning_journal?sslmode=require" > learningsteps_backup.sql
ls -lh learningsteps_backup.sql
```

![Backup verified non-empty](./screenshots/42-backup-verified-nonempty.png)

*Backup file created and confirmed non-empty (~16 KB) before proceeding - there is no undo once the migration runs.*

The backup was then downloaded from Cloud Shell to the local machine, to be used later for the restore step:

![Backup downloaded locally](./screenshots/43-backup-downloaded.png)

*Backup file downloaded from Cloud Shell to the local machine via the built-in file transfer option.*

#### Step 3: Migrate to VNet Integration (Backup-First Practice)

With a verified backup in hand, the disruptive migration was performed. A new delegated subnet and private DNS zone were added in `network.tf`:

```hcl
resource "azurerm_subnet" "db" {
  name                 = "snet-db"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]

  delegation {
    name = "postgresql"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_private_dns_zone" "postgres" {
  name                = "privatelink.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "postgres-dns-link"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.main.id
}
```

In `postgresql.tf`, the open firewall rule was removed and the server was set to private, delegated access:

```hcl
  public_network_access_enabled = false
  delegated_subnet_id           = azurerm_subnet.db.id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  depends_on                    = [azurerm_private_dns_zone_virtual_network_link.postgres]
```

`vm.tf`'s `depends_on` was updated to no longer reference the now-deleted firewall rule, preventing a "reference to undeclared resource" failure.

```bash
terraform plan
```

![Server will be replaced, public access disabled](./screenshots/44a-terraform-flexible_server.main-replaced-public_network_access_enabled-false.png)

*Plan confirms the PostgreSQL server will be replaced (delegated_subnet_id forces recreation), with public_network_access_enabled flipping from true to false.*

![New DNS zone and VNet link will be created](./screenshots/44b-terraform-private_dns_zone-virtual_network_link-will-be-created.png)

*The new private DNS zone and its VNet link are queued for creation, enabling internal-only name resolution for the database.*

![Old firewall rule will be destroyed](./screenshots/44c-terraform-firewall_rule.allow_all-will-be-destroyed.png)

*The original "allow all IPs" firewall rule is destroyed, since it becomes irrelevant once public access is disabled entirely.*

Critically, the plan showed the VM itself receiving only an in-place tag update, not a replacement - confirming the migration would not disturb the already-configured Docker/NPMplus/CrowdSec/oauth2-proxy stack on the VM.

```bash
terraform apply
```

![Migration applied successfully](./screenshots/45-terraform-apply-migration-done.png)

*Apply completes: the database is destroyed and recreated inside the private subnet, public access is closed, and the VM remains untouched throughout.*

#### Step 4: Restore and Verify Isolation

With the database now unreachable from outside the VNet, the backup was copied to the VM and restored from there, over the identity-verified SSH channel from Day 1:

```bash
scp -F azssh_config learningsteps_backup.sql <vm-ip>:/tmp/
```

![Backup copied to the VM](./screenshots/46a-backup-copied.png)

*Backup file transferred to the VM, the only place with network access to the now-private database.*

```bash
psql "host=psql-lee.postgres.database.azure.com user=psqladmin dbname=learning_journal sslmode=require" -f /tmp/learningsteps_backup.sql
```

![Restore executed](./screenshots/46b-restore-executed.png)

*Restore completes; COPY 2 confirms both seeded journal entries were successfully restored. The numerous "no privileges were granted" warnings are expected and harmless - they relate to internal PostgreSQL system-catalog grants that Azure's managed service does not permit re-granting, and do not affect application data.*

Isolation was then verified by repeating Step 1's exact connection attempt from outside the VNet:

```bash
psql "host=psql-lee.postgres.database.azure.com user=psqladmin dbname=learning_journal sslmode=require"
```

![External connection now fails to resolve](./screenshots/47-isolation-verified-external-fails.png)

*The hostname no longer resolves at all from outside the VNet ("could not translate host name") - a stronger and cleaner result than a mere connection refusal, since the private DNS zone serving this name simply does not exist outside the virtual network.*

#### Step 5: Confirm the App Recovered

Finally, the application itself - not just the database - was confirmed working, by requesting the live endpoint in a browser:

```
https://lee.westeurope.cloudapp.azure.com/entries
```

![App recovered with restored data](./screenshots/48-app-recovered-entries-restored.png)

*The application successfully serves both original seeded journal entries after the migration - confirming full recovery with zero data loss, and that the VM's connection string (built from the static server name rather than a live database attribute) survived the underlying server being replaced.*


---
# **4. Analysis & Submission Questions**

**Why is RBAC required in addition to a managed identity and the AADSSHLoginForLinux extension?**
Azure separates the management plane (control over cloud resources, e.g. Owner/Contributor) from the data plane (logging into the operating system itself). Even full subscription ownership does not grant OS-level login rights; the Virtual Machine Administrator Login role must be explicitly assigned, scoped to the specific VM resource, to close this gap deliberately rather than by default.

**Why must the NSG rule specify /32 rather than the bare IP address?**
`/32` in CIDR notation means "exactly one address, no range" - this is what restricts the rule to a single trusted host rather than an entire subnet.

**Why did the plain HTTP request return 301 instead of the JSON response after Step 4?**
Enabling Force HTTPS configures the reverse proxy to issue an HTTP redirect (301 Moved Permanently) for any request arriving unencrypted, rather than serving the response directly - ensuring no client can be served content over an unencrypted channel even by mistake.

**Why did one attack payload bypass the WAF while an equivalent one did not?**
The WAF's signature-matching rules for the SQL injection attack category did not recognize `+` as an equivalent encoding of a space, even though the backend application decodes `+` and `%20` identically. This is a real, known class of WAF-bypass technique (encoding-based evasion) and demonstrates that pattern/signature-based defenses provide probabilistic, not absolute, protection.

**Does the WAF bypass mean the application itself is vulnerable to SQL injection?**
Not necessarily, and this is an important distinction: the WAF is one layer of defense, separate from whether the application's own code uses parameterized queries (safe) or constructs raw SQL (exploitable). A WAF failing to block a payload does not, by itself, prove the underlying application is vulnerable - it only means that if the application were vulnerable, this specific bypass could reach it without being flagged in real time.

**Why did `az ad app create` fail with "Insufficient privileges" even though the account holds a valid Entra ID role?**
The error was misleading. The actual cause was a display-name collision with existing applications in a shared classroom tenant - Azure CLI attempted to patch an existing app with the same name rather than create a new one, and the account was not an owner of either existing app. Verifying with read-only ownership checks (`az ad app owner list`) before assuming a role/permissions problem was the key diagnostic step; a unique display name resolved it without any role change.

**Why did the browser login fail with a 500 error even after Microsoft authentication succeeded?**
oauth2-proxy requires an `email` claim by default to establish a user's session identity. This classroom Entra ID account's token did not populate a standard `email` claim, so oauth2-proxy had nothing to build a session from. Mapping identity to `preferred_username` (a claim reliably present for this account type) resolved it - a reminder that not every real-world identity provider or account type populates every "standard" claim a tool expects by default.

**Why did enabling the Auth Request setting in NPMplus initially fail to save?**
CrowdSec's WAF was blocking NPMplus's own admin API request (the SSH tunnel's traffic reaches NPMplus as `127.0.0.1`, previously banned by an earlier appsec decision from Day 2 testing) - the same interference pattern the Day 2 handbook explicitly warned could recur. This was not a configuration mistake in the Auth Request setting itself, but a security tool blocking its own management plane, diagnosed by reading the proxy's own logs rather than assuming the UI field was wrong.

**Why did the same attack payload return a different status code before and after Day 3's changes?**
Before Day 3, the WAF was the only layer inspecting the request, so a malicious payload was evaluated and blocked (`403`) regardless of who sent it. After Day 3, the Auth Request (identity) check runs *first* on the same location - an unauthenticated request is redirected to login (`302`) before it ever reaches the WAF, so the WAF never even evaluates it. This is not a security regression: an authenticated attacker's identical payload still reaches the WAF and is still blocked (`403`), proving both layers remain active - they simply inspect different, sequential slices of incoming traffic.

**Why did adding `delegated_subnet_id` and `private_dns_zone_id` force the database to be destroyed and recreated, rather than updated in place?**
These properties are only assignable at creation time for Azure Database for PostgreSQL Flexible Server - networking mode (public vs. VNet-delegated) is a foundational characteristic of the resource, not one Azure allows changing on a live server. This is why the exercise required a full backup-first approach rather than treating it as a simple toggle.

**Why did the local Windows `psql` client fail to run at all, and why was switching to Azure Cloud Shell an acceptable substitute rather than a workaround that weakens the exercise?**
Windows Smart App Control silently blocked the executable with no actionable unblock path short of a full OS reset. Cloud Shell is still a machine entirely outside the Azure VNet being built, so it demonstrates exactly the same property Demo 1 requires - public reachability from the open internet - without depending on a single local machine's security posture.

**Why did the restore need to happen from the VM rather than directly from a laptop?**
Once `public_network_access_enabled` was set to false, the database's DNS name only resolves inside the VNet via the newly created private DNS zone. The VM is the only resource in this environment that sits inside that VNet, making it the only place capable of reaching the database at all after the migration.

**Why did the application recover successfully without any manual reconfiguration, despite the database being fully destroyed and recreated?**
The VM's connection string was built from the statically-known server name (`psql-lee.postgres.database.azure.com`) rather than a live Terraform attribute tied to the old server's identity. Had it referenced the database's `.fqdn` output directly, that value would have become "known after apply," and since any change to `custom_data` forces VM replacement, the migration could have cascaded into destroying and recreating the entire VM - wiping the manually-installed Docker/NPMplus/CrowdSec/oauth2-proxy stack along with it. This was avoided by design.

### Explanation

Together, Day 1 and Day 2 demonstrate the principle of defense in depth applied to two different layers of the same system. Day 1 addressed the management plane: an identity-based, network-restricted SSH path replaced a globally reachable, key-based one, removing the most heavily automated class of internet attack (credential brute-forcing) as a viable path into the VM. Day 2 addressed the application's public-facing layer in three stages that build on one another - a public entry point was created, that entry point was encrypted end-to-end with a trusted certificate, and a Web Application Firewall was layered on top to inspect and block malicious request patterns before they reach the application code.

The exercise also surfaced two findings beyond the prescribed steps that reinforce this principle in practice rather than theory. The WAF encoding bypass showed that a security control can be correctly enabled, correctly configured, and still have exploitable gaps in its own detection logic - meaning a defender should verify a control's actual behavior against varied inputs rather than trusting that "enabled" means "complete protection." The unsolicited scan from Contabo GmbH showed that this is not a hypothetical concern: real automated reconnaissance reached this environment within hours of it becoming reachable at all, independent of anything the operator did to attract attention. Both findings support the same underlying lesson of the exercise: every layer of defense reduces risk, but no single layer - and no single day's work - eliminates it entirely.
