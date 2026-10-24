# Cloud locations

piikey can scan the files you keep in Microsoft 365 (SharePoint and OneDrive for work or school), OneDrive (personal), Google Drive, Dropbox and Box, next to the folders on this PC. A cloud folder is a location like any other: the Inventory records which of its files hold personal data, with counts per type and never the values.

|Provider|Ways to sign in|Who must approve|
|---|---|---|
|[Microsoft 365](#microsoft-365)|Sign in with a browser; App registration, whole tenant; App registration, selected sites|Browser: you, unless your organization lets only administrators approve apps. The two app ways: an administrator|
|[OneDrive](#onedrive) (personal)|Sign in with a browser|You|
|[Google Drive](#google-drive)|Sign in with a browser; Service account (Google Workspace)|Browser: you. Service account: a Workspace super administrator|
|[Dropbox](#dropbox)|Sign in with a browser|You|
|[Box](#box)|Sign in with a browser; App (client credentials)|Browser: you, unless your administrator has to enable the app. App: an administrator|

## How to add a cloud location

1. Open Settings > Connected accounts and choose Add account.
2. Pick a provider, pick how it signs in, and fill in what that way needs. The first field of every way is Account name: a name you give the account, unique among the accounts of that provider. It is the first part of every path of the account (`jan@acme.com › My Drive › Clients › a.docx`).
3. Choose Connect. A way that has a person sign in opens your browser; the other ways check their credentials once.
4. On the Inventory page choose Browse cloud... (beside Browse folder...) and pick a folder of the account. It becomes a location, with the same Monitor switch as a folder on this PC. A monitored cloud location is asked what changed every 5 minutes and when piikey starts. It does not use the file system watcher.

`piikey-cli account list`, `add`, `connect`, `remove` and `browse` do the same from a terminal. The flags are in the [API reference](api/README.md) (`accounts_list`, `account_add`, `account_connect`, `account_remove`, `account_browse`).

The window writes a cloud item's path as the account name and then the folders: `jan@acme.com › My Drive › Clients › a.docx`. The provider is told by its logo. The API, the CLI, the export report and `piikey-cli inventory ... --under` use the address form, which looks like the path of a network share: `\\<provider>\<account name>\<drive or site>\<folder>\<file>`, for example `\\Google Drive\jan@acme.com\My Drive\Clients\a.docx` or `\\Microsoft 365\Contoso\Finance\Shared Documents\x.xlsx`. In the Inventory tree each account is a top-level node with the provider's logo, next to the drives. Open on a cloud file opens its web page, and so does Open at this place in the findings view. Show in Explorer and Make masked copy are not offered for a cloud item.

## The ways to sign in

- **Sign in with a browser.** You sign in at the provider and allow piikey to read, through an app you or your administrator registered. piikey keeps a refresh token, so you sign in once. It reads what you can read.
- **App registration (Microsoft 365).** An app registered in your organization reads with its own credentials, without a person signing in. *Whole tenant* reads every SharePoint site; *selected sites* reads only the sites an administrator granted to the app, one by one.
- **Service account (Google Workspace).** A Google Cloud service account that a Workspace administrator authorized (domain-wide delegation) reads the Drive of each user you list, as that user.
- **App (client credentials) (Box).** A Box app that an administrator authorized reads as the app's Service Account or as one user you name.

## Who sets it up

You bring your own app. piikey ships no client secrets and no shared app registration with any provider, so no provider sees piikey as one app with many users. A person sets up the app once in the provider's console (the steps are below) and gives piikey its ID. In a company that is usually the IT administrator, who then gives the ID, and for the ways with a secret or key the secret or key, to the people who use piikey. Each provider can limit what an unverified app of yours may do; the notes under each provider say how.

## The redirect address

The browser ways sign in through a loopback listener on this PC: piikey listens on `127.0.0.1` on a port while you sign in, and the provider sends your browser back to it with a code. Each provider compares that address with what the app has registered by its own rules.

|Provider|Address piikey sends|What the app registers|
|---|---|---|
|Microsoft 365, OneDrive|`http://localhost:<free port>` (the listener is on `127.0.0.1`)|`http://localhost`, through the portal as a Mobile and desktop application: Microsoft ignores the port for `localhost`|
|Google Drive|`http://127.0.0.1:<free port>`|Nothing: a Desktop app client takes any loopback port|
|Dropbox|`http://127.0.0.1:53123/`|Exactly `http://127.0.0.1:53123/`, port and slash included|
|Box|`http://127.0.0.1:<free port>`|`http://127.0.0.1`: Box lets a loopback address use any port|

Sources: [Microsoft: redirect URI best practices and limitations](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url), [Google: OAuth 2.0 for desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app), [Box: setup with OAuth 2.0](https://developer.box.com/guides/authentication/oauth2/oauth2-setup), [Dropbox: OAuth guide](https://developers.dropbox.com/oauth-guide).

Dropbox signs in on one fixed port, `53123`. If another app already uses it on your PC, piikey says it could not listen on that port; close what uses it and try again.

## Microsoft 365

SharePoint sites and the OneDrive of a work or school account, through Microsoft Graph. A path reads `<account name> › <site or OneDrive> › <library> › <folder> › ...` in the window, and `\\Microsoft 365\<account name>\<site or OneDrive>\<library>\<folder>\...` as an address. For a person who signs in, the account lists their own OneDrive (as `OneDrive`), the sites they follow and the sites a search finds for them. The two app ways list SharePoint sites only, not the OneDrive of each person.

### Register the app (all three ways)

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com) as at least an Application Developer ([Microsoft: register an app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)).
2. Go to Entra ID > App registrations and choose New registration. Give it a name such as piikey. Single tenant only is fine as the supported account type.
3. Choose Register. On the Overview page copy the Application (client) ID and the Directory (tenant) ID.

### Sign in with a browser

1. In the app registration open Authentication > Add a platform > Mobile and desktop applications, enter `http://localhost` as the redirect URI (exactly that, no port and no path) and save ([Microsoft: register a desktop app](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-app-registration#add-a-platform-redirect-uri)). Microsoft ignores the port of a `localhost` address, so the free port piikey picks each time matches.
2. Open Authentication and, under Advanced settings (a newer portal puts it on the Redirect URI configuration tab), set Allow public client flows to Yes. This marks the app as a public client, which has no secret.
3. Open API permissions > Add a permission > Microsoft Graph > Delegated permissions and add `Files.Read.All` and `Sites.Read.All`. piikey also asks for `offline_access` (it keeps you signed in) and `User.Read` (already on a new registration) when you sign in.
4. `Files.Read.All` and `Sites.Read.All` do not need an administrator when delegated, so you can allow them at sign-in ([Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)). If your organization lets only administrators approve apps, the sign-in says so and piikey offers **Copy approval link**: send it to an administrator, who opens it and approves the app for the organization (or chooses Grant admin consent on the API permissions page). Then sign in again. The link is `https://login.microsoftonline.com/<tenant>/adminconsent?client_id=<Application (client) ID>` ([Microsoft: grant tenant-wide admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)).
5. In piikey add an account, pick Microsoft 365 and Sign in with a browser, fill in the fields below and choose Connect.

|Field in piikey|Where the value is|
|---|---|
|Account name|A name you choose|
|Tenant|Overview > Directory (tenant) ID, or a domain of the tenant such as `contoso.onmicrosoft.com`. `organizations` works only when the app registration allows accounts in any organizational directory|
|Application (client) ID|Overview > Application (client) ID|

### App registration, whole tenant

The app reads every SharePoint site of the tenant, with no one signed in. It needs an administrator.

1. Register the app as above. No redirect address and no public client setting are needed.
2. Open API permissions > Add a permission > Microsoft Graph > Application permissions and add `Sites.Read.All` and `Files.Read.All`.
3. An administrator chooses Grant admin consent for the tenant. Both application permissions need it ([Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)).
4. Give the app a credential, a certificate or a client secret (see below).
5. In piikey add an account, pick Microsoft 365 and App registration, whole tenant, fill in the fields below and choose Connect. Connect asks Microsoft for a token once, which shows that the credential works.

### App registration, selected sites

The app reads only the sites an administrator names, so it cannot see the rest of the tenant.

1. Register the app as above.
2. Add the application permission `Sites.Selected` (Microsoft Graph > Application permissions) and have an administrator grant admin consent. On its own it gives no access: each site is granted in step 4 ([Microsoft: selected permissions](https://learn.microsoft.com/en-us/graph/permissions-selected-overview)).
3. Give the app a credential, a certificate or a client secret (see below).
4. An administrator grants the app read access to each site. First get the site's ID. For `https://contoso.sharepoint.com/sites/Finance`, send `GET https://graph.microsoft.com/v1.0/sites/contoso.sharepoint.com:/sites/Finance`; the `id` in the answer (`contoso.sharepoint.com,<guid>,<guid>`) is the site ID ([Microsoft: get a site](https://learn.microsoft.com/en-us/graph/api/site-get)). Then send:
   ```http
   POST https://graph.microsoft.com/v1.0/sites/{site-id}/permissions
   Content-Type: application/json

   {
     "roles": ["read"],
     "grantedToIdentities": [{
       "application": {
         "id": "<Application (client) ID of the app>",
         "displayName": "piikey"
       }
     }]
   }
   ```
   The call needs `Sites.FullControl.All`. With an application token that is the permission of the caller's own app. With a delegated token the signed-in person must be an administrator, such as a SharePoint Administrator, and a member of the site ([Microsoft: create permission](https://learn.microsoft.com/en-us/graph/api/site-post-permissions)). Repeat for every site.
5. In piikey add an account, pick Microsoft 365 and App registration, selected sites, and list the sites in Sites, one address per line, such as `https://contoso.sharepoint.com/sites/Finance`. piikey cannot list what a `Sites.Selected` app was given, so it reads exactly the sites you list. A site the app was not granted is reported as not allowed.

### A certificate or a client secret

Pick one for the two app ways. A certificate is what Microsoft recommends for anything that lasts ([Microsoft: add credentials](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials)).

- **Certificate.** Make a key and a certificate as PEM files, for example with OpenSSL:
  ```sh
  openssl req -x509 -newkey rsa:2048 -nodes -keyout piikey.key -out piikey.crt -days 730 -subj "/CN=piikey"
  ```
  Open Certificates & secrets > Certificates > Upload certificate and upload `piikey.crt` (the portal takes `.cer`, `.pem` and `.crt`). Only the public certificate goes to Microsoft. piikey is given the paths of both files: the private key (an RSA key in a PEM file that is not password-protected) and the certificate. They stay where you keep them; keep the key where only the right people can read it.
- **Client secret.** Open Certificates & secrets > Client secrets > New client secret. The lifetime is at most 24 months, and Microsoft recommends less than 12. Copy the Value at once: it is never shown again. piikey keeps it protected by Windows DPAPI. When the secret expires, sign-in fails; make a new secret and add the account again.

|Field in piikey|Where the value is|
|---|---|
|Account name|A name you choose|
|Tenant|Overview > Directory (tenant) ID, or a domain of the tenant|
|Application (client) ID|Overview > Application (client) ID|
|Client secret|Certificates & secrets > Client secrets > Value (or give a private key file and a certificate file instead)|
|Private key file, Certificate file|The `.key` and `.crt` PEM files from the certificate step|
|Sites (selected sites only)|One site address per line|

## OneDrive

A personal Microsoft account's OneDrive (the account you use for Outlook.com or Xbox), through Microsoft Graph. A work or school OneDrive is under [Microsoft 365](#microsoft-365). A path reads `<account name> › OneDrive › <folder> › ...` in the window, and `\\OneDrive\<account name>\OneDrive\<folder>\...` as an address.

### Sign in with a browser

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com) and choose Entra ID > App registrations > New registration. You need a Microsoft Entra directory to hold the registration.
2. Under Supported account types choose Accounts in any organizational directory and personal Microsoft accounts, or Personal Microsoft accounts only. An app limited to one organization cannot sign in a personal account ([Microsoft: register an app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)). Choose Register and copy the Application (client) ID from Overview.
3. Open Authentication > Add a platform > Mobile and desktop applications, enter `http://localhost` as the redirect URI (no port and no path) and save, as under [Microsoft 365](#sign-in-with-a-browser).
4. On Authentication set Allow public client flows to Yes.
5. Open API permissions > Add a permission > Microsoft Graph > Delegated permissions and add `Files.Read`. piikey also asks for `offline_access` at sign-in. `Files.Read` needs no administrator ([Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)).
6. In piikey add an account, pick OneDrive, fill in the fields below and choose Connect. piikey sends the tenant `consumers`, so only personal accounts can sign in.

|Field in piikey|Where the value is|
|---|---|
|Account name|A name you choose|
|Application (client) ID|Overview > Application (client) ID|

## Google Drive

My Drive and every shared drive the signed-in person can see. A path reads `<account name> › My Drive › <folder> › ...` or `<account name> › <shared drive> › <folder> › ...` in the window, and `\\Google Drive\<account name>\My Drive\<folder>\...` or `\\Google Drive\<account name>\<shared drive>\<folder>\...` as an address. With a service account the top of the account lists one folder per user you list (the email address, that user's My Drive) and `Shared drives`.

Google Docs, Sheets and Slides have no file of their own, so piikey asks Google to export each one as a Word, Excel or PowerPoint file and scans that. Files in the bin are skipped.

### The restricted scope

piikey asks for one scope, `https://www.googleapis.com/auth/drive.readonly` (view and download your Drive files). Google classes it as a restricted scope ([Google: Drive API scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)). That has these effects for your own app:

- An app that uses a restricted scope has to go through Google's OAuth verification before it is offered to the public, and an app that stores restricted data on its servers needs a security assessment. You do not publish anything: the app is yours, you use it yourself and piikey stores nothing on a server, so neither applies. Without verification, Google shows the unverified app screen before the consent screen, and caps an unverified app at 100 new users ([Google: unverified apps](https://support.google.com/cloud/answer/7454865)).
- **Testing.** An app of the user type External with the publishing status Testing can be used only by the test users you add. Google gives it refresh tokens that expire after 7 days ([Google: using OAuth 2.0 to access Google APIs](https://developers.google.com/identity/protocols/oauth2#expiration)). You have to sign in to piikey again each week.
- **In production, unverified.** You can switch the status to In production without verification. The unverified app screen shows (choose to continue past it) and the 100-user cap applies. That is fine for one person or a small team.
- **Internal.** In a Google Workspace organization, an app of the user type Internal is for users of that organization only and needs no verification ([Google: unverified apps](https://support.google.com/cloud/answer/7454865)). Its refresh tokens are not limited to 7 days. This is the best choice for a company.

### Sign in with a browser

1. In the [Google Cloud console](https://console.cloud.google.com) create a project, or pick one.
2. Open the [API library](https://console.developers.google.com/apis/library), find Google Drive API and choose Enable.
3. Open Google Auth platform and set up the consent screen under Branding, Audience and Data Access ([Google: configure the consent screen](https://developers.google.com/workspace/guides/configure-oauth-consent)). Fill in the app name and your email. Under Audience choose Internal (Workspace) or External. For External keep the status Testing and add every person who will sign in as a test user, or publish it as described above. Under Data Access add the scope `https://www.googleapis.com/auth/drive.readonly`.
4. Open the [Clients page](https://console.developers.google.com/auth/clients), choose Create client, pick the application type Desktop app, give it a name and choose Create. Copy the client ID and the client secret. Google treats the secret of a desktop app as not confidential ([Google: OAuth 2.0 for desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app)). piikey still keeps it protected by Windows DPAPI. A Desktop app client needs no redirect address: it accepts a loopback address on any port.
5. In piikey add an account, pick Google Drive and Sign in with a browser, fill in the fields below and choose Connect.

|Field in piikey|Where the value is|
|---|---|
|Account name|A name you choose|
|Client ID|Clients page > the client > Client ID|
|Client secret|Clients page > the client > Client secret|

### Service account (Google Workspace)

A service account reads the Drive of the users you list, as each of them, with no one signing in. It needs a super administrator.

1. In the Google Cloud console create or pick a project and enable Google Drive API there, as above.
2. Open IAM & Admin > Service Accounts, choose Create service account, give it a name and finish. Note its email address.
3. Open the service account, open the Keys tab, choose Add key > Create new key, pick JSON and choose Create. The key file downloads once: keep it safe ([Google: create credentials](https://developers.google.com/workspace/guides/create-credentials#create_a_service_account_key)). Your organization may block creating keys with a policy.
4. Open the service account's Advanced settings and copy its Client ID (a number).
5. A super administrator opens the [Admin console](https://admin.google.com) > Security > Access and data control > API controls > Manage Domain Wide Delegation, chooses Add new, enters that Client ID, adds the scope `https://www.googleapis.com/auth/drive.readonly` and chooses Authorize. A change can take up to 24 hours to apply ([Google: domain-wide delegation](https://knowledge.workspace.google.com/admin/apps/control-api-access-with-domain-wide-delegation)).
6. In piikey add an account, pick Google Drive and Service account (Google Workspace), choose the key file, list the email addresses to read in Users, one per line, and choose Connect. A user outside the domain, or one the service account was not delegated for, is reported as not allowed.

|Field in piikey|Where the value is|
|---|---|
|Account name|A name you choose|
|Key file|The JSON key file from step 3|
|Users|The email addresses of the people whose Drive to read, one per line|

## Dropbox

The signed-in person's Dropbox. A path reads `<account name> › <folder> › ...` in the window, and `\\Dropbox\<account name>\<folder>\...` as an address.

### Sign in with a browser

1. Open the [Dropbox App Console](https://www.dropbox.com/developers/apps) and choose Create app.
2. Choose Scoped access, then the type of access ([Dropbox: OAuth guide](https://developers.dropbox.com/oauth-guide)): *Full Dropbox* reads everything in the account, *App folder* reads only the folder Dropbox makes for the app (under Apps), which is what you want if you only point piikey at a few files you put there. Name the app and create it.
3. On the Permissions tab tick `files.metadata.read` and `files.content.read` and choose Submit.
4. On the Settings tab, in the OAuth 2 section, add `http://127.0.0.1:53123/` as a redirect URI, exactly as written. Dropbox compares the address letter by letter, port and slash included. Set Allow public clients (Implicit Grant & PKCE) to Allow: piikey signs in with PKCE and needs no app secret.
5. Copy the App key from the Settings tab.
6. In piikey add an account, pick Dropbox, fill in the field below and choose Connect.

An app starts in development status, which lets only your own account connect. You can enable additional users on the app's page in the App Console, up to 500 in total. Beyond 50 linked users Dropbox wants you to apply for production status within two weeks ([Dropbox: developer guide](https://www.dropbox.com/developers/reference/developer-guide#production-approval)). For one person or a small team development status is enough.

|Field in piikey|Where the value is|
|---|---|
|Account name|A name you choose|
|App key|App Console > the app > Settings > App key|

## Box

The signed-in person's files, or the files of the Service Account or user a Box app acts as. A path reads `<account name> › <folder> › ...` in the window, and `\\Box\<account name>\<folder>\...` as an address, from Box's All Files.

### Sign in with a browser

1. Open the [Box Developer Console](https://app.box.com/developers/console), choose New App, select User as the app type (the OAuth 2.0 one) and create it ([Box: setup with OAuth 2.0](https://developer.box.com/guides/authentication/oauth2/oauth2-setup)).
2. On the Configuration tab add `http://127.0.0.1` as an OAuth 2.0 redirect URI. Box matches the address exactly but lets a loopback address use any port.
3. Under Application Scopes tick Read all files and folders stored in Box (`root_readonly`) ([Box: scopes](https://developer.box.com/guides/api-calls/permissions-and-errors/scopes)). piikey asks for that scope only.
4. Copy the Client ID and the Client secret from the OAuth 2.0 Credentials section of the Configuration tab. Box can ask you to turn on two-step verification before it shows the secret.
5. In some organizations an administrator has to enable an app before people can sign in to it: send the Client ID to a Box administrator, who adds it in the Admin Console under Platform ([Box: platform app approval](https://developer.box.com/guides/authorization/platform-app-approval)).
6. In piikey add an account, pick Box and Sign in with a browser, fill in the fields below and choose Connect.

|Field in piikey|Where the value is|
|---|---|
|Account name|A name you choose|
|Client ID|Developer Console > the app > Configuration > OAuth 2.0 Credentials > Client ID|
|Client secret|The same section > Client secret|

### App (client credentials)

A Box app reads without a person signing in. It needs an administrator.

1. In the Developer Console choose New App, select Server as the app type, keep Client Credentials Grant as the method and create it ([Box: setup with Client Credentials Grant](https://developer.box.com/guides/authentication/client-credentials/client-credentials-setup)).
2. On the Configuration tab, under Application Scopes, tick Read all files and folders stored in Box.
3. Decide whom the app acts as:
   - *The Enterprise* (the app's Service Account). The Service Account starts with an empty folder tree, so it reads only the folders that were shared with it. Share each folder with the Service Account's email address, shown in the App Details sidebar of the Configuration tab ([Box: service accounts](https://developer.box.com/guides/getting-started/users#service-account)).
   - *A user.* This reads that person's files. Set App Access Level to App + Enterprise Access and switch on Generate User Access Tokens (Additional Configuration) on the Configuration tab.
4. Save, then have an administrator authorize the app: they add its Client ID in the Admin Console under Platform > Platform Apps, or authorize it from the Configuration tab. Authorize again after every change of scope or access level ([Box: platform app approval](https://developer.box.com/guides/authorization/platform-app-approval)).
5. Copy the Client ID and Client secret from the Configuration tab.
6. In piikey add an account, pick Box and App (client credentials), fill in the fields below and choose Connect. Connect asks Box for a token once, which shows that the app is authorized.

|Field in piikey|Where the value is|
|---|---|
|Account name|A name you choose|
|Client ID|Configuration > OAuth 2.0 Credentials > Client ID|
|Client secret|The same section > Client secret|
|Act as|Enterprise ID or User ID (see below)|

The Enterprise ID is in the Admin Console under Account & Billing > Account Information, and the account menu of the web app has Copy Enterprise ID. A User ID is in the Admin Console under Users & Groups: open the user and read the ID in the summary (it is also the number in the address of the user's page). Your own is the Account ID on your Account Settings page ([Box: locating IDs](https://developer.box.com/platform/appendix/locating-values)).

## Limits

- piikey reads a file only up to 64 MB. A larger file is skipped.
- A Google Docs, Sheets or Slides file is exported to Word, Excel or PowerPoint to be scanned. Google refuses to export more than 10 MB, so a bigger one is skipped.
- Shortcuts, and Google files that have no Office format (forms, drawings, sites), are skipped.
- Two files in one Drive folder can have the same name. piikey shows the second as `name (2)`. A character Windows does not allow in a file name is shown as its full-width look-alike.
- When a provider asks piikey to slow down, piikey waits as long as it asks, up to a minute inside one call, and tries again. A longer wait ends the scan, and the next scan goes on. A scan or a call that fails for another reason says so in words (sign in again, no permission, folder gone, no connection).
- The first scan of a location lists everything, and after that piikey asks the provider what changed. A feed cannot always say where a moved or renamed file used to be, so a location that has not been listed in full for a week is listed in full again. That reads no file that did not change, and it removes what a move or rename left behind.

## Where things are stored

Everything is in the data folder, `%LOCALAPPDATA%\piikey`, readable only by your Windows user.

|File|What|
|---|---|
|`sources.json`|The accounts: provider, name, how each signs in, tenant, client or app ID, sites, users, the paths of key and certificate files. No secret and no token|
|`sources\<id>.token`|One file per account with its client secret and its tokens, protected with Windows DPAPI|
|`sources\cursors.json`|Where each cloud location's scan left off. A cursor older than 7 days is ignored, which means a full listing|

A private key file, a certificate file and a Google key file stay where you put them: piikey stores their paths, not a copy. Disconnecting an account deletes its settings, its secret and tokens and the cursors of its locations. piikey does not call the provider to revoke anything, so to withdraw the access there too, remove the app or its secret in the provider's console or in the account's list of connected apps.

What is sent: the sign-in, and read-only calls to the provider's API (list folders, ask what changed, download a file). A file is downloaded into memory, scanned and dropped. The Inventory keeps counts and paths only, and the values never leave your PC: the detection model runs on this PC, and piikey sends no file content, count or path anywhere. The connection uses Windows' own TLS, so it trusts your Windows certificate store, including a company's inspection certificate.

## Trademarks

Microsoft 365, SharePoint, OneDrive, Google Drive, Dropbox and Box are trademarks of their owners. piikey uses their names and logos only to identify the integrations, as each provider's brand guidelines allow. piikey is independent of these companies and not endorsed or sponsored by them; in particular, piikey is independent of Box, Inc. and its affiliates.

Google Drive is a trademark of Google Inc. Use of this trademark is subject to [Google Permissions](https://www.google.com/permissions/index.html).
