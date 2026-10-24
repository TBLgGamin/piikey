# Provider logos

Official logos of the cloud providers piikey can connect to. They are used only to
identify the matching integration (account rows, the provider picker, location rows,
the tree, and the details pane). Do not recolour, distort, crop, redraw or combine them.
Keep clear space around them (Microsoft publishes 1/4 of the icon size as the minimum;
Google and Dropbox state no figure, but require the logo to stay unaltered, and Dropbox
requires that our own name and logo are more prominent than theirs).

Names and logos are trademarks of their owners and are used only to identify the
integrations. No provider endorses or sponsors piikey.

All files were fetched on **2026-10-24** and are stored byte-for-byte as served
(no editing, no recolouring, no metadata stripping needed). None contains scripts,
external references or fonts.

| File | Provider | Dark or mono variant |
|---|---|---|
| `sharepoint.svg` | Microsoft SharePoint | none shipped |
| `onedrive.svg` | Microsoft OneDrive | none shipped |
| `microsoft365.svg` | Microsoft 365 | none shipped |
| `google-drive.svg` | Google Drive | none shipped |
| `dropbox.svg` | Dropbox (glyph) | none shipped as SVG (see below) |
| `box.svg` | Box | **missing**, see "Not obtained" |

## Microsoft: `sharepoint.svg`, `onedrive.svg`, `microsoft365.svg`

- **Source page:** Microsoft Fluent / Office UI Fabric "Office brand icons" (product icons),
  <https://developer.microsoft.com/en-us/fluentui#/styles/web/office-brand-icons>, from the
  `OfficeDev/office-ui-fabric-core` project, <https://github.com/OfficeDev/office-ui-fabric-core>
  (`src/data/brand-icons.json`).
- **Direct download URLs** (Microsoft's Office CDN, 48 px full-fidelity variant, one file each):
  - `https://res-1.cdn.office.net/files/fabric-cdn-prod_20240411.001/assets/brand-icons/product/svg/sharepoint_48x1.svg`
  - `https://res-1.cdn.office.net/files/fabric-cdn-prod_20240411.001/assets/brand-icons/product/svg/onedrive_48x1.svg`
  - `https://res-1.cdn.office.net/files/fabric-cdn-prod_20240411.001/assets/brand-icons/product/svg/m365_48x1.svg`
    (stored as `microsoft365.svg`)
- **Date fetched:** 2026-10-24.
- **Terms:** The icons are licensed under the Microsoft Fabric Assets License Agreement,
  <https://static2.sharepointonline.com/files/fabric/assets/license.txt>: a limited,
  royalty-free licence "solely for the purpose of developing for Office and other Office 365
  endpoints" (custom apps that connect to Microsoft 365 qualify), "not to be used for marketing
  purposes", conditioned on Microsoft's branding guidelines. Use the icons unmodified, never
  recolour, distort or crop them, and use them only to identify the Microsoft integration
  ([Microsoft 365 Trademark Guidelines](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/mscle/documents/presentations/FY26_Microsoft_365_trademark_guidelines.pdf):
  app icons are not logos, keep clear space of 1/4 of the icon size, minimum 16 px, put
  "Microsoft" before the app name on first mention).
- **Dark variant:** none. Microsoft ships a single full-colour icon per product at this size.
- **Which design:** these are the icons Microsoft publishes as SVG for developers. The Oct 2025
  Microsoft 365 icon refresh (<https://microsoft.design/articles/fluid-forms-vibrant-colors/>)
  is not offered as an official SVG download. `microsoft365.svg` is the current gradient
  Microsoft 365 icon. `sharepoint.svg` and `onedrive.svg` are the 2018-era designs from the
  same CDN, since the CDN has not been updated. Replace them if Microsoft publishes the new
  ones for developers.

## Google Drive: `google-drive.svg`

- **Source page:** <https://developers.google.com/workspace/drive/api/guides/branding>
  ("Use the Google Drive brand"). That page links the 2026 Drive logo as a PNG
  (`https://www.gstatic.com/images/branding/productlogos/drive_2026/v2/web-64dp/logo_drive_2026_color_2x_web_64dp.png`).
- **Direct download URL (SVG, same logo, Google's product-logo CDN):**
  `https://www.gstatic.com/images/branding/productlogos/drive_2026/v1/192px.svg`.
  The page itself offers PNG only. The SVG is the same 2026 artwork (a 512 px render of it
  matches the page's v1 and v2 PNGs).
- **Date fetched:** 2026-10-24.
- **Terms:** No pre-approval needed. Use is governed by the Google Drive API Terms of Service
  (<https://developers.google.com/workspace/drive/terms>). In your app you may use the logo
  to show that a file is stored in Google Drive or on a button that starts an action with
  Drive; you may resize it but make no other change; always use the full name "Google Drive";
  give attribution: "Google Drive is a trademark of Google Inc. Use of this trademark is
  subject to Google Permissions" (<https://www.google.com/permissions/index.html>).
- **Dark variant:** none.
- **Note:** the file has no `viewBox` (only `width="192" height="192"`); it was not edited.

## Dropbox: `dropbox.svg`

- **Source page:** Dropbox Brand Guidelines, <https://brand.dropbox.com/logo>. Its "Partner
  Info" / asset download link is the Dropbox shared folder
  <https://www.dropbox.com/scl/fo/6qjduc7j5ujf09f75w1p7/AFc217w49gnfwVNr64Bd1_A?rlkey=tkqw8jcoi7f24voc6577vakky&st=2l9cr2v5&dl=0>.
- **Direct download URL:** the same shared folder with `dl=1` (a ZIP); the file is
  `Logos/Dropbox/Glyph/Glyph_128.svg`:
  `https://www.dropbox.com/scl/fo/6qjduc7j5ujf09f75w1p7/AFc217w49gnfwVNr64Bd1_A?rlkey=tkqw8jcoi7f24voc6577vakky&st=2l9cr2v5&dl=1`
- **Date fetched:** 2026-10-24.
- **Terms:** Developer Brand Guidelines
  (<https://www.dropbox.com/developers/reference/branding-guide>) and Branding Guidelines
  (<https://www.dropbox.com/branding>): in an app you may use the Dropbox name and logo only to
  identify or direct a user to a Dropbox integration, only the approved logos from
  brand.dropbox.com, unmodified (no editing, recolouring, rotating or stretching), with your
  own name and logo more prominent than Dropbox's. Any other use (including marketing in
  print or broadcast) needs written approval from <brand@dropbox.com>.
- **Dark variant:** none as SVG. The kit has the glyph in Dropbox Blue `#0061FE` only
  (PNG sizes 16 to 128 and the one SVG). Dropbox's partner guidelines define "Blue Night"
  (`#3984FF`) for use on Graphite for accessibility, but ship no file in it.

## Not obtained: `box.svg`

- **Source pages:** Box Branding 101 (<https://support.box.com/hc/en-us/articles/360052362674-Box-Branding-101-Guidelines-and-Assets>)
  points to the Box brand asset kit (<https://cloud.app.box.com/v/ExternalBrandAssets>, folder
  "01 Box Corporate Logo") and the Box Brand Style Guide
  (<https://cloud.box.com/v/externalstyleguide>). The kit is a JavaScript Box shared folder
  with no direct file URLs, so it could not be downloaded from the command line.
- **Terms:** <https://www.box.com/legal/trademark> says that, unless a licence or other
  agreement with Box allows it, "third parties generally may not use any Box logo for any
  purpose", and that even to describe a relationship with Box a logo may not be used "in the
  absence of an agreement or express written authorization from Box". Contact the Box
  Partners team at <integrate@box.com> for that authorisation (and ask whether an
  integration badge exists), then download the logo from the asset kit above into `box.svg`.
  If a licence is granted, the required line is: "Box® is a registered trademark of Box, Inc.,
  and/or its affiliates in the United States and other countries", and the material must state
  that it is independent of Box.
- Until then, the UI shows the plain word "Box" with no logo. No unofficial copy was used.
