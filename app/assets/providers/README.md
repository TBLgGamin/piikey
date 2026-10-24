# Provider logos

Official logos of the cloud providers piikey can connect to. They are used only to
identify the matching integration (account rows, the provider picker, location rows,
the tree, and the details pane). Do not recolour, distort, crop, redraw or combine them.
Keep clear space around them (Microsoft publishes 1/4 of the icon size as the minimum;
Google, Dropbox and Box state no figure, but require the logo to stay unaltered, and Dropbox
requires that our own name and logo are more prominent than theirs).

Names and logos are trademarks of their owners and are used only to identify the
integrations. piikey is independent of these companies and not endorsed by them.

All files were fetched on **2026-10-24** and are stored byte-for-byte as served (no editing,
no recolouring, no metadata stripping needed), except for one change of form in Box's two files,
described under Box. None contains scripts, external references or fonts.

| File | Provider | Dark or mono variant |
|---|---|---|
| `sharepoint.svg` | Microsoft SharePoint | none shipped |
| `onedrive.svg` | Microsoft OneDrive | none shipped |
| `microsoft365.svg` | Microsoft 365 | none shipped |
| `google-drive.svg` | Google Drive | none shipped |
| `dropbox.svg` | Dropbox (glyph) | none shipped as SVG (see below) |
| `box.svg`, `box-dark.svg` | Box | `box-dark.svg`: Box's white logo, for dark backgrounds |

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

## Box: `box.svg`, `box-dark.svg`

- **Source page:** Box Developer Branding Guidelines,
  <https://developer.box.com/platform/appendix/branding-guidelines> (source:
  <https://github.com/box/developer.box.com/blob/main/content/pages/platform/appendix/branding-guidelines.md>).
  Its "Approved logos" link is the Box shared folder <https://cloud.app.box.com/v/BoxCorporateLogo>,
  folder "Web and Screen use (RGB)".
- **Direct download URLs** (Box's own shared-file download):
  - `box.svg` is "Box Logo_Blue (0061D5).svg":
    `https://cloud.app.box.com/index.php?rm=box_download_shared_file&vanity_name=BoxCorporateLogo&file_id=f_693523938544`
  - `box-dark.svg` is "Box Logo_White (FFFFFF).svg":
    `https://cloud.app.box.com/index.php?rm=box_download_shared_file&vanity_name=BoxCorporateLogo&file_id=f_1814847335727`
- **Date fetched:** 2026-10-24.
- **Terms:** the Developer Branding Guidelines say: "Many apps feature a 'connect to cloud
  services' menu, or something similar. In this case, you should feel free to use our name and
  logo to help people find us." Use only the approved logos, "Don't alter the 'Box' logo in any
  way", don't use it or any part of it as the app's icon, and don't use the name or logo so that
  the app looks like an official Box application. The general trademark guidelines
  (<https://www.box.com/legal/trademark>) also ask that material using the marks says it is
  independent of Box, Inc.; the Settings section, `docs/sources.md` and the README say so.
- **Dark variant:** `box-dark.svg`, the white logo Box ships in the same kit, shown on the dark
  theme.
- **One change of form, none of the logo:** Box's files give the colour through a CSS class in a
  `<style>` element, which WinUI's SVG renderer does not apply (the logo drew black). The colour
  was moved onto the two paths as a `fill` attribute (`#0061d5`, `#fff`) and the `<defs>` with
  the style removed; the paths, the view box and the colour are unchanged, so the logo looks
  exactly as Box's. SHA-256 of the files as served: blue
  `357da1c808cd607783cb09d8eb03c2939cb553c8838e9edc5fe06b3bfca04ed1`, white
  `fbf3314b16bf0b6ae57c55a1bbcf5018a8ff160289ad67e52c55c314943a08b7`.
