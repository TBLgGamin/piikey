# piikey API

> Generated from the code by `cargo api-docs`: never edit this file by hand. Change a doc comment in the code, or the notes in [`prose.toml`](prose.toml).

[OpenAPI 3.1 file](openapi.json) · [Interactive reference](https://tblggamin.github.io/piikey/)

piikey has one JSON API. The app serves it on a named pipe and, while the local HTTP API is switched on (Settings > Developer access), on a port of this PC. `piikey-cli` is a client of the same API, with one subcommand per operation; without the app it answers in its own process.

**Getting started**

1. Turn on **Local HTTP API** in Settings > Developer access. It listens on `127.0.0.1` only (loopback), on port 7980 unless you change it, and only while the switch is on.
2. Get the token with `piikey-cli token`, or press **Copy token** in the same place. Send it as `Authorization: Bearer <token>`.
3. Call an operation with `POST /v1/<op>` and the request's fields as a JSON body. The op is the one in the path: an `op` in the body is ignored. `GET /v1/status` also works.

```powershell
$token = piikey-cli token
'{"texts":["mail jan@acme.nl"]}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/scan_text
```

In PowerShell, plain `curl` is an alias of `Invoke-WebRequest`, so the examples use `curl.exe`, and they pass the JSON through stdin so that PowerShell does not mangle its quotes. The reply is the envelope: `{"ok":true,"result":{"results":[[{"start":5,"end":16,"kind":"email","value":"jan@acme.nl"}]]}}`.

**This specification.** `GET /v1/openapi.json` answers this specification as JSON, and it is the one call that needs no token. It is served only while the HTTP API is on, and it still refuses an `Origin` header. Postman, Insomnia and similar tools can import `http://127.0.0.1:7980/v1/openapi.json` (change the port if you changed it in Settings). Other methods get 405.

**The hosted reference cannot send requests.** The page at https://tblggamin.github.io/piikey/ cannot call piikey on your PC, because piikey refuses every request that carries an `Origin` header, which is what a web page sends (403, token or not). Copy the examples into a terminal, or import the specification into a desktop tool.

**Named pipe.** The app also serves the same operations on `\\.\pipe\piikey-<USERNAME>`, where characters other than letters, digits, `.`, `_` and `-` in the name become `_`. Only local clients can connect. A request is the bytes `P`, `2`, `0`, `0`, a `u32` little-endian length, then the request JSON with the op named in the body, for example `{"op":"scan_text","texts":["mail jan@acme.nl"]}`. The reply is a status byte (0 ok, 1 error), three zero bytes, a `u32` little-endian length and the envelope. Version 1 of the framing is no longer accepted.

**The command line.** `piikey-cli` is a client of this same API: one subcommand per operation (`open` is `show_window`), and `--json` prints the result as the JSON shown here. It asks the app over the pipe first. Without the app it runs the operations in its own process (as `--local` does), except `protection`, `explorer_scan` and `show_window`, which answer `app_required`. Each operation below starts with its command line.

## Connecting

- **Base URL:** `http://127.0.0.1:7980`, loopback only. The port is the one set in Settings > Developer access, 7980 unless changed.
- **Token:** every call except `GET /v1/openapi.json` needs the header `Authorization: Bearer <token>`, and is answered with 401 without it. `piikey-cli token` prints the token, and Settings > Developer access copies it.
- **Web pages are refused:** a request with an `Origin` header comes from a web page and is answered with 403, token or not.
- **Calls:** `POST /v1/<operation>` with the operation's fields as a JSON object, and `GET /v1/status`. The operation is the path's: an `op` in the body is ignored. An operation refuses fields it does not know, except the ones that take no fields at all. `GET /v1/openapi.json` answers this reference as OpenAPI 3.1, without a token.
- **Named pipe:** the same operations go over `\\.\pipe\piikey-<USERNAME>` as JSON objects with the operation in an `op` field, for example `{"op":"scan_text","texts":["a"]}`. That is what `piikey-cli` uses.
- **Paths** in a request are absolute, a drive or a share (`C:\Users\jan`, `\\server\share`): a relative path is a `bad_request`. Offsets of text spans are UTF-8 byte offsets.
- **Size:** a request body of more than 64 MiB is refused with 413.

## Replies

Every reply is an envelope. A call that worked is answered with status 200 and `{"ok":true,"result":<value>}`; a call that failed with `{"ok":false,"error":{"code":"<code>","message":"..."}}` and a status that depends on what failed:

| Status | `code` | Meaning |
|---|---|---|
| 400 | `bad_request` | The request is wrong. |
| 401 | `bad_request` | A token is required: there is no `Authorization: Bearer <token>` header, or the token is wrong. |
| 403 | `bad_request` | The request has an `Origin` header: it comes from a web page, and no page may talk to piikey. |
| 404 | `not_found` | There is no such op, file or record. |
| 405 | `bad_request` | The method is not allowed for the path: an operation takes `POST` (`/v1/status` also `GET`), and `/v1/openapi.json` takes `GET` alone. |
| 409 | `app_required` | The request needs the piikey app to be running. |
| 409 | `busy` | What the request needs is in use. |
| 413 | `bad_request` | The body is over 64 MiB. |
| 500 | `io` | Reading or writing a file failed. |
| 500 | `vault` | The vault could not be opened, read or written. |
| 500 | `unsupported` | A file is in a format piikey cannot read. |
| 500 | `model` | The detection model is missing or failed. |
| 500 | `internal` | Something went wrong that the request did not cause. |

## Operations

| Operation | What it does |
|---|---|
| [`scan_text`](#scan_text) | What the detector finds in each text, without changing anything (the vault is left as it is, and stand-ins piikey issued are not counted). |
| [`anonymize`](#anonymize) | Masks the personal data in each text. |
| [`deanonymize`](#deanonymize) | Restores the masked values in each text. |
| [`scan_files`](#scan_files) | Scans files and folders (recursively). |
| [`anonymize_files`](#anonymize_files) | Masks files and folders into the folder `out`. |
| [`deanonymize_files`](#deanonymize_files) | Restores files and folders into the folder `out`. |
| [`subject_search`](#subject_search) | Which files hold the given values (a name, a phone number, an email address, ...); an empty `paths` means the inventory's folders. |
| [`vault_list`](#vault_list) | The vault's records, the newest first, whose original or stand-in holds `query` (any letter case; all of them without a query), of one type if `kind` says. |
| [`vault_forget`](#vault_forget) | Removes the records whose original or stand-in is one of `values`; the vault file is rewritten without them. |
| [`vault_export`](#vault_export) | Writes every record of the vault to a new file `path` (an existing file is an error). |
| [`vault_wipe`](#vault_wipe) | Removes every record of the vault; the key stays. |
| [`inventory_status`](#inventory_status) | The inventory in numbers. |
| [`inventory_list`](#inventory_list) | The inventory's files that hold personal data, the one with the most first, at and under `under`. |
| [`inventory_tree`](#inventory_tree) | The tiles of the inventory's tree at one level: what lies directly under `under`, or without it the drives and network shares that hold files with personal data (`C:`, with `C:\` as the path). |
| [`inventory_rescan`](#inventory_rescan) | Scans the inventory's folders (the locations it scans) now, and answers when the scan is over: the inventory scans only when it is asked to. |
| [`inventory_report`](#inventory_report) | Writes the inventory's findings to a new file `path`. |
| [`settings_get`](#settings_get) | The saved settings. |
| [`settings_set`](#settings_set) | Changes the given settings, validated as a whole. |
| [`kinds`](#kinds) | Every type of personal data. |
| [`api_token`](#api_token) | The token the HTTP API wants as `Authorization: Bearer <token>`; `rotate` makes a new one first. |
| [`model_status`](#model_status) | Where the detection model stands. |
| [`model_download`](#model_download) | Downloads the detection model. |
| [`status`](#status) | How piikey is doing. |
| [`protection`](#protection) | Switches protection (masking what goes to the protected sites and apps) on or off. |
| [`explorer_scan`](#explorer_scan) | Scans files and folders into the inventory as Explorer's "Scan for personal data" does, and shows the result in a dialog in the app's window, which opens if it is hidden. |
| [`show_window`](#show_window) | Brings the app's window forward, opening it when it is closed. |

### Text

Find, mask and restore personal data in texts.

#### `scan_text`

What the detector finds in each text, without changing anything (the vault is left as it is, and stand-ins piikey issued are not counted).

CLI: `piikey-cli scan [--fail-on KINDS|any] [--no-record] [PATH...]` (no PATH: the UTF-8 text on stdin is the one text sent)

`start` and `end` are UTF-8 byte offsets into the text as you sent it, not character positions.

Without the detection model only patterns are found (emails, phone numbers, IBANs, cards and so on); names and places need it (`model_status`, `model_download`). Types switched off in Settings are not looked for.

`piikey-cli scan --fail-on` exits 1 when a listed type is found; the API has no such switch, check the result.

`POST /v1/scan_text`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `texts` | `string[]` | yes | The texts to look in. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `results` | [`Span[][]`](#span-schema) | yes | One list per text, in the order the texts were given. |

**Example**

```powershell
$token = piikey-cli token
'{"texts":["mail jan@acme.nl"]}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/scan_text
```

#### `anonymize`

Masks the personal data in each text.

CLI: `piikey-cli anonymize [--out DIR] [PATH...]` (no PATH: stdin text, and the masked text goes to stdout)

Unlike `scan_text` this writes to the vault: a value that has no stand-in yet gets one, and `deanonymize` turns it back for as long as the vault holds the record.

Types switched off in Settings > Types of personal data stay in the text. A text that is already masked comes back unchanged for the types that follow a pattern (emails, phone numbers, IBANs and so on).

The texts come back in the order you sent them.

`POST /v1/anonymize`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `texts` | `string[]` | yes | The texts to mask. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `texts` | `string[]` | yes | The texts that came out, in the order they were given. |

**Example**

```powershell
$token = piikey-cli token
'{"texts":["mail jan@acme.nl"]}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/anonymize
```

#### `deanonymize`

Restores the masked values in each text. With `tolerant`, also stand-ins that came back with a typo and names that came back alone.

CLI: `piikey-cli deanonymize [--tolerant] [--out DIR] [PATH...]` (no PATH: stdin text, and the restored text goes to stdout)

It turns back every stand-in the vault holds, whichever text it appears in; text without stand-ins comes back as it was.

A stand-in whose record was forgotten (`vault_forget`, `vault_wipe`) stays as it is.

`POST /v1/deanonymize`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `texts` | `string[]` | yes | The masked texts to restore. |
| `tolerant` | `boolean` | no | Also restore stand-ins that came back with a typo, and names that came back alone.<br><br>Default: `false`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `texts` | `string[]` | yes | The texts that came out, in the order they were given. |

**Example**

```powershell
$token = piikey-cli token
'{"texts":["mail mila.visser@example.net"]}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/deanonymize
```

### Files

The same for files and folders.

#### `scan_files`

Scans files and folders (recursively). With `record`, what was found is also kept in the inventory.

CLI: `piikey-cli scan [--fail-on KINDS|any] [--no-record] [PATH...]`

Every path must be absolute (the CLI makes its arguments absolute for you). Folders are walked recursively and symbolic links are skipped. A file named twice, or inside a folder you also named, is scanned once.

Each call reads every file again; the incremental rule that skips unchanged files belongs to `inventory_rescan`. The result holds counts per type, never the values.

The CLI's `--no-record` is `"record": false`. `piikey-cli scan --fail-on` exits 1 when a listed type is found, and 3 when a file could not be read.

`POST /v1/scan_files`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `paths` | `string[]` | yes | The files and folders to scan, as absolute paths. |
| `record` | `boolean` | no | Whether to keep what was found in the inventory.<br><br>Default: `true`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `files` | [`Entry[]`](#entry-schema) | yes | One entry per file that was read, each file once. |
| `hits` | `integer` | yes | Values found in all of them. |

**Example**

```powershell
$token = piikey-cli token
'{"paths":["C:\\Users\\jan\\Documents"]}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/scan_files
```

#### `anonymize_files`

Masks files and folders into the folder `out`.

CLI: `piikey-cli anonymize [--out DIR] [PATH...]` (with PATHs, `--out DIR` is required)

`paths` and `out` must be absolute. Folders are walked recursively and each result keeps its place relative to the folder it was found under. Missing folders under `out` are created and a file already there is overwritten, but a result is never written over an input, and an `out` inside a folder you name is refused with `bad_request`.

A result that is text (from a PDF, an image or a mail) is written as `<name>.txt`.

One file that cannot be read does not stop the others: it is listed under `failed`, and the CLI then exits 3. The files are processed in the app's own scan pool, which leaves half the cores to the PC.

`POST /v1/anonymize_files`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `paths` | `string[]` | yes | The files and folders to mask, as absolute paths. |
| `out` | `string` | yes | The folder the masked files are written to, as an absolute path. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `written` | [`Moved[]`](#moved-schema) | yes | The files that were written. |
| `failed` | [`Failed[]`](#failed-schema) | yes | The files that could not be written. |

**Example**

```powershell
$token = piikey-cli token
'{"paths":["C:\\Users\\jan\\Documents"],"out":"C:\\Users\\jan\\Masked"}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/anonymize_files
```

#### `deanonymize_files`

Restores files and folders into the folder `out`.

CLI: `piikey-cli deanonymize [--tolerant] [--out DIR] [PATH...]` (with PATHs, `--out DIR` is required)

The same rules as `anonymize_files` for paths, `out`, results written as `.txt` and files that fail.

With `tolerant` a document is read one piece of text at a time, so typos and lone names are restored within each piece.

`POST /v1/deanonymize_files`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `paths` | `string[]` | yes | The files and folders to restore, as absolute paths. |
| `out` | `string` | yes | The folder the restored files are written to, as an absolute path. |
| `tolerant` | `boolean` | no | Also restore stand-ins that came back with a typo, and names that came back alone.<br><br>Default: `false`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `written` | [`Moved[]`](#moved-schema) | yes | The files that were written. |
| `failed` | [`Failed[]`](#failed-schema) | yes | The files that could not be written. |

**Example**

```powershell
$token = piikey-cli token
'{"paths":["C:\\Users\\jan\\Documents"],"out":"C:\\Users\\jan\\Restored"}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/deanonymize_files
```

### Subject search

Find the files that mention a person, for access requests.

#### `subject_search`

Which files hold the given values (a name, a phone number, an email address, ...); an empty `paths` means the inventory's folders.

CLI: `piikey-cli subject --value V [--value V ...] [PATH...]`

A value matches a file as a whole word in any letter case, or as the same value spelled another way: `+31 6 1234 5678` and `+31612345678` match, `06 1234 5678` does not. Without `paths` it searches the inventory's locations, so with no locations there is nothing to search.

Folders are walked recursively without following links. A blank value is a `bad_request`.

This operation is in the API and the CLI only; the app's window has no subject search.

`POST /v1/subject_search`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `values` | `string[]` | yes | The values that identify the person: a name, a phone number, an email address, ... |
| `paths` | `string[]` | no | The files and folders to look in, as absolute paths. Empty: the inventory's folders.<br><br>Default: `[]`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `matches` | [`SubjectMatch[]`](#subjectmatch-schema) | yes | The files that hold some of the values, the one with the most first. |

**Example**

```powershell
$token = piikey-cli token
'{"values":["Jan Jansen","jan@acme.nl"]}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/subject_search
```

### Vault

The values piikey swapped, and the stand-ins it issued for them.

#### `vault_list`

The vault's records, the newest first, whose original or stand-in holds `query` (any letter case; all of them without a query), of one type if `kind` says. `limit` is 100 unless given, at most 10,000.

CLI: `piikey-cli vault list [--query Q] [--kind KIND] [--limit N] [--offset N]`

The reply holds the original values: treat it as personal data. The field called `proxy` is the stand-in.

`kind` takes a type name from the `kinds` operation (letter case and surrounding spaces do not matter); any other name is a `bad_request`. `total` counts every record that matched, so page with `offset` until `offset + limit` reaches it.

`POST /v1/vault_list`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `query` | `string` | no | Only the records whose original or stand-in holds this text, in any letter case. |
| `kind` | `string` | no | Only the records of this type: a name that `kinds` lists. |
| `limit` | `integer` | no | How many records at most: 100 unless given, at most 10,000. |
| `offset` | `integer` | no | How many records to skip, the newest first.<br><br>Default: `0`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `records` | [`Record[]`](#record-schema) | yes | The records on this page, the newest first. |
| `total` | `integer` | yes | Every record that matched, not only the page. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/vault_list
```

#### `vault_forget`

Removes the records whose original or stand-in is one of `values`; the vault file is rewritten without them.

CLI: `piikey-cli vault forget VALUE...`

The values are matched against the original and the stand-in of each record. `forgotten` counts the records that went, so a value that is not in the vault counts 0 and is no error.

The vault file is rewritten without them: the values are gone from disk. This cannot be undone (`vault_export` first if you need a copy), and stand-ins of forgotten records are no longer turned back. The running app drops what it holds of those values too.

`POST /v1/vault_forget`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `values` | `string[]` | yes | The values to forget: originals or stand-ins. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `forgotten` | `integer` | yes | How many records were removed. |

**Example**

```powershell
$token = piikey-cli token
'{"values":["jan@acme.nl"]}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/vault_forget
```

#### `vault_export`

Writes every record of the vault to a new file `path` (an existing file is an error).

CLI: `piikey-cli vault export --out FILE [--format json|csv]`

`path` must be absolute and must not exist yet. The file holds every original value next to its stand-in in the clear, so keep it where you would keep the personal data itself.

JSON is an array of `{"kind","original","proxy"}` objects, CSV has the header `kind,original,proxy`; the records come in the order they were issued.

`POST /v1/vault_export`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | yes | The file to write, as an absolute path. It must not exist yet. |
| `format` | [`Format`](#format-schema) | no | How the file is written.<br><br>Default: `"json"`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `records` | `integer` | yes | How many records were written. |
| `path` | `string` | yes | The file that was written. |

**Example**

```powershell
$token = piikey-cli token
'{"path":"C:\\Users\\jan\\Downloads\\vault.json"}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/vault_export
```

#### `vault_wipe`

Removes every record of the vault; the key stays. Needs `confirm: true`.

CLI: `piikey-cli vault wipe --yes`

Without `"confirm": true` the call is a `bad_request` and nothing changes; the CLI's `--yes` sends it.

Every stand-in piikey issued stops turning back, and this cannot be undone. The key stays, so the vault keeps working. The app's window has no wipe; only the API and the CLI do.

`POST /v1/vault_wipe`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `confirm` | `boolean` | no | Must be `true`: without it nothing is removed and the call is a `bad_request`.<br><br>Default: `false`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `forgotten` | `integer` | yes | How many records were removed. |

**Example**

```powershell
$token = piikey-cli token
'{"confirm":true}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/vault_wipe
```

### Inventory

What the scans found in your locations: counts and paths, never the values.

#### `inventory_status`

The inventory in numbers.

CLI: `piikey-cli inventory status`

`roots` is empty until a location has been added in the app or with `settings_set`. The inventory scans only when asked (`inventory_rescan`, `scan_files`, `explorer_scan`, the app's Scan button) and, for a location with Monitor on, when the app sees it change.

While a scan runs, `scanning` says how far it is; poll this operation to follow `inventory_rescan` called from another client.

`POST /v1/inventory_status`

This operation takes no fields: any that are sent are ignored.

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `roots` | `string[]` | yes | The folders it scans when asked: the user's locations, none until one is added. |
| `monitored` | `string[]` | yes | The locations whose changes are scanned as they happen. |
| `files` | `integer` | yes | Files the inventory knows. |
| `files_with_pii` | `integer` | yes | Of those, the files that hold personal data. |
| `hits` | `integer` | yes | Values found in all of them. |
| `scanning` | [`Progress`](#progress-schema) or `null` | yes | Files scanned so far, while a scan runs; `null` otherwise. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/inventory_status
```

#### `inventory_list`

The inventory's files that hold personal data, the one with the most first, at and under `under`. `limit` is 100 unless given, at most 10,000.

CLI: `piikey-cli inventory list [--under PATH] [--limit N] [--offset N]`

Only files that hold at least one value are listed, the one with the most first and files with equally many by path. `under` must be absolute and limits the list to that file or folder and what is below it.

`total` counts every file that matched, so page with `offset`. The entries hold counts per type, never the values.

`POST /v1/inventory_list`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `under` | `string` | no | Only the files at and under this path, an absolute path. |
| `limit` | `integer` | no | How many files at most: 100 unless given, at most 10,000. |
| `offset` | `integer` | no | How many files to skip, the one with the most values first.<br><br>Default: `0`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `entries` | [`Entry[]`](#entry-schema) | yes | The files on this page, the one with the most values first. |
| `total` | `integer` | yes | Every file that matched, not only the page. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/inventory_list
```

#### `inventory_tree`

The tiles of the inventory's tree at one level: what lies directly under `under`, or without it the drives and network shares that hold files with personal data (`C:`, with `C:\` as the path).

CLI: `piikey-cli inventory tree [--under PATH]`

One level per call, the node with the most values first. Take the `path` of a node whose `is_dir` is true and send it as `under` to open it; a drive's path is `C:\`. `under` must be absolute.

The tree follows the computer's real folders, whichever location or scan a file came from.

`POST /v1/inventory_tree`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `under` | `string` | no | The folder to look under, an absolute path. Without it: the drives and network shares that hold files with personal data. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `nodes` | [`Node[]`](#node-schema) | yes | The tiles at this level of the tree. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/inventory_tree
```

#### `inventory_rescan`

Scans the inventory's folders (the locations it scans) now, and answers when the scan is over: the inventory scans only when it is asked to.

CLI: `piikey-cli inventory rescan`

It scans the inventory's locations (`inventory_status` lists them) and answers when the scan is over, however long that takes: give your client a long timeout. With no locations there is nothing to scan.

The scan is incremental: a file whose size and write time match its entry is not read, and a changed file that turns out to hold the same content is not detected again.

Progress is visible meanwhile in `inventory_status`.

`POST /v1/inventory_rescan`

This operation takes no fields: any that are sent are ignored.

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `files` | `integer` | yes | Files the inventory knows. |
| `files_with_pii` | `integer` | yes | Of those, the ones that hold personal data. |
| `hits` | `integer` | yes | Values found, of every type. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/inventory_rescan
```

#### `inventory_report`

Writes the inventory's findings to a new file `path`.

CLI: `piikey-cli inventory report --out FILE [--format json|csv]`

`path` must be absolute and must not exist yet. The report covers the whole inventory: every file that holds personal data or could not be checked, in path order.

CSV has one row per file: `path`, `status`, `hits`, a column for each type that occurs, and `scanned` as a UTC time. JSON has the same fields, with `counts` as an object. Never the values.

`POST /v1/inventory_report`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | yes | The file to write, as an absolute path. It must not exist yet. |
| `format` | [`Format`](#format-schema) | no | How the file is written.<br><br>Default: `"json"`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `rows` | `integer` | yes | How many rows were written. |
| `path` | `string` | yes | The file that was written. |

**Example**

```powershell
$token = piikey-cli token
'{"path":"C:\\Users\\jan\\Downloads\\inventory.json"}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/inventory_report
```

### Settings

What piikey is set to, the types of personal data, and the API token.

#### `settings_get`

The saved settings.

CLI: `piikey-cli settings get`

The reply has an `enabled` field (protection), but `settings_set` does not take it: switch protection with the `protection` operation. The app answers with the settings it holds at that moment.

`POST /v1/settings_get`

This operation takes no fields: any that are sent are ignored.

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | yes | Whether protection is on: piikey masks what goes to the protected sites and apps below. `settings_set` does not take it; the `protection` operation switches it. |
| `sites` | `string[]` | yes | The protected sites: host patterns, `example.com` or `*.example.com`. |
| `programs` | `string[]` | yes | The protected apps, as lowercase exe names, e.g. `chrome.exe`. |
| `disabled_kinds` | [`TypeName[]`](#typename-schema) | yes | Types of personal data piikey leaves alone in new text; empty means every type is masked. |
| `highlight` | [`Highlight`](#highlight-schema) | yes | When the field in focus is outlined if it holds personal data. |
| `explorer_menu` | `boolean` | yes | Whether Explorer's right-click menu offers "Scan for personal data". |
| `background` | `boolean` | yes | Whether closing the window leaves piikey running in the tray, with protection, the highlight, monitoring and the API still working. Off: closing the window quits piikey. |
| `inventory_roots` | `string[]` | yes | The inventory's locations: absolute folders it scans when asked. None until the user adds one. |
| `monitored_roots` | `string[]` | yes | Locations (each one of `inventory_roots`) whose file changes are scanned as they happen. None by default. |
| `http_api` | `boolean` | yes | Whether the app serves the local HTTP API on `127.0.0.1`. |
| `http_port` | `integer (1 to 65535)` | yes | The port of the local HTTP API, 1 to 65535. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/settings_get
```

#### `settings_set`

Changes the given settings, validated as a whole.

CLI: `piikey-cli settings set KEY=VALUE...` (the keys are the `guard.cfg` keys, except `enabled`; a list key repeats, `site=a site=b`, and an empty value empties the list)

The body holds the fields under `settings`. A field you leave out is unchanged; a list you send replaces the whole list. The patch is checked as a whole: when one value is invalid, nothing changes and the error names it. A monitored folder must be one of the inventory's folders after the same patch.

Folders must be absolute. `enabled` is refused: protection is switched with `protection`. The CLI's keys are singular (`site`, `program`, `disabled_kind`, `inventory_root`, `monitor_root`), the JSON fields plural (`sites`, `programs`, ...).

In the running app the change takes effect the way a click in Settings does (Explorer menu, highlight, inventory, HTTP API). Changing `http_api` or `http_port` answers first and then restarts the listener, so a new port applies from the next call.

`POST /v1/settings_set`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `settings` | [`SettingsPatch`](#settingspatch-schema) | yes | The settings to change. A setting that is left out stays as it is. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | yes | Whether protection is on: piikey masks what goes to the protected sites and apps below. `settings_set` does not take it; the `protection` operation switches it. |
| `sites` | `string[]` | yes | The protected sites: host patterns, `example.com` or `*.example.com`. |
| `programs` | `string[]` | yes | The protected apps, as lowercase exe names, e.g. `chrome.exe`. |
| `disabled_kinds` | [`TypeName[]`](#typename-schema) | yes | Types of personal data piikey leaves alone in new text; empty means every type is masked. |
| `highlight` | [`Highlight`](#highlight-schema) | yes | When the field in focus is outlined if it holds personal data. |
| `explorer_menu` | `boolean` | yes | Whether Explorer's right-click menu offers "Scan for personal data". |
| `background` | `boolean` | yes | Whether closing the window leaves piikey running in the tray, with protection, the highlight, monitoring and the API still working. Off: closing the window quits piikey. |
| `inventory_roots` | `string[]` | yes | The inventory's locations: absolute folders it scans when asked. None until the user adds one. |
| `monitored_roots` | `string[]` | yes | Locations (each one of `inventory_roots`) whose file changes are scanned as they happen. None by default. |
| `http_api` | `boolean` | yes | Whether the app serves the local HTTP API on `127.0.0.1`. |
| `http_port` | `integer (1 to 65535)` | yes | The port of the local HTTP API, 1 to 65535. |

**Example**

```powershell
$token = piikey-cli token
'{"settings":{"highlight":"always"}}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/settings_set
```

#### `kinds`

Every type of personal data.

CLI: `piikey-cli kinds`

The `kind` field of each item is the name that `vault_list`, `settings_set` (`disabled_kinds`) and `piikey-cli scan --fail-on` take. `enabled: false` means the type is switched off in Settings, which also applies to the CLI.

`POST /v1/kinds`

This operation takes no fields: any that are sent are ignored.

**Result**

A list of `TypeInfo`, each with these fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | [`TypeName`](#typename-schema) | yes | The name the API uses for the type. |
| `label` | `string` | yes | What a person calls it. |
| `group` | `string` | yes | The group it is listed under. |
| `enabled` | `boolean` | yes | Whether scans and masking look for it. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/kinds
```

#### `api_token`

The token the HTTP API wants as `Authorization: Bearer <token>`; `rotate` makes a new one first.

CLI: `piikey-cli token [--rotate]`

Without `rotate` the existing token is returned (one is made the first time). The token is in the data folder, so treat it like a password.

With `rotate` a new token replaces the old one, and the app restarts the HTTP API with it: use the new token from then on.

`POST /v1/api_token`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `rotate` | `boolean` | no | Make a new token first. The old one stops working.<br><br>Default: `false`. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes | The bearer token. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/api_token
```

### Model

The detection model.

#### `model_status`

Where the detection model stands.

CLI: `piikey-cli model status`

The app loads the model only while something needs it (protection or highlighting on, a monitored location, a scan running) and frees it afterwards, so `unloaded` is normal for a model that is downloaded.

`downloading` appears only when the app is downloading it.

`POST /v1/model_status`

This operation takes no fields: any that are sent are ignored.

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `state` | [`ModelState`](#modelstate-schema) | yes | Where the model stands. |
| `device` | [`Device`](#device-schema) or `null` | yes | Present while the model is loaded; `null` otherwise. |
| `error` | `string` or `null` | no | Why it failed, when it did. |
| `downloading` | [`Progress`](#progress-schema) or `null` | no | Only the app says it: the download it is running, in bytes. |
| `dir` | `string` | yes | The folder the model lives in. |

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/model_status
```

#### `model_download`

Downloads the detection model.

CLI: `piikey-cli model download` (it always downloads in its own process, and prints the progress in MB on stderr)

The reply comes when the download is finished. Over the pipe or HTTP the app does the download and the call waits until the model is ready, so give your client a long timeout. The model is about 340 MB.

Without the model only patterns are found.

`POST /v1/model_download`

This operation takes no fields: any that are sent are ignored.

**Result**

An empty object, `{}`.

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/model_download
```

### App

How piikey is doing, and what only the running app can do.

#### `status`

How piikey is doing.

CLI: `piikey-cli status`

This is the one operation that also answers `GET /v1/status`.

When the app is not running (the CLI in its own process), `app` is false and `protection` is `null`: protection is the app's.

`GET /v1/status` or `POST /v1/status`

This operation takes no fields: any that are sent are ignored.

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `app` | `boolean` | yes | Whether the app is running (it answers for itself, and says `true`). |
| `protection` | `boolean` or `null` | yes | Whether protection is on; `null` when the app is not running, as it is the app's. |
| `version` | `string` | yes | piikey's version. |
| `vault_records` | `integer` | yes | How many records the vault holds. |
| `model` | [`Model`](#model-schema) | yes | Where the detection model stands. |
| `highlight` | [`Highlight`](#highlight-schema) | yes | When the field in focus is outlined if it holds personal data. |
| `explorer_menu` | `boolean` | yes | Whether Explorer's right-click menu offers "Scan for personal data". |
| `monitoring` | `boolean` | yes | Whether any location is monitored. |
| `http_api` | `boolean` | yes | Whether the local HTTP API is switched on. |

**Example**

```powershell
$token = piikey-cli token
curl.exe -s -H "Authorization: Bearer $token" http://127.0.0.1:7980/v1/status
```

#### `protection`

Switches protection (masking what goes to the protected sites and apps) on or off. Needs the app.

CLI: `piikey-cli protection on|off` (needs the app)

Without the app the call answers `app_required` (HTTP 409).

The call returns when protection stands as asked. Turning it on can fail for a reason you have to fix (the certificate, the port); the error message says which, with code `internal`.

`POST /v1/protection`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `on` | `boolean` | yes | `true` switches protection on, `false` switches it off. |

**Result**

| Field | Type | Required | Description |
|---|---|---|---|
| `protection` | `boolean` | yes | Whether protection is on. |

**Example**

```powershell
$token = piikey-cli token
'{"on":true}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/protection
```

#### `explorer_scan`

Scans files and folders into the inventory as Explorer's "Scan for personal data" does, and shows the result in a dialog in the app's window, which opens if it is hidden. Needs the app. Answers when the scan is queued, not when it is over.

CLI: none (it is what the Explorer menu "Scan for personal data" uses)

Needs the app: without it the call answers `app_required`. At least one path is required, each must be absolute and exist (`not_found` otherwise).

The call returns when the scan is queued, not when it is over: follow it with `inventory_status`. The result opens in the app's window.

`POST /v1/explorer_scan`

**Request fields**

| Field | Type | Required | Description |
|---|---|---|---|
| `paths` | `string[]` | yes | The files and folders to scan, as absolute paths that exist. |

**Result**

An empty object, `{}`.

**Example**

```powershell
$token = piikey-cli token
'{"paths":["C:\\Users\\jan\\Documents"]}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/explorer_scan
```

#### `show_window`

Brings the app's window forward, opening it when it is closed. What a second start of `piikey.exe` asks of the app that runs. Needs the app.

CLI: `piikey-cli open` (needs the app)

Without the app the call answers `app_required`. It returns at once; the window comes forward on the app's own thread.

`POST /v1/show_window`

This operation takes no fields: any that are sent are ignored.

**Result**

An empty object, `{}`.

**Example**

```powershell
$token = piikey-cli token
'{}' | curl.exe -s -H "Authorization: Bearer $token" --data-binary '@-' http://127.0.0.1:7980/v1/show_window
```

## Schemas

The objects and values that the tables above point at.

### `Device` schema

What the loaded model runs on.

| Value | Meaning |
|---|---|
| `cpu` | The CPU alone. |
| `hybrid` | The CPU and the GPU together. |

### `Entry` schema

What a scan found out about one file.

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | yes | The file's path. |
| `size` | `integer` | yes | The file's size in bytes. |
| `modified` | `integer` | yes | The file's write time as Windows keeps it, a FILETIME: 100 ns ticks since 1601. With the size it says whether the file changed since the scan. 0 when it is not known: the file could not be read, so the next scan looks at it again. |
| `scanned` | `integer` | yes | When the scan ran, in seconds since the Unix epoch. |
| `status` | `"ok"` or `"unsupported"` or `"too_large"` or `"failed"` | yes | How far the file got in the scan. |
| `error` | `string` | no | Why the file failed. Present only when `status` is `failed`. |
| `hits` | `integer` | yes | Values found in the file, of every type. |
| `counts` | `object of integer` | yes | How many values of each type were found, as an object keyed by the type's name, the most first. |

### `Failed` schema

A file that could not be written, and why.

| Field | Type | Required | Description |
|---|---|---|---|
| `input` | `string` | yes | The file that could not be written. |
| `error` | `string` | yes | Why it could not be. |

### `Format` schema

How an export or a report is written.

| Value | Meaning |
|---|---|
| `json` | A JSON array with one object per row. |
| `csv` | RFC 4180 CSV with a header row. |

### `Highlight` schema

When the field you type in is outlined because it holds personal data.

| Value | Meaning |
|---|---|
| `off` | Never. |
| `always` | Whenever the field in focus holds personal data. |
| `hotkey` | When the hotkey is pressed (Ctrl+Alt+P), for the field in focus. |

### `Model` schema

`model_status`: the detection model.

| Field | Type | Required | Description |
|---|---|---|---|
| `state` | [`ModelState`](#modelstate-schema) | yes | Where the model stands. |
| `device` | [`Device`](#device-schema) or `null` | yes | Present while the model is loaded; `null` otherwise. |
| `error` | `string` or `null` | no | Why it failed, when it did. |
| `downloading` | [`Progress`](#progress-schema) or `null` | no | Only the app says it: the download it is running, in bytes. |
| `dir` | `string` | yes | The folder the model lives in. |

### `ModelState` schema

Where the detection model stands.

| Value | Meaning |
|---|---|
| `missing` | Not downloaded. |
| `unloaded` | Downloaded, loaded when it is needed. |
| `ready` | Loaded and detecting. |
| `failed` | Loading or running failed. |

### `Moved` schema

A file that was written.

| Field | Type | Required | Description |
|---|---|---|---|
| `input` | `string` | yes | The file that was read. |
| `output` | `string` | yes | The file that was written. |

### `Node` schema

A folder or a file of the tree, with what lies under it added up.

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | yes | Where it is. For a volume at the top of the tree, its root, such as `C:\`. |
| `name` | `string` | yes | The last component of the path, for display. A volume is called what Explorer calls it: the drive (`C:`) or the share (`\\server\share`). |
| `is_dir` | `boolean` | yes | Whether it is a folder. |
| `hits` | `integer` | yes | Values found in the files under it. |
| `files` | `integer` | yes | Files under it that hold any. |
| `counts` | `object of integer` | yes | How many values of each type were found, as an object keyed by the type's name, the most first. |

### `Progress` schema

How far a scan or a download is: `done` of `total`.

| Field | Type | Required | Description |
|---|---|---|---|
| `done` | `integer` | yes | How many are done. |
| `total` | `integer` | yes | How many there are in all (files for a scan, bytes for a download). |

### `Record` schema

A value and the stand-in piikey issued for it.

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | [`TypeName`](#typename-schema) | yes | The type of personal data, by the name `kinds` lists it. |
| `original` | `string` | yes | The value. |
| `proxy` | `string` | yes | The stand-in piikey issued for it. |

### `SettingsPatch` schema

A partial update of the settings, as `settings_set` carries it.

Every field that is present replaces the saved one, the others stay. All values are validated like typed input, and nothing changes if any of them is invalid. A field that is absent is not written, so a patch serialized and read back is the same patch.

| Field | Type | Required | Description |
|---|---|---|---|
| `sites` | `string[]` | no | Replaces `sites`; each entry is a host (`chat.example.com`), a wildcard (`*.example.com`: any subdomain, not the apex) or a pasted URL of which only the host is kept. Duplicates are dropped. |
| `programs` | `string[]` | no | Replaces `programs`; each entry is an exe name: a path stands for its file name, the name is lowercased and gets `.exe` when it has no extension. Duplicates are dropped. |
| `disabled_kinds` | [`TypeName[]`](#typename-schema) | no | Replaces `disabled_kinds`; each entry is a type name, an empty list clears it. |
| `highlight` | [`Highlight`](#highlight-schema) | no | Replaces `highlight`: `off`, `always` or `hotkey`. |
| `explorer_menu` | `boolean` | no | Replaces `explorer_menu`. |
| `background` | `boolean` | no | Replaces `background`. |
| `inventory_roots` | `string[]` | no | Replaces `inventory_roots`; each entry must be an absolute folder. |
| `monitored_roots` | `string[]` | no | Replaces `monitored_roots`; each entry must be one of the `inventory_roots` after this patch. |
| `http_api` | `boolean` | no | Replaces `http_api`. |
| `http_port` | `integer (1 to 65535)` | no | Replaces `http_port`; 1 to 65535. |

### `Span` schema

A value found in a text.

| Field | Type | Required | Description |
|---|---|---|---|
| `start` | `integer` | yes | UTF-8 byte offset of its first byte. |
| `end` | `integer` | yes | UTF-8 byte offset after its last byte. |
| `kind` | [`TypeName`](#typename-schema) | yes | The type of personal data, by the name `kinds` lists it. |
| `value` | `string` | yes | The value that was found, as it stands in the text. |

### `SubjectMatch` schema

A file that holds some of the values searched for.

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | yes | The file's path. |
| `values` | `integer[]` | yes | Which of the values searched for the file holds, as indexes into them, in order. |
| `count` | `integer` | yes | How many times the file holds them, of all the values it holds added up. A value that stands in the file as it was given and is also found by the detector counts once. |

### `TypeName` schema

A type of personal data, by the name the API uses: the `kind` field of a result, the entries of `disabled_kinds`. The `kinds` operation lists them with their group and whether each is on.

| Value | Meaning |
|---|---|
| `secret` | Secret |
| `url_credential` | URL password |
| `email` | Email |
| `iban` | IBAN |
| `credit_card` | Card number |
| `ipv6` | IPv6 address |
| `mac` | MAC address |
| `ipv4` | IPv4 address |
| `us_ssn` | SSN |
| `nl_bsn` | BSN |
| `phone` | Phone |
| `person` | Name |
| `person_alias` | Alias or nickname |
| `person_identifier` | Personal ID number |
| `person_attribute` | Personal trait |
| `person_role` | Role or title |
| `date_of_birth` | Date of birth |
| `phone_number` | Other phone number |
| `contact_handle` | Social handle |
| `postal_address` | Postal address |
| `location` | Place |
| `geo_location` | Coordinates |
| `device_identifier` | Device ID |
| `identifying_link` | Personal link |
| `account_identifier` | Account ID |
| `auth_secret` | Password |
| `bank_account` | Other bank account |
| `payment_card` | Other card number |
| `card_security` | Card security code |
| `financial_amount` | Amount of money |
| `document_identifier` | Document number |
| `document_reference` | Document reference |
| `vehicle_identifier` | Licence plate or VIN |
| `organization_name` | Organization |
| `organization_identifier` | Company number |
| `proper_name` | Other proper name |
| `health_data` | Health |
| `biometric_data` | Biometric data |
| `ethnic_origin` | Ethnic origin |
| `political_opinion` | Political opinion |
| `religion_or_belief` | Religion or belief |
| `sexual_orientation` | Sexual orientation |
| `trade_union` | Trade union |
| `criminal_offence` | Criminal record |
