//! What the reference says before the first operation: how to connect, what a reply is and what
//! the statuses mean. Everything here comes from the code that does it (`http`, `Code`, the
//! default port), so a change there changes the text and the fingerprint of the intro prose.

use std::fmt::Write as _;

use serde_json::{Map, Value, json};

use super::{PIPE, schema};
use crate::{
    api::{ApiError, Code, http},
    policy::DEFAULT_HTTP_PORT,
};

/// The path that answers this reference.
pub(super) const SPEC_ROUTE: &str = http::SPEC_ROUTE;

/// How one call can end badly: the status, the code of the error and what it means.
pub(super) struct Ending {
    pub status: u16,
    pub code: &'static str,
    pub meaning: String,
}

/// What each status is called in `components/responses`, in the order of the statuses.
pub(super) const RESPONSES: [(u16, &str); 8] = [
    (400, "BadRequest"),
    (401, "Unauthorized"),
    (403, "Forbidden"),
    (404, "NotFound"),
    (405, "MethodNotAllowed"),
    (409, "Conflict"),
    (413, "PayloadTooLarge"),
    (500, "InternalError"),
];

/// How every call can fail: by the codes of the errors an operation gives (with the status the
/// HTTP API answers them with), and by what the server refuses before an operation is reached.
/// The meaning of a code is its doc comment, which the `ErrorCode` schema carries.
pub(super) fn endings(components: &Map<String, Value>) -> Vec<Ending> {
    let meanings = components
        .get("ErrorCode")
        .and_then(|code| code.get("x-enumDescriptions"))
        .and_then(Value::as_object);
    let mut endings: Vec<Ending> = Code::ALL
        .into_iter()
        .map(|code| Ending {
            status: http::status_of(&ApiError::new(code, "")).as_u16(),
            code: code.as_str(),
            meaning: meanings
                .and_then(|all| all.get(code.as_str()))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        })
        .collect();
    // The refusals before an operation are all `bad_request`, and the status says why.
    let refused = |status: u16, meaning: String| Ending {
        status,
        code: Code::BadRequest.as_str(),
        meaning,
    };
    endings.extend([
        refused(
            401,
            "A token is required: there is no `Authorization: Bearer <token>` header, or the token is wrong.".to_owned(),
        ),
        refused(
            403,
            "The request has an `Origin` header: it comes from a web page, and no page may talk to piikey.".to_owned(),
        ),
        refused(
            405,
            format!(
                "The method is not allowed for the path: an operation takes `POST` (`/v1/status` also `GET`), and `{SPEC_ROUTE}` takes `GET` alone."
            ),
        ),
        refused(
            413,
            format!("The body is over {} MiB.", http::MAX_BODY / (1024 * 1024)),
        ),
    ]);
    // By status, and in the order of `Code::ALL` within one.
    endings.sort_by_key(|ending| ending.status);
    endings
}

/// The entry of `components/responses` for `status`: every way a call ends with it.
pub(super) fn response(status: u16, endings: &[Ending]) -> Value {
    let meanings: Vec<String> = endings
        .iter()
        .filter(|ending| ending.status == status)
        .map(|ending| format!("`{}`: {}", ending.code, ending.meaning))
        .collect();
    let mut response = json!({
        "description": meanings.join(" "),
        "content": {
            "application/json": {"schema": schema::reference("Failure")}
        }
    });
    // The headers that say what to do about it.
    let header = match status {
        401 => Some(("WWW-Authenticate", "`Bearer`.")),
        405 => Some(("Allow", "The methods the path allows.")),
        _ => None,
    };
    if let (Some((name, about)), Some(fields)) = (header, response.as_object_mut()) {
        fields.insert(
            "headers".to_owned(),
            json!({ name: {"description": about, "schema": {"type": "string"}} }),
        );
    }
    response
}

/// The intro of the reference, as `OpenAPI` `info.description` and as the top of the page:
/// Markdown whose headings are of the second level. The prose of the intro, when there is any,
/// follows the first paragraph.
pub(super) fn text(endings: &[Ending], prose: Option<&str>) -> String {
    let port = DEFAULT_HTTP_PORT;
    let mebibytes = http::MAX_BODY / (1024 * 1024);
    let mut out = String::from(
        "piikey has one JSON API. The app serves it on a named pipe and, while the local HTTP API is switched on (Settings > Developer access), on a port of this PC. `piikey-cli` is a client of the same API, with one subcommand per operation; without the app it answers in its own process.\n\n",
    );
    if let Some(prose) = prose {
        out.push_str(prose);
        out.push_str("\n\n");
    }
    let _ = write!(
        out,
        r#"## Connecting

- **Base URL:** `http://127.0.0.1:{port}`, loopback only. The port is the one set in Settings > Developer access, {port} unless changed.
- **Token:** every call except `GET {SPEC_ROUTE}` needs the header `Authorization: Bearer <token>`, and is answered with 401 without it. `piikey-cli token` prints the token, and Settings > Developer access copies it.
- **Web pages are refused:** a request with an `Origin` header comes from a web page and is answered with 403, token or not.
- **Calls:** `POST /v1/<operation>` with the operation's fields as a JSON object, and `GET /v1/status`. The operation is the path's: an `op` in the body is ignored. An operation refuses fields it does not know, except the ones that take no fields at all. `GET {SPEC_ROUTE}` answers this reference as OpenAPI 3.1, without a token.
- **Named pipe:** the same operations go over `{PIPE}` as JSON objects with the operation in an `op` field, for example `{{"op":"scan_text","texts":["a"]}}`. That is what `piikey-cli` uses.
- **Paths** in a request are absolute, a drive or a share (`C:\Users\jan`, `\\server\share`): a relative path is a `bad_request`. Offsets of text spans are UTF-8 byte offsets.
- **Size:** a request body of more than {mebibytes} MiB is refused with 413.

## Replies

Every reply is an envelope. A call that worked is answered with status 200 and `{{"ok":true,"result":<value>}}`; a call that failed with `{{"ok":false,"error":{{"code":"<code>","message":"..."}}}}` and a status that depends on what failed:

| Status | `code` | Meaning |
|---|---|---|
"#
    );
    for ending in endings {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} |",
            ending.status,
            ending.code,
            ending.meaning.replace('|', r"\|")
        );
    }
    out.truncate(out.trim_end().len());
    out
}

/// What the intro prose is reviewed against: the text above (without the prose), and the shape
/// of a failed reply.
pub(super) fn contract(endings: &[Ending], failure: &Value) -> Value {
    json!({
        "text": text(endings, None),
        "failure": failure,
    })
}
