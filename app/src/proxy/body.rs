//! Reading hudsucker bodies without extra crates: `hudsucker::Body` is a
//! plain `http_body::Body`, polled here frame by frame.

use std::{future::poll_fn, pin::Pin};

use hudsucker::{
    Body, Error as BodyError,
    hyper::body::{Body as _, Bytes},
};

/// Why a body could not be collected.
#[derive(Debug)]
pub(super) enum CollectError {
    /// More than the limit arrived.
    TooLarge,
    /// The connection failed or the data was corrupt (bad compression).
    Read(BodyError),
}

/// The next chunk of data; trailers are skipped. `None` at the end.
pub(super) async fn next_data(body: &mut Body) -> Option<Result<Bytes, BodyError>> {
    loop {
        match poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await? {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    return Some(Ok(data));
                }
            }
            Err(e) => return Some(Err(e)),
        }
    }
}

/// The whole body, or an error when it is longer than `limit` bytes.
pub(super) async fn collect(mut body: Body, limit: usize) -> Result<Vec<u8>, CollectError> {
    let mut out = Vec::new();
    while let Some(data) = next_data(&mut body).await {
        let data = data.map_err(CollectError::Read)?;
        if out.len() + data.len() > limit {
            return Err(CollectError::TooLarge);
        }
        out.extend_from_slice(&data);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use hudsucker::futures::stream;

    use super::*;

    fn body(chunks: &[&'static str]) -> Body {
        let items: Vec<Result<Bytes, BodyError>> = chunks
            .iter()
            .map(|chunk| Ok(Bytes::from_static(chunk.as_bytes())))
            .collect();
        Body::from_stream(stream::iter(items))
    }

    #[tokio::test]
    async fn collects_every_chunk_in_order() {
        let all = collect(body(&["ab", "", "cd", "e"]), 100).await;
        assert_eq!(all.ok().as_deref(), Some(b"abcde".as_slice()));
        let empty = collect(Body::empty(), 100).await;
        assert_eq!(empty.ok().as_deref(), Some(b"".as_slice()));
    }

    #[tokio::test]
    async fn the_limit_is_inclusive() {
        assert!(collect(body(&["abc"]), 3).await.is_ok());
        assert!(matches!(
            collect(body(&["ab", "cd"]), 3).await,
            Err(CollectError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn a_failing_stream_is_an_error() {
        let items: Vec<Result<Bytes, BodyError>> =
            vec![Ok(Bytes::from_static(b"ok")), Err(BodyError::Unknown)];
        let result = collect(Body::from_stream(stream::iter(items)), 100).await;
        assert!(matches!(result, Err(CollectError::Read(_))), "{result:?}");
    }
}
