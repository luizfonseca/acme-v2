use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use serde::de::DeserializeOwned;

use crate::Result;
use crate::req::{Response, req_safe_read_body};

pub(crate) fn base64url<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(input)
}

/// How long to wait for the CA to check a challenge, or to issue a certificate
pub(crate) const POLL_TIMEOUT: Duration = Duration::from_secs(300);

/// What a poll found: done, or still in `status` (to ask again after `retry_after`, if the CA
/// said)
pub(crate) enum Polled<T> {
    Done(T),
    Pending {
        status: String,
        retry_after: Option<Duration>,
    },
}

/// Calls `check` until it's done, waiting `delay` in between (or what the CA asked for), for
/// up to `timeout`
pub(crate) fn poll<T>(
    delay: Duration,
    timeout: Duration,
    mut check: impl FnMut() -> Result<Polled<T>>,
) -> Result<T> {
    let deadline = Instant::now() + timeout;
    loop {
        let (status, retry_after) = match check()? {
            Polled::Done(done) => return Ok(done),
            Polled::Pending {
                status,
                retry_after,
            } => (status, retry_after),
        };
        let wait = retry_after.unwrap_or(delay);
        if Instant::now() + wait > deadline {
            return Err(format!("still {status} after {timeout:?}").into());
        }
        thread::sleep(wait);
    }
}

pub(crate) fn read_json<T: DeserializeOwned>(res: Response) -> Result<T> {
    let res_body = req_safe_read_body(res);
    debug!("{}", res_body);
    Ok(serde_json::from_str(&res_body)?)
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use super::{Polled, poll};

    const SHORT: Duration = Duration::from_millis(1);

    fn pending(retry_after: Option<Duration>) -> Polled<u32> {
        Polled::Pending {
            status: "pending".into(),
            retry_after,
        }
    }

    #[test]
    fn test_polling_stops_once_done() {
        let mut calls = 0;
        let done = poll(SHORT, Duration::from_secs(5), || {
            calls += 1;
            Ok(if calls < 3 {
                pending(None)
            } else {
                Polled::Done(calls)
            })
        });
        assert_eq!(done.unwrap(), 3);
    }

    #[test]
    fn test_polling_gives_up_at_the_deadline() {
        let start = Instant::now();
        let err = poll(SHORT, Duration::from_millis(50), || Ok(pending(None))).unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(err.to_string(), "still pending after 50ms");
    }

    #[test]
    fn test_polling_waits_as_the_ca_asks() {
        let mut calls = 0;
        let start = Instant::now();
        let done = poll(SHORT, Duration::from_secs(5), || {
            calls += 1;
            let wait = Some(Duration::from_millis(100));
            Ok(if calls < 2 {
                pending(wait)
            } else {
                Polled::Done(calls)
            })
        });
        assert_eq!(done.unwrap(), 2);
        assert!(start.elapsed() >= Duration::from_millis(100));

        // Asked to wait past the deadline
        let start = Instant::now();
        let far = Some(Duration::from_secs(3600));
        assert!(poll(SHORT, Duration::from_secs(5), || Ok(pending(far))).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
