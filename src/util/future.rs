//! Future abstraction for polling a value either synchronously or asynchronously

use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "async")]
use tokio::time::{sleep, Sleep};

/// Provides a value after some delay
pub trait FutureProvider<T> {
    fn poll_timeout(&self, duration: Duration) -> Result<T, crate::Error>;
}

/// Synchronous future
pub struct SyncFuture<T> {
    value: Arc<Mutex<Option<T>>>,
}

impl<T: Clone> SyncFuture<T> {
    pub fn new(value: T) -> SyncFuture<T> {
        SyncFuture {
            value: Arc::new(Mutex::new(Some(value))),
        }
    }
}

impl<T: Clone> FutureProvider<T> for SyncFuture<T> {
    fn poll_timeout(&self, _duration: Duration) -> Result<T, crate::Error> {
        let value = self.value.lock().map_err(|_| {
            crate::Error::Poison("Failed to lock value".to_string())
        })?;
        value.clone().ok_or_else(|| {
            crate::Error::Timeout
        })
    }
}

#[cfg(feature = "async")]
pub struct AsyncFuture<T> {
    sleep: Sleep,
    value: Arc<Mutex<Option<T>>>,
}

#[cfg(feature = "async")]
impl<T: Clone + Send + Sync + 'static> AsyncFuture<T> {
    pub fn new(value: T, duration: Duration) -> AsyncFuture<T> {
        AsyncFuture {
            sleep: sleep(duration),
            value: Arc::new(Mutex::new(Some(value))),
        }
    }
}

#[cfg(feature = "async")]
impl<T: Clone + Send + Sync + 'static> FutureProvider<T> for AsyncFuture<T> {
    fn poll_timeout(&self, duration: Duration) -> Result<T, crate::Error> {
        let value = self.value.lock().map_err(|_| {
            crate::Error::Poison("Failed to lock value".to_string())
        })?;
        if value.is_none() {
            return Err(crate::Error::Timeout);
        }
        Ok(value.clone().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn sync_future() {
        let future = SyncFuture::new(42);
        assert_eq!(future.poll_timeout(Duration::from_secs(1)).unwrap(), 42);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn async_future() {
        let future = AsyncFuture::new(42, Duration::from_millis(100));
        assert_eq!(future.poll_timeout(Duration::from_secs(1)).unwrap(), 42);
    }
}
