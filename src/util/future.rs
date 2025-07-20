use std::fmt;
use std::mem::swap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "async")]
use tokio::sync::oneshot::{self, Receiver, Sender};

#[cfg(not(feature = "async"))]
struct Sender<T>(Arc<Mutex<Option<T>>>);

#[cfg(not(feature = "async"))]
struct Receiver<T>(Arc<Mutex<Option<T>>>);

/// A promise for a value in the future
pub struct Future<T> {
    #[cfg(feature = "async")]
    rx: Receiver<T>,
    #[cfg(not(feature = "async"))]
    rx: Receiver<T>,
}

/// A provider for a Future's value
pub struct FutureProvider<T> {
    #[cfg(feature = "async")]
    tx: Sender<T>,
    #[cfg(not(feature = "async"))]
    tx: Sender<T>,
}

impl<T: Send> Future<T> {
    /// Creates a new future and its provider
    pub fn new() -> (Future<T>, FutureProvider<T>) {
        #[cfg(feature = "async")]
        let (tx, rx) = oneshot::channel();

        #[cfg(not(feature = "async"))]
        let (tx, rx) = {
            let shared = Arc::new(Mutex::new(None));
            (Sender(shared.clone()), Receiver(shared))
        };

        (Future { rx }, FutureProvider { tx })
    }

    /// Creates a future that returns a specific value
    pub fn single(value: T) -> Future<T> {
        let (mut provider, future) = Future::new();
        provider.put(value);
        future
    }

    /// Waits for a value and consumes the future
    #[cfg(not(feature = "async"))]
    pub fn get(self) -> T {
        loop {
            let guard = self.rx.0.lock().unwrap();
            if let Some(value) = guard.as_ref() {
                return value.clone();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(feature = "async")]
    pub async fn get(self) -> T {
        self.rx.await.unwrap()
    }

    /// Waits up to a certain duration for a value and consumes the future
    #[cfg(not(feature = "async"))]
    pub fn get_timeout(self, duration: Duration) -> Result<T, Future<T>> {
        let start = std::time::Instant::now();
        loop {
            let guard = self.rx.0.lock().unwrap();
            if let Some(value) = guard.as_ref() {
                return Ok(value.clone());
            }
            if start.elapsed() > duration {
                return Err(self);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(feature = "async")]
    pub async fn get_timeout(self, duration: Duration) -> Result<T, Future<T>> {
        match tokio::time::timeout(duration, self.rx).await {
            Ok(Ok(value)) => Ok(value),
            _ => Err(self),
        }
    }
}

impl<T: Send> FutureProvider<T> {
    /// Sets a value and unblocks the Future
    pub fn put(self, value: T) {
        #[cfg(feature = "async")]
        let _ = self.tx.send(value);

        #[cfg(not(feature = "async"))]
        *self.tx.0.lock().unwrap() = Some(value);
    }
}

impl<T> fmt::Debug for Future<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = "pending"; // Simplified, as we can't check easily
        f.write_str(&format!("Future({})", state))
    }
}

impl<T> fmt::Debug for FutureProvider<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = "pending"; // Simplified
        f.write_str(&format!("FutureProvider({})", state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn across_threads() {
        let (future, provider) = Future::<u32>::new();
        thread::spawn(move || provider.put(3));
        assert!(future.get_timeout(Duration::from_secs(1)).unwrap() == 3);
    }

    #[test]
    fn timeout() {
        let (future, _provider) = Future::<u32>::new();
        assert!(future.get_timeout(Duration::from_millis(1)).is_err());
    }
}
