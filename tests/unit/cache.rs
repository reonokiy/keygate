use super::*;
use std::{
    future::{Future, poll_fn},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Poll,
};
struct Probe {
    entry: Versioned,
    fail: AtomicBool,
    reads: AtomicUsize,
    hang: bool,
    missing: bool,
}
#[async_trait::async_trait]
impl Store for Probe {
    async fn get(&self, _: Uuid) -> Result<Option<Versioned>, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.missing {
            return Ok(None);
        }
        if self.fail.load(Ordering::SeqCst) {
            Err(StoreError::Unavailable)
        } else {
            Ok(Some(self.entry.clone()))
        }
    }
    async fn list(&self) -> Result<Vec<Versioned>, StoreError> {
        unreachable!("authorizer must not list applications")
    }
    async fn put(&self, _: &Application, _: u64) -> Result<(), StoreError> {
        unreachable!("authorizer must never write")
    }
}
fn probe() -> Arc<Probe> {
    Arc::new(Probe {
        entry: Versioned {
            app: Application {
                id: Uuid::new_v4(),
                name: "app".into(),
                keys: vec![],
            },
            version: 1,
        },
        fail: AtomicBool::new(false),
        reads: AtomicUsize::new(0),
        hang: false,
        missing: false,
    })
}
#[tokio::test]
async fn cache_hits_do_not_extend_revocation_deadline_or_use_stale_records() {
    let store = probe();
    let id = store.entry.app.id;
    let auth = Authorizer::new(store.clone(), Duration::from_secs(30), 16);
    auth.app(id).await.unwrap();
    let original = auth.cache.get(&id).await.unwrap().fetched_at;
    store.fail.store(true, Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(auth.app(id).await.unwrap().unwrap().id, id);
    }
    assert_eq!(store.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        auth.cache.get(&id).await.unwrap().fetched_at,
        original,
        "hits must not slide the TTL"
    );
    auth.cache
        .insert(
            id,
            Cached {
                app: Arc::new(store.entry.app.clone()),
                fetched_at: Instant::now() - Duration::from_secs(31),
            },
        )
        .await;
    assert_eq!(
        auth.app(id).await.err().unwrap().0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(store.reads.load(Ordering::SeqCst), 2);
}
#[tokio::test(start_paused = true)]
async fn capacity_exhaustion_closed_semaphore_and_backend_timeout_fail_closed() {
    let store = probe();
    let id = store.entry.app.id;
    let auth = Authorizer::new(store.clone(), Duration::ZERO, 16);
    let permit = auth.inflight.acquire_many(32).await.unwrap();
    assert_eq!(auth.app(id).await.err().unwrap().1, "authenticator busy");
    assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    drop(permit);
    auth.inflight.close();
    assert_eq!(
        auth.app(id).await.err().unwrap().1,
        "authenticator unavailable"
    );
    let mut hanging = probe();
    Arc::get_mut(&mut hanging).unwrap().hang = true;
    let auth = Authorizer::new(hanging, Duration::ZERO, 16);
    assert_eq!(auth.app(id).await.err().unwrap().1, "storage timeout");
}
#[tokio::test]
async fn queued_lookup_rechecks_cache_before_reading_backend() {
    let store = probe();
    let id = store.entry.app.id;
    let auth = Authorizer::new(store.clone(), Duration::from_secs(30), 16);
    let permit = auth.inflight.acquire_many(32).await.unwrap();
    let mut pending = Box::pin(auth.app(id));
    poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    auth.cache
        .insert(
            id,
            Cached {
                app: Arc::new(store.entry.app.clone()),
                fetched_at: Instant::now(),
            },
        )
        .await;
    drop(permit);
    assert_eq!(pending.await.unwrap().unwrap().id, id);
    assert_eq!(store.reads.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn corrupt_plugin_record_is_not_cached_or_authorized() {
    for bad_id in [true, false] {
        let mut store = probe();
        let mut id = store.entry.app.id;
        if bad_id {
            id = Uuid::new_v4();
        } else {
            Arc::get_mut(&mut store).unwrap().entry.version = 0;
        }
        let auth = Authorizer::new(store, Duration::from_secs(30), 16);
        assert_eq!(
            auth.app(id).await.err().unwrap().1,
            "invalid storage record"
        );
        assert!(auth.cache.get(&id).await.is_none());
    }
}

#[tokio::test]
async fn disabled_cache_always_reads_and_unknown_apps_are_not_cached() {
    let store = probe();
    let id = store.entry.app.id;
    let auth = Authorizer::new(store.clone(), Duration::ZERO, 16);
    for _ in 0..2 {
        assert!(auth.app(id).await.unwrap().is_some());
    }
    assert_eq!(store.reads.load(Ordering::SeqCst), 2);
    assert!(auth.cache.get(&id).await.is_none());
    let mut missing = probe();
    Arc::get_mut(&mut missing).unwrap().missing = true;
    let auth = Authorizer::new(missing.clone(), Duration::from_secs(30), 16);
    for _ in 0..2 {
        assert!(auth.app(id).await.unwrap().is_none());
    }
    assert_eq!(missing.reads.load(Ordering::SeqCst), 2);
    assert!(auth.cache.get(&id).await.is_none());
}
