use crate::atl::AccessTokenList;
use std::sync::Arc;
use tokio::{
    task::JoinHandle,
    time::{interval, Duration},
};

pub async fn spawn_garbage_collector(
    atl: Arc<AccessTokenList>,
    interval_dur: Duration,
) -> JoinHandle<()> {
    let atl_cloned = atl.clone();
    let mut i = interval(interval_dur);

    tokio::spawn(async move {
        loop {
            i.tick().await;
            let _ = atl_cloned.remove_expired().await;
        }
    })
}
