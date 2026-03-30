use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::token::ScopedToken;

/// Object-safe boxed future used by TokenProvider methods.
pub type TokenProviderFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Core provider abstraction for mint/refresh/revoke token lifecycle.
pub trait TokenProvider: Send + Sync {
    fn mint<'a>(
        &'a self,
        role: &'a str,
        ttl: Duration,
    ) -> TokenProviderFuture<'a, Result<ScopedToken, TokenProviderError>>;

    fn refresh<'a>(
        &'a self,
        token: &'a ScopedToken,
    ) -> TokenProviderFuture<'a, Result<ScopedToken, TokenProviderError>>;

    fn revoke<'a>(
        &'a self,
        token: &'a ScopedToken,
    ) -> TokenProviderFuture<'a, Result<(), TokenProviderError>>;
}

/// Error for TokenProvider operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenProviderError {
    message: String,
}

impl TokenProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TokenProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl StdError for TokenProviderError {}

/// A future wrapper that runs cleanup if dropped before completion.
pub struct CleanupOnDropFuture<F>
where
    F: Future,
{
    inner: F,
    cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
}

/// Wrap a mint future so dropping it triggers cleanup.
pub fn with_mint_cleanup<'a, C>(
    future: TokenProviderFuture<'a, Result<ScopedToken, TokenProviderError>>,
    cleanup: C,
) -> TokenProviderFuture<'a, Result<ScopedToken, TokenProviderError>>
where
    C: FnOnce() + Send + 'static,
{
    Box::pin(CleanupOnDropFuture::new(future, cleanup))
}

impl<F> CleanupOnDropFuture<F>
where
    F: Future,
{
    pub fn new<C>(future: F, cleanup: C) -> Self
    where
        C: FnOnce() + Send + 'static,
    {
        Self {
            inner: future,
            cleanup: Some(Box::new(cleanup)),
        }
    }
}

impl<F> Future for CleanupOnDropFuture<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        let poll_result = unsafe { Pin::new_unchecked(&mut this.inner) }.poll(cx);

        if poll_result.is_ready() {
            this.cleanup = None;
        }

        poll_result
    }
}

impl<F> Drop for CleanupOnDropFuture<F>
where
    F: Future,
{
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use chrono::Utc;
    use secrecy::SecretString;

    use super::{CleanupOnDropFuture, TokenProvider};
    use crate::token::ScopedToken;

    struct DummyProvider;

    impl TokenProvider for DummyProvider {
        fn mint<'a>(
            &'a self,
            role: &'a str,
            ttl: Duration,
        ) -> super::TokenProviderFuture<'a, Result<ScopedToken, super::TokenProviderError>>
        {
            let expires_at = Utc::now() + chrono::Duration::from_std(ttl).unwrap();
            let mut metadata = HashMap::new();
            metadata.insert("provider".to_string(), "dummy".to_string());

            let token = ScopedToken::new_with_metadata(
                SecretString::from(format!("token-for-{role}")),
                role,
                expires_at,
                metadata,
            );

            Box::pin(async move { Ok(token) })
        }

        fn refresh<'a>(
            &'a self,
            token: &'a ScopedToken,
        ) -> super::TokenProviderFuture<'a, Result<ScopedToken, super::TokenProviderError>>
        {
            let mut metadata = token.metadata().clone();
            metadata.insert("refreshed".to_string(), "true".to_string());

            let refreshed = ScopedToken::new_with_metadata(
                SecretString::from(format!("{}-new", token.expose_secret())),
                token.role(),
                token.expires_at() + chrono::Duration::minutes(30),
                metadata,
            );

            Box::pin(async move { Ok(refreshed) })
        }

        fn revoke<'a>(
            &'a self,
            _token: &'a ScopedToken,
        ) -> super::TokenProviderFuture<'a, Result<(), super::TokenProviderError>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct CleanupAwareProvider {
        cleaned: Arc<AtomicBool>,
    }

    impl TokenProvider for CleanupAwareProvider {
        fn mint<'a>(
            &'a self,
            role: &'a str,
            ttl: Duration,
        ) -> super::TokenProviderFuture<'a, Result<ScopedToken, super::TokenProviderError>>
        {
            let expires_at = Utc::now() + chrono::Duration::from_std(ttl).unwrap();
            let mut metadata = HashMap::new();
            metadata.insert("provider".to_string(), "cleanup-aware".to_string());
            let token = ScopedToken::new_with_metadata(
                SecretString::from(format!("token-for-{role}")),
                role,
                expires_at,
                metadata,
            );

            let cleaned_flag = Arc::clone(&self.cleaned);
            let fut = Box::pin(async move { Ok(token) });
            super::with_mint_cleanup(fut, move || {
                cleaned_flag.store(true, Ordering::SeqCst);
            })
        }

        fn refresh<'a>(
            &'a self,
            token: &'a ScopedToken,
        ) -> super::TokenProviderFuture<'a, Result<ScopedToken, super::TokenProviderError>>
        {
            let mut metadata = token.metadata().clone();
            metadata.insert("refreshed".to_string(), "true".to_string());
            let refreshed = ScopedToken::new_with_metadata(
                SecretString::from(format!("{}-new", token.expose_secret())),
                token.role(),
                token.expires_at() + chrono::Duration::minutes(30),
                metadata,
            );
            Box::pin(async move { Ok(refreshed) })
        }

        fn revoke<'a>(
            &'a self,
            _token: &'a ScopedToken,
        ) -> super::TokenProviderFuture<'a, Result<(), super::TokenProviderError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn ns_015_token_provider_method_signatures_object_safe_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn TokenProvider>();

        let provider: Box<dyn TokenProvider> = Box::new(DummyProvider);

        let minted = provider
            .mint("admin", Duration::from_secs(120))
            .await
            .expect("mint must succeed");
        assert_eq!(minted.role(), "admin");

        let refreshed = provider
            .refresh(&minted)
            .await
            .expect("refresh must succeed");
        assert_ne!(refreshed.expose_secret(), minted.expose_secret());

        provider
            .revoke(&refreshed)
            .await
            .expect("revoke must succeed");
    }

    #[test]
    fn ns_016_scoped_token_mandatory_expiry_and_zeroizing_type() {
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "test".to_string());
        metadata.insert("token_id".to_string(), "tok-123".to_string());

        let expiry = Utc::now() + chrono::Duration::minutes(10);
        let token = ScopedToken::new_with_metadata(
            SecretString::from("secret-value".to_string()),
            "reader",
            expiry,
            metadata,
        );

        let _: chrono::DateTime<Utc> = token.expires_at();
        static_assertions::assert_not_impl_any!(ScopedToken: Clone);
        assert_eq!(token.expires_at(), expiry);
    }

    #[tokio::test]
    async fn ns_017_refresh_returns_new_token_and_does_not_mutate_existing() {
        let provider = DummyProvider;
        let original = provider
            .mint("operator", Duration::from_secs(300))
            .await
            .expect("mint must succeed");
        let original_secret = original.expose_secret().to_string();
        let original_expiry = original.expires_at();

        let refreshed = provider
            .refresh(&original)
            .await
            .expect("refresh must succeed");

        assert_eq!(original.expose_secret(), original_secret);
        assert_eq!(original.expires_at(), original_expiry);
        assert_ne!(refreshed.expose_secret(), original.expose_secret());
        assert!(refreshed.expires_at() > original.expires_at());
    }

    #[tokio::test]
    async fn ns_018_dropped_mint_future_runs_cleanup_handler() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let cleaned_flag = Arc::clone(&cleaned);

        let mint_fut = async {
            let mut metadata = HashMap::new();
            metadata.insert("provider".to_string(), "dummy".to_string());
            Ok::<ScopedToken, super::TokenProviderError>(ScopedToken::new_with_metadata(
                SecretString::from("sensitive-token".to_string()),
                "deployer",
                Utc::now() + chrono::Duration::minutes(5),
                metadata,
            ))
        };

        let guarded = CleanupOnDropFuture::new(mint_fut, move || {
            cleaned_flag.store(true, Ordering::SeqCst);
        });

        drop(guarded);
        assert!(
            cleaned.load(Ordering::SeqCst),
            "cleanup handler should run when mint future is dropped"
        );
    }

    #[tokio::test]
    async fn ns_018_drop_through_token_provider_mint_runs_cleanup() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let provider: Box<dyn TokenProvider> = Box::new(CleanupAwareProvider {
            cleaned: Arc::clone(&cleaned),
        });

        let mint_future = provider.mint("auditor", Duration::from_secs(60));
        drop(mint_future);

        assert!(
            cleaned.load(Ordering::SeqCst),
            "dropping mint future from TokenProvider::mint should trigger cleanup"
        );
    }

    #[tokio::test]
    async fn ns_018_cleanup_not_called_when_mint_future_completes() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let cleaned_flag = Arc::clone(&cleaned);

        let mint_fut = async {
            let mut metadata = HashMap::new();
            metadata.insert("provider".to_string(), "dummy".to_string());
            Ok::<ScopedToken, super::TokenProviderError>(ScopedToken::new_with_metadata(
                SecretString::from("sensitive-token".to_string()),
                "deployer",
                Utc::now() + chrono::Duration::minutes(5),
                metadata,
            ))
        };

        let guarded = super::with_mint_cleanup(Box::pin(mint_fut), move || {
            cleaned_flag.store(true, Ordering::SeqCst);
        });

        let _ = guarded.await.expect("mint should succeed");
        assert!(
            !cleaned.load(Ordering::SeqCst),
            "cleanup must not run after successful completion"
        );
    }
}
