//! Tonic clients and shared application state.

use proto::auth::v1::auth_service_client::AuthServiceClient;
use proto::user::v1::user_service_client::UserServiceClient;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::Channel;

/// Injects the shared internal token into every outgoing call so the services
/// can authenticate the gateway (defense-in-depth).
#[derive(Clone)]
pub struct TokenInterceptor {
    token: String,
}

impl Interceptor for TokenInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if !self.token.is_empty() {
            if let Ok(v) = MetadataValue::try_from(self.token.as_str()) {
                req.metadata_mut().insert("x-internal-token", v);
            }
        }
        Ok(req)
    }
}

pub type AuthClient = AuthServiceClient<InterceptedService<Channel, TokenInterceptor>>;
pub type UserClient = UserServiceClient<InterceptedService<Channel, TokenInterceptor>>;

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthClient,
    pub user: UserClient,
}

impl AppState {
    /// Lazily connect (channels reconnect on demand) to the auth and user services.
    pub async fn connect(auth_addr: &str, user_addr: &str, token: String) -> anyhow::Result<Self> {
        let interceptor = TokenInterceptor { token };
        let auth_channel = Channel::from_shared(auth_addr.to_string())?.connect_lazy();
        let user_channel = Channel::from_shared(user_addr.to_string())?.connect_lazy();
        Ok(Self {
            auth: AuthServiceClient::with_interceptor(auth_channel, interceptor.clone()),
            user: UserServiceClient::with_interceptor(user_channel, interceptor),
        })
    }
}
