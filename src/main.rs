use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use std::{collections::HashSet, env, fmt::Write, net::SocketAddr, sync::Arc};
use url::Url;

struct AppState {
    client: Client,
    imgproxy_url: String,
    resize_type: String,
    key: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    allowed_sources: Vec<String>,
    allowed_sizes: HashSet<u32>,
}

fn getenv(k: &str, def: &str) -> String {
    env::var(k).unwrap_or_else(|_| def.to_owned())
}

fn parse_allowed_sources(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_ascii_lowercase())
        .collect()
}

fn parse_allowed_sizes(v: &str) -> HashSet<u32> {
    v.split(',')
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .collect()
}

fn is_allowed_source(raw: &str, allowed: &[String]) -> bool {
    let url = match Url::parse(raw) {
        Ok(u) => u,
        Err(_) => return false,
    };

    match url.scheme() {
        "http" | "https" => {}
        _ => return false,
    }

    let host = match url.host_str() {
        Some(h) => h,
        _ => return false,
    };

    let mut source = String::with_capacity(url.scheme().len() + 3 + host.len() + 6);
    source.push_str(url.scheme());
    source.push_str("://");
    source.push_str(host);
    if let Some(port) = url.port() {
        let _ = write!(source, ":{port}");
    }
    let source_lower = source.to_ascii_lowercase();

    allowed.iter().any(|a| a == &source_lower)
}

fn sign(path: &str, key: Option<&[u8]>, salt: Option<&[u8]>) -> String {
    let (Some(key), Some(salt)) = (key, salt) else {
        return "unsafe".to_owned();
    };

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(salt);
    mac.update(path.as_bytes());

    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn best_format(accept: Option<&str>) -> &'static str {
    let accept = match accept {
        Some(a) => a,
        _ => return "",
    };
    if accept.contains("image/avif") {
        return "avif";
    }
    if accept.contains("image/webp") {
        return "webp";
    }
    ""
}

fn build_imgproxy_url(
    state: &AppState,
    src: &str,
    width: u32,
    quality: u32,
    ext: &str,
) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(src.as_bytes());

    let path = if ext.is_empty() {
        format!(
            "/rs:{}:{}:0:0/q:{}/sm:1/sh:0.3/{}",
            state.resize_type, width, quality, encoded,
        )
    } else {
        format!(
            "/rs:{}:{}:0:0/q:{}/sm:1/sh:0.3/{}.{}",
            state.resize_type, width, quality, encoded, ext,
        )
    };

    let sig = sign(&path, state.key.as_deref(), state.salt.as_deref());

    format!("{}/{}{}", state.imgproxy_url, sig, path)
}

#[derive(serde::Deserialize)]
struct Params {
    url: Option<String>,
    w: Option<String>,
    q: Option<String>,
}

async fn handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<Params>,
) -> Response {
    let src = match &params.url {
        Some(u) if !u.is_empty() => u.as_str(),
        _ => return (StatusCode::BAD_REQUEST, "missing url\n").into_response(),
    };

    if !is_allowed_source(src, &state.allowed_sources) {
        return (StatusCode::BAD_REQUEST, "invalid source url\n").into_response();
    }

    if Url::parse(src).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid source url\n").into_response();
    }

    let width: u32 = params
        .w
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(800);

    if !state.allowed_sizes.contains(&width) {
        return (StatusCode::BAD_REQUEST, "invalid size\n").into_response();
    }

    let quality: u32 = params
        .q
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let accept = headers.get("accept").and_then(|v| v.to_str().ok());
    let ext = best_format(accept);

    let adjusted_quality = match ext {
        "avif" => (quality as f32 * 0.65).round() as u32,
        "webp" => (quality as f32 * 0.80).round() as u32,
        _ => quality,
    };

    let target = build_imgproxy_url(&state, src, width, adjusted_quality, ext);

    let mut req = state.client.get(&target);
    for (name, value) in &headers {
        if name == "host" {
            continue;
        }
        req = req.header(name, value);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return (StatusCode::BAD_GATEWAY, e.to_string()).into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let mut response_headers = HeaderMap::with_capacity(upstream.headers().len());
    for (k, v) in upstream.headers() {
        response_headers.append(k.clone(), v.clone());
    }

    let body = axum::body::Body::from_stream(upstream.bytes_stream());

    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = response_headers;
    resp
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    let key_hex = env::var("IMGPROXY_KEY").unwrap_or_default();
    let salt_hex = env::var("IMGPROXY_SALT").unwrap_or_default();

    let key = if key_hex.is_empty() {
        None
    } else {
        Some(hex::decode(&key_hex).expect("IMGPROXY_KEY must be valid hex"))
    };
    let salt = if salt_hex.is_empty() {
        None
    } else {
        Some(hex::decode(&salt_hex).expect("IMGPROXY_SALT must be valid hex"))
    };

    let state = Arc::new(AppState {
        client: Client::builder()
            .pool_max_idle_per_host(64)
            .build()
            .expect("failed to build HTTP client"),
        imgproxy_url: getenv("IMGPROXY_URL", "http://localhost:8080")
            .trim_end_matches('/')
            .to_owned(),
        resize_type: getenv("IMGPROXY_RESIZE_TYPE", "fit"),
        key,
        salt,
        allowed_sources: parse_allowed_sources(&getenv(
            "ALLOWED_SOURCES",
            "https://api.wecoach.gg",
        )),
        allowed_sizes: parse_allowed_sizes(&getenv(
            "ALLOWED_SIZES",
            "50,128,256,640,750,828,1080,1600",
        )),
    });

    let app = Router::new()
        .route("/_vercel/image", get(handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    eprintln!("Listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    eprintln!("shutting down");
}
