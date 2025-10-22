use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use reqwest::Client;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use tower_http::cors::{Any, CorsLayer};
use hex::encode as hex_encode;
use tokio::net::TcpListener;

const BITS_FILE: &str = "random_bits.bin";
const CACHE_FILE: &str = "external_entropy_cache.txt";
const CACHE_LIFETIME_SECS: u64 = 3600;

#[derive(Deserialize)]
struct GenerateRequest {
    range_min: u64,
    range_max: u64,
    count: u32,
    client_entropy: Option<String>,
    source: Option<String>,
}

#[derive(Serialize)]
struct RandomResponse {
    numbers: Vec<u64>,
    binary_file: String,
    hash: String,
    log: Vec<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

/// Внешняя энтропия (NASA / Open-Meteo) с кэшированием
async fn fetch_external_entropy(source: &str) -> String {
    use std::fs;
    let cache_path = Path::new(CACHE_FILE);

    if let Ok(meta) = fs::metadata(cache_path) {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().unwrap().as_secs() < CACHE_LIFETIME_SECS {
                if let Ok(cached) = fs::read_to_string(cache_path) {
                    return format!("cached {}", cached);
                }
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .unwrap();

    let data: Option<String> = if source == "donki" {
        if let Ok(key) = std::env::var("NASA_API_KEY") {
            let url = format!(
                "https://api.nasa.gov/DONKI/FLR?startDate=2025-01-01&endDate=2025-12-31&api_key={}",
                key
            );
            match client.get(&url).send().await {
                Ok(resp) => resp.text().await.ok(),
                Err(_) => None,
            }
        } else {
            None
        }
    } else {
        let url = "https://api.open-meteo.com/v1/forecast?latitude=55.75&longitude=37.62&hourly=temperature_2m";
        match client.get(url).send().await {
            Ok(resp) => resp.text().await.ok(),
            Err(_) => None,
        }
    };

    let data = data.unwrap_or_else(|| "fallback_external_entropy".to_string());
    let _ = fs::write(cache_path, &data);
    data
}

/// Локальная системная энтропия
fn local_entropy() -> String {
    let start = Instant::now();
    let mut acc = 0u64;
    for i in 0..50_000 {
        acc = acc.wrapping_add(i ^ (i << 1));
    }
    let dur = start.elapsed().as_nanos();
    format!("local_entropy:{}:{}", acc, dur)
}


fn expand_seed_to_bytes(seed: &[u8], needed_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(needed_bytes);
    let mut counter: u64 = 0;
    while out.len() < needed_bytes {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let block = hasher.finalize();
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(needed_bytes);
    out
}

fn bytes_to_bits_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 8);
    for b in bytes {
        for i in (0..8).rev() {
            s.push(if (b >> i) & 1 == 1 { '1' } else { '0' });
        }
    }
    s
}

/// Приведение хэша к диапазону [min,max]
fn map_hash_to_range(hash_bytes: &[u8], min: u64, max: u64) -> Option<u64> {
    if min > max {
        return None;
    }
    let range = (max - min) as u128 + 1;
    let value = BigUint::from_bytes_be(hash_bytes);
    let two_pow = BigUint::from(1u8) << (hash_bytes.len() * 8);
    let range_b = BigUint::from(range);
    let quotient = &two_pow / &range_b;
    let limit = &quotient * &range_b;
    if value < limit {
        let rem = (&value % &range_b).to_u128().unwrap_or(0);
        let out = min as u128 + rem;
        return Some(out as u64);
    }
    None
}

async fn generate_handler(Json(req): Json<GenerateRequest>) -> impl IntoResponse {
    let mut log = Vec::new();
    log.push("Начало генерации энтропии".into());

    let source = req.source.clone().unwrap_or_else(|| "weather".into());
    let ext_data = fetch_external_entropy(&source).await;
    log.push(format!("Внешняя энтропия: {}", &source));

    let local_data = local_entropy();
    log.push("Локальная энтропия собрана".into());

    let user_data = req.client_entropy.unwrap_or_else(|| "none".into());
    log.push(format!("Пользовательская энтропия: {} символов", user_data.len()));

    let mut hasher = Sha256::new();
    hasher.update(ext_data.as_bytes());
    hasher.update(local_data.as_bytes());
    hasher.update(user_data.as_bytes());
    hasher.update(now_millis().to_be_bytes());
    let seed = hasher.finalize();
    let seed_hex = hex_encode(&seed);
    log.push(format!("Итоговый seed: {}", &seed_hex[..32]));

    let stream = expand_seed_to_bytes(&seed, 125_000);
    let mut file = BufWriter::new(File::create(BITS_FILE).unwrap());
    file.write_all(&stream).unwrap();
    file.flush().unwrap();
    log.push("Файл random_bits.bin сохранен".into());

    let mut h2 = Sha256::new();
    h2.update(&stream);
    let file_hash = hex_encode(h2.finalize());
    log.push(format!("Хэш файла: {}", &file_hash[..32]));

    use std::collections::HashSet;

    let range_size = req.range_max - req.range_min + 1;
    if range_size < req.count as u64 {
        let err = format!(
            "Ошибка: диапазон [{}..{}] меньше количества требуемых чисел ({})",
            req.range_min, req.range_max, req.count
        );
        log.push(err.clone());
        let resp = ErrorResponse { error: err };
        return (StatusCode::BAD_REQUEST, Json(resp)).into_response();
    }

    let mut used = HashSet::new();
    let mut numbers = Vec::new();
    let mut counter = 0u64;

    while numbers.len() < req.count as usize {
        let mut h = Sha256::new();
        h.update(&seed);
        h.update(counter.to_be_bytes());
        let block = h.finalize();

        if let Some(v) = map_hash_to_range(&block, req.range_min, req.range_max) {
            if !used.contains(&v) {
                used.insert(v);
                numbers.push(v);
            }
        }
        counter += 1;
    }

    log.push(format!(
        "Сгенерировано {} уникальных чисел в диапазоне [{}..{}]",
        numbers.len(),
        req.range_min,
        req.range_max
    ));

    let resp = RandomResponse {
        numbers,
        binary_file: BITS_FILE.into(),
        hash: file_hash,
        log,
    };
    (StatusCode::OK, Json(resp)).into_response()
}

async fn get_bits_file() -> impl IntoResponse {
    if Path::new(BITS_FILE).exists() {
        match std::fs::read(BITS_FILE) {
            Ok(b) => (
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                b,
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("file read error: {}", e),
            )
                .into_response(),
        }
    } else {
        (StatusCode::NOT_FOUND, "no bits file").into_response()
    }
}

async fn analyze_handler() -> impl IntoResponse {
    if !Path::new(BITS_FILE).exists() {
        return (StatusCode::NOT_FOUND, "no bits file").into_response();
    }

    let mut bytes = Vec::new();
    File::open(BITS_FILE).unwrap().read_to_end(&mut bytes).unwrap();

    let mut total_bits = 0usize;
    let mut ones = 0usize;
    let mut runs = 0usize;
    let mut last_bit: Option<u8> = None;

    for &byte in &bytes {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            total_bits += 1;
            if bit == 1 {
                ones += 1;
            }

            match last_bit {
                Some(prev) if prev != bit => runs += 1,
                None => runs = 1,
                _ => {}
            }

            last_bit = Some(bit);
        }
    }

    let ones_fraction = ones as f64 / total_bits as f64;
    let avg_run_length = total_bits as f64 / runs as f64;

    let res = serde_json::json!({
        "ones_fraction": ones_fraction,
        "runs_count": runs,
        "avg_run_length": avg_run_length
    });

    (StatusCode::OK, Json(res)).into_response()
}

use axum::http::Method;

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/generate", post(generate_handler))
        .route("/api/bits", get(get_bits_file))
        .route("/api/analyze", get(analyze_handler))
        .layer(cors);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("RandomTrust Backend v2 запущен на https://test-backend-iqyp.onrender.com");
    axum::serve(listener, app).await.unwrap();
}
