#![feature(proc_macro_hygiene, decl_macro)]

use std::error::Error;

use halo2_circuits::ecc::ecdsa_p256::{download_keys, generate_proof};
use rocket::http::Method;
use rocket_contrib::json::Json;
use hex::FromHexError;
use rocket_cors::{AllowedOrigins, AllowedHeaders, CorsOptions, Cors};
#[macro_use] extern crate rocket;

#[get("/<name>/<age>")]
fn hello(name: String, age: u8) -> String {
    format!("Hello, {} year old named {}!", age, name)
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!!!"
}

#[get("/setup")]
fn setup() -> &'static str {
    download_keys(17, Some("./proving_key.pk"), Some("./verifying_key.vk"));
    "Done"
}

fn concat_arrays(a: [u8; 32], b: [u8; 32]) -> [u8; 64] {
    let mut result = [0; 64];
    result[..32].copy_from_slice(&a);
    result[32..].copy_from_slice(&b);
    result
}

#[derive(serde::Deserialize)]
struct ProveRequestBody {
    r: [u8; 32],
    s: [u8; 32],
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    msghash: [u8; 32],
    proving_key_path: String,
}

#[post("/prove", format = "application/json", data = "<request_body>")]
fn prove(request_body: Json<ProveRequestBody>) -> Result<String, FromHexError> {
    let proof = generate_proof(&request_body.pubkey_x, &request_body.pubkey_y, &request_body.r, &request_body.s, &request_body.msghash, &request_body.proving_key_path, 17).unwrap();
    let proof_hex = hex::encode(proof);
    println!("{}", proof_hex);
    Ok(proof_hex)
}

fn make_cors() -> Cors {
    CorsOptions { // 5.
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .expect("error while building CORS")
}

fn main() {
    rocket::ignite().mount("/", routes![hello, index, setup, prove]).attach(make_cors()).launch();
}