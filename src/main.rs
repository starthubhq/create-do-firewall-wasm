use std::io::{self, Read};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use waki::Client;

#[derive(Deserialize)]
struct Input {
    #[serde(default)] state: Value,
    #[serde(default)] params: Value,
}

fn main() {
    // ---------- read stdin ----------
    let mut buf = String::new();
    let _ = io::stdin().read_to_string(&mut buf);
    let input: Input = serde_json::from_str(&buf)
        .unwrap_or(Input { state: Value::Null, params: Value::Null });

    // ---------- resolve token ----------
    // Prefer params.do_access_token; accept params.do_token; then env DO_TOKEN/do_access_token
    let token = input.params.get("do_access_token").and_then(|v| v.as_str())
        .or_else(|| input.params.get("do_token").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .or_else(|| std::env::var("DO_TOKEN").ok())
        .or_else(|| std::env::var("do_access_token").ok());

    if token.as_deref().unwrap_or("").is_empty() {
        eprintln!("Error: missing token (params.do_access_token or env DO_TOKEN)");
        return;
    }
    let token = token.unwrap();

    // ---------- inputs ----------
    let name = input.params.get("name").and_then(|v| v.as_str()).unwrap_or("starthub-firewall");

    let droplet_ids: Vec<i64> = input.params.get("droplet_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();

    let tags: Vec<String> = input.params.get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    // sensible defaults if not provided
    let inbound_rules = input.params.get("inbound_rules").cloned().unwrap_or(json!([
        { "protocol": "tcp", "ports": "22", "sources": { "addresses": ["0.0.0.0/0", "::/0"] } }
    ]));

    let outbound_rules = input.params.get("outbound_rules").cloned().unwrap_or(json!([
        { "protocol": "tcp", "ports": "all", "destinations": { "addresses": ["0.0.0.0/0", "::/0"] } },
        { "protocol": "udp", "ports": "all", "destinations": { "addresses": ["0.0.0.0/0", "::/0"] } }
    ]));

    // ---------- build DO payload ----------
    let req_body = json!({
        "name": name,
        "droplet_ids": droplet_ids,
        "tags": tags,
        "inbound_rules": inbound_rules,
        "outbound_rules": outbound_rules
    });

    // ---------- call DO API ----------
    let resp = Client::new()
        .post("https://api.digitalocean.com/v2/firewalls")
        .headers([
            ("Content-Type", "application/json"),
            ("Accept", "application/json"),
            ("Authorization", &format!("Bearer {}", token)),
        ])
        .json(&req_body)
        .connect_timeout(Duration::from_secs(15))
        .send();

    match resp {
        Ok(r) => {
            let status = r.status_code();
            let body = r.body().unwrap_or_default();

            let body_json: Value = serde_json::from_slice(&body)
                .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&body) }));

            if (200..300).contains(&status) {
                let fw_id = body_json
                    .get("firewall").and_then(|f| f.get("id")).and_then(|id| id.as_str())
                    .unwrap_or_default();

                if fw_id.is_empty() {
                    eprintln!("Error: firewall.id not found in response");
                    eprintln!("{}", serde_json::to_string_pretty(&body_json).unwrap());
                    return;
                }

                // ✅ Emit exactly what the manifest declares
                println!("::starthub:state::{}", json!({ "firewall_id": fw_id }).to_string());

                // Human-readable log
                let fw_name = body_json.get("firewall").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or(name);
                eprintln!("Created firewall '{}' ({})", fw_name, fw_id);
            } else {
                eprintln!("DigitalOcean API returned status {}", status);
                eprintln!("{}", serde_json::to_string_pretty(&body_json).unwrap());
            }
        }
        Err(e) => {
            eprintln!("Request error: {}", e);
        }
    }
}
