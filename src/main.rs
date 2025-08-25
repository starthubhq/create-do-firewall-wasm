use std::io::{self, Read};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use waki::Client;

#[derive(Deserialize)]
struct Input {
    #[serde(default)] state: Value,
    #[serde(default)] params: Value,
}

#[derive(Serialize)]
struct Patch {
    my_action: serde_json::Value,
}

fn main() {
    // ---------- read stdin ----------
    let mut buf = String::new();
    let _ = io::stdin().read_to_string(&mut buf);
    let input: Input = serde_json::from_str(&buf)
        .unwrap_or(Input { state: Value::Null, params: Value::Null });

    // ---------- resolve token ----------
    let token = std::env::var("DO_TOKEN")
        .ok()
        .or_else(|| input.params.get("do_token").and_then(|v| v.as_str()).map(|s| s.to_string()));

    if token.is_none() {
        emit_patch(json!({
            "ok": false,
            "error": "missing DigitalOcean token: set env DO_TOKEN or params.do_token",
        }));
        return;
    }
    let token = token.unwrap();

    // ---------- build request body ----------
    // If params.firewall is present, pass it through untouched (raw DO shape).
    // Otherwise, synthesize a minimal firewall from helper params.
    let req_body = if let Some(fw) = input.params.get("firewall") {
        fw.clone()
    } else {
        let name = input.params.get("name").and_then(|v| v.as_str()).unwrap_or("starthub-firewall");

        let droplet_ids: Vec<i64> = input.params.get("droplet_ids")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_i64()).collect())
            .unwrap_or_default();

        let tags: Vec<String> = input.params.get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let inbound_rules = input.params.get("inbound_rules").cloned().unwrap_or(json!([
            {
              "protocol": "tcp",
              "ports": "22",
              "sources": { "addresses": ["0.0.0.0/0", "::/0"] }
            }
        ]));

        let outbound_rules = input.params.get("outbound_rules").cloned().unwrap_or(json!([
            {
              "protocol": "tcp",
              "ports": "all",
              "destinations": { "addresses": ["0.0.0.0/0", "::/0"] }
            },
            {
              "protocol": "udp",
              "ports": "all",
              "destinations": { "addresses": ["0.0.0.0/0", "::/0"] }
            }
        ]));

        json!({
            "name": name,
            "droplet_ids": droplet_ids,
            "tags": tags,
            "inbound_rules": inbound_rules,
            "outbound_rules": outbound_rules
        })
    };

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

            // Try JSON; fall back to raw string
            let body_json: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => json!({ "raw": String::from_utf8_lossy(&body) }),
            };

            emit_patch(json!({
                "ok": (200..300).contains(&status),
                "status": status,
                "request": req_body,
                "firewall_id": body_json.get("firewall").and_then(|f| f.get("id")).cloned(),
                "response": body_json
            }));
        }
        Err(e) => {
            emit_patch(json!({
                "ok": false,
                "error": format!("request error: {}", e),
                "request": req_body
            }));
        }
    }
}

fn emit_patch(value: serde_json::Value) {
    let patch = Patch { my_action: value };
    let line = format!("::starthub:state::{}", serde_json::to_string(&patch).unwrap());
    println!("{}", line);
}
