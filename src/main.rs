use std::io::{self, Read};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use bytes::Bytes;
use http::{Request, Method, header::HeaderValue};
use wasi_experimental_http::request as wasi_http_request;

#[derive(Deserialize)]
struct Input {
    #[serde(default)] state: Value,
    #[serde(default)] params: Value,
}

#[derive(Serialize)]
struct Patch {
    firewall: serde_json::Value,
    firewall_id: String,
    firewall_name: String,
}

fn bearer(h: &str) -> HeaderValue {
    let mut v = HeaderValue::from_str(&format!("Bearer {}", h)).expect("header");
    v.set_sensitive(true);
    v
}

fn main() {
    // 1) read stdin
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf).unwrap_or(0);
    let input: Input = serde_json::from_str(&buf)
        .unwrap_or(Input { state: Value::Null, params: Value::Null });

    // 2) params
    let p = &input.params;

    let token = p.get("do_access_token").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if token.is_empty() {
        eprintln!("Error: missing do_access_token in params");
        std::process::exit(1);
    }

    let name  = p.get("name").and_then(|v| v.as_str()).unwrap_or("default-firewall").to_string();

    // Optional arrays: pass through as-is if provided
    let inbound_rules  = p.get("inbound_rules").cloned().unwrap_or(Value::Null);
    let outbound_rules = p.get("outbound_rules").cloned().unwrap_or(Value::Null);
    let droplet_ids    = p.get("droplet_ids").cloned().unwrap_or(Value::Null);
    let tags           = p.get("tags").cloned().unwrap_or(Value::Null);
    let project_id     = p.get("project_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // 3) Ensure at least one rule (DO requires >= 1 inbound OR outbound rule).
    let have_in = matches!(inbound_rules, Value::Array(_));
    let have_out = matches!(outbound_rules, Value::Array(_));
    let outbound_rules_final = if have_in || have_out {
        outbound_rules
    } else {
        json!([{
          "protocol": "tcp",
          "ports": "all",
          "destinations": { "addresses": ["0.0.0.0/0", "::/0"] }
        }])
    };

    // 4) Build create-firewall payload
    let mut body = json!({
        "name": name,
        "outbound_rules": outbound_rules_final
    });
    if have_in {
        body.as_object_mut().unwrap().insert("inbound_rules".into(), inbound_rules);
    }
    if droplet_ids.is_array() { body.as_object_mut().unwrap().insert("droplet_ids".into(), droplet_ids); }
    if tags.is_array()       { body.as_object_mut().unwrap().insert("tags".into(), tags); }

    // 5) POST /v2/firewalls
    let url = "https://api.digitalocean.com/v2/firewalls";
    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .header("authorization", bearer(&token))
        .body(Some(Bytes::from(body.to_string())))     // <-- Option<Bytes>
        .unwrap();

    let mut resp = wasi_http_request(req).expect("http request");
    let status = resp.status_code.as_u16();   // <- convert to u16
    let bytes = resp.body_read_all().expect("read body");
    let text = String::from_utf8(bytes.to_vec()).unwrap_or_default();

    if status < 200 || status >= 300 {
        eprintln!("DigitalOcean API error (create firewall): HTTP {}\n{}", status, text);
        std::process::exit(1);
    }

    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let fw_id   = v.pointer("/firewall/id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let fw_name = v.pointer("/firewall/name").and_then(|x| x.as_str()).unwrap_or("").to_string();

    if fw_id.is_empty() {
        eprintln!("Error: could not parse firewall.id from response.\n{}", text);
        std::process::exit(1);
    }

    // 6) Optional: assign to project
    if !project_id.is_empty() {
        let assign_url = format!("https://api.digitalocean.com/v2/projects/{}/resources", project_id);
        let payload = json!({ "resources": [ format!("do:firewall:{}", fw_id) ] });
        let req2 = Request::builder()
            .method(Method::POST)
            .uri(assign_url)
            .header("content-type", "application/json")
            .header("authorization", bearer(&token))
            .body(Some(Bytes::from(payload.to_string())))  // <-- Option<Bytes>
            .unwrap();
        let mut resp2 = wasi_http_request(req2).expect("http request");
        let code2 = resp2.status_code.as_u16();   // <- convert to u16                   // <-- u16
        if code2 < 200 || code2 >= 300 {
            let txt2 = String::from_utf8(resp2.body_read_all().unwrap_or_default().to_vec()).unwrap_or_default();
            eprintln!("Warning: project assignment failed (ignored): HTTP {}\n{}", code2, txt2);
        }
    }

    // 7) Emit patch
    let patch = Patch {
        firewall: json!({"id": fw_id, "name": fw_name }),
        firewall_id: fw_id.clone(),
        firewall_name: if fw_name.is_empty() { name } else { fw_name },
    };
    println!("::starthub:state::{}", serde_json::to_string(&patch).unwrap());
}
