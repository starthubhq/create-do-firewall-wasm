use std::io::{self, Read};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Input {
    #[serde(default)] state: Value,
    #[serde(default)] params: Value,
}

#[derive(Serialize)]
struct Patch {
    my_action: serde_json::Value
}

fn main() {
    // Read all stdin
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf).unwrap_or(0);

    // Parse input (be forgiving)
    let input: Input = serde_json::from_str(&buf).unwrap_or(Input { state: Value::Null, params: Value::Null });

    // --- do work here using input.params / input.state ---
    // Example: echo back a small patch including a derived value
    let name = input.params.get("name").and_then(|v| v.as_str()).unwrap_or("world");
    let result = json!({ "greeting": format!("hello, {name}") });

    // Emit patch marker
    let patch = Patch { my_action: result };
    let line = format!("::starthub:state::{}", serde_json::to_string(&patch).unwrap());
    println!("{}", line);
}
