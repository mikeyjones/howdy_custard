//// What is kept in the browser between requests, encrypted with AES-256-GCM
//// under a key made from the app's client secret, so it can be neither
//// read nor changed there:
////
//// - the session: the ID token the guard checks, and the refresh token
////   that gets a new one when it expires;
//// - while signing in, the flow: what the callback checks the service's
////   answer against, and where to go back to.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/json
import gleam/option.{type Option, None}
import gleam/result

pub const session_cookie = "custard_session"

pub const flow_cookie = "custard_flow"

pub type Session {
  Session(id_token: String, refresh_token: Option(String))
}

pub type Flow {
  Flow(
    state: String,
    nonce: String,
    /// PKCE: what the code is exchanged with.
    verifier: String,
    /// A path in the app.
    return_to: String,
  )
}

/// The cookies' key, from the client secret.
pub fn key(client_secret: String) -> BitArray {
  crypto.hash(
    crypto.Sha256,
    bit_array.from_string("howdy_custard/session:" <> client_secret),
  )
}

pub fn seal_session(key: BitArray, session: Session) -> String {
  json.object([
    #("id", json.string(session.id_token)),
    #("refresh", json.nullable(session.refresh_token, json.string)),
  ])
  |> seal(key, _)
}

pub fn open_session(key: BitArray, sealed: String) -> Result(Session, Nil) {
  use text <- result.try(open(key, sealed))
  json.parse(text, {
    use id_token <- decode.field("id", decode.string)
    use refresh_token <- decode.optional_field(
      "refresh",
      None,
      decode.optional(decode.string),
    )
    decode.success(Session(id_token:, refresh_token:))
  })
  |> result.replace_error(Nil)
}

pub fn seal_flow(key: BitArray, flow: Flow) -> String {
  json.object([
    #("state", json.string(flow.state)),
    #("nonce", json.string(flow.nonce)),
    #("verifier", json.string(flow.verifier)),
    #("return_to", json.string(flow.return_to)),
  ])
  |> seal(key, _)
}

pub fn open_flow(key: BitArray, sealed: String) -> Result(Flow, Nil) {
  use text <- result.try(open(key, sealed))
  json.parse(text, {
    use state <- decode.field("state", decode.string)
    use nonce <- decode.field("nonce", decode.string)
    use verifier <- decode.field("verifier", decode.string)
    use return_to <- decode.field("return_to", decode.string)
    decode.success(Flow(state:, nonce:, verifier:, return_to:))
  })
  |> result.replace_error(Nil)
}

/// Random text for a state, nonce or PKCE verifier.
pub fn random() -> String {
  crypto.strong_random_bytes(32) |> bit_array.base64_url_encode(False)
}

/// The PKCE challenge for a verifier: its SHA-256, base64url.
pub fn challenge(verifier: String) -> String {
  crypto.hash(crypto.Sha256, bit_array.from_string(verifier))
  |> bit_array.base64_url_encode(False)
}

fn seal(key: BitArray, value: json.Json) -> String {
  ffi_seal(key, bit_array.from_string(json.to_string(value)))
  |> bit_array.base64_url_encode(False)
}

fn open(key: BitArray, sealed: String) -> Result(String, Nil) {
  use bits <- result.try(bit_array.base64_url_decode(sealed))
  use opened <- result.try(ffi_open(key, bits))
  bit_array.to_string(opened)
}

@external(erlang, "howdy_custard_ffi", "seal")
fn ffi_seal(key: BitArray, plaintext: BitArray) -> BitArray

@external(erlang, "howdy_custard_ffi", "open")
fn ffi_open(key: BitArray, sealed: BitArray) -> Result(BitArray, Nil)
