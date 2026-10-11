//// A sign-in service for tests: a key, tokens signed with it, and a
//// transport answering for its key set and token endpoint.

import gleam/bit_array
import gleam/http/request.{type Request}
import gleam/http/response
import gleam/json.{type Json}
import gleam/list
import gleam/result
import gleam/uri
import howdy_custard

pub type PrivateKey

pub type Signer {
  Signer(key: PrivateKey, modulus: BitArray, exponent: BitArray)
}

@external(erlang, "howdy_custard_test_ffi", "new_key")
fn new_key() -> #(PrivateKey, BitArray, BitArray)

@external(erlang, "howdy_custard_test_ffi", "sign")
fn sign_with(key: PrivateKey, data: BitArray) -> BitArray

pub const issuer = "https://auth--live-shop-acme.example.com"

pub const client_id = "client-1"

pub const app_origin = "https://live-shop-acme.example.com"

pub fn signer() -> Signer {
  let #(key, modulus, exponent) = new_key()
  Signer(key:, modulus:, exponent:)
}

/// A JWT with these claims, signed by `signer` as key `kid`.
pub fn token(
  signer: Signer,
  kid: String,
  claims: List(#(String, Json)),
) -> String {
  let encode = fn(value: Json) {
    json.to_string(value)
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)
  }
  let header =
    encode(
      json.object([#("alg", json.string("RS256")), #("kid", json.string(kid))]),
    )
  let data = header <> "." <> encode(json.object(claims))
  data
  <> "."
  <> bit_array.base64_url_encode(
    sign_with(signer.key, bit_array.from_string(data)),
    False,
  )
}

/// Claims of an ID token for Alice, of Bob's Bakery, an admin, expiring
/// `expires_in` seconds from `now`.
pub fn alice(
  now: Int,
  expires_in: Int,
  nonce: String,
) -> List(#(String, Json)) {
  [
    #("iss", json.string(issuer)),
    #("aud", json.array([client_id, "project-1"], json.string)),
    #("sub", json.string("user-1")),
    #("exp", json.int(now + expires_in)),
    #("iat", json.int(now)),
    #("nonce", json.string(nonce)),
    #("email", json.string("alice@bobsbakery.test")),
    #("email_verified", json.bool(True)),
    #("name", json.string("Alice Baker")),
    #("urn:zitadel:iam:user:resourceowner:id", json.string("org-1")),
    #("urn:zitadel:iam:user:resourceowner:name", json.string("Bob's Bakery")),
    #(
      "urn:zitadel:iam:org:project:roles",
      json.object([
        #("admin", json.object([#("org-1", json.string("bobs-bakery"))])),
        #("baker", json.object([#("org-1", json.string("bobs-bakery"))])),
      ]),
    ),
  ]
}

pub fn jwks(signer: Signer, kid: String) -> String {
  let b64 = bit_array.base64_url_encode(_, False)
  json.object([
    #(
      "keys",
      json.preprocessed_array([
        json.object([
          #("kty", json.string("RSA")),
          #("kid", json.string(kid)),
          #("alg", json.string("RS256")),
          #("n", json.string(b64(signer.modulus))),
          #("e", json.string(b64(signer.exponent))),
        ]),
      ]),
    ),
  ])
  |> json.to_string
}

/// The library against a service whose token endpoint gives Alice's ID
/// token, with the code sent as its nonce, and a refresh token.
pub fn custard(signer: Signer, now: Int) -> howdy_custard.Custard {
  howdy_custard.with_transport(
    howdy_custard.Settings(
      issuer:,
      url: "http://zitadel:8080",
      client_id:,
      client_secret: "s3cret",
      app_origin:,
    ),
    fn(req: Request(String)) {
      case req.path {
        "/oauth/v2/keys" ->
          Ok(response.new(200) |> response.set_body(jwks(signer, "k1")))
        "/oauth/v2/token" -> {
          let form = uri.parse_query(req.body) |> result.unwrap([])
          let nonce = case list.key_find(form, "code") {
            Ok(code) -> code
            Error(Nil) -> "refreshed"
          }
          let body =
            json.object([
              #(
                "id_token",
                json.string(token(signer, "k1", alice(now, 3600, nonce))),
              ),
              #("refresh_token", json.string("refresh-1")),
            ])
            |> json.to_string
          Ok(response.new(200) |> response.set_body(body))
        }
        _ -> Ok(response.new(404) |> response.set_body("{}"))
      }
    },
  )
}
