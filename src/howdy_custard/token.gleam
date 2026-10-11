//// Checking a token from the sign-in service: a JWT signed with RS256 by
//// one of its keys (`keys.gleam`), issued by it, for this app, and not
//// expired. Done here, without asking the service each time.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

/// One of the service's public keys: an RSA modulus and exponent.
pub type Key {
  Key(id: String, modulus: BitArray, exponent: BitArray)
}

pub type TokenError {
  /// Not a JWT, or not one this checks: only RS256.
  Malformed
  /// Signed with a key the service does not have, or no longer has.
  UnknownKey(String)
  BadSignature
  /// Issued by another service.
  WrongIssuer
  /// Issued for another app.
  WrongAudience
  Expired
  /// Not the sign-in this app started.
  WrongNonce
}

/// Seconds a token is still taken after it expires, for clocks that differ.
const leeway = 60

/// The token's payload as JSON, once its signature, issuer, audience and
/// expiry are checked against `now`, in seconds since 1970, and its nonce
/// when one is given. `find_key` gives the key with an id.
pub fn verify(
  token: String,
  find_key find_key: fn(String) -> Result(Key, Nil),
  issuer issuer: String,
  audience audience: String,
  now now: Int,
  nonce nonce: Option(String),
) -> Result(String, TokenError) {
  use #(header, payload, signature, signed) <- result.try(split(token))
  use #(alg, kid) <- result.try(
    json.parse(header, {
      use alg <- decode.field("alg", decode.string)
      use kid <- decode.field("kid", decode.string)
      decode.success(#(alg, kid))
    })
    |> result.replace_error(Malformed),
  )
  use _ <- result.try(case alg {
    "RS256" -> Ok(Nil)
    _ -> Error(Malformed)
  })
  use key <- result.try(find_key(kid) |> result.replace_error(UnknownKey(kid)))
  use _ <- result.try(
    case
      verify_rs256(
        key.modulus,
        key.exponent,
        bit_array.from_string(signed),
        signature,
      )
    {
      True -> Ok(Nil)
      False -> Error(BadSignature)
    },
  )
  use claims <- result.try(
    json.parse(payload, {
      use iss <- decode.field("iss", decode.string)
      use aud <- decode.field(
        "aud",
        decode.one_of(decode.list(decode.string), [
          decode.string |> decode.map(fn(one) { [one] }),
        ]),
      )
      use exp <- decode.field("exp", decode.int)
      use found_nonce <- decode.optional_field(
        "nonce",
        None,
        decode.string |> decode.map(Some),
      )
      decode.success(#(iss, aud, exp, found_nonce))
    })
    |> result.replace_error(Malformed),
  )
  let #(iss, aud, exp, found_nonce) = claims
  use _ <- result.try(check(iss == issuer, WrongIssuer))
  use _ <- result.try(check(list.contains(aud, audience), WrongAudience))
  use _ <- result.try(check(now <= exp + leeway, Expired))
  use _ <- result.try(case nonce {
    None -> Ok(Nil)
    Some(expected) -> check(found_nonce == Some(expected), WrongNonce)
  })
  Ok(payload)
}

/// The header and payload as JSON text, the signature, and what was signed.
fn split(
  token: String,
) -> Result(#(String, String, BitArray, String), TokenError) {
  case string.split(token, ".") {
    [header, payload, signature] -> {
      let text = fn(part) {
        bit_array.base64_url_decode(part)
        |> result.try(bit_array.to_string)
        |> result.replace_error(Malformed)
      }
      use header_text <- result.try(text(header))
      use payload_text <- result.try(text(payload))
      use signature <- result.try(
        bit_array.base64_url_decode(signature)
        |> result.replace_error(Malformed),
      )
      Ok(#(header_text, payload_text, signature, header <> "." <> payload))
    }
    _ -> Error(Malformed)
  }
}

fn check(ok: Bool, error: TokenError) -> Result(Nil, TokenError) {
  case ok {
    True -> Ok(Nil)
    False -> Error(error)
  }
}

pub fn describe(error: TokenError) -> String {
  case error {
    Malformed -> "the token is not one this app can read"
    UnknownKey(kid) -> "the token was signed with an unknown key, " <> kid
    BadSignature -> "the token's signature does not match"
    WrongIssuer -> "the token was issued by another sign-in service"
    WrongAudience -> "the token was issued for another app"
    Expired -> "the token has expired"
    WrongNonce -> "the token is not from the sign-in this app started"
  }
}

@external(erlang, "howdy_custard_ffi", "verify_rs256")
fn verify_rs256(
  modulus: BitArray,
  exponent: BitArray,
  data: BitArray,
  signature: BitArray,
) -> Bool
