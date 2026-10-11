import gleam/json
import gleam/list
import gleam/option.{None, Some}
import howdy_custard/keys
import howdy_custard/support
import howdy_custard/token

const now = 1_800_000_000

fn check(signer, jwt, nonce) {
  let assert Ok([key]) = keys.parse_jwks(support.jwks(signer, "k1"))
  token.verify(
    jwt,
    find_key: fn(id) {
      case id == key.id {
        True -> Ok(key)
        False -> Error(Nil)
      }
    },
    issuer: support.issuer,
    audience: support.client_id,
    now:,
    nonce:,
  )
}

pub fn takes_a_token_from_the_service_for_this_app_test() {
  let signer = support.signer()
  let jwt = support.token(signer, "k1", support.alice(now, 600, "n-1"))
  let assert Ok(_) = check(signer, jwt, Some("n-1"))
  let assert Ok(_) = check(signer, jwt, None)
}

pub fn refuses_what_is_not_test() {
  let signer = support.signer()
  let with = fn(changes: List(#(String, json.Json))) {
    let claims =
      support.alice(now, 600, "n-1")
      |> list.filter(fn(c) { !list.any(changes, fn(x) { x.0 == c.0 }) })
      |> list.append(changes)
    support.token(signer, "k1", claims)
  }
  assert check(signer, with([#("iss", json.string("https://elsewhere"))]), None)
    == Error(token.WrongIssuer)
  assert check(signer, with([#("aud", json.string("another-app"))]), None)
    == Error(token.WrongAudience)
  assert check(signer, with([#("exp", json.int(now - 120))]), None)
    == Error(token.Expired)
  // A minute's leeway for clocks.
  let assert Ok(_) = check(signer, with([#("exp", json.int(now - 30))]), None)
  assert check(
      signer,
      support.token(signer, "k1", support.alice(now, 600, "n-1")),
      Some("n-2"),
    )
    == Error(token.WrongNonce)
  assert check(
      signer,
      support.token(signer, "k9", support.alice(now, 600, "n")),
      None,
    )
    == Error(token.UnknownKey("k9"))
  // Signed by someone else's key.
  let other =
    support.token(support.signer(), "k1", support.alice(now, 600, "n"))
  assert check(signer, other, None) == Error(token.BadSignature)
  assert check(signer, "not.a-token", None) == Error(token.Malformed)
}
