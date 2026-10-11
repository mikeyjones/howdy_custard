//// The sign-in service's public keys, kept for ten minutes. A token signed
//// with a key not known is a cue to read them again, as the service
//// rotates them, but at most every 30 seconds, so tokens made up to cause
//// it cannot.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/erlang/process.{type Subject}
import gleam/json
import gleam/list
import gleam/otp/actor
import gleam/result
import gleam/time/timestamp
import howdy_custard/token.{type Key, Key}

const keep_ms = 600_000

const refetch_ms = 30_000

pub opaque type Keys {
  Keys(subject: Subject(Message))
}

type State {
  State(
    fetch: fn() -> Result(List(Key), String),
    keys: Dict(String, Key),
    fetched_at: Int,
  )
}

type Message {
  Find(id: String, reply: Subject(Result(Key, Nil)))
}

/// Keys read with `fetch`, such as from the service's JWKS address.
pub fn start(fetch: fn() -> Result(List(Key), String)) -> Keys {
  let assert Ok(started) =
    actor.new(State(fetch:, keys: dict.new(), fetched_at: 0))
    |> actor.on_message(handle)
    |> actor.start
  Keys(started.data)
}

pub fn find(keys: Keys, id: String) -> Result(Key, Nil) {
  process.call(keys.subject, 10_000, Find(id, _))
}

fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  let Find(id:, reply:) = message
  let now = now_ms()
  let stale = now - state.fetched_at > keep_ms
  let unknown = !dict.has_key(state.keys, id)
  let state = case stale || unknown && now - state.fetched_at > refetch_ms {
    False -> state
    True ->
      case state.fetch() {
        Ok(fetched) ->
          State(
            ..state,
            keys: dict.from_list(list.map(fetched, fn(k) { #(k.id, k) })),
            fetched_at: now,
          )
        // Kept as they were: the service may be back by the next try.
        Error(_) -> state
      }
  }
  process.send(reply, dict.get(state.keys, id))
  actor.continue(state)
}

/// The RSA keys in a JWKS document.
pub fn parse_jwks(body: String) -> Result(List(Key), String) {
  let bytes = fn(text) {
    bit_array.base64_url_decode(text) |> result.replace_error(Nil)
  }
  json.parse(
    body,
    decode.field(
      "keys",
      decode.list({
        use kty <- decode.field("kty", decode.string)
        use kid <- decode.field("kid", decode.string)
        use n <- decode.optional_field("n", "", decode.string)
        use e <- decode.optional_field("e", "", decode.string)
        decode.success(#(kty, kid, n, e))
      }),
      decode.success,
    ),
  )
  |> result.replace_error("the service's keys could not be read")
  |> result.map(
    list.filter_map(_, fn(found) {
      let #(kty, kid, n, e) = found
      case kty {
        "RSA" -> {
          use modulus <- result.try(bytes(n))
          use exponent <- result.try(bytes(e))
          Ok(Key(id: kid, modulus:, exponent:))
        }
        _ -> Error(Nil)
      }
    }),
  )
}

fn now_ms() -> Int {
  let #(seconds, nanoseconds) =
    timestamp.system_time() |> timestamp.to_unix_seconds_and_nanoseconds
  seconds * 1000 + nanoseconds / 1_000_000
}
