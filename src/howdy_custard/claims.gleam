//// Reading a `User` from a token's claims. The sign-in service is Zitadel,
//// and this is the one place that knows what it calls things: apps only
//// ever see the contract's names (`user.gleam`).
////
//// | Contract | Zitadel |
//// | --- | --- |
//// | `user_id` | `sub` |
//// | `email`, `email_verified`, `name` | the same |
//// | `org_id`, `org_name` | `urn:zitadel:iam:user:resourceowner:id`, `:name` |
//// | `roles` | the keys of `urn:zitadel:iam:org:project:roles` |

import gleam/dict
import gleam/dynamic/decode.{type Decoder}
import gleam/list
import gleam/string
import howdy_custard/user.{type User, User}

/// The scopes that ask for every claim a `User` has.
pub const scopes = [
  "openid", "profile", "email", "offline_access",
  "urn:zitadel:iam:org:project:roles", "urn:zitadel:iam:user:resourceowner",
]

pub fn scope() -> String {
  string.join(scopes, " ")
}

/// A `User` from the claims of an ID token, or an access token, which has
/// fewer: what it lacks is left empty.
pub fn decoder() -> Decoder(User) {
  use user_id <- decode.field("sub", decode.string)
  use email <- decode.optional_field("email", "", decode.string)
  use email_verified <- decode.optional_field(
    "email_verified",
    False,
    decode.bool,
  )
  use name <- decode.optional_field("name", "", decode.string)
  use org_id <- decode.optional_field(
    "urn:zitadel:iam:user:resourceowner:id",
    "",
    decode.string,
  )
  use org_name <- decode.optional_field(
    "urn:zitadel:iam:user:resourceowner:name",
    "",
    decode.string,
  )
  use roles <- decode.optional_field(
    "urn:zitadel:iam:org:project:roles",
    [],
    decode.dict(decode.string, decode.dynamic)
      |> decode.map(fn(found) { dict.keys(found) |> list.sort(string.compare) }),
  )
  decode.success(User(
    user_id:,
    email:,
    email_verified:,
    name:,
    org_id:,
    org_name:,
    roles:,
  ))
}
