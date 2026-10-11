//// Sign people in to a Howdy app deployed on The Custard Factory, with its
//// environment's own sign-in service. The platform sets everything this
//// needs as environment variables (its `docs/contract.md`):
////
//// ```gleam
//// let assert Ok(custard) = howdy_custard.from_env()
////
//// howdy.new()
//// |> howdy.controller(howdy_custard.routes(custard))
//// |> howdy.controller(
////   controller.guarded("account", howdy_custard.required(custard))
////   |> controller.get("/", fn(ctx) {
////     let user = ctx.guard  // a howdy_custard/user.User
////     ...
////   })
////   |> controller.build,
//// )
//// // Browsers that are not signed in go to sign in, then come back.
//// |> howdy.middleware(howdy_custard.middleware(custard))
//// ```
////
//// | Route | Does |
//// | --- | --- |
//// | `GET /_custard/auth/login?return_to=/path` | Sign in, or carry on a session that has expired, then go to the path |
//// | `GET /_custard/auth/callback` | Where the sign-in service sends people back |
//// | `GET /_custard/auth/logout` | Sign out, here and at the service |
////
//// Tokens are checked here, against the service's published keys, kept for
//// a while: nothing is asked of the service per request.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/timestamp
import gleam/uri
import howdy/content.{type Content}
import howdy/controller.{type Context, type Next}
import howdy/cookie
import howdy/env
import howdy/service
import howdy_custard/claims
import howdy_custard/keys.{type Keys}
import howdy_custard/session.{type Session, Flow, Session}
import howdy_custard/token.{type TokenError}
import howdy_custard/user.{type User}

pub type Settings {
  Settings(
    /// The sign-in service as browsers reach it, and its tokens' issuer:
    /// `CUSTARD_AUTH_ISSUER`.
    issuer: String,
    /// Where this server reaches the same service: `CUSTARD_AUTH_URL`.
    url: String,
    client_id: String,
    client_secret: String,
    /// Where people reach the app: `APP_ORIGIN`.
    app_origin: String,
  )
}

/// Sends a request to the sign-in service. Replaced in tests.
pub type Transport =
  fn(Request(String)) -> Result(Response(String), String)

pub opaque type Custard {
  Custard(
    settings: Settings,
    transport: Transport,
    keys: Keys,
    cookie_key: BitArray,
  )
}

/// From the environment variables the platform sets.
pub fn from_env() -> Result(Custard, String) {
  let required = fn(name) {
    env.get(name) |> result.replace_error(name <> " is not set")
  }
  use issuer <- result.try(required("CUSTARD_AUTH_ISSUER"))
  use client_id <- result.try(required("CUSTARD_AUTH_CLIENT_ID"))
  use client_secret <- result.try(required("CUSTARD_AUTH_CLIENT_SECRET"))
  use app_origin <- result.try(required("APP_ORIGIN"))
  Ok(
    new(Settings(
      issuer: trim_slash(issuer),
      url: trim_slash(env.get_or("CUSTARD_AUTH_URL", issuer)),
      client_id:,
      client_secret:,
      app_origin: trim_slash(app_origin),
    )),
  )
}

pub fn new(settings: Settings) -> Custard {
  with_transport(settings, send)
}

pub fn with_transport(settings: Settings, transport: Transport) -> Custard {
  let fetch = fn() {
    use res <- result.try(
      transport(service_request(settings, http.Get, "/oauth/v2/keys")),
    )
    case res.status {
      200 -> keys.parse_jwks(res.body)
      status -> Error("the service's keys answered " <> int.to_string(status))
    }
  }
  Custard(
    settings:,
    transport:,
    keys: keys.start(fetch),
    cookie_key: session.key(settings.client_secret),
  )
}

pub const callback_path = "/_custard/auth/callback"

pub const login_path = "/_custard/auth/login"

pub const logout_path = "/_custard/auth/logout"

// -- Guards --------------------------------------------------------------------

/// For `controller.guarded`: the signed-in user, from the session cookie or
/// a bearer token, or 401.
pub fn required(custard: Custard) -> fn(Context) -> service.Result(User) {
  fn(ctx: Context) {
    case current(custard, ctx.request) {
      Some(user) -> Ok(user)
      None -> Error(service.Unauthorized)
    }
  }
}

/// For pages anyone may see: the user if someone is signed in.
pub fn optional(
  custard: Custard,
) -> fn(Context) -> service.Result(Option(User)) {
  fn(ctx: Context) { Ok(current(custard, ctx.request)) }
}

/// Only those with `role`, or 403.
pub fn with_role(
  custard: Custard,
  role: String,
) -> fn(Context) -> service.Result(User) {
  fn(ctx: Context) {
    case current(custard, ctx.request) {
      None -> Error(service.Unauthorized)
      Some(user) ->
        case user.has_role(user, role) {
          True -> Ok(user)
          False -> Error(service.Forbidden)
        }
    }
  }
}

fn current(custard: Custard, req: Request(a)) -> Option(User) {
  let from_bearer = case request.get_header(req, "authorization") {
    Ok("Bearer " <> token) -> Some(token)
    _ -> None
  }
  let token = case from_bearer {
    Some(token) -> Some(token)
    None ->
      read_cookie(req, session.session_cookie)
      |> option.then(fn(sealed) {
        session.open_session(custard.cookie_key, sealed) |> option.from_result
      })
      |> option.map(fn(found) { found.id_token })
  }
  option.then(token, fn(token) {
    user_from_token(custard, token, None) |> option.from_result
  })
}

/// The user a token is for, once checked.
pub fn user_from_token(
  custard: Custard,
  token: String,
  nonce: Option(String),
) -> Result(User, TokenError) {
  use payload <- result.try(token.verify(
    token,
    find_key: keys.find(custard.keys, _),
    issuer: custard.settings.issuer,
    audience: custard.settings.client_id,
    now: now_seconds(),
    nonce:,
  ))
  json.parse(payload, claims.decoder()) |> result.replace_error(token.Malformed)
}

/// Turns the 401 a browser gets from a guarded page into a trip to sign in
/// and back. API clients keep the 401.
pub fn middleware(_custard: Custard) -> fn(Context, Next) -> Response(Content) {
  fn(ctx: Context, next: Next) {
    let res = next(ctx)
    case res.status == 401 && wants_html(ctx.request) {
      True ->
        redirect(
          login_path
          <> "?"
          <> uri.query_to_string([#("return_to", back(ctx.request))]),
        )
      False -> res
    }
  }
}

// -- Routes --------------------------------------------------------------------

/// Signing in, coming back, and signing out, under `/_custard/auth`.
pub fn routes(custard: Custard) -> controller.Controller {
  controller.new("_custard/auth")
  |> controller.get("/login", fn(ctx) { login(custard, ctx) })
  |> controller.get("/callback", fn(ctx) { callback(custard, ctx) })
  |> controller.get("/logout", fn(ctx) { logout(custard, ctx) })
  |> controller.build
}

fn login(custard: Custard, ctx: Context) -> Response(Content) {
  let return_to = safe_path(query_value(ctx.request, "return_to"))
  // A session that has expired is carried on without a trip to the service.
  let refreshed =
    read_cookie(ctx.request, session.session_cookie)
    |> option.then(fn(sealed) {
      session.open_session(custard.cookie_key, sealed) |> option.from_result
    })
    |> option.then(fn(found) { found.refresh_token })
    |> option.then(fn(refresh_token) {
      exchange(
        custard,
        [
          #("grant_type", "refresh_token"),
          #("refresh_token", refresh_token),
          #("scope", claims.scope()),
        ],
        None,
      )
      |> option.from_result
    })
  case refreshed {
    Some(found) -> redirect(return_to) |> set_session(custard, found)
    None -> {
      let flow =
        Flow(
          state: session.random(),
          nonce: session.random(),
          verifier: session.random(),
          return_to:,
        )
      let query =
        uri.query_to_string([
          #("response_type", "code"),
          #("client_id", custard.settings.client_id),
          #("redirect_uri", custard.settings.app_origin <> callback_path),
          #("scope", claims.scope()),
          #("state", flow.state),
          #("nonce", flow.nonce),
          #("code_challenge", session.challenge(flow.verifier)),
          #("code_challenge_method", "S256"),
        ])
      redirect(custard.settings.issuer <> "/oauth/v2/authorize?" <> query)
      |> cookie.set(
        session.flow_cookie,
        session.seal_flow(custard.cookie_key, flow),
        cookie_options(custard)
          |> cookie.path("/_custard/auth")
          |> cookie.max_age(600),
      )
    }
  }
}

fn callback(custard: Custard, ctx: Context) -> Response(Content) {
  let flow =
    read_cookie(ctx.request, session.flow_cookie)
    |> option.then(fn(sealed) {
      session.open_flow(custard.cookie_key, sealed) |> option.from_result
    })
  let outcome = case flow, query_value(ctx.request, "error") {
    _, Some(error) ->
      Error(
        "The sign-in service said: "
        <> option.unwrap(query_value(ctx.request, "error_description"), error),
      )
    None, _ ->
      Error("This sign-in was not started here, or took too long. Try again.")
    Some(flow), None ->
      case query_value(ctx.request, "state"), query_value(ctx.request, "code") {
        Some(state), Some(code) if state == flow.state ->
          exchange(
            custard,
            [
              #("grant_type", "authorization_code"),
              #("code", code),
              #("redirect_uri", custard.settings.app_origin <> callback_path),
              #("code_verifier", flow.verifier),
            ],
            Some(flow.nonce),
          )
          |> result.map(fn(found) { #(found, flow.return_to) })
        _, _ ->
          Error("This sign-in does not match the one started here. Try again.")
      }
  }
  let clear_flow = cookie.delete(
    _,
    session.flow_cookie,
    cookie_options(custard) |> cookie.path("/_custard/auth"),
  )
  case outcome {
    Ok(#(found, return_to)) ->
      redirect(return_to) |> set_session(custard, found) |> clear_flow
    Error(message) ->
      response.new(400)
      |> response.set_body(content.Text(message))
      |> response.set_header("content-type", "text/plain; charset=utf-8")
      |> clear_flow
  }
}

fn logout(custard: Custard, ctx: Context) -> Response(Content) {
  // Whose session to end, so the service need not ask.
  let hint =
    read_cookie(ctx.request, session.session_cookie)
    |> option.then(fn(sealed) {
      session.open_session(custard.cookie_key, sealed) |> option.from_result
    })
    |> option.map(fn(found) { [#("id_token_hint", found.id_token)] })
    |> option.unwrap([])
  let query =
    uri.query_to_string([
      #("client_id", custard.settings.client_id),
      #("post_logout_redirect_uri", custard.settings.app_origin <> "/"),
      ..hint
    ])
  redirect(custard.settings.issuer <> "/oidc/v1/end_session?" <> query)
  |> cookie.delete(session.session_cookie, cookie_options(custard))
}

// Ask the token endpoint for tokens, and keep them once the ID token is
// checked, against the nonce when signing in.
fn exchange(
  custard: Custard,
  form: List(#(String, String)),
  nonce: Option(String),
) -> Result(Session, String) {
  let credentials =
    bit_array.base64_encode(
      bit_array.from_string(
        uri.percent_encode(custard.settings.client_id)
        <> ":"
        <> uri.percent_encode(custard.settings.client_secret),
      ),
      True,
    )
  let req =
    service_request(custard.settings, http.Post, "/oauth/v2/token")
    |> request.set_header("authorization", "Basic " <> credentials)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_body(uri.query_to_string(form))
  use res <- result.try(custard.transport(req))
  use #(id_token, refresh_token) <- result.try(case res.status {
    200 ->
      json.parse(res.body, {
        use id_token <- decode.field("id_token", decode.string)
        use refresh_token <- decode.optional_field(
          "refresh_token",
          None,
          decode.string |> decode.map(Some),
        )
        decode.success(#(id_token, refresh_token))
      })
      |> result.replace_error("The sign-in service's answer could not be read.")
    _ ->
      Error("The sign-in service refused: " <> string.slice(res.body, 0, 200))
  })
  use _ <- result.try(
    user_from_token(custard, id_token, nonce)
    |> result.map_error(fn(error) {
      "The sign-in could not be checked: " <> token.describe(error)
    }),
  )
  Ok(Session(id_token:, refresh_token:))
}

fn set_session(
  res: Response(Content),
  custard: Custard,
  found: Session,
) -> Response(Content) {
  cookie.set(
    res,
    session.session_cookie,
    session.seal_session(custard.cookie_key, found),
    cookie_options(custard) |> cookie.max_age(60 * 60 * 24 * 30),
  )
}

// -- Helpers -------------------------------------------------------------------

// A request to the sign-in service, at the address this server reaches it
// at, for the host browsers know it by.
fn service_request(
  settings: Settings,
  method: http.Method,
  path: String,
) -> Request(String) {
  let assert Ok(req) = request.to(settings.url <> path)
    as "CUSTARD_AUTH_URL is not a valid URL"
  let req = request.set_method(req, method)
  case settings.url == settings.issuer, uri.parse(settings.issuer) {
    False, Ok(issuer) ->
      case issuer.host, issuer.port {
        Some(host), Some(port) ->
          request.set_header(req, "host", host <> ":" <> int.to_string(port))
        Some(host), None -> request.set_header(req, "host", host)
        None, _ -> req
      }
    _, _ -> req
  }
}

fn cookie_options(custard: Custard) -> cookie.Options {
  cookie.defaults()
  |> cookie.secure(string.starts_with(custard.settings.app_origin, "https://"))
}

fn read_cookie(req: Request(a), name: String) -> Option(String) {
  request.get_cookies(req)
  |> list.key_find(name)
  |> result.try(uri.percent_decode)
  |> option.from_result
}

fn query_value(req: Request(a), name: String) -> Option(String) {
  request.get_query(req)
  |> result.unwrap([])
  |> list.key_find(name)
  |> option.from_result
}

// Only a path in this app: never another site.
fn safe_path(path: Option(String)) -> String {
  case path {
    Some("/" <> rest) ->
      case string.starts_with(rest, "/") || string.starts_with(rest, "\\") {
        True -> "/"
        False -> "/" <> rest
      }
    _ -> "/"
  }
}

fn back(req: Request(a)) -> String {
  case req.method, req.query {
    http.Get, Some(query) -> req.path <> "?" <> query
    http.Get, None -> req.path
    _, _ -> "/"
  }
}

fn wants_html(req: Request(a)) -> Bool {
  request.get_header(req, "accept")
  |> result.unwrap("")
  |> string.contains("text/html")
}

fn redirect(to: String) -> Response(Content) {
  response.new(303)
  |> response.set_header("location", to)
  |> response.set_body(content.Empty)
}

fn now_seconds() -> Int {
  let #(seconds, _) =
    timestamp.system_time() |> timestamp.to_unix_seconds_and_nanoseconds
  seconds
}

fn trim_slash(url: String) -> String {
  case string.ends_with(url, "/") {
    True -> string.drop_end(url, 1)
    False -> url
  }
}

fn send(req: Request(String)) -> Result(Response(String), String) {
  httpc.configure()
  |> httpc.timeout(10_000)
  |> httpc.dispatch(req)
  |> result.map_error(fn(error) {
    case error {
      httpc.ResponseTimeout -> "the sign-in service did not answer in time"
      httpc.FailedToConnect(..) -> "the sign-in service could not be reached"
      httpc.InvalidUtf8Response ->
        "the sign-in service answered with something unreadable"
    }
  })
}
