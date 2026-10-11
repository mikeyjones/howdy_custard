//// Signing in through the routes, against a fake sign-in service, then
//// reaching a guarded page; and what happens to those not signed in.

import gleam/http/response
import gleam/list
import gleam/option.{Some}
import gleam/result
import gleam/string
import gleam/time/timestamp
import gleam/uri
import howdy
import howdy/content
import howdy/controller
import howdy/testing
import howdy_custard
import howdy_custard/session
import howdy_custard/support

fn now() -> Int {
  let #(seconds, _) =
    timestamp.system_time() |> timestamp.to_unix_seconds_and_nanoseconds
  seconds
}

/// An app with a page only for those signed in, and one only for admins.
fn app(custard) {
  howdy.new()
  |> howdy.controller(howdy_custard.routes(custard))
  |> howdy.controller(
    controller.guarded("account", howdy_custard.required(custard))
    |> controller.get("/", fn(ctx) {
      response.new(200)
      |> response.set_body(content.Text(
        ctx.guard.name
        <> " of "
        <> ctx.guard.org_name
        <> ": "
        <> string.join(ctx.guard.roles, ","),
      ))
    })
    |> controller.build,
  )
  |> howdy.controller(
    controller.guarded("bakery", howdy_custard.with_role(custard, "owner"))
    |> controller.get("/", fn(_) {
      response.new(200) |> response.set_body(content.Empty)
    })
    |> controller.build,
  )
  |> howdy.middleware(howdy_custard.middleware(custard))
}

fn location(res) -> String {
  let assert Ok(to) = response.get_header(res, "location")
  to
}

fn query(url: String, name: String) -> String {
  let assert Ok(parsed) = uri.parse(url)
  let assert Some(q) = parsed.query
  let assert Ok(pairs) = uri.parse_query(q)
  let assert Ok(value) = list.key_find(pairs, name)
  value
}

fn cookie(res, name: String) -> String {
  let assert Ok(value) = testing.cookies(res) |> list.key_find(name)
  value
}

/// Sign in, returning the session cookie.
fn sign_in(app) -> String {
  let started =
    testing.get("/_custard/auth/login?return_to=/account")
    |> testing.send(app)
  assert started.status == 303
  let to = location(started)
  assert string.starts_with(to, support.issuer <> "/oauth/v2/authorize?")
  assert query(to, "client_id") == support.client_id
  assert query(to, "redirect_uri")
    == support.app_origin <> "/_custard/auth/callback"
  assert query(to, "code_challenge_method") == "S256"
  assert string.contains(
    query(to, "scope"),
    "urn:zitadel:iam:org:project:roles",
  )
  // The service sends them back; the fake takes the code for the nonce.
  let back =
    testing.get(
      "/_custard/auth/callback?"
      <> uri.query_to_string([
        #("code", query(to, "nonce")),
        #("state", query(to, "state")),
      ]),
    )
    |> testing.cookie(session.flow_cookie, cookie(started, session.flow_cookie))
    |> testing.send(app)
  assert back.status == 303
  assert location(back) == "/account"
  cookie(back, session.session_cookie)
}

pub fn signs_in_and_reaches_a_guarded_page_test() {
  let app = app(support.custard(support.signer(), now()))
  let session = sign_in(app)
  let page =
    testing.get("/account")
    |> testing.cookie(session.session_cookie, session)
    |> testing.send(app)
  assert page.status == 200
  assert testing.text(page) == "Alice Baker of Bob's Bakery: admin,baker"
}

pub fn the_session_cannot_be_read_or_changed_in_the_browser_test() {
  let app = app(support.custard(support.signer(), now()))
  let session = sign_in(app)
  assert !string.contains(session, "eyJ")
  let tampered = string.drop_end(session, 2) <> "AA"
  let page =
    testing.get("/account")
    |> testing.cookie(session.session_cookie, tampered)
    |> testing.send(app)
  assert page.status == 401
}

pub fn a_sign_in_not_started_here_is_refused_test() {
  let app = app(support.custard(support.signer(), now()))
  let started = testing.get("/_custard/auth/login") |> testing.send(app)
  let forged =
    testing.get("/_custard/auth/callback?code=x&state=not-the-state")
    |> testing.cookie(session.flow_cookie, cookie(started, session.flow_cookie))
    |> testing.send(app)
  assert forged.status == 400
  let no_flow =
    testing.get("/_custard/auth/callback?code=x&state=y") |> testing.send(app)
  assert no_flow.status == 400
}

pub fn browsers_not_signed_in_go_to_sign_in_test() {
  let app = app(support.custard(support.signer(), now()))
  let page =
    testing.get("/account?tab=1")
    |> testing.header("accept", "text/html")
    |> testing.send(app)
  assert page.status == 303
  assert location(page) == "/_custard/auth/login?return_to=%2Faccount%3Ftab%3D1"
  // API clients keep the 401.
  assert { testing.get("/account") |> testing.send(app) }.status == 401
}

pub fn only_paths_in_the_app_are_returned_to_test() {
  let app = app(support.custard(support.signer(), now()))
  let to =
    testing.get("/_custard/auth/login?return_to=//evil.example")
    |> testing.send(app)
    |> location
  assert string.starts_with(to, support.issuer)
  let flow_back = fn(return_to) {
    let started =
      testing.get(
        "/_custard/auth/login?"
        <> uri.query_to_string([#("return_to", return_to)]),
      )
      |> testing.send(app)
    let to = location(started)
    testing.get(
      "/_custard/auth/callback?"
      <> uri.query_to_string([
        #("code", query(to, "nonce")),
        #("state", query(to, "state")),
      ]),
    )
    |> testing.cookie(session.flow_cookie, cookie(started, session.flow_cookie))
    |> testing.send(app)
    |> location
  }
  assert flow_back("//evil.example") == "/"
  assert flow_back("https://evil.example") == "/"
  assert flow_back("/\\evil.example") == "/"
  assert flow_back("/orders/7") == "/orders/7"
}

pub fn takes_a_bearer_token_test() {
  let signer = support.signer()
  let app = app(support.custard(signer, now()))
  let jwt = support.token(signer, "k1", support.alice(now(), 600, "n"))
  let page =
    testing.get("/account")
    |> testing.header("authorization", "Bearer " <> jwt)
    |> testing.send(app)
  assert page.status == 200
}

pub fn roles_are_required_where_asked_test() {
  let app = app(support.custard(support.signer(), now()))
  let session = sign_in(app)
  let page =
    testing.get("/bakery")
    |> testing.cookie(session.session_cookie, session)
    |> testing.send(app)
  assert page.status == 403
}

pub fn an_expired_session_is_carried_on_test() {
  // Signed in an hour and a half ago: its ID token has expired.
  let signer = support.signer()
  let expired =
    support.token(signer, "k1", support.alice(now() - 5400, 3600, "n"))
  let session =
    session.seal_session(
      session.key("s3cret"),
      session.Session(id_token: expired, refresh_token: Some("refresh-1")),
    )
  let app = app(support.custard(signer, now()))
  let page =
    testing.get("/account")
    |> testing.header("accept", "text/html")
    |> testing.cookie(session.session_cookie, session)
    |> testing.send(app)
  assert page.status == 303
  // Sign-in sees the refresh token: back to the page with a new session,
  // without a trip to the service.
  let again =
    testing.get(location(page))
    |> testing.cookie(session.session_cookie, session)
    |> testing.send(app)
  assert again.status == 303
  assert location(again) == "/account"
  let renewed = cookie(again, session.session_cookie)
  let page =
    testing.get("/account")
    |> testing.cookie(session.session_cookie, renewed)
    |> testing.send(app)
  assert page.status == 200
}

pub fn signs_out_here_and_at_the_service_test() {
  let app = app(support.custard(support.signer(), now()))
  let session = sign_in(app)
  let res =
    testing.get("/_custard/auth/logout")
    |> testing.cookie(session.session_cookie, session)
    |> testing.send(app)
  // Saying whose session, so the service does not ask.
  assert string.starts_with(query(location(res), "id_token_hint"), "eyJ")
  assert res.status == 303
  assert string.starts_with(
    location(res),
    support.issuer <> "/oidc/v1/end_session?",
  )
  assert query(location(res), "post_logout_redirect_uri")
    == support.app_origin <> "/"
  let cleared =
    response.get_cookies(res)
    |> list.find(fn(c) { c.0 == session.session_cookie })
    |> result.is_ok
  assert cleared
}
