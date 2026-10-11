//// A small app signing people in with howdy_custard, to try it against a
//// real sign-in service: set the variables The Custard Factory would (its
//// `docs/contract.md`), then `gleam run -m example` and open
//// http://localhost:8799/account.

import gleam/erlang/process
import gleam/http/response
import gleam/string
import howdy
import howdy/content
import howdy/controller
import howdy_custard

pub fn main() {
  let assert Ok(custard) = howdy_custard.from_env()
  let assert Ok(_) =
    howdy.new()
    |> howdy.controller(howdy_custard.routes(custard))
    |> howdy.controller(
      controller.guarded("account", howdy_custard.required(custard))
      |> controller.get("/", fn(ctx) {
        let user = ctx.guard
        page(
          "<h1>Hello, "
          <> user.name
          <> "</h1><p>"
          <> user.email
          <> " of "
          <> user.org_name
          <> " ("
          <> user.org_id
          <> "), roles: "
          <> string.join(user.roles, ", ")
          <> "</p><p><a href=\"/_custard/auth/logout\">Sign out</a></p>",
        )
      })
      |> controller.build,
    )
    |> howdy.controller(
      controller.new("")
      |> controller.get("/", fn(_) {
        page("<h1>Example</h1><p><a href=\"/account\">Your account</a></p>")
      })
      |> controller.build,
    )
    |> howdy.middleware(howdy_custard.middleware(custard))
    |> howdy.bind("127.0.0.1")
    |> howdy.listening(8799)
    |> howdy.start
  process.sleep_forever()
}

// Values here come from the sign-in service and are escaped by nothing:
// fine for trying it out, not for a real app, which uses Lustre.
fn page(body: String) {
  response.new(200)
  |> response.set_header("content-type", "text/html; charset=utf-8")
  |> response.set_body(content.Text(
    "<!doctype html><title>Example</title>" <> body,
  ))
}
