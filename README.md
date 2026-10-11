# howdy_custard

Sign people in to a [Howdy](https://github.com/mikeyjones/howdy) app
deployed on The Custard Factory, with its environment's own sign-in
service: its users, their organisations (your customers) and their roles.

The platform sets everything this needs as environment variables, as its
contract between it and apps describes (`docs/contract.md` in The Custard
Factory): `CUSTARD_AUTH_ISSUER`, `CUSTARD_AUTH_URL`,
`CUSTARD_AUTH_CLIENT_ID`, `CUSTARD_AUTH_CLIENT_SECRET` and `APP_ORIGIN`.

```gleam
import howdy
import howdy/controller
import howdy_custard

pub fn app() {
  let assert Ok(custard) = howdy_custard.from_env()

  howdy.new()
  // /_custard/auth/login, /callback and /logout
  |> howdy.controller(howdy_custard.routes(custard))
  |> howdy.controller(
    controller.guarded("account", howdy_custard.required(custard))
    |> controller.get("/", fn(ctx) {
      let user = ctx.guard
      // user.user_id, email, name, org_id, org_name, roles
      ...
    })
    |> controller.build,
  )
  // Browsers that are not signed in go to sign in, then come back.
  |> howdy.middleware(howdy_custard.middleware(custard))
}
```

- `required` gives the signed-in `User` or answers 401; `optional` gives
  `Option(User)`; `with_role(custard, "admin")` answers 403 to everyone
  else. Each also takes a bearer token, for API clients.
- Link people to `/_custard/auth/login?return_to=/somewhere` to sign in and
  to `/_custard/auth/logout` to sign out.
- Tokens are checked in the app, against the service's published keys,
  kept for ten minutes: nothing is asked of the service per request. A
  session whose token has expired is carried on with its refresh token.
- The session is kept in a cookie encrypted with a key made from the
  client secret, so it can be neither read nor changed in the browser.

## Trying it

`dev/example.gleam` is a small app to sign in to: set the variables above
and `gleam run -m example`, then open http://localhost:8799/account.

## Development

```sh
gleam test
```
