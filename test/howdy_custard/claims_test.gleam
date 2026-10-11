import gleam/json
import howdy_custard/claims
import howdy_custard/support
import howdy_custard/user.{User}

pub fn reads_a_user_in_the_contracts_names_test() {
  let text = json.to_string(json.object(support.alice(0, 0, "n")))
  assert json.parse(text, claims.decoder())
    == Ok(
      User(
        user_id: "user-1",
        email: "alice@bobsbakery.test",
        email_verified: True,
        name: "Alice Baker",
        org_id: "org-1",
        org_name: "Bob's Bakery",
        roles: ["admin", "baker"],
      ),
    )
}

pub fn an_access_token_has_less_test() {
  let text = "{\"sub\":\"user-1\"}"
  let assert Ok(found) = json.parse(text, claims.decoder())
  assert found.user_id == "user-1"
  assert found.roles == []
  assert found.email == ""
}
