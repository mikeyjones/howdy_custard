//// The person signed in, as the contract between The Custard Factory and
//// apps names them (`docs/contract.md` in The Custard Factory), whatever
//// the sign-in service behind it calls things.

import gleam/list

pub type User {
  User(
    /// Stable for the life of the environment: store this to refer to them.
    user_id: String,
    email: String,
    email_verified: Bool,
    /// For showing.
    name: String,
    /// The organisation they belong to: one of the app's customers.
    org_id: String,
    org_name: String,
    /// Their roles in the app, such as "admin".
    roles: List(String),
  )
}

/// Whether they have `role`.
pub fn has_role(user: User, role: String) -> Bool {
  list.contains(user.roles, role)
}
