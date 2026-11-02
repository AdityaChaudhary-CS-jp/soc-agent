"""Role-based access control (RBAC) with synthetic users.

  viewer   can read only.
  analyst  can approve SAFE actions (verify, review, audit) and reject any.
  admin    can approve and reject everything, including sensitive actions
           (block IP, isolate host, reset credentials...).
"""
USERS = {
    "viewer1": "viewer",
    "analyst1": "analyst",
    "analyst2": "analyst",
    "admin1": "admin",
}


def role_of(username: str) -> str:
    role = USERS.get(username)
    if role is None:
        raise PermissionError(f"Unknown user '{username}'.")
    return role


def can_decide(role: str, sensitive: bool, approve: bool) -> bool:
    if role == "admin":
        return True
    if role == "analyst":
        return (not sensitive) or (not approve)   # analysts may reject anything
    return False                                  # viewers cannot decide
