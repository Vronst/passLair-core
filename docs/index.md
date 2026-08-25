# passLair

**passLair** is a Python library for building a password manager: user
registration and login, an encrypted credential vault, and import/export of
vault contents to JSON, CSV, and plain-text formats (as files or via the
system clipboard).

It's a *library*, not a finished application — passLair doesn't ship a CLI
or web UI itself. The `passlair.core.interface` facades exist specifically
to be wrapped by one.

## Installation

```bash
pip install passlair
```

From source, with [uv](https://docs.astral.sh/uv/):

```bash
uv sync
```

## Core concepts

- **`Identity`** (`passlair.core.interface.identity`) — registration,
  login, logout, and password changes.
- **`PasswordManager`** (`passlair.core.interface.password_manager`) —
  reading and writing individual vault entries for the logged-in user.
- **`Exporter`** / **`Importer`** (`passlair.share`) — bulk export and
  import of a user's vault to/from JSON, CSV, or plain-text.

Every credential is encrypted at rest. Decryption only ever happens for an
authenticated user's own active session — there's no code path that
decrypts one user's vault using another user's session key.

See [API Reference](api-reference.md) for the generated class and method
documentation.
