# Per-node authorizers cannot create keys or list applications.
path "kv/data/keygate/apps/*" {
  capabilities = ["read"]
}
