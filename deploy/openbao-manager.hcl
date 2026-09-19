# Dedicated KV v2 mount/prefix; adjust to match KEYGATE_BAO_MOUNT/PREFIX.
path "kv/data/keygate/apps/*" {
  capabilities = ["create", "read", "update"]
}
path "kv/metadata/keygate/apps" {
  capabilities = ["list"]
}
