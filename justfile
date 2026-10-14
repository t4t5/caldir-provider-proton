check:
    cargo check
    cargo clippy --all-targets -- -D warnings

test:
    cargo test

fmt:
    cargo fmt --all

# Install provider binary to PATH
install:
  cargo install --path . --features hv

# Remove provider binary from PATH
uninstall:
  cargo uninstall caldir-provider-proton
