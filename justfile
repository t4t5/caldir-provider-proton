check:
    cargo check
    cargo clippy --all-targets -- -D warnings

test:
    cargo test

fmt:
    cargo fmt --all

# Install provider binary to PATH
install:
  cargo install --path .
