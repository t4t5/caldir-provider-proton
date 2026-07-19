# caldir-provider-proton

A [caldir](https://caldir.org) provider for [Proton Calendar](https://proton.me/calendar)

## Install

Install from crates.io:

```bash
cargo install caldir-provider-proton
```

<details>
<summary>Install from source</summary>

```bash
git clone https://github.com/t4t5/caldir-provider-proton.git
cd caldir-provider-proton
cargo install --path .
```

</details>

`caldir-provider-proton` should now be available on `PATH` for caldir to discover it.

## Connect

```bash
caldir connect proton
```

Enter the email and password for your Proton account to authenticate.

## License

MIT
