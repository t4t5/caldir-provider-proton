# caldir-provider-proton

A [caldir](https://caldir.org) provider for [Proton Calendar](https://proton.me/calendar)

## renCal

If you use [renCal](https://rencal.org), install the [Proton plugin](https://rencal.org/plugins/t4t5.proton/) instead of following the steps below.

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

The default Cargo install stays GUI-free. To let `caldir connect proton` open Proton's CAPTCHA window when human verification is required, build with the `hv` feature:

```bash
cargo install caldir-provider-proton --features hv
```

On Debian and Ubuntu, building with `hv` requires `libwebkit2gtk-4.1-dev`. Release archives are built with `hv`.

## Connect

```bash
caldir connect proton
```

Enter the email and password for your Proton account to authenticate. If Proton asks for a CAPTCHA and the provider was built with `hv`, a small verification window opens and the same connect command continues after it is solved.

On a headless machine, or without the helper, sign in at [account.proton.me](https://account.proton.me) from the same network and retry the connect command.

## License

MIT
