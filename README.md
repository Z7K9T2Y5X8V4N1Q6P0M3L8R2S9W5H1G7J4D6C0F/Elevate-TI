# Elevate-TI

## Description

A safe, idiomatic Rust library to obtain Windows `TrustedInstaller` privileges and relaunch the current process into the active user desktop.

## Getting started

## Install

Add this to your `Cargo.toml`:

```toml
[dependencies]
elevate-ti = { git = "https://github.com/Z7K9T2Y5X8V4N1Q6P0M3L8R2S9W5H1G7J4D6C0F/Elevate-TI.git", branch = "main" }
```

### Usage

```rust
use elevate_ti::{check_elevation_status, relaunch_as_trusted_installer, ElevationStatus};

fn main() -> anyhow::Result<()> {
    if check_elevation_status()? == ElevationStatus::RequiresElevation {
        relaunch_as_trusted_installer()?;
        return Ok(());
    }

    println!("Now running with TrustedInstaller privileges!");
    Ok(())
}
```

## Back matter

### Legal disclaimer

Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

### License

This project is licensed under the [MIT License](LICENSE).