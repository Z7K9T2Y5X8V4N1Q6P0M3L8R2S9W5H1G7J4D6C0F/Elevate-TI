<div align="center">

# Elevate-TI

<p align="center">
  <strong>A safe, idiomatic Rust library to obtain Windows TrustedInstaller privileges.</strong>
</p>

[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)](https://microsoft.com)
[![Rust](https://img.shields.io/badge/Language-Rust-dea584?style=flat-square&logo=rust)](https://rust-lang.org)

</div>

---

## Description

A safe and idiomatic Rust library designed to obtain Windows `TrustedInstaller` privileges and seamlessly relaunch the current process into the active user desktop session.

---

## Getting Started

### Installation

Add the following dependency to your `Cargo.toml`:

```toml
[dependencies]
elevate-ti = { git = "https://github.com/Z7K9T2Y5X8V4N1Q6P0M3L8R2S9W5H1G7J4D6C0F/Elevate-TI.git", branch = "main" }
```

---

## Usage

```rust
use elevate_ti::{check_elevation_status, relaunch_as_trustedinstaller, ElevationStatus};

fn main() -> anyhow::Result<()> {
    if check_elevation_status()? == ElevationStatus::RequiresElevation {
        relaunch_as_trustedinstaller()?;
        return Ok(());
    }

    println!("Now running with TrustedInstaller privileges!");
    Ok(())
}
```