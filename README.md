# Johnny can encrypt

[![CircleCI branch](https://img.shields.io/circleci/project/github/kushaldas/johnnycanencrypt/main.svg)](https://circleci.com/gh/kushaldas/workflows/johnnycanencrypt/tree/main)

Johnnycanencrypt aka **jce** is a Python module written in Rust to do basic encryption and decryption, and detached signing operations.
It uses amazing [sequoia-pgp](https://sequoia-pgp.org/) library for the actual OpenPGP operations.

You can also use Yubikeys for the private key operations using this module.

# How to build?

## Prerequisites
- Install [uv](https://github.com/astral-sh/uv):
  - With pipx: `pipx install uv`
  - Or see uv's documentation for other methods
- Install [Rustup toolchain](https://rustup.rs) for your user.

First install [Rustup toolchain](https://rustup.rs) for your user.

### Build dependencies in Fedora

```
sudo dnf install nettle clang clang-devel nettle-devel python3-devel pcsc-lite-devel
```

### Build dependencies in Debian Bullseye

```
sudo apt install -y python3-dev libnettle8 nettle-dev libhogweed6 python3-pip python3-venv clang libpcsclite-dev libpcsclite1 libclang-9-dev pkg-config

```


```
# Recommended: use uv for setup and development
uv sync
uv run -m maturin_import_hook site install
maturin develop
```

After this, you can simply import the package in Python and the Rust extension will be rebuilt automatically if needed, thanks to the maturin import hook.

Legacy setup (not recommended):
```
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
maturin develop
```

For a release build use the following command.

```
maturin build --release
```

## Introduction

Please read the [Introduction](https://johnnycanencrypt.readthedocs.io/en/latest/introduction.html) documentation.

## API documentation

Please go through the [full API documentation](https://johnnycanencrypt.readthedocs.io/en/latest/api.html) for detailed
descriptions.

## LICENSE: LGPL-3.0-or-later

