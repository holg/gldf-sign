# GLDF Sign

GLDF Sign is a Rust-based tool for signing and verifying GLDF (General Lighting
Data Format) files. Leveraging the cryptographic strength of `minisign`, GLDF
Sign provides an intuitive and secure method to ensure the integrity and
authenticity of GLDF files.

## Features

- **Embedded Public Key**: The public key is stored within the
  `meta-information.xml` inside the GLDF container, eliminating the need to
  manage separate public key files.
- **Secure Signing**: Utilizes the cryptographic capabilities of `minisign` for
  robust signing.
- **Easy Verification**: Seamlessly verify the authenticity of any GLDF file
  without needing an external public key.
- **Cross-Platform**: Compatible with Windows, macOS, Linux, and WebAssembly
  platforms.
- **CLI Support**: Features a command-line interface for straightforward
  integration into various workflows.

## Installation

```bash
cargo install gldf-sign
```

## Usage

### Key Generation

Generate a new key pair:

```bash
gldf-sign generate
```

Options:

- `-p, --public-key-path <PUBLIC_KEY_PATH>`: Specify the path to the new public
  key.
- `-s, --secret-key-path <SECRET_KEY_PATH>`: Specify the path to the new secret
  key.
- `-f, --force`: Force generate a new key pair.
- `-c, --comment <COMMENT>`: Add a one-line untrusted comment.
- `-W, --passwordless`: Don't use a password for the secret key.

### Signing a File

Sign a file using a given private key:

```bash
gldf-sign sign -s <SECRET_KEY_FILE> -p <PUBLIC_KEY_FILE> <FILE>
```

### Signing a GLDF File

Sign a GLDF file and embed the public key into its meta-information:

```bash
gldf-sign signgldf -s <SECRET_KEY_FILE> -p <PUBLIC_KEY_FILE> <GLDFFILE>
```

### Verifying a File

Verify a signed file:

```bash
gldf-sign verify <FILE>
```

### Verifying a GLDF File

Verify a signed GLDF file:

```bash
gldf-sign verifygldf <GLDFFILE>
```

## Contributing

Contributions are always appreciated! For more details on how to contribute,
please refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GLDF Sign is licensed under the GPL-3.0-or-later. For more information, see the
[LICENSE](LICENSE) file.
