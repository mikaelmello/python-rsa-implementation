# RSA Implementation in Python

Made as an exercise to learn about practical implementations of RSA.

This program allows you to generate a pair of RSA keys of a selected size and export them.

You can then import those keys and use them to encrypt/decrypt small messages, sign files and verify signatures.

# Usage

```
usage: python3 main.py <command> [<args>]

The most commonly used commands are:
   generate     Generates a keypair
   encrypt      Encrypts a string using an imported key
   decrypt      Decrypts a string using an imported key
   sign         Signs a file using an imported private key
   verify       Verifies a signature using an imported public key
```

### Generate

```
usage: main.py generate keysize outdir

Generates a keypair

positional arguments:
  generate    Generate
  keysize     Size of the key in bits, allowed values: 512, 1024, 2048, 4096
  outdir      Where to store the generated keys
```

### Encrypt

```
usage: main.py encrypt public_key_file_path message

Encrypts a string using a key

positional arguments:
  encrypt               Encrypt
  public_key_file_path  Path of where the key is located
  message               Message to be encrypted
```

### Decrypt

```
usage: main.py decrypt private_key_file_path message

Decrypts a string using a key

positional arguments:
  decrypt                Decrypt
  private_key_file_path  Path of where the key is located
  message                Message to be decrypted
```

### Sign

```
usage: main.py sign input_file_path private_key_file_path output_file_path

Signs a file using a private key

positional arguments:
  sign                   Sign
  input_file_path        Path of where the input file is located
  private_key_file_path  Path of the private key
  output_file_path       Path to store signature
```

### Verify

```
usage: main.py sign input_file_path public_key_file_path signature_file_path

Verify a signature

positional arguments:
  sign                  Sign
  input_file_path       Path of where the input file is located
  public_key_file_path  Path of the public key
  signature_file_path   Path to store signature
```