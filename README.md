# The Rust example of the end-to-end encryption approach (key exchange);

## How it works:

It utilizes the Diffie-Hellman secret key exchange method as well as Blake2 encryption function since shared secrets computed through Eliptic Curve Deffie-Hellman key exchange can't be used directly for symmetric encryption.

## Run the example:
```
cargo run
```