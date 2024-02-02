# rust-vss

Rust-vss is a secure and versatile Verifiable Secret Sharing (VSS) Library for Rust.

## Overview

- Securely split secrets into shares for distribution among multipler parties.
- Verify shares without reconstructing the secret, protecting against compromised parties.
- Flexibility to tailor security parameters such as share count and threshold to your needs.
- Leverage Shamir's Secret Sharing and Chaum-Pedersen Protocol for security and flexibility.

## Key Features

- Threshold based secret sharing: Divide secrets into shares, requiring a minimum number of shares to reconstruct.
- Verifiable shares: Ensure shares are valid and belong to the chosen set, preventing forgery.
- Simplicity: Clear and intuitive functions for splitting, verifying, and combining shares.

## Getting Started

You will need to have Rust and Cargo installed.

```bash
# Build the project
$ cargo build --release

# Run all tests
$ cargo test

# Run examples
$ cargo run --example vss_all_participants
$ cargo run --example vss_missing_participant
```

## Usage

```Rust
use rust_vss::{string_from_secret, string_to_secret, Participant};

fn main() {
  let secret_message = String::from("This is a secret!");

  // Initialize the dealer
  let mut dealer = Participant::new();
  dealer.initialize();

  // Initialize the participants
  let mut participant1 = Participant::new();
  let mut participant2 = Participant::new();
  let mut participant3 = Participant::new();
  participant1.initialize();
  participant2.initialize();
  participant3.initialize();

  // Distribute the secret to participants
  let threshold = 3;
  let distribute_shares_box = dealer.distribute_secret(
    &string_to_secret(&secret_message),
    &vec![
      participant1.publickey.clone(),
      participant2.publickey.clone(),
      participant3.publickey.clone(),
    ],
    threshold,
  );

  // Verify the validity of distributed shares
  assert_eq!(participant1.verify_distribution_shares(&distribute_share_boxes), true);
  assert_eq!(participant2.verify_distribution_shares(&distribute_share_boxes), true);
  assert_eq!(participant3.verify_distribution_shares(&distribute_share_boxes), true);

  // Share extraction
  let sharebox1 = participant1
    .extract_secret_share(&distribute_share_boxes, &participant1.privatekey)
    .unwrap();
  let sharebox2 = participant2
    .extract_secret_share(&distribute_share_boxes, &participant2.privatekey)
    .unwrap();
  let sharebox3 = participant3
    .extract_secret_share(&distribute_share_boxes, &participant3.privatekey)
    .unwrap();

  // Share verification
  assert_eq!(
    participant1.verify_share(&sharebox2, &distribute_share_boxes, &participant2.publickey),
    true
  );
  assert_eq!(
    participant2.verify_share(&sharebox3, &distribute_share_boxes, &participant3.publickey),
    true
  );
  assert_eq!(
    participant3.verify_share(&sharebox1, &distribute_share_boxes, &participant1.publickey),
    true
  );

  // Secret reconstruction
  let share_boxes = [sharebox1, sharebox2, sharebox3];
  let reconstruct1 = participant1
    .reconstruct(&share_boxes, &distribute_share_boxes)
    .unwrap();
  let reconstruct2 = participant2
    .reconstruct(&share_boxes, &distribute_share_boxes)
    .unwrap();
  let reconstruct3 = participant3
    .reconstruct(&share_boxes, &distribute_share_boxes)
    .unwrap();

  let reconstruct1_str = string_from_secret(&reconstruct1);
  assert_eq!(reconstruct1_str, secret_message.clone());

  let reconstruct2_str = string_from_secret(&reconstruct2);
  assert_eq!(reconstruct2_str, secret_message.clone());

  let reconstruct3_str = string_from_secret(&reconstruct3);
  assert_eq!(reconstruct3_str, secret_message.clone());
}
```

Kindly refer to the `examples` directory for more usage examples.

## Disclaimer

This library is still under development and may not be suitable for production use. Please use it with caution and at your own risk.
