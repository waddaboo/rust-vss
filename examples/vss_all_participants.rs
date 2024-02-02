use rust_vss::{string_from_secret, string_to_secret, Participant};

fn main() {
    let secret_message = String::from("Test");
    let mut dealer = Participant::new();

    dealer.initialize();

    let mut participant1 = Participant::new();
    let mut participant2 = Participant::new();
    let mut participant3 = Participant::new();

    participant1.initialize();
    participant2.initialize();
    participant3.initialize();

    // distribute process
    let distribute_share_boxes = dealer.distribute_secret(
        &string_to_secret(&secret_message),
        &vec![
            participant1.publickey.clone(),
            participant2.publickey.clone(),
            participant3.publickey.clone(),
        ],
        3,
    );

    assert_eq!(
        participant1.verify_distribution_shares(&distribute_share_boxes),
        true
    );
    assert_eq!(
        participant2.verify_distribution_shares(&distribute_share_boxes),
        true
    );
    assert_eq!(
        participant3.verify_distribution_shares(&distribute_share_boxes),
        true
    );

    // extract process
    let sharebox1 = participant1
        .extract_secret_share(&distribute_share_boxes, &participant1.privatekey)
        .unwrap();
    let sharebox2 = participant2
        .extract_secret_share(&distribute_share_boxes, &participant2.privatekey)
        .unwrap();
    let sharebox3 = participant3
        .extract_secret_share(&distribute_share_boxes, &participant3.privatekey)
        .unwrap();

    // verify process
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

    // reconstruct process
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

    println!("Secret message: {}", secret_message);
    println!("Reconstructed string 1: {}", reconstruct1_str);
    println!("Reconstructed string 2: {}", reconstruct2_str);
    println!("Reconstructed string 3: {}", reconstruct3_str);
}
