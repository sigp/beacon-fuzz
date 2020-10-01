use ssz::Encode; //Decode

use types::{Attestation, MainnetEthSpec};

pub fn get_raw_data_from_fuzzer() -> Vec<u8> {
    return vec![0xff; 1085];
}

use arbitrary::{Arbitrary, Unstructured};
pub fn run_attestation_struct(beacon_blob: &[u8], data: &[u8], debug: bool) {
    // SSZ Decoding of the beaconstate
    let state = lighthouse::ssz_beaconstate(&beacon_blob)
        .expect("[LIGHTHOUSE] BeaconState SSZ decoding failed");

    // generate attestation

    // Get the raw data from the fuzzer or wherever else.
    let data: &[u8] = &get_raw_data_from_fuzzer();

    // Wrap that raw data in an `Unstructured`.
    let mut unstructured = Unstructured::new(data);

    // Generate an arbitrary instance of `MyType` and do stuff with it.
    if let Ok(value) = Attestation::<MainnetEthSpec>::arbitrary(&mut unstructured) {
        println!("{:?}", value);
    }

    println!("{:?}", Attestation::<MainnetEthSpec>::size_hint(0));

    println!(
        "{:?}",
        Attestation::<MainnetEthSpec>::arbitrary_take_rest(unstructured)
    );
}

// TODO - use closure for ssz decoding type
pub fn run_attestation(beacon_blob: &[u8], data: &[u8], debug: bool) {
    // SSZ Decoding of the beaconstate
    let state = lighthouse::ssz_beaconstate(&beacon_blob)
        .expect("[LIGHTHOUSE] BeaconState SSZ decoding failed");

    // SSZ Decoding of the container
    if let Ok(att) = lighthouse::ssz_attestation(&data) {
        if debug {
            println!("[LIGHTHOUSE] SSZ decoding {}", true);
        }
        // Clone the beaconstate locally
        let beacon_clone = state.clone();

        // call lighthouse and get post result
        // focus only on valid post here
        if let Ok(post) = lighthouse::process_attestation(beacon_clone, att.clone()) {
            if debug {
                println!("[LIGHTHOUSE] Processing {}", true);
            }
            //TODO avoid serializing post 3 times

            // call prysm
            let res = prysm::process_attestation(&beacon_blob, &data, &post.as_ssz_bytes());

            if debug {
                println!("[PRYSM] Processing {}", res);
            } else {
                assert_eq!(res, true);
            }

            // call nimbus
            let res = nimbus::process_attestation(&state.clone(), &att, &post.as_ssz_bytes());

            if debug {
                println!("[NIMBUS] Processing {}", res);
            } else {
                assert_eq!(res, true);
            }

            // call teku
            let res = teku::process_attestation(&state.clone(), &att, &post.as_ssz_bytes());

            if debug {
                println!("[TEKU] Processing {}", res);
            } else {
                assert_eq!(res, true);
            }
        } else {
            if debug {
                println!("[LIGHTHOUSE] Processing {}", false);
            }

            // Verify that prysm give same result than lighthouse
            let res = prysm::process_attestation(&beacon_blob, &data, &beacon_blob.clone());

            if debug {
                println!("[PRYSM] Processing {}", res);
            } else {
                assert_eq!(res, false);
            }

            // Verify that nimbus give same result than lighthouse
            let res = nimbus::process_attestation(&state.clone(), &att, &beacon_blob.clone());

            if debug {
                println!("[NIMBUS] Processing {}", res);
            } else {
                assert_eq!(res, false);
            }

            // Verify that teku gives same result as lighthouse
            let res = teku::process_attestation(&state.clone(), &att, &beacon_blob.clone());

            if debug {
                println!("[TEKU] Processing {}", res);
            } else {
                assert_eq!(res, false);
            }
        }

    // Data is an invalid SSZ container
    } else {
        if debug {
            println!("[LIGHTHOUSE] Container SSZ decoding {}", false);
        }

        // Verify that prysm give same result than lighthouse
        let res = prysm::ssz_attestation(&data);

        if debug {
            println!("[PRYSM] Container SSZ decoding {}", false);
        } else {
            assert_eq!(res, false);
        }

        // TODO - nimbus decoding
        // TODO - create dedicated ssz_decoding function for nimbus and prysm
    }
}
