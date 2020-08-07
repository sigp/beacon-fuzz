use ssz::Encode; //Decode

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

            // call prysm
            let res = prysm::process_attestation(
                &beacon_blob, //target.pre.as_ssz_bytes(),
                &data,
                &post.as_ssz_bytes(),
            );
            assert_eq!(res, true);

            if debug {
                println!("[PRYSM] Processing {}", true);
            }

            // call nimbus
            let res = nimbus::process_attestation(
                &state.clone(), //target.pre.as_ssz_bytes(),
                &att,
                &post.as_ssz_bytes(),
            );
            assert_eq!(res, true);

            if debug {
                println!("[NIMBUS] Processing {}", true);
            }
        } else {
            if debug {
                println!("[LIGHTHOUSE] Processing {}", false);
            }

            // we assert that we should get false
            // as return value because lighthouse process
            // returned an error
            let res = prysm::process_attestation(
                &beacon_blob, //target.pre.as_ssz_bytes(),
                &data,
                &[], // we don't care of the value here
                     // because prysm should reject
                     // the module first
            );
            assert_eq!(res, false);

            if debug {
                println!("[PRYSM] Processing {}", false);
            }

            // we assert that we should get false
            // as return value because lighthouse process
            // returned an error
            let res = nimbus::process_attestation(
                &state.clone(), //target.pre.as_ssz_bytes(),
                &att,
                &[],
            );
            assert_eq!(res, false);

            if debug {
                println!("[NIMBUS] Processing {}", false);
            }
        }
    // Data is an invalid SSZ container
    } else {
        if debug {
            println!("[LIGHTHOUSE] Container SSZ decoding {}", false);
        }

        // Verify that prysm give same result than lighthouse
        let res = prysm::process_attestation(
            &beacon_blob, //target.pre.as_ssz_bytes(),
            &data,
            &[], // we don't care of the value here
                 // because prysm should reject
                 // the module first
        );
        assert_eq!(res, false);

        if debug {
            println!("[PRYSM] Container SSZ decoding {}", false);
        }

        // TODO - nimbus decoding
        // TODO - create dedicated ssz_decoding function for nimbus and prysm
    }
}
