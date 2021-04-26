extern crate tbn;
extern crate rand;

use tbn::{Group, Fr, G1, G2, Gt, pairing};
use super::{VerificationKey};

/*
 * ----------------------------------------------
 * |    REGISTRATION AUTHORITY (RA)             |
 * ----------------------------------------------
 *
 * The registration is a special user that can perform the following actions:
 *      - Register authorized users under an ID
 *          + Authorize unique user ID when user joins
 *          + Issue master user token to allow users to participate in surveys
 *          + Generate signature key-pair that allows them to sign and others to verify values
 *          + Specify a list of user IDs (authenticated by the RA) to send the survey to
*/

pub struct RegistrationAuthority {
    pub vk: VerificationKey,
    sk: Fr
}

impl RegistrationAuthority {
    
    /* Create Registration Authority */
    pub fn new(g:G1, g2:G2) -> Self {

        // TODO: Call user initialization
        
        // Generate parameters for RA
        let (vk, x) =  Self::gen_RA(g, g2);

        // Return user with verification and signing key for registering users
        RegistrationAuthority {vk, sk: x}
    }

    /* Generate public and private keys for registration authority */
    #[allow(non_snake_case)]
    fn gen_RA(g:G1, g2:G2) -> (VerificationKey, Fr) {

        // crytpographiclaly secure thread-local rng
        let rng = &mut rand::thread_rng();

        // Generate random u,v,h in G_1
        let u:G1 = G1::random(rng);
        let v:G1 = G1::random(rng);
        let h:G1 = G1::random(rng);

        // Generate secret x as element of cyclic group with order r (q, in ANONIZE's notation)
        let x:Fr = Fr::random(rng);

        // Compute e(g, g2)^x
        let pair:Gt = pairing(g, g2).pow(x);

        let vk = VerificationKey { u, v, h, pk: pair };

        // Return parameters for Registration Authority
        (vk, x)
    }
}

#[test]
#[allow(non_snake_case)]
// Test to ensure that e(g, g2)^(sk_RA) = vk_RA
fn test_RA_keys() {
    let rng = &mut rand::thread_rng();
    let (g, g2):(G1, G2) = (G1::random(rng), G2::random(rng));
    let ra = RegistrationAuthority::new(g, g2);
    assert!( pairing(g, g2).pow(ra.sk) == ra.vk.pk ); 
}

