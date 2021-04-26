extern crate tbn;
extern crate rand;

pub use self::RA::RegistrationAuthority;
use tbn::{Group, Fr, G1, G2, Gt, pairing};

// Signaure verification key used by Survey & Registration Authorities
pub struct VerificationKey {
    pub u: G1,
    pub v: G1,
    pub h: G1,
    pub pk: Gt
}

pub struct User {
    
    // TODO: id
    
    pub vk: VerificationKey,
    // Secret signing key used by Survey & Registration Authorities
    sk: Fr,
}


/*
 * ----------------------------------------------
 * |    SURVEY AUTHORITY (SA)                   |
 * ----------------------------------------------
 *
 * Any user can be a survey authority. As an SA, they can perform the following actions:
 *      - Create a survey
 *          + Choose survey identity vid
 *          + Generate signature key-pair that allows them to sign and others to verify values
 *          + Specify a list of user IDs (authenticated by the RA) to send the survey to
*/

pub trait SurveyAuthority {
    
    // Static method aliasing gen_SA
    fn new(g:G1, g2:G2) -> Self;
    
    // Concrete static method that creates values for SA
//    fn gen_SA(g:G1, g2:G2) -> (VerificationKey, Fr);

    #[allow(non_snake_case)]
    fn gen_SA(g:G1, g2:G2) -> (VerificationKey, Fr) {

        // crytpographiclaly secure thread-local rng
        let rng = &mut rand::thread_rng();

        // Generate random u,v,h in G_1
        let u:G1 = G1::random(rng);
        let v:G1 = G1::random(rng);
        let h:G1 = G1::random(rng);

        // Generate secret y as element of cyclic group with order r (q, in ANONIZE's notation)
        let y:Fr = Fr::random(rng);

        // Compute e(g, g2)^y
        let pair:Gt = pairing(g, g2).pow(y);

        // Construct public verification key
        let vk = VerificationKey { u, v, h, pk: pair };
        
        // Return the public and private keys
        (vk, y)
    }
}

impl SurveyAuthority for User {
    
    /* Create Survey Authority */
    fn new(g:G1, g2:G2) -> User {
 
        // Generate parameters for SA
        let (vk, y) = Self::gen_SA(g, g2);
        // Return user with verification and signing key for creating surveys
        User { vk, sk: y }
    }
}

#[allow(non_snake_case)]
pub mod RA;
