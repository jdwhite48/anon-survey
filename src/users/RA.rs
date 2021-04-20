extern crate tbn;
extern crate rand;

use tbn::{Group, Fr, G1, G2, Gt, pairing};

// Signaure verification key used by Registration Authority
pub struct VkRA {
    pub u: G1,
    pub v: G1,
    pub h: G1,
    pub pk: Gt
}

// Secret signing key used by Registration Authority
struct SkRA {
    y: Fr
}

pub struct RegistrationAuthority {
    pub vk: VkRA,
    sk: SkRA
}

impl RegistrationAuthority {
    
    /* Create Registration Authority */
    pub fn new(g:G1, g2:G2) -> RegistrationAuthority {

        // TODO: Call user initialization
        
        RegistrationAuthority::gen_RA(g, g2)
    }

    /* Generate public and private keys for registration authority */
    #[allow(non_snake_case)]
    pub(crate) fn gen_RA(g:G1, g2:G2) -> RegistrationAuthority {

        // crytpographiclaly secure thread-local rng
        let rng = &mut rand::thread_rng();

        // Generate random u,v,h in G_1
        let u:G1 = G1::one() * Fr::random(rng);
        let v:G1 = G1::one() * Fr::random(rng);
        let h:G1 = G1::one() * Fr::random(rng);

        // Generate secret y as element of cyclic group with order r (q, in ANONIZE's notation)
        let y:Fr = Fr::random(rng);

        // Compute e(g, g2)^y
        let pair:Gt = pairing(g, g2).pow(y);

        // Get public and private keys
        let vk:VkRA = VkRA { u, v, h, pk: pair };
        let sk:SkRA = SkRA { y };

        // Return RegistrationAuthority
        RegistrationAuthority { vk, sk }
    }
}
