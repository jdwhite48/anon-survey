extern crate tbn;
extern crate rand;

use tbn::{Group, Fr, G1, G2, Gt, pairing};

// Signaure verification key used by Survey Authority
pub struct VkSA {
    pub u: G1,
    pub v: G1,
    pub h: G1,
    pub pk: Gt
}

// Secret signing key used by Survey Authority
struct SkSA {
    y: Fr
}

pub struct SurveyAuthority {
    pub vk: VkSA,
    sk: SkSA
}

impl SurveyAuthority {
    
    /* Create Survey Authority */
    pub fn new(g:G1, g2:G2) -> SurveyAuthority {

        // TODO: Call user initialization
        
        SurveyAuthority::gen_SA(g, g2)
    }

    /* Generate public and private keys for survey authority */
    #[allow(non_snake_case)]
    pub(crate) fn gen_SA(g:G1, g2:G2) -> SurveyAuthority {

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
        let vk:VkSA = VkSA { u, v, h, pk: pair };
        let sk:SkSA = SkSA { y };

        // Return SurveyAuthority
        SurveyAuthority { vk, sk }
    }
}
