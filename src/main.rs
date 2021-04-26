
extern crate tbn;
extern crate rand;

mod users;
use users::SA::SurveyAuthority;
use users::RA::RegistrationAuthority;


use tbn::{Group, Fr, Fq, G1, G2, pairing};
use tbn::arith::U256;



// Returns generators (g, g2) in (G1, G2)
// Because G1 and G2 are additive cyclic groups of prime order by construction of BN curves
// It is sufficient to randomly choose elements in G1 and G2 to get g and g2
fn get_generator_pair() -> (G1, G2) {
    
    // Crytpographiclaly secure thread-local rng
    let rng = &mut rand::thread_rng();

    // Generate random elements in G1 and G2
    let (mut g, mut g2):(G1, G2) = (G1::random(rng), G2::random(rng));
    // Ensure that g,g2 are both generators (i.e. non-zero in additive cyclic group of prime
    // order)
    while g.is_zero() {
        g = G1::random(rng);
    }
    while g2.is_zero() {
        g2 = G2::random(rng);
    }

    // Return generator pair
    (g, g2)
}

fn main() {
    
    // Crytpographiclaly secure thread-local rng
    let rng = &mut rand::thread_rng();

    
    // TODO: Is this the right modulus / order of cyclic groups ???
    let q:U256 = Fq::modulus();
    println!("modulus = {:?}", q);
    println!();

    // TODO: Have all users run on separate threads
    let (g, g2):(G1, G2) = get_generator_pair();

    // Instantiate new Registration Authority
    let ra:RegistrationAuthority = RegistrationAuthority::new(g, g2);
    println!("Registration Authority (RA)");
    println!("u = {:?}", ra.vk.u);
    println!("v = {:?}", ra.vk.v);
    println!("h = {:?}", ra.vk.h);
    println!();

    // Instantiate new Survey Authority
    let sa:SurveyAuthority = SurveyAuthority::new(g, g2);
    println!("Survey Authority (SA)");
    println!("u = {:?}", sa.vk.u);
    println!("v = {:?}", sa.vk.v);
    println!("h = {:?}", sa.vk.h);
    // TODO: Figure out how to print something of type Gt
//    println!("pair = {:?}", sa.vk.pk.0);
    println!();
}


// Fuzzy test for if we have a good generator for pairing-based crypto
#[test]
fn test_generators() {
    let (g, g2):(G1, G2) = get_generator_pair();
    // Try 5 different random values to see if assertion holds each time
    // For random a and b, asserts that e(g^a, g_2^b) = e(g,g_2)^{ab} (RHS is generator for Gt)
    let rng = &mut rand::thread_rng();
    for _ in 0..5 {
        let a = Fr::random(rng);
        let b = Fr::random(rng);
        assert!( pairing(g * a, g2 * b) == pairing(g, g2).pow(a * b) );
    }
}
