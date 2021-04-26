
extern crate tbn;
extern crate rand;

mod users;
use users::{User, SurveyAuthority, RegistrationAuthority};

use tbn::{Group, Fq, G1, G2};
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
    
    // Prime order of cyclic group for G1 and G2

    println!("Pairing-friendly Barreto-Naehrig (BN) curve:");
    // TODO: Have all users run on separate threads
    let (g, g2):(G1, G2) = get_generator_pair();
    println!("g ∈ G1 (generator) = {:?}", g);
    println!("g2 ∈ G2 (generator) = {:?}", g2);
    println!("Bilinear pairing e : G1 × G2 -> Gt, with:");
    let q:U256 = Fq::modulus();
    println!("\tq (prime order for G1, G2, and Gt, and modulus for E) = {:?}", q);
    println!("\te : y^2 = x^3 + b");
    let b:U256 = G1::b().into_u256();
    let mut iter = 0;
    let mut byte:u8 = 0;
    // Compute bits MSB -> LSB
    let mut bytes:Vec<u8> = vec![];
    for bit_bool in b.bits() {
        let bit = bit_bool as u8;
        if iter % 8 == 0 {
            bytes.push(byte);
            byte = 0;
        }
        byte += bit * u8::pow(2, 7 - (iter % 8));
        iter += 1;
    }
    bytes.push(byte);
    println!("\t\tb (constant coefficient) ∈ 𝔽_q for G1 = {}", hex::encode(bytes).as_str());
    println!("\t\tb (constant coefficient) ∈ 𝔽_q2 for G2 = {:?} + {:?} i", G2::b().real().into_u256(), G2::b().imaginary().into_u256());
    // TODO: Figure out how to print elements of type Gt
//    println!("\te(g, g2) ∈ Gt (generator) = {:?}", pairing(g, g2));
    println!("\te(g, g2) ∈ Gt (generator)");
    println!();

    // Instantiate new Registration Authority
    println!("Generating signature-verification key pair (x, vk_RA) for Registration Authority (RA)...");
    let ra:RegistrationAuthority = RegistrationAuthority::new(g, g2);
    println!("vk_RA.u ∈ ℤ_q = {:?}", ra.vk.u);
    println!("vk_RA.v ∈ ℤ_q = {:?}", ra.vk.v);
    println!("vk_RA.h ∈ ℤ_q = {:?}", ra.vk.h);
    println!();

    // Instantiate new Survey Authority
    println!("Generating signature-verification key pair (y, vk_SA) for Survey Authority (SA)...");
    let sa:User = SurveyAuthority::new(g, g2);
    println!("vk_SA.u ∈ ℤ_q = {:?}", sa.vk.u);
    println!("vk_SA.v ∈ ℤ_q = {:?}", sa.vk.v);
    println!("vk_SA.h ∈ ℤ_q = {:?}", sa.vk.h);
    println!();
    
    // TODO: Figure out how to print something of type Gt
//    println!("pair = {:?}", sa.vk.pk.0);
    println!();
}


// Fuzzy test for if we have a good generator for pairing-based crypto
#[test]
fn test_generators() {

    use tbn::{Fr, pairing};

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
