
extern crate tbn;
extern crate rand;

mod users;
use users::SA::SurveyAuthority;
use users::RA::RegistrationAuthority;


use tbn::{Group, Fr, Fq, G1, G2, pairing};
use tbn::arith::U256;

fn main() {
    println!("Hello, world!");
    
    
    
    // Crytpographiclaly secure thread-local rng
    let rng = &mut rand::thread_rng();
    
    // Construct "generators" g in G_1 and g_2 in G_2? 
    // TODO: What are the actual generators of G_1 and G_2 ???
    let (g, g2):(G1, G2) = (G1::one() * Fr::random(rng), G2::one() * Fr::random(rng));
    
    // TODO: Is this the right modulus / order of cyclic groups ???
    let q:U256 = Fq::modulus();
    print!("modulus = {:?}", q);
    println!();

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



    // TODO: Remove test DH protocol  

    let alice_sk = Fr::random(rng);
    let bob_sk = Fr::random(rng);
    let carol_sk = Fr::random(rng);

    // Generate public keys in G1 and G2
    let (alice_pk1, alice_pk2) = (G1::one() * alice_sk, G2::one() * alice_sk);
    let (bob_pk1, bob_pk2) = (G1::one() * bob_sk, G2::one() * bob_sk);
    let (carol_pk1, carol_pk2) = (G1::one() * carol_sk, G2::one() * carol_sk);

    let b = G1::b();
    println!("G1");
    println!("b = {:?}", b);
    let buint: U256 = b.into_u256();
    println!("b (U256) = {:?}", buint.0);
    println!();

    println!("Alice");
    println!("pk:\npk1 = {:?}\npk2 = {:?}", alice_pk1, alice_pk2);

    println!();
    println!("Bob");
    println!("pk:\npk1 = {:?}\npk2 = {:?}", bob_pk1, bob_pk2);
    
    println!();
    println!("Carol");
    println!("pk:\npk1 = {:?}\npk2 = {:?}", carol_pk1, carol_pk2);
    
    println!();

    // Compute shared DH secret
    let alice_secret = pairing(bob_pk1, carol_pk2).pow(alice_sk);
    let bob_secret = pairing(carol_pk1, alice_pk2).pow(bob_sk);
    let carol_secret = pairing(alice_pk1, bob_pk2).pow(carol_sk);

    assert!(alice_secret == bob_secret && bob_secret == carol_secret);
}
