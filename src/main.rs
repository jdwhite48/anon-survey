
extern crate tbn;
extern crate rand;
use tbn::{Group, Fr, Fq, G1, G2, pairing};
use tbn::arith::U256;

fn main() {
    println!("Hello, world!");

    // TODO: Remove test DH protocol  
    // Thread-local CSRNG
    let rng = &mut rand::thread_rng();

    let alice_sk = Fr::random(rng);
    let bob_sk = Fr::random(rng);
    let carol_sk = Fr::random(rng);

    // Generate public keys in G1 and G2
    let (alice_pk1, alice_pk2) = (G1::one() * alice_sk, G2::one() * alice_sk);
    let (bob_pk1, bob_pk2) = (G1::one() * bob_sk, G2::one() * bob_sk);
    let (carol_pk1, carol_pk2) = (G1::one() * carol_sk, G2::one() * carol_sk);
    
    let q = Fq::modulus();
    print!("modulus = {:?}", q);
    println!();

    let b = G1::b();
    println!("G1 - b = {:?}", b);
    let buint: U256 = b.into_u256();
    println!("G1 - b (U256)= {:?}", buint.0.0);
    println!();

    println!("Alice");
    println!("pk:\npk1 = {:?}\npk2 = {:?}", alice_pk1, alice_pk2);

    let x = alice_pk1.x();
    println!("x = {:?}", x);
    println!("x (U256)= {:?}", x.into_u256());
    let y = alice_pk1.y();
    println!("y = {:?}", y);
    println!("y (U256)= {:?}", y.into_u256());
    let z = alice_pk1.z();
    println!("z = {:?}", z);
    println!("z (U256)= {:?}", z.into_u256());

    let x_real = alice_pk2.x().real();
    let x_i = alice_pk2.x().imaginary();
    println!("x (real) = {:?}", x_real);
    println!("x (real, U256)= {:?}", x_real.into_u256());
    println!("x (imaginary) = {:?}", x_i);
    println!("x (imaginary, U256)= {:?}", x_i.into_u256());
    println!();
    

    println!();
    println!("Bob");
    println!("pk:\npk1 = {:?}\npk2 = {:?}", bob_pk1, bob_pk2);
    
    println!();
    println!("Carol");
    println!("pk:\npk1 = {:?}\npk2 = {:?}", carol_pk1, carol_pk2);
    
    println!();


    // Compute shared secret
    let alice_secret = pairing(bob_pk1, carol_pk2).pow(alice_sk);
    let bob_secret = pairing(carol_pk1, alice_pk2).pow(bob_sk);
    let carol_secret = pairing(alice_pk1, bob_pk2).pow(carol_sk);

    assert!(alice_secret == bob_secret && bob_secret == carol_secret);
}
