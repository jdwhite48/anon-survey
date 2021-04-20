
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
    println!("modulus = {:?}", q);
    println!();

    // TODO: Have all users run on separate threads

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
