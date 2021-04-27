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
    sk: Fr,
    // A list of users for the anonymous survey system. Essentially an anonymity set
    pub userid_list: Vec<Fr>
}

impl RegistrationAuthority {
    
    /* Create Registration Authority */
    pub fn new(g:G1, g2:G2) -> Self {

        // TODO: Call user initialization
        
        // Generate parameters for RA
        let (vk, x) =  Self::gen_RA(g, g2);

        let userid_list:Vec<Fr> = Vec::new();
        // Return user with verification and signing key for registering users
        RegistrationAuthority {vk, sk: x, userid_list}
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


/*
 * Unit tests
 */

#[test]
#[allow(non_snake_case)]
// Test to ensure that e(g, g2)^(sk_RA) = vk_RA
fn test_RA_keys() {
    let rng = &mut rand::thread_rng();
    let (g, g2):(G1, G2) = (G1::random(rng), G2::random(rng));
    let ra = RegistrationAuthority::new(g, g2);
    assert!( pairing(g, g2).pow(ra.sk) == ra.vk.pk ); 
}


/*
 * Benchmark tests
 */

#[test]
#[ignore]
#[allow(non_snake_case)]
// Test 100 iterations of GenRA to get mean and standard deviation
fn bench_100_gen_RA() {

    use std::time::{Duration, Instant};

    // Setup 
    let rng = &mut rand::thread_rng();
    let (g, g2):(G1, G2) = (G1::random(rng), G2::random(rng));
    
    // 100 irerations of GenRA
    const NUM_TRIALS:usize = 100;
    assert!(NUM_TRIALS > 1);
    println!("GenRA Benchmark Test ({} trials)", NUM_TRIALS);
    let mut sum:Duration = Duration::new(0,0);
    let mut durs:[Duration;NUM_TRIALS] = [Duration::new(0,0);NUM_TRIALS];
    for i in 0..NUM_TRIALS {
        let start = Instant::now(); 
        let _ra = RegistrationAuthority::new(g, g2);
        durs[i] = start.elapsed();
        sum += durs[i];
        println!("Trial {}:\t{:?}", i+1, durs[i]);
    }
    println!();
    // Calculate mean
    let mean = sum / (NUM_TRIALS as u32);
    // Calculate standard deviation
    let mut sum_of_diff:f32 = 0.0;
    for i in 0..NUM_TRIALS {
        sum_of_diff += f32::powf((((durs[i].as_millis() as i128) - (mean.as_millis() as i128)) as f32)/1000.0, 2.0);
    }
    let sd = ( sum_of_diff / ((NUM_TRIALS as f32)- 1.0)).sqrt();
 
    println!("Mean:\t\t{:?}", mean);
    println!("Std Dev:\t{:?}s", sd);
}


#[test]
#[allow(non_snake_case)]
// Test 5 iterations of GenRA to get mean and standard deviation
fn bench_5_gen_RA() {

    use std::time::{Duration, Instant};

    // Setup 
    let rng = &mut rand::thread_rng();
    let (g, g2):(G1, G2) = (G1::random(rng), G2::random(rng));
    
    // 5 irerations of GenRA
    const NUM_TRIALS:usize = 5;
    assert!(NUM_TRIALS > 1);
    println!("GenRA Benchmark Test ({} trials)", NUM_TRIALS);
    let mut sum:Duration = Duration::new(0,0);
    let mut durs:[Duration;NUM_TRIALS] = [Duration::new(0,0);NUM_TRIALS];
    for i in 0..NUM_TRIALS {
        let start = Instant::now(); 
        let _ra = RegistrationAuthority::new(g, g2);
        durs[i] = start.elapsed();
        sum += durs[i];
        println!("Trial {}:\t{:?}", i+1, durs[i]);
    }
    println!();
    // Calculate mean
    let mean = sum / (NUM_TRIALS as u32);
    // Calculate standard deviation
    let mut sum_of_diff:f32 = 0.0;
    for i in 0..NUM_TRIALS {
        sum_of_diff += f32::powf((((durs[i].as_millis() as i128) - (mean.as_millis() as i128)) as f32)/1000.0, 2.0);
    }
    let sd = ( sum_of_diff / ((NUM_TRIALS as f32)- 1.0)).sqrt();
 
    println!("Mean:\t\t{:?}", mean);
    println!("Std Dev:\t{:?}s", sd);
}
