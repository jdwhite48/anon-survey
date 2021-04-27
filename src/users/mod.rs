extern crate tbn;
extern crate rand;


#[allow(non_snake_case)]
pub mod RA;
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
    
    // Unique user ID (kept hidden to others when submitting surveys -- user chooses when to
    // reveal
    id: Fr,
    pub vk: VerificationKey,
    // Secret signing key used by Survey & Registration Authorities
    sk: Fr,
    // List of owned surveys (by vid)
    pub owned_surveys: Vec<Fr>,
    // (survey id, {RA's published user ids -> their signature})
    pub verid_list: Vec<(Fr, Vec<(Fr, G1, G2)>)>
}

impl User {
    

    // Generate (hopefully) unique id and return new User
    pub fn new() -> Self {

        // crytpographiclaly secure thread-local rng
        let rng = &mut rand::thread_rng();
        
        // Create empty struct if user ever decides to become SA
        let vk = VerificationKey {
            u: G1::zero(),
            v: G1::zero(),
            h: G1::zero(),
            pk: Gt::one(),
        };

        User {
            id: Fr::random(rng),
            vk,
            sk: Fr::zero(),
            owned_surveys: Vec::new(),
            verid_list: Vec::new()
        }
    }

    // Re-generate id and returns old ID
    pub fn re_identify(&mut self, ra: &mut RegistrationAuthority) -> Fr {

        // Generate new ID
        let old_id:Fr = (*self).id;
        let rng = &mut rand::thread_rng();
        (*self).id = Fr::random(rng);
    
        // Re-register new ID with RA, removing old ID if necessary
        let opt_index = (*ra).userid_list.iter().position(|id| *id == old_id);
        match opt_index {
            Some(old_id_index) => (*ra).userid_list.remove(old_id_index),
            _ => Fr::zero()
        };
        (*self).reg_user(ra);

        return old_id;
    }

    
    pub fn reg_user(&mut self, ra: &mut RegistrationAuthority) {
        // TODO: Follow the protocol to register with RA, send id to RA, and receive master token
        
        // Add own id to list provided by RA
        (*ra).userid_list.push((*self).id);
    }

    // TODO: Allow user to dynamically implement SurveyAuthority trait if they wish to do so after
    // initialization.

    // Generate signature-verification keys on the fly to be able to generate surveys
//    pub fn become_SA(&mut self, g:G1, g2:G2) -> impl SurveyAuthority {
        
//        let (vk, y) = SurveyAuthority::gen_SA(g, g2);
//        (*self).vk = vk;
//        (*self).y = y;
//        println!("{:?}", (*self).vk.u);
//        self
//    }
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
    
    #[allow(non_snake_case)]
    // Static method that creates values for SA
    fn gen_SA(g:G1, g2:G2) -> (VerificationKey, Fr) {

        // crytpographiclaly secure thread-local rng
        let rng = &mut rand::thread_rng();

        // Generate random u,v,h in G_1
        let u:G1 = G1::random(rng);
        let v:G1 = G1::random(rng);
        let h:G1 = G1::random(rng);

        // Generate secret y as element of cyclic group with order r (q, in ANONIZE's notation???)
        let y:Fr = Fr::random(rng);

        // Compute e(g, g2)^y
        let pair:Gt = pairing(g, g2).pow(y);

        // Construct public verification key
        let vk = VerificationKey { u, v, h, pk: pair };
        
        // Return the public and private keys
        (vk, y)
    }

    // Instance method that generate survey with signature for each provided user id
    fn gen_survey(&mut self, L:Vec<Fr>, g:G1, g2:G2, vk_ra: &VerificationKey) -> Option<(Fr, Vec<(Fr, G1, G2)>)>;
}

impl SurveyAuthority for User {
    
    /* Create Survey Authority */
    fn new(g:G1, g2:G2) -> User {
 
        let mut sa = User::new();
        
        // Return user with verification and signing key for creating surveys
        let (vk, y) = Self::gen_SA(g, g2);
        sa.vk = vk;
        sa.sk = y;
        return sa;
    }


        
    fn gen_survey(&mut self, L:Vec<Fr>, g:G1, g2:G2, vk_ra: &VerificationKey) -> Option<(Fr, Vec<(Fr, G1, G2)>)> {
        // crytpographiclaly secure thread-local rng
        let rng = &mut rand::thread_rng();

        // Choose random survey id as well
        let vid = Fr::random(rng);
        // Add vid to the list of owned surveys (by ID)
        (*self).owned_surveys.push(vid);

        /* --------------------------------------------------------------------------
         *          Variation of Boneh-Boyen (BB) ID-based Signature Scheme
         * --------------------------------------------------------------------------
         */

        /* Hoist invariant code to loop pre-header for efficiency */
        // Sign with secret key
        let sign_val:G1 = g * (*self).sk;
        // Sign with vid
        let vid_val:G1 = (*self).vk.u * vid;
        
        // Authorize all users in L (even if they're not registered -- this would be caught later)
        // to submit a survey by constructing a signature with their id
        for id in &L {
            
            // Choose random r in Z_q (TODO: Move this and sigma_2 outside of loop???)
            let r = Fr::random(rng);
            // Sign with participant ID
            let user_val:G1 = (*self).vk.v * *id;
            // Put it all together to get the first signature
            let sigma_1:G1 = sign_val + (vid_val + user_val + (*vk_ra).h) * r;
            // Also sign 2nd group generator with random to get second signature
            let sigma_2:G2 = g2 * r;
            let user_signature:(Fr, G1, G2) = (*id, sigma_1, sigma_2);
            
            let mut found:bool = false;
            // Loop through the various survey(s) the SA owns
            for (owned_vid, id_list) in &mut (*self).verid_list {
                // Found entry to add (id, signature) to
                if *owned_vid == vid {
                    found = true;
                    id_list.push(user_signature);
                    break;
                }
            }
            if !found {   
                // Add (sigma_1, sigma_2) to the list assoc with this vid and participant id
                let mut user_list:Vec<(Fr, G1, G2)> = Vec::new();
                user_list.push(user_signature);
                let survey_entry:(Fr, Vec<(Fr, G1, G2)>)  = (vid, user_list);
                // Must create new entry for (vid, {(ids, signatures)})
                (*self).verid_list.push(survey_entry);
            }
        }
        // "Publish" list of signatures for each participant of survey vid
        for (owned_vid, id_list) in &(*self).verid_list {
            // NOTE: unless something were to remove it during a race condition, should always return
            if *owned_vid == vid {
                let vid_list:(Fr, Vec<(Fr, G1, G2)>) = (vid, (*id_list).clone());
                return Some(vid_list);
            }
        }
        return None;
    }
}


/*
 * Unit tests
 */

#[test]
#[allow(non_snake_case)]
// Test to ensure that e(g, g2)^(sk_SA) = vk_SA
fn test_SA_keys() {
    let rng = &mut rand::thread_rng();
    let (g, g2):(G1, G2) = (G1::random(rng), G2::random(rng));
    let sa:User = SurveyAuthority::new(g, g2);
    assert!( pairing(g, g2).pow(sa.sk) == sa.vk.pk ); 
}


/*
 * Benchmark tests
 */

#[test]
#[ignore]
#[allow(non_snake_case)]
// Test 100 iterations of GenSA to get mean and standard deviation
fn bench_100_gen_SA() {

    use std::time::{Duration, Instant};

    // Setup 
    let rng = &mut rand::thread_rng();
    let (g, g2):(G1, G2) = (G1::random(rng), G2::random(rng));
    
    // 100 irerations of GenSA
    const NUM_TRIALS:usize = 100;
    assert!(NUM_TRIALS > 1);
    println!("GenSA Benchmark Test ({} trials)", NUM_TRIALS);
    let mut sum:Duration = Duration::new(0,0);
    let mut durs:[Duration;NUM_TRIALS] = [Duration::new(0,0);NUM_TRIALS];
    for i in 0..NUM_TRIALS {
        let start = Instant::now(); 
        let _sa:User = SurveyAuthority::new(g, g2);
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
// Test 5 iterations of GenSA to get mean and standard deviation
fn bench_5_gen_SA() {

    use std::time::{Duration, Instant};

    // Setup 
    let rng = &mut rand::thread_rng();
    let (g, g2):(G1, G2) = (G1::random(rng), G2::random(rng));
    
    // 5 irerations of GenSA
    const NUM_TRIALS:usize = 5;
    assert!(NUM_TRIALS > 1);
    println!("GenSA Benchmark Test ({} trials)", NUM_TRIALS);
    let mut sum:Duration = Duration::new(0,0);
    let mut durs:[Duration;NUM_TRIALS] = [Duration::new(0,0);NUM_TRIALS];
    for i in 0..NUM_TRIALS {
        let start = Instant::now(); 
        let _sa:User = SurveyAuthority::new(g, g2);
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
