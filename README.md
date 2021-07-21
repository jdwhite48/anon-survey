# Anonymous Survey System
A (partial) implementation of the ANONIZE [[1]](https://eprint.iacr.org/2015/681) anonymous survey system, written in Rust.

## ⚠ WARNING ⚠ ##
This project was written for educational purposes ONLY.

The source code is in an unfinished state and has not undergone thorough testing. I cannot guarantee the security or anonymity provided by this application, and so **this code should NOT be used in production**.

Use this code at your own risk (or actually, just don't).

## Overview ##

An anonymous survey system is a system which allows registered users to anonymously submit a survey response *at most once* to the survey's creator (i.e. a survey authority). In an *ad-hoc* system such as ANONIZE, these survey authorities can be any user of the system, and have the ability to dynamically select a group of individuals at survey creation who are allowed to submit a response. 



## Build guide ##

Don't.

## Implementation details ##

### Setup ###
- [X] GenRA
  - Generates the keys and other parameters for the Registration Authority (RA)
- [X] GenSA
  - Generates the keys and other parameters for the Survey Authority (SA)

### User Registration ###
- [ ] RegUser
  - User interactively registers their *id* with the RA after a zk-proof, receiving a master credential with which they can respond to surveys.  *Must be done over a mutually authenticated secure communication channel*.

### Survey Generation ###
- [X] GenSurvey
  - User (as SA) non-interactively authorizes a list of users (by *id*) to be eligible take the survey *vid* by assigning them each a partially-blinded signature corresponding to their credential.
- [X] Authorized
  - Verifies whether the user is allowed to take the given survey

### Survey Submission ###
- [ ] SubmitSurvey
  - If they are registered and are authorized to take the survey, user submits a survey token associated with their credential along with their survey response to the SA and a zk-proof that their survey token corresponds to their credential. *Must be done over an anonymous communication channel*.
- [ ] Check
  - Verifier checks the proof, and accepts the survey response if it was correctly computed by the user. They then store the submission (and overwrite their response if the response associated with that token already exists)

## References ##

**[1]** S. Hohenberger, S. Myers, R. Pass and A. Shelat, *"ANONIZE: A Large-Scale Anonymous Survey System,"* 2014 IEEE Symposium on Security and Privacy, 2014, pp. 375-389, doi: 10.1109/SP.2014.31.
