
### Phase 1: Distributed Key Generation (DKG)

This diagram illustrates how the Coordinator manages the Signer nodes to create the shared public key `Y`.

```
      USER                  COORDINATOR                   SIGNER 1          SIGNER 2          SIGNER 3
       |                        |                           |                 |                 |
       | 1. POST /dkg/start     |                           |                 |                 |
       |----------------------> |                           |                 |                 |
       |                        | (Orchestrating DKG...)    |                 |                 |
       |                        |                           |                 |                 |
       |                        | 2. POST /dkg/round1/start |                 |                 |
       |                        |-------------------------->|                 |                 |
       |                        |-------------------------------------------->|                 |
       |                        |-------------------------------------------------------------->|
       |                        |                           |                 |                 |
       |                        |   (Signers now broadcast commitments to each other)           |
       |                        |                           |                 |                 |
       |                        |                    3. POST /dkg/commitments |                 |
       |                        |                           |---------------->|                 |
       |                        |                           |---------------------------------->|
       |                        |                           |                 |                 |
       |                        |                    3. POST /dkg/commitments |                 |
       |                        |                           |<----------------|                 |
       |                        |                           |                 |---------------->|
       |                        |                           |                 |                 |
       |                        |                    3. POST /dkg/commitments |                 |
       |                        |                           |                 |<----------------|
       |                        |                           |<----------------------------------|
       |                        |                           |                 |                 |
       |                        | 4. POST /dkg/round2/start_share_exchange    |                 |
       |                        |-------------------------->|                 |                 |
       |                        |-------------------------------------------->|                 |
       |                        |-------------------------------------------------------------->|
       |                        |                           |                 |                 |
       |                        |     (Signers now exchange secret shares)                      |
       |                        |                           |5.POST /dkg/share|                 |
       |                        |                           |<----------------|                 |
       |                        |                           |---------------------------------->|
       |                        |                           |                 |                 |
       |                        | 6. POST /dkg/round4/compute_keys            |                 |
       |                        |-------------------------->|                 |                 |
       |                        |-------------------------------------------->|                 |
       |                        |-------------------------------------------------------------->|
       |                        |                           |                 |                 |
       |                        | (Verifying success by checking keys...)     |                 |
       |                        |                           |                 |                 |
       |                        | 7. GET /dkg/aggregated_public_key           |                 |
       |                        |-------------------------> |                 |                 |
       |                        |    8. 200 OK {Y}          |                 |                 |
       |                        |<--------------------------|                 |                 |
       |                        |-------------------------------------------->|                 |
       |                        |                           |<----------------------------------|
       |                        |-------------------------------------------------->            |
       |                        |                           |                 |<----------------|
       |                        |                           |                 |                 |
       | 9. 200 OK (DKG Success)|                           |                 |                 |
       |<-----------------------|                           |                 |                 |
       |                        |                           |                 |                 |

```
**Explanation:**
1.  **User -> Coordinator:** The user starts the entire process with one command.
2.  **Coordinator -> Signers:** The Coordinator initiates Round 1 (Commitments).
3.  **Signers <-> Signers:** The Signers talk to each other to exchange their public commitments.
4.  **Coordinator -> Signers:** The Coordinator initiates Round 2 (Share Exchange).
5.  **Signers <-> Signers:** The Signers talk to each other again to exchange their secret shares.
6.  **Coordinator -> Signers:** The Coordinator tells the Signers to compute their final keys.
7.  **Coordinator -> Signers:** The Coordinator asks each Signer for the final aggregated public key (`Y`).
8.  **Signers -> Coordinator:** Each Signer returns its calculated public key. The Coordinator confirms they all match.
9.  **Coordinator -> User:** The Coordinator reports that the DKG was successful.

---

### Phase 2: Coordinated Signature Generation

This diagram shows how the Coordinator acts as a "switchboard" to prevent race conditions and produce a valid signature. For this example, **Signer 1** and **Signer 3** are participating.

```
      USER                      COORDINATOR                         SIGNER 1             SIGNER 3
       |                             |                               |                    |
       | 1. POST /request-signature  |                               |                    |
       | {hash, [1, 3]}              |                               |                    |
       |---------------->            |                               |                    |
       |                             | (Collecting Nonces...)        |                    |
       |                             |                               |                    |
       |                             | 2. POST /generate-nonce-share |                    |
       |                             |------------------------------>|                    |
       |                             |   3. 200 OK {R_1}             |                    |
       |                             |<------------------------------|                    |
       |                             |--------------------------------------------------->|
       |                             |                               |<-------------------|
       |                             |                               |  3. 200 OK {R_3}   |
       |                             |                               |                    |
       |                             | (Distributing All Nonces and getting 'r')          |
       |                             |                               |                    |
       |                             | 4. POST /receive-and-aggregate-r {R_1,R_3}         |
       |                             |------------------------------>|                    |
       |                             |    5. 200 OK {r}              |                    |
       |                             |<------------------------------|                    |
       |                             |--------------------------------------------------->|
       |                             |                               |<-------------------|
       |                             |                               |    5. 200 OK {r}   |
       |                             |                               |                    |
       |                             | (Collecting Final Secret Shares...)                |
       |                             |                               |                    |
       |                             | 6. POST /send-shares-to-coordinator                |
       |                             |------------------------------>| 7. POST /submit-shares {k_1,λ1x1}
       |                             |                               |------------------->|
       |                             |--------------------------------------------------->|
       |                             |                               |                    | 7. POST /submit-shares {k_3,λ3x3}
       |                             |                               |<-------------------|
       |                             | (Assembling s = k_inv*(e+r*x))                     |
       |                             | +----------------+            |                    |
       |                             | | Verify (r,s)   |            |                    |
       |                             | +----------------+            |                    |
       |                             |                               |                    |
       | 8. 200 OK (Signature {r,s}) |                               |
       |<----------------            |                               |                    |
       |                             |                               |                    |

```
**Explanation:**
1.  **User -> Coordinator:** The user requests a signature from parties 1 and 3.
2.  **Coordinator -> Signers:** The Coordinator polls each signer individually to get their public nonces (`R₁`, `R₃`).
3.  **Signers -> Coordinator:** The signers respond with their public nonces.
4.  **Coordinator -> Signers:** The Coordinator sends the *complete list* of all nonces to each signer.
5.  **Signers -> Coordinator:** The signers, now having all the public data, calculate and return the signature's `r` value.
6.  **Coordinator -> Signers:** The Coordinator tells the signers to send their final secret shares.
7.  **Signers -> Coordinator:** Each signer sends its secret components (`kᵢ` and `λᵢxᵢ`) directly to the Coordinator's `/submit-shares` endpoint.
8.  **Coordinator -> User:** The Coordinator assembles and verifies the final signature, then returns it to the user.
