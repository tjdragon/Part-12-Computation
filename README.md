# Partouze Computation

Open Source MPC (Multi-Party Computation) in Python.  
90% done with the help of AI.

## Algorithm

Consider N parties involved and a threshold T.

If N = 5 and T = 2, it means that 2 parties are required to sign the message.

See [the maths](./Gemini/MPC-Maths.pdf)

## Message flow

The following sequence diagram illustrates the flow for N = 3.


![Message Flow N=3](./images/mpc-algo.png)

## How to Securely Share Commitments?

We just passed the commitment objects around in a Python dictionary.  
In the real world, this is insecure.  
A malicious party could show one commitment to Alice and a different one to Bob.  
This is called **equivocation**.

### Why are Zero-Knowledge Proofs Needed?

This is the most critical security layer that our simulation omits for simplicity.  
The commitments ($C_i$) and nonce shares ($R_i$) prove that a party is "committed" to a value, but they don't prove that the party acted honestly to create that commitment.

A malicious party could still cheat. This is where ZKPs come in. They force each party to prove they followed the rules without revealing their secrets.

Here are the two key places in the protocol where ZKPs are non-negotiable:

#### During Distributed Key Generation (DKG):

The Problem: When a party i creates its polynomial and broadcasts its commitment $C_{i0} = a_{i0} * G$, how do we know they actually know the secret $a_{i0}$? They could have copied another party's commitment or generated it in a malicious way. 

The ZKP Solution: Each party must also broadcast a Proof of Knowledge of the secret $a_{i0}$. They essentially prove: "I know a secret value x such that this public point P equals x * G, but I am not telling you what x is." This is a standard Schnorr-style proof and it confirms that the party is acting honestly and knows the secret corresponding to their public commitment.

#### During Signing:

The Problem: When a signing party i commits to their nonce by broadcasting $R_i = k_i * G$, a malicious party could try to influence the final signature.  
For example, they could set their $R_i$ to be the inverse of another party's $R_j$, causing the aggregate R to be compromised: this can leak information about the other parties' private key shares. This is known as a rogue-key attack.

The ZKP Solution: Each signing party must provide a ZKP that they know the discrete logarithm of their public nonce $R_i$. They prove: "I know the secret nonce k_i that corresponds to this public point $R_i$." This prevents them from deriving their $R_i$ from other public information and forces them to use a properly generated random secret, defeating the rogue-key attack.

#### How-To?

- [ZoKrates](https://zokrates.github.io/)
- [DIY with ECDSA: Non-Interactive Schnorr Proof of Knowledge](./Gemini/ZKP_Schnorr_PoK.ipynb)