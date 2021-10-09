import random
from umbral import (
    SecretKey, Signer, CapsuleFrag,
    encrypt, generate_kfrags, reencrypt, decrypt_original, decrypt_reencrypted)

# Generate an Umbral key pair
# ---------------------------
# First, Let's generate two asymmetric key pairs for Alice:
# A delegating key pair and a Signing key pair.

alices_secret_key = SecretKey.random()
alices_public_key = alices_secret_key.public_key()

alices_signing_key = SecretKey.random()
alices_verifying_key = alices_signing_key.public_key()
alices_signer = Signer(alices_signing_key)

# Encrypt some data for Alice
# ---------------------------
# Now let's encrypt data with Alice's public key.
# Invocation of `pre.encrypt` returns both the `ciphertext`,
# and a `capsule`. Anyone with Alice's public key can perform
# this operation.

# encrypt alices account value 
plaintext = b'100.365'
alice_capsule, ciphertext = encrypt(alices_public_key, plaintext)
print(ciphertext)

# Decrypt data for Alice
# ----------------------
# Since data was encrypted with Alice's public key,
# Alice can open the capsule and decrypt the ciphertext with her private key.

cleartext = decrypt_original(alices_secret_key, alice_capsule, ciphertext)
print(cleartext)


# Bob Exists
# -----------

bobs_secret_key = SecretKey.random()
bobs_public_key = bobs_secret_key.public_key()
bobs_signing_key = SecretKey.random()
bobs_verifying_key = bobs_signing_key.public_key()
bobs_signer = Signer(bobs_signing_key)

# Encrypt some data for Alice
# ---------------------------
# Now let's encrypt data with Alice's public key.
# Invocation of `pre.encrypt` returns both the `ciphertext`,
# and a `capsule`. Anyone with Alice's public key can perform
# this operation.


#encrypt bobs acount value 
plaintext = b'10.65'

transaction amount = b'5'

capsule_bob, ciphertext = encrypt(bobs_public_key, plaintext)
print(ciphertext)

bob_capsule = capsule_bob

# Attempt Bob's decryption (fail)
try:
    fail_decrypted_data = decrypt_original(bobs_secret_key, bob_capsule, ciphertext)
    print(fail_decrypted_data, "")
except ValueError:
    print("Decryption failed! Bob doesn't has access granted yet.")

# Alice grants access to Bob by generating kfrags
# -----------------------------------------------
# When Alice wants to grant Bob access to open her encrypted messages,
# she creates *threshold split re-encryption keys*, or *"kfrags"*,
# which are next sent to N proxies or *Ursulas*.
# She uses her private key, and Bob's public key, and she sets a minimum
# threshold of 10, for 20 total shares




#generate alices_kfrags 
kfrags_alice = generate_kfrags(delegating_sk=alices_secret_key,
                         receiving_pk=bobs_public_key,
                         signer=alices_signer,
                         threshold=10,
                         shares=20)

#generate bob_kfrags 

kfrags_bob = generate_kfrags(delegating_sk=bobs_secret_key,
                         receiving_pk=alices_public_key,
                         signer=bobs_signer,
                         threshold=10,
                         shares=20)
# Ursulas perform re-encryption
# ------------------------------
# Bob asks several Ursulas to re-encrypt the capsule so he can open it.
# Each Ursula performs re-encryption on the capsule using the `kfrag`
# provided by Alice, obtaining this way a "capsule fragment", or `cfrag`.
# Let's mock a network or transport layer by sampling `threshold` random `kfrags`,
# one for each required Ursula.



kfrags_alice = random.sample(kfrags_alice,  # All kfrags from above
                       10)   

kfrags_bob = random.sample(kfrags_bob,  # All kfrags from above
                       10)      # M - Threshold

# Bob collects the resulting `cfrags` from several Ursulas.
# Bob must gather at least `threshold` `cfrags` in order to open the capsule.
cfrags_alice = list() # alice's cfrag collection being submitted to node 
cfrags_bob = list()  # Bob's cfrag collection being submitted to


for kfrag in kfrags:
    cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
    cfrags.append(cfrag)  # Bob collects a cfrag

assert len(cfrags) == 10

# Bob checks the capsule fragments
# --------------------------------
# If the node received the capsule fragments in serialized form,
# the node can verify that they are valid and really originate from Alice,
# using Alice's public key (this could even be a temporary metadata key)

suspicious_cfrags = [CapsuleFrag.from_bytes(bytes(cfrag)) for cfrag in cfrags]

cfrags = [cfrag.verify(capsule,
                       verifying_pk=alices_verifying_key,
                       delegating_pk=alices_public_key,
                       receiving_pk=bobs_public_key,
                       )
          for cfrag in suspicious_cfrags]

# Bob opens the capsule
# ------------------------------------
# Finally, Bob decrypts the re-encrypted ciphertext using his key.

bob_cleartext = decrypt_reencrypted(receiving_sk=bobs_secret_key,
                                    delegating_pk=alices_public_key,
                                    capsule=bob_capsule,
                                    verified_cfrags=cfrags,
                                    ciphertext=ciphertext)
print(bob_cleartext)
assert bob_cleartext == plaintext