import random
from umbral import (
    SecretKey, Signer, CapsuleFrag,
    encrypt, generate_kfrags, reencrypt, decrypt_original, decrypt_reencrypted)
from phe import paillier
import pickle
# Notes 

# 1. We need to add some sort of signature here so that we can basically ensure when a node rights back to the DB that it cant use some random homomorphically encrypted value object. It has to be the one connected to the user 

# 2. all FHE encrtptions occur and exist at the account node level. So these are all issuance specific interactions 
# 3. all PRE encryptions occur and exist at the transaction node level. So these are all transaction specific interactions


# Generate an Umbral key pair for Alice 
# ---------------------------
# First, Let's generate two asymmetric key pairs for Alice:
# A delegating key pair and a Signing key pair.


alices_secret_key = SecretKey.random()
alices_public_key = alices_secret_key.public_key()

alices_signing_key = SecretKey.random()
alices_verifying_key = alices_signing_key.public_key()
alices_signer = Signer(alices_signing_key)


#FHE 'node' creates an account and assigns the keys to a keyring.
# this is how we essential are able to maintain securities compatability. 
# we can generate access to an account for a regulator but at the node level we process transactions using 
# homorphic encryption 

public_key, private_key = paillier.generate_paillier_keypair()

keyring = paillier.PaillierPrivateKeyring()
keyring.add(private_key)
public_key1, private_key1 = paillier.generate_paillier_keypair(keyring)
public_key2, private_key2 = paillier.generate_paillier_keypair(keyring)
secret_number_list = [3141593245234121237238320, 28232432543521341324, 100000062562655460]

Transaction_signature = [12332314314432434] 

### if transaction number = 

d,e,f = secret_number_list
encrypted_number_list = [public_key.encrypt(x) for x in secret_number_list]
a,b,c = encrypted_number_list
print("A, HFE object ", a)
a1=pickle.dumps(a)
a1test= pickle.loads(a1)
print( "Test of dumping anloading", a1test)
## so this works. we can probably move stuff using this. Its just im not sure about the encrypted signature .
# Encrypt Alices account state 
# ---------------------------
# Now let's encrypt data with Alice's public key.
# Invocation of `pre.encrypt` returns both the `ciphertext`,
# and a `capsule`. Anyone with Alice's public key can perform
# this operation.

# encrypt alices account value 
alice_plaintext = a1
print(a1)
print(alice_plaintext)
alice_capsule, alice_ciphertext = encrypt(alices_public_key, alice_plaintext)
print(alice_ciphertext, "1. alice cypher text to be decripte ")




# Decrypt data for Alice
# ----------------------
# Since data was encrypted with Alice's public key,
# Alice can open the capsule and decrypt the ciphertext with her private key.

alice_cleartext = decrypt_original(alices_secret_key, alice_capsule, alice_ciphertext)
print(alice_cleartext, "2. alice account decrypts her stuff ")

#use homomorphic encryption to encrypt alices account state 



# Create and Encrypt Bob's Account and state 

bobs_secret_key = SecretKey.random()
bobs_public_key = bobs_secret_key.public_key()
bobs_signing_key = SecretKey.random()
bobs_verifying_key = bobs_signing_key.public_key()
bobs_signer = Signer(bobs_signing_key)
b1 = pickle.dumps(b)
bob_plaintext =  b1

# transaction amount = b'5'

bob_capsule, bob_ciphertext = encrypt(bobs_public_key, bob_plaintext)
print(bob_ciphertext, "3. Bobs account cyperher text and value ")

bob_cleartext = decrypt_original(bobs_secret_key, bob_capsule, bob_ciphertext)
print(bob_cleartext, "4. Bobs account decrypts his acount value ")
# bob cant decrypt alice data 
try:
    fail_decrypted_data = decrypt_original(bobs_secret_key, bob_capsule, alice_ciphertext)
    print(fail_decrypted_data, " 5 bobs account fails to decrypt data")

except ValueError:
    print("5 . Decryption failed! Bob doesn't has access granted yet.")

#alice cant decrypt bob's data 

try:
    fail_decrypted_data = decrypt_original(alices_secret_key, alice_capsule, bob_ciphertext)
    print(fail_decrypted_data, " 6 alice account fails to decrypt bob's data")

except ValueError:
    print("6. Decryption failed! alice doesn't has access granted yet.")



# Alice inititates transaction to Bob by generating kfrags sending 10 string
# -----------------------------------------------
# 1. Alice grants access to a node to initiate a transaction  
    # she uses her private key and bob's public key to initiate transaction and generate kfrags
  # The node autonomously generates a signing pair between parties 

alices_nodes_secret_key = SecretKey.random() 
alices_nodes_public_key = alices_nodes_secret_key.public_key()

alices_nodes_signing_key = SecretKey.random()
alices_nodes_verifying_key = alices_nodes_signing_key.public_key()
alices_nodes_signer = Signer(alices_nodes_signing_key)

transaction_address = bobs_public_key

## I think when we encrypt the transaction amount homomorphically using the HFE node we can add a signature related to this value because this value needs to be generated
transaction_amount = b"100000000"


# she creates *threshold split re-encryption keys*, or *"kfrags"*,
# which are next sent to N proxies or *Ursulas*.
# threshold of 10, for 20 total shares

kfrags_alice = generate_kfrags(delegating_sk=alices_secret_key,
                         receiving_pk=alices_nodes_public_key,
                         signer=alices_signer,
                         threshold=10,
                         shares=20) #here you can add a transaction value Possibly hold on 

print (kfrags_alice, "6. we see Alice's Kfrags") # when submitting info to nodes we need to add "noise maybe not right word but add synthetic data "

cfrags_alice = list()

kfrags_alice = random.sample(kfrags_alice,  # All kfrags from above
                       10)   
for kfrag in kfrags_alice:
    cfrag = reencrypt(capsule=alice_capsule, kfrag=kfrag)
    cfrags_alice.append(cfrag)  # Bob collects a cfrag
print (cfrags_alice, "7. the node collects the information on alices cfrags ")
print (len(cfrags_alice))
assert len(cfrags_alice) == 10


# node checks alices capsule fragments
# --------------------------------
# If the node received the capsule fragments in serialized form,
# the node can verify that they are valid and really originate from Alice,
# using Alice's public key (this could even be a temporary metadata key)

suspicious_cfrags = [CapsuleFrag.from_bytes(bytes(cfrag)) for cfrag in cfrags_alice]

cfrags_alice = [cfrag.verify(alice_capsule,
                       verifying_pk=alices_verifying_key,
                       delegating_pk=alices_public_key,
                       receiving_pk=alices_nodes_public_key,
                       )
          for cfrag in suspicious_cfrags]

print(cfrags_alice, "8. the node checks for suspicious cfrags")


alice_account_value_node = decrypt_reencrypted(receiving_sk=alices_nodes_secret_key, #node_secret_key
                                    delegating_pk=alices_public_key,
                                    capsule=alice_capsule,
                                    verified_cfrags=cfrags_alice,
                                    ciphertext=alice_ciphertext)

print (alice_account_value_node, "9. alice account value decrypted in node ")

# if bobs wallet is unlocked transactions, the node will generate keys specific to the transaction
 
bobs_nodes_secret_key = SecretKey.random() 
bobs_nodes_public_key = bobs_nodes_secret_key.public_key()

bobs_nodes_signing_key = SecretKey.random()
bobs_nodes_verifying_key = bobs_nodes_signing_key.public_key()
bobs_nodes_signer = Signer(bobs_nodes_signing_key)
  
    # this requires Alice's public key and bobs private key
# we generate a set of kfrags for bob for the node to decrypt 

kfrags_bob = generate_kfrags(delegating_sk=bobs_secret_key,
                         receiving_pk=bobs_nodes_public_key,
                         signer=bobs_signer,
                         threshold=10,
                         shares=20) 
print (kfrags_bob, "10. we see bob's Kfrags")


cfrags_bob = list()

kfrags_bob = random.sample(kfrags_bob,  # All kfrags from above
                       10)   
for kfrag in kfrags_bob:
    cfrag = reencrypt(capsule=bob_capsule, kfrag=kfrag)
    cfrags_bob.append(cfrag)  # Bob collects a cfrag
print (cfrags_bob, "11. the node collects the information on alices cfrags ")
print (len(cfrags_bob))
assert len(cfrags_bob) == 10


# node checks alices capsule fragments
# --------------------------------
# If the node received the capsule fragments in serialized form,
# the node can verify that they are valid and really originate from Alice,
# using Alice's public key (this could even be a temporary metadata key)

suspicious_cfrags = [CapsuleFrag.from_bytes(bytes(cfrag)) for cfrag in cfrags_bob]

cfrags_bob = [cfrag.verify(bob_capsule,
                       verifying_pk=bobs_verifying_key,
                       delegating_pk=bobs_public_key,
                       receiving_pk=bobs_nodes_public_key,
                       )
          for cfrag in suspicious_cfrags]

print(cfrags_bob, "12. the node checks for suspicious cfrags")


bob_account_value_node = decrypt_reencrypted(receiving_sk=bobs_nodes_secret_key, #node_secret_key
                                    delegating_pk=bobs_public_key,
                                    capsule=bob_capsule,
                                    verified_cfrags=cfrags_bob,
                                    ciphertext=bob_ciphertext)


#stop transaction here if alice does not have money. this should be an initial thing before even querying bob

print (bob_account_value_node, "14. bobs account value decrypted in node ")
transaction_amount= transaction_amount
bob_account_value_node = bob_account_value_node
alice_account_value_node = alice_account_value_node
print (transaction_amount , bob_account_value_node)
## node transaction computation (if this was homomorphic we could actualyl just use homomorphic to do this. However in our case we are going to have to protect node data very well on the inside )
a=pickle.loads(alice_account_value_node)

new_bob_account_value_node = b+c
new_bob_account_value_node = pickle.dumps(new_bob_account_value_node)
print("15. bobs accountr value= " , new_bob_account_value_node, "bob accountr value =", bob_plaintext)

new_alice_account_value_node =  a+(-1*c)
new_alice_account_value_node =  pickle.dumps(new_alice_account_value_node)

print("16. alice accountr value= " , new_alice_account_value_node, "alice account value =", alice_plaintext)
print("17. This is C", c)
## node account update 


bob_capsule, new_bob_account_value_node = encrypt(bobs_public_key, new_bob_account_value_node)
print(new_bob_account_value_node, "17. Bobs account cyperher text and value ")

bob_cleartext = decrypt_original(bobs_secret_key, bob_capsule, new_bob_account_value_node)
bob_cleartext =pickle.loads(bob_cleartext)



bob_cleartext = keyring.decrypt(bob_cleartext)
print(bob_cleartext, "18. Bobs account decrypts his acount value ")


## there are two ways to handle a single proxy carry the same key for transaction. 
alice_capsule, new_alice_account_value_node = encrypt(alices_public_key, new_alice_account_value_node)

##********* This needs to be addressed regardless of the transaction when a node writes back to a DB it must have some sort of signature from the original transaction. That ensures that a similarly encrypted HFE system is directly related to teh original user 
print(new_alice_account_value_node, "19.alice account cyperher text and value ")

alice_cleartext = decrypt_original(alices_secret_key, alice_capsule,new_alice_account_value_node)
alice_cleartext = pickle.loads(alice_cleartext)
alice_cleartext = keyring.decrypt(alice_cleartext)

print(alice_cleartext, "20. alice account decrypts her account value ")

alice_account_test_update = d - f
bob_account_test_update = e+f 

print("transaction test for bob is good", bob_account_test_update == bob_cleartext)
print("transaction test for alice is good", alice_account_test_update == alice_cleartext)

## we could pass the values to a calculation node 



#So in theory we could even use homomorphic encryption when managing the public account ID. It would be possible to never share anybodies wallet address.  the node can use alice's public key to reencrypt the data. This would allow 

# oh so basically if the PRE generates a public key one to one with a transaction than this public key could theoretically have nothing to do with the public address. This address could be an internal transaction address. 