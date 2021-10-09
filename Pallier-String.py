from phe import paillier


public_key, private_key = paillier.generate_paillier_keypair()

keyring = paillier.PaillierPrivateKeyring()
keyring.add(private_key)
public_key1, private_key1 = paillier.generate_paillier_keypair(keyring)
public_key2, private_key2 = paillier.generate_paillier_keypair(keyring)
secret_number_list = [31415932452341212421412421424.00, 31232432543521341324124214.00]
# indications are decimals effect the Pallier 
encrypted_number_list = [public_key.encrypt(x) for x in secret_number_list]
a,b = encrypted_number_list
z = a+b
updated_account = keyring.decrypt(z)
print(z)
print(updated_account)
secret_number_list = [314159324523412123723832000000010202020000, -28232432543521341324324342432213213210000]
c,d = secret_number_list
real_value = c + d 
encrypted_number_list = [public_key.encrypt(x) for x in secret_number_list]
a,b = encrypted_number_list
z = a+b
updated_account_subtraction = keyring.decrypt(z)
print(z)
print(real_value)
print(updated_account_subtraction)
print(real_value == updated_account_subtraction)