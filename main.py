from Crypto.Cipher import AES, ARC4, DES3, PKCS1_OAEP
from Crypto.Hash import MD5, SHA, SHA256
from Crypto.PublicKey import DSA, RSA
from Crypto import Random
from Crypto.Random import random
import base64
import time

BS = 16
iterations = 1000
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

def generate_keys():
    modulus_length = 1024
    key = RSA.generate(modulus_length)
    pub_key = key.publickey()
    return key, pub_key

def oaep_enc(msg, key):
    msg = msg.encode()
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(msg))

def oaep_dec(msg, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(msg))

def aes_enc(key, raw):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB, iv)
    return base64.b64encode(cipher.encrypt(raw))

def aes_dec(key, enc):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

def des_enc(key, raw):
    raw = pad(raw)
    iv = Random.new().read(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    return base64.b64encode(cipher.encrypt(raw))

def des_dec(key, enc):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = DES3.new(key, DES3.MODE_ECB, iv)
    return unpad(cipher.decrypt(enc[16:]))

def rc4_enc(key,p):
	return ARC4.new(key).encrypt(p)

def rc4_dec(key,msg):
	return ARC4.new(key).decrypt(msg)


def signing_verifying():
    test_vectors =[
        ['0x5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653'+
        '92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D'+
        '4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6'+
        '82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B',
        '0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D'+
        '89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD'+
        '87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4'+
        '17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD',
        '0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447'+
        'E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88'+
        '73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C'+
        '881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779',
        '0x996F967F6C8E388D9E28D01E205FBA957A5698B1',
        '0x411602CB19A6CCC34494D79D98EF1E7ED5AF25F7'],
        ['0x92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D'+
        '5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653'+
        '4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6'+
        '82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B',
        '0x89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD'+
        '07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D'+
        '87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4'+
        '17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD',
        '0xE6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88'+
        '86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447'+
        '73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C'+
        '881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779',
        '0x411602CB19A6CCC34494D79D98EF1E7ED5AF25F7',
        '0x996F967F6C8E388D9E28D01E205FBA957A5698B1 '],
        ['0x7DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653'+
        '82195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D'+
        '3CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6'+
        '72F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B',
        '0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D'+
        '79BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD'+
        '77995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4'+
        '07BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD',
        '0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447'+
        'D6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88'+
        '63ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C'+
        '781870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779',
        '0x896F967F6C8E388D9E28D01E205FBA957A5698B1',
        '0x311602CB19A6CCC34494D79D98EF1E7ED5AF25F7'],
        ['0x72195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D'+
        '3DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653'+
        '2CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6'+
        '82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B',
        '0x89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD'+
        '07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D'+
        '67995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4'+
        '37BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD',
        '0xE6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88'+
        '66F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447'+
        '53ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C'+
        '681870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779',
        '0x211602CB19A6CCC34494D79D98EF1E7ED5AF25F7',
        '0x796F967F6C8E388D9E28D01E205FBA957A5698B1 '],
        ['0x6DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653'+
        '82195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D'+
        '3CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6'+
        '72F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B',
        '0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D'+
        '79BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD'+
        '77995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4'+
        '27BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD',
        '0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447'+
        'C6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88'+
        '63ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C'+
        '781870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779',
        '0x896F967F6C8E388D9E28D01E205FBA957A5698B1',
        '0x311602CB19A6CCC34494D79D98EF1E7ED5AF25F7'],
    ]

    signing_time_table = []
    verifying_time_table = []

    for vector in test_vectors:
        sign_times = []
        ver_times = []
        y = vector[0] #public
        g = vector[1] #generator modulo
        p = vector[2] #prime 1
        q = vector[3] #prime 2
        x = vector[4] #private
        tuple = (int(y,16),int(g,16),int(p,16),int(q,16),int(x, 16))
        signing_time_acum_dsa = 0
        verifying_time_acum_dsa = 0
        signing_time_acum_rsa = 0
        verifying_time_acum_rsa = 0

        for i in range(iterations):
            message = "sample"
            h = SHA.new(message).digest()

            # DSA
            time_start = time.time()
            key = DSA.construct(tuple)
            k = random.StrongRandom().randint(1,key.q-1)
            sig = key.sign(h,k)
            signing_time_acum_dsa += time.time() - time_start
            time_start = time.time()
            V = key.verify(h,sig)
            verifying_time_acum_dsa += time.time() - time_start

            #RSA_PSS
            time_start = time.time()
            key = RSA.construct(tuple)
            k = random.StrongRandom().randint(1,key.q-1)
            sig = key.sign(h, k)
            signing_time_acum_rsa += time.time() - time_start
            time_start = time.time()
            pubkey = key.publickey()
            V = pubkey.verify(h,sig)
            verifying_time_acum_rsa += time.time() - time_start

        signing_time_table.append([
        signing_time_acum_dsa/iterations,
        signing_time_acum_rsa/iterations])
        verifying_time_table.append([
        verifying_time_acum_dsa/iterations,
        verifying_time_acum_rsa/iterations])

    print ("\nSigning")
    print("\t\t\tDSA\t\t\tRSA-PSS")
    for idx,times in enumerate(verifying_time_table):
        print("Vector " + str(idx + 1) + ":\t" + str(times[0]) + "\t" + str(times[1]))
    print ('\n')
    print ("Verifying")
    print("\t\t\tDSA\t\t\tRSA-PSS")
    for idx,times in enumerate(signing_time_table):
        print("Vector " + str(idx + 1) + ":\t" + str(times[0]) + "\t" + str(times[1]))
    print ('\n')

def encrypt_decrypt():
    # [Key, Plain]
    test_vectors = [
        ['EAEAEAEAEAEAEAEA', 'AC4B251F989E005E'],
        ['E4E4E4E4E4E4E4E4', '7060B673459206F7'],
        ['CACACACACACACACA', '40414B449374572C'],
        ['BCBCBCBCBCBCBCBC', 'BFC1B068D95BC1D4'],
        ['2BD6459F82C5B300', 'B10F843097A0F932']
    ]
    private, public = generate_keys()
    encrypt_time_table = []
    decrypt_time_table = []
    pointer = 0
    for vector in test_vectors:
        enc_times = []
        dec_times = []
        key = vector[0]
        plane = vector[1]

        encryption_time_acum_aes = 0
        decryption_time_acum_aes = 0
        encryption_time_acum_rc4 = 0
        decryption_time_acum_rc4 = 0
        encryption_time_acum_des = 0
        decryption_time_acum_des = 0
        encryption_time_acum_oaep = 0
        decryption_time_acum_oaep = 0
        for i in range(iterations):
            # AES
            time_start = time.time()
            encrypted = aes_enc(key, plane)
            encryption_time_acum_aes += time.time() - time_start
            time_start = time.time()
            decrypted = aes_dec(key, encrypted)
            decryption_time_acum_aes += time.time() - time_start

            # RC4
            nonce=Random.new().read(16)
            rca_key =key + nonce
            rca_key = SHA256.new(rca_key).digest()
            time_start = time.time()
            encrypted = rc4_enc(key, plane)
            encryption_time_acum_rc4 += time.time() - time_start
            time_start = time.time()
            decrypted = rc4_dec(key, encrypted)
            decryption_time_acum_rc4 += time.time() - time_start

            # DES
            time_start = time.time()
            encrypted = des_enc(key, plane)
            encryption_time_acum_des += time.time() - time_start
            time_start = time.time()
            decrypted = des_dec(key, encrypted)
            decryption_time_acum_des += time.time() - time_start

            #OAEP
            time_start = time.time()
            encrypted = oaep_enc(plane, public)
            encryption_time_acum_oaep += time.time() - time_start
            time_start = time.time()
            decrypted = oaep_dec(encrypted, private)
            decryption_time_acum_oaep += time.time() - time_start

        encrypt_time_table.append([
        encryption_time_acum_aes/iterations,
        encryption_time_acum_rc4/iterations,
        encryption_time_acum_des/iterations,
        encryption_time_acum_oaep/iterations])
        decrypt_time_table.append([
        decryption_time_acum_aes/iterations,
        decryption_time_acum_rc4/iterations,
        decryption_time_acum_des/iterations,
        decryption_time_acum_oaep/iterations])

    print ("Encryption")
    print("\t\t\tAES\t\t\tRC4\t\t\tDES\t\t\tOAEP")
    for idx,times in enumerate(encrypt_time_table):
        print("Vector " + str(idx + 1) + ":\t" + str(times[0]) + "\t" + str(times[1]) + "\t" + str(times[2]) + "\t" + str(times[3]))
    print ('\n')
    print ("Decryption")
    print("\t\t\tAES\t\t\tRC4\t\t\tDES\t\t\tOAEP")
    for idx,times in enumerate(decrypt_time_table):
        print("Vector " + str(idx + 1) + ":\t" + str(times[0]) + "\t" + str(times[1]) + "\t" + str(times[2]) + "\t" + str(times[3]))
    print ('\n')

def hash_functions():

    test_vectors = []
    test_vectors.append("")
    test_vectors.append("a")
    test_vectors.append("abc")
    test_vectors.append("message digest")
    test_vectors.append("abcdefghijklmnopqrstuvwxyz")
    test_vectors.append("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    test_vectors.append("1234567890" * 8)
    test_vectors.append("a" * 1000000)

    times_list = []

    for idx,test in enumerate(test_vectors):

        time_list = []

        # SHA-1
        acum = 0
        sha_time = time.time()
        for i in range(0,iterations):
            sha_obj = SHA.new()
            sha_obj.update(test)
            sha_enc = sha_obj.hexdigest()
        sha_time = time.time() - sha_time
        acum += sha_time
        sha_time = acum / iterations
        time_list.append(sha_time)

        # SHA-2
        acum = 0
        sha2_time = time.time()
        for i in range(0,iterations):
            sha256_obj = SHA256.new()
            sha256_obj.update(test)
            sha256_enc = sha256_obj.hexdigest()
        sha2_time = time.time() - sha2_time
        acum += sha2_time
        sha2_time = acum / iterations
        time_list.append(sha2_time)

        # MD5
        acum = 0
        md5_time = time.time()
        for i in range(0,iterations):
            md5_obj = MD5.new()
            md5_obj.update('Hello')
            md5_enc = md5_obj.hexdigest()
        md5_time = time.time() - md5_time
        acum += md5_time
        md5_time = acum / iterations
        time_list.append(md5_time)

        times_list.append(time_list)

    print("Hashing")
    print("\t\t\tSHA-1\t\t\tSHA-2\t\t\tMD5")
    for idx,times in enumerate(times_list):
        print("Vector " + str(idx + 1) + ":\t" + str(times[0]) + "\t" + str(times[1]) + "\t" + str(times[2]))

encrypt_decrypt()
hash_functions()
signing_verifying()
