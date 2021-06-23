from logging import fatal
import streamlit as st
import numpy as np
import math
import random
from itertools import accumulate
from operator import xor


st.title('Security-Project')

st.write("""
#
""")




s0 = [
[1,0,3,2],
 [3,2,1,0],
 [0,2,1,3],
 [3,1,3,2]]
s1 = [
[0,1,2,3],
 [2,0,1,3],
 [3,0,1,0],
 [2,1,0,3]]

conversion_list = ['2','3','4','5','6','7','8','9','A','B','C','D','E','F']

def get_decimal_from_binary_pair(pair):
    if pair == [0,0]:
        return 0
    if pair == [0,1]:
        return 1
    if pair == [1,0]:
        return 2
    if pair == [1,1]:
        return 3

def get_binary_from_decimal(decimal):
    if decimal == 0:
        return [0,0]
    if decimal == 1:
        return [0,1]
    if decimal == 2:
        return [1,0]
    if decimal == 3:
        return [1,1]
    
def convert_string_to_list(string):
    list=[]
    list[:0]=string
    return list

def convert_hex_to_binary(input):
    if input == '2':
        return [0,0,1,0]
    if input == '3':
        return [0,0,1,1]
    if input == '4':
        return [0,1,0,0]
    if input == '5':
        return [0,1,1,0]
    if input == '6':
        return [0,1,0,1]
    if input == '7':
        return [0,1,1,1]
    if input == '8':
        return [1,0,0,0]
    if input == '9':
        return [1,0,0,1]
    if input == 'A':
        return [1,0,1,0]
    if input == 'B':
        return [1,0,1,1]
    if input == 'C':
        return [1,1,0,0]
    if input == 'D':
        return [1,1,0,1]
    if input == 'E':
        return [1,1,1,0]
    if input == 'F':
        return [1,1,1,1]

    
class SDES():
    
    def get_binary_sbox(input):
        left_input = input[:len(input)//2]
        right_input = input[len(input)//2:]

        pair1 = [left_input[0]] + [left_input[3]]
        pair2 = [left_input[1]] + [left_input[2]]
        val1 = get_binary_from_decimal(s0[get_decimal_from_binary_pair(pair1)][get_decimal_from_binary_pair(pair2)])
        pair1 = [right_input[0]] + [right_input[3]]
        pair2 = [right_input[1]] + [right_input[2]]
        val2 = get_binary_from_decimal(s1[get_decimal_from_binary_pair(pair1)][get_decimal_from_binary_pair(pair2)])
        val = val1+val2
        st.text(f"S-Box return value: {val}")
        return val

    @staticmethod
    def perform_round(ip_input, key, p10, p8, p4, ip, ep, k1, k2, swap):
        ##Encryption starts here
        left_ip_input = ip_input[:len(ip_input)//2]
        right_ip_input = ip_input[len(ip_input)//2:]


        ###################################Round 1###################################
        #EP starts here
        r1_input = []
        for i in ep:
            r1_input.append(right_ip_input[i-1])
        st.text(f"Round 1 input: {r1_input}")

        #XOR with K1 starts here
        temp_xor = []
        for i in range(len(r1_input)):
            if swap:
                temp_xor.append(r1_input[i] ^ k1[i])
            else:
                temp_xor.append(r1_input[i] ^ k2[i])
        r1_input = temp_xor
        if swap:
            st.text(f"XOR with K1: {r1_input}")
        else:
            st.text(f"XOR with K2: {r1_input}")

        #S-Boxes start here
        r1_input = SDES.get_binary_sbox(r1_input)

        #P4 starts here
        temp_r1_input = []
        for i in p4:
            temp_r1_input.append(r1_input[i-1])
        r1_input = temp_r1_input
        st.text(f"P4: {r1_input}")


        #XOR with left of input starts here
        temp_xor = []
        for i in range(len(r1_input)):
            temp_xor.append(r1_input[i] ^ left_ip_input[i])
        r1_input = temp_xor
        st.text(f"XOR with with Left of the IP (plain text): {r1_input}")

        if swap:
            val = right_ip_input + r1_input
            st.text(f"Round 1 after swapping: {val}")
            return val
        else:
            val = r1_input + right_ip_input
            st.text(f"Round 2: {val}")
            return val


    @staticmethod
    def encrypt(input, key, operation, type = 'binary'):
        input = input.replace(" ", "")
        key = key.replace(" ", "")

        input = convert_string_to_list(input)
        key = convert_string_to_list(key)
        temp_list=[]
        for i in range(len(input)):
            if input[i] == '0' or input[i] == '1':
                temp_list.append(int(input[i]))
            if input[i] in conversion_list:
                converted_list = convert_hex_to_binary(input[i])
                for j in range(len(converted_list)):
                    temp_list.append(converted_list[j])
        input = temp_list

        temp_list=[]
        for i in range(len(key)):
            if key[i] == '0' or key[i] == '1':
                temp_list.append(int(key[i]))
            if key[i] in conversion_list:
                converted_list = convert_hex_to_binary(key[i])
                for j in range(len(converted_list)):
                    temp_list.append(converted_list[j])
        key = temp_list

        if len(input) != 8:
            st.warning("Please enter an 8-bit input.")
            return
        if len(key) != 10:
            st.warning("Please enter a 10-bit key.")
            return

        p10 = [3,5,2,7,4,10,1,9,8,6]
        p8  = [6,3,7,4,8,5,10,9] 
        p4  = [2,4,3,1]
        ip  = [2,6,3,1,4,8,5,7]
        ep  = [4,1,2,3,2,3,4,1]
        ip_inv = [4,1,3,5,7,2,8,6]
        


        #Preparing K1
        #Ordering key by p10
        temp_key = []
        for i in p10:
            temp_key.append(key[i-1])
        key = temp_key

        #split key into left 5 bits and right 5 bits
        temp_left = left = key[:len(key)//2]
        temp_right = right = key[len(key)//2:]
        
        #Circular left shifting here
        l_swapper = left[0]
        r_swapper = right[0]
        i=0
        while i < len(left)-1:
            left[i] = left[i+1]
            right[i] = right[i+1]
            i += 1
        left[-1] = l_swapper
        right[-1] = r_swapper
        key = left+right

        #Ordering key by p8
        temp_key = []
        for i in p8:
            temp_key.append(key[i-1])
        k1 = temp_key



        #Preparing K2
        #Ordering key by p8
        left = temp_left
        right = temp_right
        temp_key = []
        i = 0
        while i<2:
            left += [left.pop(0)]
            right += [right.pop(0)]
            i+=1
        key = left+right
        
        #Ordering key by p8
        temp_key = []
        for i in p8:
            temp_key.append(key[i-1])
        k2 = temp_key

        st.text(f"Key 1: {k1}")
        st.text(f"Key 2: {k2}")


        if operation == 'Decryption':
            k_swp = k1
            k1 = k2
            k2 = k_swp


        ##Initial Permutation starts here
        ip_input = []
        for i in ip:
            ip_input.append(input[i-1])
        st.text(f"IP(Input): {ip_input}")



        ##Encryption starts here
        ip_input = SDES.perform_round(ip_input, key, p10, p8, p4, ip, ep, k1, k2, True)
        st.text(ip_input)
        ip_input = SDES.perform_round(ip_input, key, p10, p8, p4, ip, ep, k1, k2, False)
        st.text(ip_input)

        #Ordering key by IP Inverse
        temp_ip_input = []
        for i in ip_inv:
            temp_ip_input.append(ip_input[i-1])
        val = temp_ip_input
        

        if operation == 'Encryption':
            st.subheader(f"Ciphertext: {val}")
        else:
            st.subheader(f"Plaintext: {val}")

class RC4:
    def encrypt(plainTxt,key):
        
        P=RC4.splt(plainTxt)
        K=RC4.splt(key)
        S=[*range(0,8)]
        T=K.copy()
        T.extend(T)
        cipherTxt=[]

        i = j = 0;
        for i in range(0, 8):
            j = (j + S[i] + T[i]) % 8
            S[i] , S[j] = S[j] , S[i]



        i = j = 0;
        for i in range(0, 4):
            i = (i + 1) % 8;
            j = (j + S[i]) % 8;
            S[i] , S[j] = S[j] , S[i]
            t = (S[i] + S[j]) % 8;
            kk = S[t];
            cipherTxt.append(kk ^ P[i-1])

        st.subheader(f"Ciphertext: {cipherTxt}")
    


    def encrypt_with_steps(plainTxt,key):
        
        P=RC4.splt(plainTxt)
        K=RC4.splt(key)
        S=[*range(0,8)]
        T=K.copy()
        T.extend(T)
        cipherTxt=[]

        st.text (f'S= {S}')
        st.text (f'T={T},\n\n>>>>>>>>>>>>>>>>>>>>Iterations:')

        i = j = 0;
        for i in range(0, 8):
            j = (j + S[i] + T[i]) % 8
            S[i] , S[j] = S[j] , S[i]
            st.text(f'i={i}')
            st.text(f'j={j}')
            st.text(f'S={S} \n--')


        st.text('\n\n>>>>>>>>>>>>>>>>>>>>Encryption:')


        i = j = 0;
        for i in range(0, 4):
            i = (i + 1) % 8;
            j = (j + S[i]) % 8;
            S[i] , S[j] = S[j] , S[i]
            t = (S[i] + S[j]) % 8;
            kk = S[t];
            cipherTxt.append(kk ^ P[i-1])
            st.text(f'i= {i}')
            st.text(f'j= {j}')
            st.text(f'S= {S}\n')
            st.text(f't= {t}')
            st.text(f'k= {kk}')
            st.text(f'c={cipherTxt[len(cipherTxt)-1]},\n--')

        st.subheader(f"Ciphertext: {cipherTxt}")


    #input: string  output: int array
    def splt(x):
        try:
            Y=list(map(int, x.split()))
            
        except:
            Y=list(map(int, x.split(',')))

        if len(Y) == 1:
            Y=list(map(int, x))

        return Y

class AES():
    def encrypt(ps,ks):
        input = ps.replace(" ", "")
        key = ks.replace(" ", "")
        ps= input
        ks = key
        
        sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
                 0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

        w = [None] * 6
         
        
        def mult(p1, p2):
            """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
            p = 0
            while p2:
                if p2 & 0b1:
                    p ^= p1
                p1 <<= 1
                if p1 & 0b10000:
                    p1 ^= 0b11
                p2 >>= 1
            return p & 0b1111
         
        def intToVec(n):
        
            return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]            
         
        def vecToInt(m):
            """Convert a 4-element vector into 2-byte integer"""
            return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]
         
        def addKey(s1, s2):
            """Add two keys in GF(2^4)"""  
            return [i ^ j for i, j in zip(s1, s2)]
             
        def sub4NibList(s):
            """Nibble substitution function"""
            return [sBox[e] for e in s]
             
        def shiftRow(s):
            """ShiftRow function"""
            return [s[0], s[1], s[3], s[2]]
         
        def keyExp(key):
            """Generate the three round keys"""
            def sub2Nib(b):
                """Swap each nibble and substitute it using sBox"""
                return sBox[b >> 4] + (sBox[b & 0x0f] << 4)
         
            Rcon1, Rcon2 = 0b10000000, 0b00110000
            st.text("Steps >>>>>>>>>>>>>>>>>>>>")
            w[0] = (key & 0xff00) >> 8
            w[1] = key & 0x00ff
            w[2] = w[0] ^ Rcon1 ^ sub2Nib(w[1])
            w[3] = w[2] ^ w[1]
            w[4] = w[2] ^ Rcon2 ^ sub2Nib(w[3])
            w[5] = w[4] ^ w[3]
            st.text(f"w0= {decimalToBinary(w[0])}")
            st.text(f"w1= {decimalToBinary(w[1])}")
            st.text(f"w2= {decimalToBinary(w[2])}")
            st.text(f"w3= {decimalToBinary(w[3])}")
            st.text(f"w4= {decimalToBinary(w[4])}")
            st.text(f"w5= {decimalToBinary(w[5])} >>>>>>>>>>>>>>>>>>>>")
            st.text(f"key0= {decimalToBinary(key)}")
            st.text(f"key1= {decimalToBinary((w[2] << 8) + w[3])}") 
            st.text(f"key2= {decimalToBinary((w[4] << 8) + w[5])} >>>>>>>>>>>>>>>>>>>>")
                  
        def encrypt(ptext,key):
            """Encrypt plaintext block"""
            def mixCol(s):
                return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4,s[3]),
                        s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]    
             
            state = intToVec(key ^ ptext)
            st.text(f"Plaintext XOR Key0= {decimalToBinary(key ^ ptext)} ")
            st.text(f"Nibble sub= {decimalToBinary(vecToInt(sub4NibList(state)))}")
            st.text(f"shiftRow= {decimalToBinary(vecToInt(shiftRow(sub4NibList(state))))}")
            state = mixCol(shiftRow(sub4NibList(state)))
            st.text(f"mix col= {decimalToBinary(vecToInt(state))} >>>>>>>>>>>>>>>>>>>>")
            state = addKey(intToVec((w[2] << 8) + w[3]), state)
            st.text(f"Result of mix column XOR Key1 = {decimalToBinary(vecToInt(state))}")
            st.text(f"Nibble sub = {decimalToBinary(vecToInt(sub4NibList(state)))}")
            state = shiftRow(sub4NibList(state))
            st.text(f"shift row = {decimalToBinary(vecToInt(state))} >>>>>>>>>>>>>>>>>>>>")
            st.text(f"Result of Shift rows XOR Key2 = {decimalToBinary(vecToInt(addKey(intToVec((w[4] << 8) + w[5]), state)))} >>>>>>>>>>>>>>>>>>>>")
            st.text(vecToInt(addKey(intToVec((w[4] << 8) + w[5]), state)))
            
            return vecToInt(addKey(intToVec((w[4] << 8) + w[5]), state))

     
             
        def decimalToBinary(n):
            return bin(n).replace("0b", "")
         
        if __name__ == '__main__':
            
            plaintext = int(ps,2)
            key = int(ks,2)
        
            keyExp(key)
            final=decimalToBinary(encrypt(plaintext,key))
            final=final.zfill(16)  
            st.subheader(f"Ciphertext: {final}")
        
class PlayFair():
    def table_gen(key):
        i = 0
        j = 0
        index = 0
        index2 = 0
        mtx = [[" ", " ",  " ", " ", " "], [" ", " ",  " ", " ", " "],[" ", " ",  " ", " ", " "],[" ", " ",  " ", " ", " "],[" ", " ",  " ", " ", " "]]
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        temp_key = key
        while(i < 5):
            j = 0
            while(j < 5): 

                if ((index < len(key)) and (temp_key[index] != " ")):
                    mtx[i][j] = temp_key[index]
                    alphabet = alphabet.replace(temp_key[index]," ")
                    temp_key = temp_key.replace(temp_key[index]," ")
                    j+=1

                elif((index >= len(key)) and (alphabet[index2] != " ")) :
                    mtx[i][j] = alphabet[index2]
                    j+=1
                if index > len(key) - 1:
                    index2+=1

                index+=1
            i+=1
        #print(mtx)
        return mtx

    def pairs_gen(plain_txt):
        is_even = True
        pairs = []
        if len(plain_txt)%2 != 0:
            is_even = False
        i = 0
        while(i < len(plain_txt)):
            if i == len(plain_txt) - 1:
                pairs.append(plain_txt[i])
                pairs.append("X")
                is_even = not is_even
                break
            
            if plain_txt[i] != plain_txt[i+1]:
                pairs.append(plain_txt[i])
                pairs.append(plain_txt[i+1])
                i+=2
            else:
                pairs.append(plain_txt[i])
                pairs.append("X")
                is_even = not is_even
                i+=1
        if not is_even:
            pairs.append(plain_txt[len(plain_txt) - 1])
            pairs.append("X")
        #print(pairs)
        return pairs
        
    def get_location(mtx,c1,c2):
        row1 = row2 = col1 = col2 = 0
        i = j = 0
        is_found = 0
        while i < 5:
            j = 0
            while j < 5:
                if c1 == mtx[i][j]:
                    row1 = i
                    col1 = j
                    is_found+=1
                elif c2 == mtx[i][j]:
                    row2 = i
                    col2 = j
                    is_found += 1
                if is_found == 2:
                    return row1,row2,col1,col2
                j+=1
            i+=1
        return row1,row2,col1,col2
        
    def enc_map_location2char(row1,row2,col1,col2,mtx):
        if row1 == row2:
            x = mtx[row1][(col1+1)%5]
            y = mtx[row2][(col2+1)%5]
        
        elif col1 == col2:
            x = mtx[(row1+1)%5][col1]
            y = mtx[(row2+1)%5][col2]
        else:
            x = mtx[row1][col2]
            y = mtx[row2][col1]
        return x,y
    
    def dec_map_location2char(row1,row2,col1,col2,mtx):
        if row1 == row2:
            x = mtx[row1][(col1+4)%5]
            y = mtx[row2][(col2+4)%5]
        
        elif col1 == col2:
            x = mtx[(row1+4)%5][col1]
            y = mtx[(row2+4)%5][col2]
        else:
            x = mtx[row1][col2]
            y = mtx[row2][col1]
        return x,y
        
    def encrypt(plain_txt,key):
        cipher_txt = ""
        key = key.upper()
        key = key.replace(" ", "")
        plain_txt = plain_txt.upper()
        plain_txt = plain_txt.replace(" ", "")
        mtx = PlayFair.table_gen(key)
        pairs = PlayFair.pairs_gen(plain_txt)
        i = 0
        while(i < len(pairs)):
            row1,row2,col1,col2 = PlayFair.get_location(mtx,pairs[i],pairs[i+1])
            x,y = PlayFair.enc_map_location2char(row1,row2,col1,col2,mtx)
            cipher_txt += x
            cipher_txt += y
            #print(row1," ",row2," ",col1," ",col2)
            i+=2
        
        st.write("Matrix: ")
        st.table(mtx)
        st.subheader(f"Ciphertext: {cipher_txt}")
    
    def decrypt(cipher_txt,key):
        plain_txt = ""
        key = key.upper()
        key = key.replace(" ", "")
        plain_txt = plain_txt.upper()
        plain_txt = plain_txt.replace(" ", "")
        mtx = PlayFair.table_gen(key)
        #pairs = pairs_gen(cipher_txt)
        i = 0
        while i < len(cipher_txt):
            row1,row2,col1,col2 = PlayFair.get_location(mtx,cipher_txt[i],cipher_txt[i+1])
            x,y = PlayFair.dec_map_location2char(row1,row2,col1,col2,mtx)
            plain_txt += x
            plain_txt += y
            i+=2
        
        st.write("Matrix: ")
        st.table(mtx)
        st.subheader(f"Ciphertext: {plain_txt}")

class RSA:
    def encrypt(p,q, e, s):
        p = int(p)
        q = int(q)
        e = int(e)
        s = int(s)

        st.text(f"Choosen primes:\np= {str(p)} , q= {str(q)} ")
        n=p*q
        st.text(f"n = p * q = {str(n)} ")
        phi=(p-1)*(q-1)
        st.text(f"Euler's function (totient) [phi(n)]: {str(phi)} ")
        def gcd(a, b):
            while b != 0:
                c = a % b
                a = b
                b = c
            return a
        def modinv(a, m):
            for x in range(1, m):
                if (a * x) % m == 1:
                    return x
            return None
        def coprimes(a):
            l = []
            for x in range(2, a):
                if gcd(a, x) == 1 and modinv(x,phi) != None:
                    l.append(x)
            for x in l:
                if x == modinv(x,phi):
                    l.remove(x)
            return l
        st.text("Choose an e from a below coprimes array:\n")
        st.text(str(coprimes(phi)))
        d=modinv(e,phi)
        
        st.text(f"Your public key is a pair of numbers (e= {str(e)} , n=  {str(n)}  )")
        st.text(f"Your private key is a pair of numbers (d=  {str(d)} , n=  {str(n)}  )")
       
        def encrypt_block(m):
            c = (np.power(m, e) % n)
            #c = (m**e)%n
            if c == None: st.text(f"No modular multiplicative inverse for block  {str(m)} ")
            
            return c
        def decrypt_block(c):
            m = (np.power(c, d) % n)
            #m =  (c**d)%n
            if m == None: st.text(f"No modular multiplicative inverse for block  {str(c)}  ")
            return m
        
        enc=encrypt_block(int(s))
        st.text(f"Encrypted message: {str(enc)} ")
        dec = decrypt_block(int(s))
        st.text(f"Decrypted message: {(dec)} ")

class GAMAL():
    def encrypt(q,a,xa,k,m):
        q = int(q)
        a = int(a)
        xa = int(xa)
        k = int(k)
        m = int(m)

        if (a >= q or m >= q or xa >= q-1 or k >= q):
            st.warning("Invalid Parameters. Please re-check parameters and try again.")
            return
        ya = GAMAL.sm(a,xa,q)
        K2 = GAMAL.sm(ya,k,q)
        c1 = GAMAL.sm(a,k,q)
        c2 = K2*m%q

        st.text(f"c1 --> {c1} , c2 --> {c2} , K2 --> {K2} , ya --> {ya}")

    """
    def decrypt(q,a,xa,c1,c2):
        k = sm(c1,xa,q)
        k_inv = sm(c1,q-1-a,q)
        M = (c2*k_inv)%q
        return M
    """    
    def prime_gen():
        is_prime = False
        while(not is_prime):
            q = random.randint(2,2000)
            sqrt_q = math.sqrt(q)
            sqrt_q = math.floor(sqrt_q)
            i = 2
            is_prime = True
            while i <= sqrt_q:
                if q%i == 0:
                    is_prime = False
                    break
                i+=2
        return q

    def sm(base,power,mod):
        power_bi = bin(power)[2:]
        i = 0
        res = 1
        while i < len(power_bi):
            if power_bi[i] == '1':
                res = (res**2) * base
                res = res%mod
            else:
                res = (res**2)
                res = res%mod
            i=i+1

        return res



algorithm = st.selectbox("Select encryption/decryption algorithm", ('S-DES', 'RC4', 'Playfair', 'S-AES', 'RSA', 'El-Gamal'))
input = st.text_input("Enter input here")

if algorithm == 'S-DES':
    key = st.text_input("Enter key here")
    operation = st.selectbox("Select encryption or decryption", ('Encryption', 'Decryption'))

if algorithm == 'RC4':
    key = st.text_input("Enter key here")

if algorithm == 'Playfair':
    key = st.text_input("Enter key here")
    operation = st.selectbox("Select encryption or decryption", ('Encryption', 'Decryption'))

if algorithm == 'S-AES':
    key = st.text_input("Enter key here")

if algorithm == 'RSA':
    p = st.text_input("Enter P here")
    q = st.text_input("Enter Q here")
    e = st.text_input("Enter E here")

if algorithm == 'El-Gamal':
    q = st.text_input("Enter Q here")
    a = st.text_input("Enter A here")
    xa = st.text_input("Enter XA here")
    k = st.text_input("Enter K here")
   
input_submit = st.button('Apply Selected Options')



if input_submit:
    st.write(input)
    st.write(algorithm)

    if algorithm == 'S-DES':
        SDES.encrypt(input, key, operation)
    if algorithm == 'RC4':
        RC4.encrypt_with_steps(input,key)
    if algorithm == 'S-AES':
        AES.encrypt(input, key)
    if algorithm == 'Playfair':
        if operation == 'Encryption':
            PlayFair.encrypt(input,key)
        if operation == 'Decryption':
            PlayFair.decrypt(input,key)
    if algorithm == 'RSA':
        RSA.encrypt(p,q,e,input)
    if algorithm == 'El-Gamal':
        GAMAL.encrypt(q,a,xa,k,input)





        
