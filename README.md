# Shared Secret Exchange via Diffie Hellman

## What is the shared key?
The result of the Diffie Hellman Key Exchange is to generate a shared key without sending your private key to the public. This is useful, as the private key should always be private (like the name says). This key will be used to encrypt and decrypt any message. <i>The steps to generate such shared key will be explained in the next chapter.</i>


Using these videos I noted some steps to follow to create a shared key establishment. Using these shared keys we are able to encrypt/decrypt some data we want to E2E-encrypt.

NumberPhile Diffie Hellman Exchange:<br>
https://youtu.be/jkV1KEJGKRA <br>
https://youtu.be/NmM9HA2MQGI <br>
https://youtu.be/Yjrfm_oRO0w

### Steps to produce a shared key
#### As user 1:
 1. Get "commonground"/server generator values <i>g, n</i>
 2. Get our own private key
 3. Get user 2's public key
 4. (our_private^their_public) mod <i>n</i>
 5. result is shared key
 
#### As user 2:
 1. Get "commonground"/server generator values <i>g, n</i>
 2. Get our own private key
 3. Get user 1's public key
 4. (our_private^their_public) mod <i>n</i>
 5. result is shared key
 
<i>These steps are almost the same, but the important part here is that a user never gets the other user's private key.</i>
 
 
### Steps to encrypt/decrypt data
 
#### As user 1 (sender):
 1. Input message string
 2. Get shared key with user 2 (see chapter above)
 3. Get message integer represenation via hex value of string.
 4. Multiply message integer representation with the shared key (= This is the encrypted message)
 5. Send message to user 2
 

#### As user 2 (receiver)
 6. Receive the encrypted message from user 1
 7. Get shared key with user 1 (see chapter above)
 8. Devide the encrypted message with the shared key
 9. Convert integer representation back to string via hex value of integer
 10. Message String retrieved from integer value

## Workplace
Using these steps, we will be developing some python code that runs the E2E encryption.

## Import required packages


```python
import asyncio
import websockets # Has to be installed via pip
import time
import json
import uuid
import hashlib
```

# Steps to reproduce shared key and encryption

### 0. Determine generator settings (these will be returned by a commonground like a server)
The common-ground (<i>read as: server</i>) determines the generator for the encryption. These values are represented as <i>g, n</i>
- <i>(g)</i> may be a small number
- <i>(n)</i> must be a big prime numer

The <i>n</i> in generator is the part which determines how heavily encrypted the messages will be. 

The bigger the better, but bigger also means it will take more storage.


```python
g = 88
n = pow(2, 512) - 1
g, n
```




    (88,
     13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084095)



### 1. Insert passwords
Let the users generate a private key. This private key is quite hard to remember so we'll have to generate a private key using their password.


```python
password1 = "abc"
password2 = "def"
password1, password2
```




    ('abc', 'def')



### 2. sha256(password) will be private key
We will be using the sha256 hashing algorithm to generate a private key based on the password the user uses. The private key needs to be stored safely onto their own instance and should never be sent to another instance.


```python
def generatePrivateKey(password: str) -> int:
    return int(hashlib.sha256(password.encode("utf-8")).hexdigest(), 16)

private_key1 = generatePrivateKey(password1)
private_key1 = generatePrivateKey(password2)
private_key1, private_key2
```




    (92051804979740629421189945248725688817512453204385593803422519596832200088372,
     92051804979740629421189945248725688817512453204385593803422519596832200088372)



### 3. Generate public keys
Generate public keys based on the user's public key. These public keys are safe to send to another instance.

For this calculation we use Diffie Hellman's cyclic key generation:
> (g ^ private_key) mod n


```python
def generatePublicKey(private_key: int) -> int:
    return pow(g, private_key, n)
    
public_key1 = generatePublicKey(private_key1)
public_key2 = generatePublicKey(private_key2)
public_key1, public_key2
```




    (13128352008253942051667753469830757488230391264491613668875614928593681075809859343934445764198421450690165687812068693507907804237753882945945909769454661,
     13128352008253942051667753469830757488230391264491613668875614928593681075809859343934445764198421450690165687812068693507907804237753882945945909769454661)



### 4. Generate Shared keys
User1 uses their own private key (private_key1) and user 2's public key (public_key2)

For this calculation we use Diffie Hellman's cyclic key generation:
> (public_key1 ^ private_key2) mod n


```python
def generateSharedKey(public_key: int, private_key: int, n: int) -> int:
    return pow(public_key, private_key, n)

shared_key1 = generateSharedKey(public_key2, private_key1, n) # this will be run on client 1
shared_key2 = generateSharedKey(public_key1, private_key2, n) # this will be run on client 2

shared_key1, shared_key2
```




    (9808255847542313238372186959596741531911507132545048110232205443938953036380809782231510496597163005941941717960919180556944678596351319813834539054429071,
     9808255847542313238372186959596741531911507132545048110232205443938953036380809782231510496597163005941941717960919180556944678596351319813834539054429071)



we assume that these two keys are the same now (if all data went through correctly)

### 5. Encrypt message using shared_key1
Determine a message which needs to be encrypted


```python
message = "Hello, world!"
```

#### 5.1 Convert message to int via hex representation of string
1. Convert the message to hex
2. Convert the message to int


```python
def stringToHex(message: str) -> hex:
    return message.encode("utf-8").hex()

hex_message = stringToHex(message)
hex_message
```




    '48656c6c6f2c20776f726c6421'




```python
def hexToInt(hex_message: hex) -> int:
    return int(hex_message, 16)

int_message = hexToInt(hex_message)
int_message
```




    5735816763073854953388147237921



#### 5.2 Multiply message int with shared key
Multiply the message with the established shared key to encrypt the message 

<i><b>Explanation:</b></i>

<i>If you dont know the message and the shared key, you wont be able to determine which input values were used. <b>BUT:</b></i>
- <i>If you know the message, you are able to calculate the shared_key</i>
- <i>If you know the shared_key, you are able to calculate the message</i>


```python
def encryptInt(int_message: int, shared_key: int) -> int:
    return int_message * shared_key

encrypted_message = encryptInt(int_message, shared_key1)
encrypted_message
```




    56258358306850360902891264921602295222973709526794112212347832879262493197983944392814113681372858013872906347412347131196456294187523250042188584565084005522241492738225509990256001391



#### 5.3 combine all functions into one


```python
def encryptString(message: str, shared_key: int):
    hex_message = stringToHex(message)
    int_message = hexToInt(hex_message)
    encrypted = encryptInt(int_message, shared_key)
    return encrypted
```


```python
encrypted_message = encryptString(message, shared_key1)
encrypted_message
```




    56258358306850360902891264921602295222973709526794112212347832879262493197983944392814113681372858013872906347412347131196456294187523250042188584565084005522241492738225509990256001391



### 6. Decrypt message using shared_key2
Do the same steps while encrypting, but reversed:
- Divide the message with the established shared_key
- Convert int to hex
- Convert hex to string


```python
int_message_decrypted = encrypted_message // shared_key2
int_message_decrypted
```




    5735816763073854953388147237921




```python
hex_message_decrypted = hex(int_message_decrypted)
hex_message_decrypted
```




    '0x48656c6c6f2c20776f726c6421'



### 7. Voila! Encrypted message received and decrypted!


```python
message_decrypted = bytes.fromhex(hex_message_decrypted[2:]).decode("utf-8")
message_decrypted
```




    'Hello, world!'



## But what if we try to decrypt the message with a wrong shared key?
We have the public key of user 1, but not the private key of user 2. What happens if we use the wrong password to generate a private key for user 2?


```python
invalid_private_key2 = generatePrivateKey("abcedf")
invalid_shared_key2 = generateSharedKey(public_key1, invalid_private_key2, n)
invalid_shared_key2
```




    6355916182475601949448427884593489634170311707947796587350384792772450366740320824891239815660770926188143055182081990615903256376755158245341003607692251



### 1. Decrypt the message with wrong shared_key


```python
int_message_invalid = encrypted_message // invalid_shared_key2
int_message_invalid
```




    8851337351169721199990686347426




```python
hex_message_invalid = hex(int_message_invalid)
hex_message_invalid
```




    '0x6fb836a6ed03dd9511f043f0a2'



### 2. Hex to string should throw error
"invalid continuation byte"

Nice! That means we cannot decrypt the message while don't have the right shared_key


```python
message_invalid = bytes.fromhex(hex_message_invalid[2:]).decode("utf-8")
message_invalid
```


    ---------------------------------------------------------------------------

    UnicodeDecodeError                        Traceback (most recent call last)

    Cell In [155], line 1
    ----> 1 message_invalid = bytes.fromhex(hex_message_invalid[2:]).decode("utf-8")
          2 message_invalid
    

    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xb8 in position 1: invalid start byte
