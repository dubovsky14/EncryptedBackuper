

Package description
---------------------
The package is design for safe (encrypted) back-up of data.

The key features, that the framework was design to accomplish:

* This framework + encrypted file + password is enough to decrypt the files.
* The password is not needed for the encryption step and the password is not stored on disk (or anywhere else), so that the encryption and back-up processes can be fully automated without a security risk of exposing the password to an attacker.
* Password must be a string that a user can choose at will (i.e. RSA private key calculated from public key using Extended Euclidean Algorithm is not a good password, as for the user it's just a random number at least 2048 bits long - good luck with memorizing such password ... Choosing private key as (hash of) a password, and calculating public key is also not a good idea, since it limits the set of available passwords - it cannot result in even number private key for example)
* Without a password, an attacker cannot say anything about the encrypted files except for their approximate total size (from size of the encrypted binary).
* Decrypting the files without the password must be as difficult as 256-bit AES cracking or cracking the RSA of a chosen length.

To use the framework, the user needs to generate pair of RSA keys, using ```generate_key_file``` executable. He will be asked to provide a password.
The pair of RSA keys is created at this step and the private key is XOR-ed with a pseudo-random number of the same length, obtained from SHA3-512 algorithm, with the password being the input for the hash function.
The key pair is then saved to a text file (with P*Q, key length and public key saved in plain text, private key being XOR-ed with the password hash).

The encryption step looks at the provided filelist, hashes all the files in it, add a random number, hashes it again and uses this number as 256-bit AES key.
This AES key is used to encrypt the files and after encrypting with the RSA public key, it is also saved into the output binary.
In order to decrypt the AES key, one has to know the private key, and in order to get the private key, the password is required, so that it can be XOR-ed with the encrypted private key saved in the encrypted file.


How to download and compile the package
----------------------------------------

Boost library is necessary to compile the code. In order to install it on Linux:

```
sudo apt-get install libboost-all-dev
```

The package also depends on AES package, which is added as a submodule.

In order to checkout and compile the code (when the boost is already installed):

```
git clone --recursive  git@github.com:dubovsky14/EncryptedBackuper.git

mkdir bin

cd bin

cmake ../.

make
```

How to generate RSA pair of keys
---------------------------------
```
./bin/generate_key_file <RSA key length> <output text file>
```

```RSA key length``` is the maximal lenght of private key (or p*q) in bits. Multiples of 512 are allowed.
Longer key takes more time to generate and then more time to validate, however too short keys are vulnerable against some kinds of attacks.
Recommended key length for real world applications is at least 2048 bits, preferably 4096 bits.

```output text file``` is the output file where the RSA keys will be stored

The user will be asked to provide a password. The password will be hashed using SHA3-512.
Then Keccak-f function will be applied ```RSA key length/512``` times in on order to get pseudo-random number of the same length as private key.
This pseudo-random number will then be XOR-ed with the private key and the result will be stored in the output text file (and copied to the encrypted binaries during encryption step).

How to encrypt
---------------------------------

Before the  encryption step, one has to generate the pair of RSA keys (described above) and create a filelist. The filelist is just a list of files (each line being one file), which are going to be encrypted.

In order to run the encryption:

```
./bin/Encryptor <text file with RSA keys> <filelist> <address of the encrypted output file>
```

How to encrypt automatically
---------------------------------

The framework provides also additional way to encrypt, which checks all files in the filelists and create the encrypted file only if there is a change with respect to the previous backup. This can be used to automate encryption and back-up. The name and address of the binary is selected by the user, but timestamp suffix is added in order not to rewrite older back-ups

```
./bin/Encryptor <text file with RSA keys> <filelist> <address of the encrypted output file (without timestamp suffix)> <address of the text file where hashes will be stored>
```

The framework looks at the text file with hashes. If all hashes match, it does not run the encryption.
If the hash file does not exist, or if at least one file is changed, it runs the encryption and updates the file with hashes.

How to decrypt
---------------------------------

Decryption step reads all the keys from the encrypted file, so text file with RSA keys is not needed.
During the encryption you will be asked to provide the password.
Password will be verified and program will warn you and quit if the password is incorrect (the AES key cannot be decrypted in that case).

In order to run the decryption:

```
./bin/Decryptor <address of the encrypted file> <address of the folder where decrypted files will be stored>
```