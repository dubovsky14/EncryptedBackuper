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

Package description
---------------------
The package is design for safe (encrypted) back-up of data.
The key requirement is that the password required to decrypt the data is not saved anywhere on the disk and it is not needed for the encryption step.

User needs to generate pair of RSA keys, using ```generate_key_file``` executable. He will be asked to provide a password.
The pair of RSA keys is created in this step and the private key is XOR-ed with a pseudo-random number of the same length, obtained from SHA3-512 algorithm, with the password being the input for the hash function.
The key pair is then saved to a text file (with P*Q, key length and public key saved in plane text, private key being XOR-ed with the password hash).

The encryption step looks at the provided filelist, hash all the files in it, add a random number, hashes it and uses this number as 256-bit AES key. This AES key is used to encrypt the files and after encrypting with the RSA public key, it is also saved into the output binary.

The package is still under development, with decryption part missing.

How to generate RSA pair of keys
---------------------------------
```
./bin/generate_key_file <RSA key length> <output text file>
```

```RSA key length``` is the maximal lenght of private key (or p*q) in bits, with options 512, 1024, 2048 and 4096 supported. For real applications at least 2048 is recommended.

```output text file``` is the output file where the RSA keys will be stored


How to encrypt
---------------------------------

Before the  encryption step, one has to generate the pair of RSA keys (describe above) and create a filelist. The filelist is just a list of files (each line being one file), which are going to be encrypted.

In order to run the encryption:

```
./bin/Encryptor <text file with RSA keys> <filelist> <address of the encrypted output file>
```