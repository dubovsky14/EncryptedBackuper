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

The package is still under development, with no useful executable, except for the one for running the CI tests.