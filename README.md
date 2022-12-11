Boost library is necessary to compile the code. In order to install it on Linux:

```
sudo apt-get install libboost-all-dev
```

In order to compile the code (when the boost is already installed):

```
mkdir bin

cd bin

cmake ../.

make
```

The package is still under development, with no useful executable, except for the one for running the CI tests.