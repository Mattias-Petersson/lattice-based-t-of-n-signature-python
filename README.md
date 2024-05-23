# GKS23
An implementation of the GKS23 scheme presented in https://eprint.iacr.org/2023/1318. 

## Introduction
As part of a thesis at Lunds Tekniska Högskola, spring 2024, our work was to implement the GKS23 scheme completely and to analyze it. We did this with the department of electrical and information technology. Our full implementation can be seen [here](GKS23).
As this scheme is based on security of R-LWE, we have our own polynomial class that is a wrapper utilizing CyPari2.  
Our implementation includes BDLOP16 as a commitment scheme and for NIZKPs, available from https://eprint.iacr.org/2016/997, code for this is found [here](BDLOP16). 
Additionally, we are using a distributed version of the BGV12 algorithm for encryption/decryption, presented in the GKS23 paper. The original BGV12 algorithm can be seen at https://eprint.iacr.org/2011/277.pdf. [Click](BGV12) for our implementation.  

## Dependencies
Python >= 3.12 for type statements.  
CyPari >= 2.1.4 for handling of polynomials.  
pytest >= 8.0.2 for running the tests.

## Usage
Our implementation includes some rudamentary tests that can be run with pytest.  
To run the GKS23 scheme, initialize the GKS23 class with values, where default values for 1 signature per key generation and for 365 values can be found [here](utils/values.py). Then, after having run  `KGen()` messages can be signed in R_p. 
A signature can be verified by a participant. The GKS23 controller supports calling `sign()` and `vrfy()` method, but requires sending in one or many participants as it does not keep the states necessary to perform these calculations. 
