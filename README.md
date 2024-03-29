# Checksumly

![LogoMakr-4C03e7](https://user-images.githubusercontent.com/33039708/144717156-e8b516d0-a5bd-410f-867f-ad2351baac29.png)


Checksumly is a small Program in python with Tkinter used for Frontend which Demonstrates the use of Checksums by generating Checksum and also comparing two checksums to check for file integrity for files downloaded over internet.

Give a star if you liked it!!

UPDATE : Version 2 released Check it out here : https://github.com/Cyborg117/Checksum-Utility/tree/main/V2

# How to use
1. firstly install pyperclip using "pip install pyperclip"

2. use Checker to compare Hashes of files and Generator to Generate Hash of a file (MD5,SHA256,SHA512,Blake2)

# Output
![output1](https://user-images.githubusercontent.com/33039708/119959454-a30c0780-bfc1-11eb-8cd9-1c7bdeb3ad39.JPG)     ![output2](https://user-images.githubusercontent.com/33039708/119959502-adc69c80-bfc1-11eb-9905-dbeec3b7fda2.JPG)
![output3](https://user-images.githubusercontent.com/33039708/119959582-c1720300-bfc1-11eb-8611-950f5c74b64b.JPG)


# About Checksums
A checksum is a small-sized block of data derived from another block of digital data for the purpose of detecting errors that may have been introduced during its transmission or storage. By themselves, checksums are often used to verify data integrity but are not relied upon to verify data authenticity.
Simply Put,
A checksum is a sequence of numbers and letters used to check data for errors. If you know the checksum of an original file, you can use a checksum utility to confirm your copy is identical.

# How Checksum Works
lets Suppose you Downloaded a File Over Internet and it downloaded completely and successfully then, how would you know if the shown file and the downloaded file are the same? simple , you just compare their checksums which are created by a Specific Hashing Algorithm and if the Checksums match the file is identical and if it doesnt then either the download wasnt completed successfully or the file contains altered/added data.

# Note
1. Length of Checksums will always remain same and doesnot depend on size of file so , a 1Mb file and a 1Gb file will have same checksum length if same Hashing Algorithm is used
2. The Smallest change in a File will generate Different Checksums.

# Hashing
Hashing is Cryptographic Function that is used for mapping data of any length to a fixed-length output using an algorithm.

Hashes are irreversible it means you can Encrypt Plaintext to ciphertext but cannot Decrypt Ciphertext to get the Plaintext back.

# Hashing Algorithms
  1. MD5    - Least Secure (collision prone) but fastest
  2. SHA256 - More Secure but Slow
  3. SHA512 - Most Secure but Slowest
  4. Blake2 - More Secure than MD5 and Fast Enough (Recommended)

# Request a Feature
If you want me to add a Particular Feature in the Source then
1. Goto Issues and Create a New Issue
2. There Select a Feature Request Template and Click Get Started
3. Write Accordingly
4. OR Contact me at hrithikraj137@gmail.com

# V2
1. To Add Support for more Filetypes (Currently only text files(.txt) is used) - done
2. To add More Hashing Algorithms - done

# Whats New in V2
V2 released Check it out here : https://github.com/Cyborg117/Checksum-Utility/tree/main/V2
1. Compare and Generate Checksums
2. Supports all Files (* . *)
3. Added a Mechanism to Read Binary Data of Extremely big file in 64Kb Chunks So as to Not Overload the Memory.
4. Hashing Algorithms:
     1.  Md5                
     2.  SHA256             
     3.  SHA512               
     4.  Blake2s               
     5.  SHA224   (new)        
     6.  SHA384   (new)
     7.  SHA3_224 (new)
     8.  SHA3_256 (new) 
     9.  SHA3_384 (new)
     10. SHA3_512 (new)
     
# V3 - ??
V2 will be the Final Major Update. From Now on there will only be minor updates like Bug Fixes and Feature Requests.
I want Inspiration to Release V3 , If you Have Ideas That I can Implement then I'll be Grateful. 
