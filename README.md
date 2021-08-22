# RandyAndy
Open source Android Ransomware using crypto currency ransom.   
   
### History     
I have been looking into cyber security 9n Android devices lately and it occured to me that to, to fully understand what we are dealing with - I need to understand how to make them.
    
Learning about Ransomware has been an a great educational advantage for me as a software developer, knowing now how important self-signature checking and package has calculations are so important.    
Hackers are getting extremely advanced, and in the case of this application - it can completely take over control of the device until a payment is verified.
  
#### Pointers    
I found several methods to attack the payment verification system and the application itself through modified preference files in the application data using root access, most notable were the following methods,   
• Payment Response Spoofing from Blockchain     
• Payment Response Spoofing through PHP Backend    
• Reusing an already verified TxID to trick the ( Not well designed ) Ransomware        
• Editing the preferences files using root access via ADB, to spoof a verification of payment   
    
I also learnt that mostly all methods being researched are based on reversing the encryption of the files, focusing on the actual extension name,   
this leaves people open to attack be associating names to an extension or encryption method.    
   
For example, people will call AES 256 bit encryption by the extension the software has given it - making a randomly generated name for each device a massive headache.   
 
Certain features have been removed for the purpose of install safety, including allowing Old TxID's if necessary and including a Demo TxID.   
   
  
For people using a device that has nothing on it - absolutely no important files or at least an emulator with no important files, you can test a fully Active version of the application here,
https://www.apkfiles.com/apk-609697/android-nightmare   
 
 
Do not Install This Application unless testing 9n a Virtual Environment or a Empty Device, so nothing gets encrypted.    
   


#### This source code is released under the MIT License terms, entirely for educational purposes only.    
    
Encrypts personal files until a Bitcoin payment TxID is verified.     
Protocol,     
• AES 128 Bit Byte Encryption. (changeable)       
    
Uninstalling will destroy files forever.    
 
### NOT SECURE         
• Server Spoofing Response 201 payment verified     
• Reusing TxID from a previous transaction   
• Reverse Engineering to Enable Instant Decryption     
• Root Access to get AES key from data directory     
    
### TO:DO    
• TxID verification of time since install    
• Encrypted messages to server through PGP keys on both ends   
• Obfuscation of strings and functions   
• Decentralized key provider   
• Automatic key removal when closing the app (session only keys)   
 
   
## PROGRESS    
• Automatic key removal, session ONLY valid keys.   
• Warnings not to exit the application, impossible to decrypt.    

  
All of these things could be addressed easily using a decentralized system, this application is purely centralized apart from transaction verification.
       
    
   
  
> uses Bitcoin transaction Verification file found here, https://github.com/GreyJustice/BitcoinTransactionChecker
