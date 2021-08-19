# RandyAndy
Open source Android Ransomware using crypto currency ransom

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
