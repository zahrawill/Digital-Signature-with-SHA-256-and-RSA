# Digital-Signature-with-SHA-256-and-RSA
1)  Generate RSA Key Pair:

 Run the code in terminal:
 python signature_app.py generate
 
 The program automatically uses key size _____
 
 or specify a size:
 python signature_app.py generate --key-size 4096

2) Sign a Message:
 python signature_app.py sign --message "This is a secure message that needs authentication"
 
  (signature.bin should appear)
 
  or sign content in file:
  python signature_app.py sign --message-file text.txt
 
  3) Verify a Signature:
  python signature_app.py verify --message "This is a secure message that needs authentication"
 
  or
  python signature_app.py verify --message-file text.txt
 
  After running all of this you should get this message: Signature verification successful! Message is authentic.


# Requirements:
```bash
pip install cryptography
