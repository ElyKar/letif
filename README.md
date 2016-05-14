## Let's Encrypt This Important File − letif ##

Use AES-256 to encrypt or decrypt a file, it is simple-enough to use:

Encryption:
`
letif -i data.txt -o out.ltf
`

Decryption: 
`
letif -i out.ltf -o data.txt -d
`

Passphrase must not be empty, and are limited to the 32 first bytes.
If longer, it is truncated and if shorter, it is repeated to achieve the desired length.

