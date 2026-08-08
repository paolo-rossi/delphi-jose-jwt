# Keys for RSA Algorithms (NID: 6)
openssl genrsa -out rs256-private.pem
openssl rsa -pubout -in rs256-private.pem -out rs-public.pem
openssl req -new -x509 -key rs-private.pem -out rs-x509.pem -days 360

# An unrelated RSA public key, for the RS* "must not verify under the wrong key" tests.
# Only the public half is kept - nothing ever needs to sign with it.
openssl genrsa -out rsa-other-private.pem 2048
openssl rsa -pubout -in rsa-other-private.pem -out rsa-other-public.pem
rm rsa-other-private.pem

# Keys for ES256 Algorithm (NID: 408)
openssl ecparam -name prime256v1 -genkey -noout -out es256-private.pem             
openssl ec -in es256-private.pem -pubout -out es256-public.pem                    
openssl req -new -x509 -key es256-private.pem -out es256-x509.pem -days 360

# Keys for ES256K Algorithm (NID: 408)
openssl ecparam -name secp256k1 -genkey -noout -out es256k-private.pem              
openssl ec -in es256k-private.pem -pubout -out es256k-public.pem                    
openssl req -new -x509 -key es256k-private.pem -out es256k-x509.pem -days 360

# Keys for ES384 Algorithm (NID: 408)
openssl ecparam -name secp384r1 -genkey -noout -out es384-private.pem             
openssl ec -in es384-private.pem -pubout -out es384-public.pem                    
openssl req -new -x509 -key es384-private.pem -out es384-x509.pem -days 360

# Keys for ES512 Algorithm (NID: 408)
openssl ecparam -name secp521r1 -genkey -noout -out es512-private.pem
openssl ec -in es512-private.pem -pubout -out es512-public.pem
openssl req -new -x509 -key es512-private.pem -out es512-x509.pem -days 360

# P-256 key whose x coordinate starts with a 0x00 byte, for the EC component-width tests.
# RFC 7518 6.2.1.2 requires x/y to be fixed-width, so this is the key that catches a provider
# emitting the minimal (31-byte) encoding instead. About one generated key in 256 qualifies,
# hence the loop rather than a single genkey.
while true; do
  openssl ecparam -name prime256v1 -genkey -noout -out es256-leadzero-private.pem
  X=$(openssl ec -in es256-leadzero-private.pem -pubout -outform DER | xxd -p | tr -d '\n')
  X=${X: -130}
  [ "${X:2:2}" = "00" ] && break
done
openssl ec -in es256-leadzero-private.pem -pubout -out es256-leadzero-public.pem
