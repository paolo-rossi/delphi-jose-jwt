# Keys for RSA Algorithms (NID: 6)
openssl genrsa -out rs256-private.pem
openssl rsa -pubout -in rs256-private.pem -out rs-public.pem
openssl req -new -x509 -key rs-private.pem -out rs-x509.pem -days 360

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
