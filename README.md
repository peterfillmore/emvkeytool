# Project Title

emvkeytool.py
a tool for obtaining, testing and dumping RSA keys on EMV chip cards.

## Getting Started


### Prerequisites

```
pip install -r requirements.txt
```

### Running
#### Printing Options
```
python emvkeytool.py -h

usage: emvkeytool.py [-h] [-V] [-v] [-l] [-r USE_READER] [-j IMPORT_JSON]
                     [-A IMPORT_AID] [-D] [-t]

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         print version
  -v, --verbose         print verbose information
  -l, --list-readers    print connected readers
  -r USE_READER, --use-reader USE_READER
                        select reader number (default to first detected)
  -j IMPORT_JSON, --import-json IMPORT_JSON
                        import a custom CA List
  -A IMPORT_AID, --import-aid IMPORT_AID
                        import a custom AID List
  -D, --dump-keys       import a custom AID List
  -t, --test-keys       test found keys for Infineon weak key
``` 

#### Viewing keys
```
python emvkeytool.py

[*] Using AID:a00000038410
NO VALID CA KEY FOUND
[*] Using AID:a00000038420
NO VALID CA KEY FOUND
[*] Using AID:a0000000031010
[*] CA Public Key Length :1408 bits
[*] CA Public Key Modulus :D9FD6ED75D51D0E30664BD157023EAA1FFA871E4DA65672B863D255E81E137A51DE4F72BCC9E44ACE12127F87E263D3AF9DD9CF35CA4A7B01E907000BA85D24954C2FCA3074825DDD4C0C8F186CB020F683E02F2DEAD3969133F06F7845166ACEB57CA0FC2603445469811D293BFEFBAFAB57631B3DD91E796BF850A25012F1AE38F05AA5C4D6D03B1DC2E568612785938BBC9B3CD3A910C1DA55A5A9218ACE0F7A21287752682F15832A678D6E1ED0B
[*] CA Public Key Exponent: 03
[*] Issuer Public Key Length :1408 bits
[*] Issuer Public Key Modulus :<REDACTED>
[*] Issuer Public Key Exponent: 03
Issuer Key is safe
[*] ICC Public Key Length:768 bits
[*] ICC Public Key Modulus:<REDACTED>
[*] ICC Public Key Exponent:03
ICC Key is safe
```
#### Testing for ROCA infinion weak keys 
```
python emvkeytool.py -t

[*] Using AID:a00000038410
NO VALID CA KEY FOUND
[*] Using AID:a00000038420
NO VALID CA KEY FOUND
[*] Using AID:a0000000031010
[*] CA Public Key Length :1408 bits
[*] CA Public Key Modulus :D9FD6ED75D51D0E30664BD157023EAA1FFA871E4DA65672B863D255E81E137A51DE4F72BCC9E44ACE12127F87E263D3AF9DD9CF35CA4A7B01E907000BA85D24954C2FCA3074825DDD4C0C8F186CB020F683E02F2DEAD3969133F06F7845166ACEB57CA0FC2603445469811D293BFEFBAFAB57631B3DD91E796BF850A25012F1AE38F05AA5C4D6D03B1DC2E568612785938BBC9B3CD3A910C1DA55A5A9218ACE0F7A21287752682F15832A678D6E1ED0B
[*] CA Public Key Exponent: 03
[*] Issuer Public Key Length :1408 bits
[*] Issuer Public Key Modulus : <REDACTED>
[*] Issuer Public Key Exponent: 03
Issuer Key is safe
[*] ICC Public Key Length:768 bits
[*] ICC Public Key Modulus: <REDACTED>
[*] ICC Public Key Exponent:03
ICC Key is safe
```

#### Dumping keys 
```
[*] Using AID:a00000038410
NO VALID CA KEY FOUND
[*] Using AID:a00000038420
NO VALID CA KEY FOUND
[*] Using AID:a0000000031010
[*] CA Public Key Length :1408 bits
[*] CA Public Key Modulus :D9FD6ED75D51D0E30664BD157023EAA1FFA871E4DA65672B863D255E81E137A51DE4F72BCC9E44ACE12127F87E263D3AF9DD9CF35CA4A7B01E907000BA85D24954C2FCA3074825DDD4C0C8F186CB020F683E02F2DEAD3969133F06F7845166ACEB57CA0FC2603445469811D293BFEFBAFAB57631B3DD91E796BF850A25012F1AE38F05AA5C4D6D03B1DC2E568612785938BBC9B3CD3A910C1DA55A5A9218ACE0F7A21287752682F15832A678D6E1ED0B
[*] CA Public Key Exponent: 03
[*] Issuer Public Key Length :1408 bits
[*] Issuer Public Key Modulus : <REDACTED>
[*] Issuer Public Key Exponent: 03
[*] Dumping Issuer Public Key to:a0000000031010_Issuer_PK.pem
[*] ICC Public Key Length:768 bits
[*] ICC Public Key Modulus:<REDACTED>
[*] ICC Public Key Exponent:03
[*] Dumping ICC Public Key to:a0000000031010_ICC_PK.pem
```

## Built With

* [pytlv](https://pypi.python.org/pypi/pytlv) - modified to work properly with long tags 
* [ROCA](https://github.com/crocs-muni/roca) - Test for Infinion weak keys 
* [AID List](https://eftlab.co.uk/index.php/site-map/knowledge-base/211-emv-aid-rid-pix) - List of AIDs for bruteforcing
* [EMV CA Keys](https://www.eftlab.co.uk/index.php/site-map/knowledge-base/243-ca-public-keys) - List of CA Keys 
 

## Contributing

Just submit a pull request.

## Authors

* **Peter Fillmore** - *Initial work* - [PurpleBooth](https://github.com/PurpleBooth)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Matus Nemec, Marek Sys, Petr Svenda, Dusan Klinec and Vashek Matyas for the ROCA RSA research 
* Upright ducks worldwide 
