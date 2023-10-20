## CONTRIBUTION GUIDELINES

1. Currently, TLExport only uses classes and methods from [cryptography](https://pypi.org/project/cryptography/) for cryptographic computations,
therefore we suggest having a look at the documentation
2. When adding a new cipher suite, add the cipher suite to the `cipher_suites` dictionary in the `cipher_suite_parser.py`  
If that cipher suite uses other algorithms than those listed in `README.md` you have to add the algorithms in the `cipher_suite_parser.py`
and their functionalities in the `decryptor.py`
