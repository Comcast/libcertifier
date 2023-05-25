VENDOR_ID?=4381
PRODUCT_ID?=4353

all:
	python certifier_cd_gen.py --vendor-id $(VENDOR_ID) --product-id $(PRODUCT_ID)

install:
	pip install pycryptodome
	pip install ecdsa
	pip install cryptography
	pip install ctypescrypto
