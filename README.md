# Pythia

*Under Development*

## Description

> To those who ask for oracles<br>
> Let the God's answer come<br>
>   \- Pythian Priests

While completing a CTF recently I needed to exploit a padding oracle with custom encoding and then further exploit another service through it. While I had some success with already available scripts, they were very slow. They also did not integrate well with the rest of the attack chain and required a lot of hands-on work.

I am developing `Pythia` as a Python library rather than a command line tool to make customization as simple as possible. It supports decrypting existing ciphertext and encrypting chosen plaintext using an oracle. It expects an oracle function that is responsible for the request and detecting the oracle response.

## Usage

```python
import pythia
import requests

def oracle(data):
	url = b'http://website.example/?data=' + data.hex()
	response = requests.get(url)
	return not b'Padding Error' in response.text

stream = Pythia.Stream(16, oracle, threads=100)
decrypted = stream.decrypt(ciphertext)
encrypted = stream.encrypt(plaintext)
```

Pythia works purely on `bytes`. Any encoding (Hex, Base64, UTF-8, etc) must be done by the oracle function. The oracle function responds `True` when a valid response is received and `False` when a padding error is detected.
