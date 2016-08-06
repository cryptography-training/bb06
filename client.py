import requests
import binascii

def send(name, sig):
    url = "http://localhost:4242/api"
    data = {
        'sig': binascii.hexlify(sig),
        'name': name,
    }
    return requests.get(url, params=data)

