# THIS IS ALL BROKEN< DO NOT USE SERIOUSLY

import hashlib, math, binascii
from flask import Flask, request, abort, render_template
import rsa

app = Flask(__name__)

(public_key, _) = rsa.newkeys(2048)
public_key.e = 3

@app.route('/')
def show_info():
    return render_template('info.html', n=public_key.n)

@app.route('/api')
def handle_api():
    if not 'name' in request.args: abort(400)
    if not 'sig' in request.args: abort(400)

    sig = binascii.unhexlify(request.args['sig'])
    if not rsa.verify(request.args['name'].encode('utf8'), sig, public_key):
        abort(403)

    return 'Welcome user %s!' % request.args['name']


if __name__ == '__main__':
    app.run(port=4242)
