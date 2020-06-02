import sys
import os
import string
import struct
import time
import urllib.request
import json
import base64
from datetime import timedelta
from functools import update_wrapper
from flask import Flask, jsonify, abort, Response, make_response, \
     request, current_app, redirect
import jwt
#import jwt.contrib.algorithms
#import jwt.contrib.algorithms.pycrypto
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from Crypto.PublicKey import RSA
from functools import wraps

oauth_rsa_keys = None

class TokenVerifier(object):
  """
  A class that can verify a JWT/OpenID token
  """
  def __init__(self, app=None):
    self.app = app
    if (app is not None):
        self.init_app(app)

  def init_app(self, app):
    """
      Do setup that requires a Flask app.
      :param app: The application to initialize.
      :type app: Flask
    """

    # # Set some default configuration options
    # app.config.setdefault('OIDC_SCOPES', ['openid'])
    # app.config.setdefault('OIDC_VALID_ISSUERS',
    #                       (self.client_secrets.get('issuer')))
    # app.config.setdefault('OIDC_OPENID_REALM', None)

  # ------------------------------------------------------------------------
  # (Some code adapted from https://github.com/rohe/pyjwkest)
  #
  def base64url_decode(self, b64):
    b64_len = len(b64) % 4
    if b64_len:
      b64 += "=" * (4 - b64_len)
    return base64.urlsafe_b64decode(b64.encode("utf-8"))

  def base64_to_long(self, b64):
    b64 = b64.encode("utf-8")
    decoded = base64.urlsafe_b64decode(bytes(b64) + b'==')
    return int(''.join(["%02x" % b for b in \
                       struct.unpack('%sB' % len(decoded), decoded)]), 16)

  def logerr(self, message):
    request.environ.get('wsgi.errors', sys.stderr).write(
      "[token verifier] %s\n" % (message))

  def ensure_keychain(self):
    global oauth_rsa_keys

    # If we've cached a set of keys, return them.
    if oauth_rsa_keys:
      return oauth_rsa_keys

    # If we aren't already caching keys, fetch the keychain from the
    # application (allowing for a few retries if the fetch fails).  Once
    # we get the keychain, we'll create and keep RSA key objects for the
    # keys of interest therein.
    # New endpoint /oauth/auth/token/keyset is introduced in 17.1, but keeping
    # /sf/... until SvnEdge no longer supports TeamForge 16.x
    keychain_url = 'http://keycloak:8080/auth/realms/dai/protocol/openid-connect/certs'

    for delay in [0.5, 2.5, 5.0, None]:
      try:
        response = urllib.request.urlopen(keychain_url, timeout=10)
        keychain = json.load(response)

        # Keychain looks something like this:
        #
        # { 'keys': [
        #   { 'use': 'sig',
        #     'e': 'AQAB',
        #     'kty': 'RSA',
        #     'alg': 'RS256',
        #     'n': '-AML1G...',
        #     'kid': '1'
        #   },
        #   ...
        #   ]
        # }
        for key in keychain['keys']:
          if (key['kty'] == 'RSA' and
              key['alg'] == 'RS256' and
              'n' in key and
              'e' in key):
            if 'd' in key:
              rsa_key = RSA.construct((self.base64_to_long(key['n']),
                                       self.base64_to_long(key['e']),
                                       self.base64_to_long(key['d'])))
            else:
              rsa_key = RSA.construct((self.base64_to_long(key['n']),
                                       self.base64_to_long(key['e'])))
            if oauth_rsa_keys is None:
              oauth_rsa_keys = {}
            oauth_rsa_keys[key['kid']] = rsa_key
        return oauth_rsa_keys
      except Exception as e:
        self.logerr("Warning: trouble retrieving OAuth key: %s" % (str(e)))
        if delay is not None:
          time.sleep(delay)

    # If we get here, we've failed to fetch and parse the keychain.
    self.logerr("Error parsing OAuth keyset")
    abort(500)

  def verify_bearer(self, bearer):
    # Bearer is a dotted triplet of base64url-encoded bits.
    try:
      header, payload, signature = bearer.split('.', 2)
      header = json.loads(self.base64url_decode(header))
      payload = json.loads(self.base64url_decode(payload))
    except:
      self.logerr("Malformed bearer token: %s" % bearer)
      abort(500)

    # Get the OAuth keychain and specific key against which we validate.
    rsa_key = None
    try:
      rsa_key = self.ensure_keychain()[header['kid']]
    except Exception as e:
      self.logerr("Error retrieving OAuth key: %s" % (str(e)))
      self.logerr("Requested OAuth key not found (kid=%s)" % (header['kid']))
      abort(500)

    # Try to decode and validate the bearer token.  If we succeed,
    # return the username.  Any failure falls through to a 401 abort.
    issuer = self.app.config.get('OIDC_ISSUER', '')
    try:
      verify_options = {
        'verify_aud': True,
        'verify_iss': True if issuer else False,
        'verify_exp': True,
        'verify_iat': True,
        'verify_nbf': True,
        'verify_signature': True,
        }
      return jwt.decode(bearer, rsa_key.exportKey(), leeway=30,
                        audience=self.app.config['OIDC_CLIENT_ID'],
                        issuer=issuer,
                        options=verify_options)
    except jwt.InvalidTokenError as e: # PyJWT errors subclass this
      self.logerr("Error decoding OAuth token: %s" % (str(e)))
    except Exception as e:
      self.logerr("Unknown error decoding OAuth token: %s" % (str(e)))
    abort(401)

  def validate_token(self):
    # Check for authorization details.  We check the following places, in order:
    # 1. The 'access_token' query parameter
    # 2. The request's Authorization header
    # 3. The HTTP_AUTHORIZATION environment variable[*]
    #
    # [*] mod_wsgi with "WSGIPassAuthorization on" uses this.
    username = None
    access_token = request.form.get('access_token',
                                    request.args.get('access_token', None))
    authorization = request.headers.get('Authorization',
                                        request.environ.get('HTTP_AUTHORIZATION'))
    if access_token:
      return self.verify_bearer(access_token)
    elif authorization:
      try:
        token_type, access_token = filter(None, authorization.split())
        token_type = token_type.lower()
        if token_type == 'bearer': # OAuth
          return self.verify_bearer(access_token)
        else:
          self.logerr("Unsupported authorization token type: %s" % (token_type))
          abort(401)
      except Exception as e:
        self.logerr("Error parsing authorization token: %s" % (str(e)))
        abort(401)
    return None


  def authorize(self, require_token=True, scopes_required=None,
                roles_required=None, render_errors=True):
    """
          Use this to decorate view functions that should accept OAuth2 tokens
          :param require_token: Whether a token is required for the current
              function. If this is True, we will abort the request if there
              was no token provided.
          :type require_token: bool
          :param roless_required: List of roles, one of which is required to be
              granted by the token before being allowed to call the protected
              function.
          :type scopes_required: list
          :param scopes_required: List of scopes that are required to be
              granted by the token before being allowed to call the protected
              function.
          :type scopes_required: list
          :param render_errors: Whether or not to eagerly render error objects
              as JSON API responses. Set to False to pass the error object back
              unmodified for later rendering.
          :type render_errors: callback(obj) or None
          .. versionadded:: 1.0
    """

    def wrapper(view_func):
      @wraps(view_func)
      def decorated(*args, **kwargs):
        if require_token:
          token = self.validate_token()
          if token is not None:
            has_required_roles = True
            has_required_scopes = True
            if roles_required is not None:
              token_roles = token['resource_access'][self.app.config['OIDC_CLIENT_ID']]['roles']
              has_required_roles = set(roles_required).intersection(set(token_roles))
            if scopes_required is not None:
              token_scopes = token.get('scope', '').split(' ')
              has_required_scopes = set(scopes_required).issubset(set(token_scopes))
            if has_required_roles and has_required_scopes:
              return view_func(*args, **kwargs)
            else:
              return abort(403)
          else:
            response_body = {'error': 'invalid_token',
                             'error_description': token}
            if render_errors:
              response_body = json.dumps(response_body)
            return response_body, 401, {'WWW-Authenticate': 'Bearer'}
        else:
          return view_func(*args, **kwargs)
      return decorated
    return wrapper
