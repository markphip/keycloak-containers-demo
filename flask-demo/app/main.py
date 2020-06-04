import os
import flask
import json
from base64 import b64decode
from flask import request, jsonify, abort
from token_verifier import TokenVerifier
from flask_cors import CORS

app = flask.Flask(__name__)
app.config.update({
  'TESTING': True,
  'DEBUG': True,
  'OIDC_CLIENT_ID': os.getenv('OIDC_CLIENT_ID'),
  'OIDC_ISSUER': os.getenv('OIDC_ISSUER'),
})
CORS(app)
verifier = TokenVerifier(app)

@app.route('/', methods=['GET'])
def home():
  return """
    <h1>Flask demo API</h1><p>This is an API for testing Keycloak auth.</p>
    <p>It has 3 endpoints. /public does not require authentication. The other
    two require a Bearer token and are not directly available via the browser</p>
    <ul>
      <li><a href="/api/v1/public">Public</a></li>
      <li><a href="/api/v1/secured">Secured</a></li>
      <li><a href="/api/v1/admin">Admin</a></li>
    </ul>
  """

@app.route('/api/v1/public', methods=['GET'])
def public():
  return jsonify({
    'message': "public"
  })

@app.route('/api/v1/secured', methods=['GET'])
@verifier.authorize()
def secured():
  return jsonify({
    'message': "secured",
    # 'token': verifier.validate_token()
  })

@app.route('/api/v1/admin', methods=['GET'])
@verifier.authorize(roles_required=['admin'])
def admin():
   return jsonify({
    'message': "admin",
    # 'token': verifier.validate_token()
   })
 
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')

