"""
WISEcode Platform login resource
"""

import flask
from flask_restful import Resource
import time

from fence.user import get_current_user
from fence.config import config
from fence.blueprints.login.base import _login, prepare_login_log
from fence import wisecode_user_sdk
from fence.errors import UserError
from fence.models import IdentityProvider
from fence.jwt.token import generate_signed_access_token


class WISEcodePlatformLogin(Resource):
    """
    WISEcode Platform login resource
    """

    def post(self):
        """
        Processes requests from the WISEcode for Business Platform. The platform calls this endpoint with its user's Cognito
        JWT in the Authorization header. This handler calls the WISEcode User service Read JWT User service action
        to validate the JWT and get the user resource. Last, a Fence JWT is made and added to a cookie in the reponse.
        """

        authorization_header = flask.request.headers.get("Authorization")
        if authorization_header:
            response = wisecode_user_sdk.read_user_jwt(authorization_header)
            if response.status_code == 200:
                username = response.json()["cognito_attributes"]["username"]
                _login(username, IdentityProvider.wisecode, email=username)
                prepare_login_log(IdentityProvider.wisecode)
                keypair = flask.current_app.keypairs[0]
                scopes = config["SESSION_ALLOWED_SCOPES"]
                now = int(time.time())
                expiration = now + config.get("ACCESS_TOKEN_EXPIRES_IN")
                access_token = generate_signed_access_token(
                    keypair.kid,
                    keypair.private_key,
                    get_current_user(),
                    config.get("ACCESS_TOKEN_EXPIRES_IN"),
                    scopes,
                    forced_exp_time=expiration,
                ).token
                return flask.jsonify({"jwt": access_token})

        raise UserError("WISEcode user not found associated to JWT")
