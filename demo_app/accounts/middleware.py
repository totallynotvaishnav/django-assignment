import firebase_admin
import json
import requests

from rest_framework.authentication import BaseAuthentication
from django.contrib.auth.models import User
from django.conf import settings
from django.urls import reverse
from firebase_admin import credentials, auth
from .exceptions import InvalidAuthToken, NoAuthToken, FirebaseError


cred = credentials.Certificate({
    "type": settings.FIREBASE_ACCOUNT_TYPE,
    "project_id": settings.FIREBASE_PROJECT_ID,
    "private_key_id": settings.FIREBASE_PRIVATE_KEY_ID,
    "private_key": settings.FIREBASE_PRIVATE_KEY.replace('\\n', '\n'),
    "client_email": settings.FIREBASE_CLIENT_EMAIL,
    "client_id": settings.FIREBASE_CLIENT_ID,
    "auth_uri": settings.FIREBASE_AUTH_URI,
    "token_uri": settings.FIREBASE_TOKEN_URI,
    "auth_provider_x509_cert_url": settings.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    "client_x509_cert_url": settings.FIREBASE_CLIENT_X509_CERT_URL,
    "universe_domain": settings.FIREBASE_UNIVERSE_DOMAIN
})


default_app = firebase_admin.initialize_app(cred)

def verify_custom_token(custom_token):
    api_key=settings.FIREBASE_API_KEY
    url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key={0}".format(api_key)
    headers = {"content-type": "application/json; charset=UTF-8"}
    data = json.dumps({"returnSecureToken": True, "token": custom_token})
    try:
        request_object = requests.post(url, headers=headers, data=data)
        response = request_object.json()
        return response
    except Exception as e:
        print(e)
        raise InvalidAuthToken("Invalid auth token")

class FirebaseAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):   
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
                raise NoAuthToken("No auth token provided")
        custom_token = auth_header.split(" ").pop()
        decoded_token = None
        try:
            id_token = verify_custom_token(custom_token)
            decoded_token = auth.verify_id_token(id_token.get("idToken"))
        except Exception as e:
            print(e)
            raise InvalidAuthToken("Invalid auth token")
        if not custom_token or not decoded_token:
                request.user = None
        else:
            try:
                uid = decoded_token.get("uid")
                user, created = User.objects.get_or_create(id=uid)
                request.user = user
            except Exception:
                request.user = None

        response = self.get_response(request)
        return response