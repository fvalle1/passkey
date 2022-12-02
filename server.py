import sys  # noqa: 402
sys.path.append("./py_webauthn")  # noqa: 402
import pickle
import uvicorn
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    RegistrationCredential,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticationCredential,
)
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import base64
import json
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware


class Database():
    def __init__(self):
        self.db = None
        self.read()

    def read(self) -> None:
        if os.path.exists("database.db"):
            with open("database.db", "rb") as file:
                self.db = pickle.load(file)
        else:
            self.db = {}

    def dump(self) -> None:
        with open("database.db", 'wb') as file:
            pickle.dump(self.db, file)

    def get(self, _key: str) -> dict:
        self.read()
        return self.db[_key]

    def set(self, _key: str, obj) -> None:
        self.db[_key] = obj
        self.dump()

    def __getitem__(self, __name: str) -> dict:
        return self.get(__name)


DB = Database()
app = FastAPI()
origins = ["localhost", "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def index():
    return "Hello world"


@app.post("/register")
def register(request: dict):
    simple_registration_options = generate_registration_options(
        rp_id="localhost",
        rp_name="Elemento",
        user_id="MTIz",
        user_name="admin",
    )
    raw_id = request["rawId"].replace(
        "+", "-").replace("/", "_").replace("=", "")
    registration_verification = verify_registration_response(
        credential=RegistrationCredential.parse_obj(
            {"id": request["id"],
             "rawId": base64url_to_bytes(raw_id),
             "response": {
                "attestationObject": base64.b64decode(request["response"]["attestationObject"]),
                "clientDataJSON": base64.b64decode(request["response"]["clientDataJSON"]),
            },
                "type": request["type"],
                "clientExtensionResults": {},
                "transports": ["internal"]}
        ),
        expected_challenge=base64url_to_bytes(
            # base64.urlsafe_b64encode("".join(map(chr,[3,1,4,1,5,9,2,42])).encode())
            "AwEEAQUJAio="
        ),
        expected_origin="http://localhost:8080",
        expected_rp_id="localhost",
        require_user_verification=True,
    )
    DB.set(request["user_id"]["0"],
           {
        "public_key": bytes_to_base64url(registration_verification.credential_public_key),
        "credential_id": raw_id,
        "transpors": ["internal"]})

    return request


@app.post("/auth")
def authenticate(request: dict):
    simple_authentication_options = generate_authentication_options(
        rp_id="example.com")
    raw_id = request["rawId"].replace(
        "+", "-").replace("/", "_").replace("=", "")
    authentication_verification = verify_authentication_response(
        credential=AuthenticationCredential.parse_obj(
            {"id": request["id"],
             "rawId": base64url_to_bytes(raw_id),
             "response": {
                "authenticatorData": base64.b64decode(request["response"]["authenticatorData"]),
                "clientDataJSON": base64.b64decode(request["response"]["clientDataJSON"]),
                "signature": base64.b64decode(request["response"]["signature"]),
                "userHandle": base64.b64decode(request["response"]["userHandle"])
            },
                "type": request["type"],
                "clientExtensionResults": {},
            }
        ),
        expected_challenge=base64url_to_bytes(
            "AwEEAQUJAio="
        ),
        expected_rp_id="localhost",
        expected_origin="http://localhost:8080",
        credential_public_key=base64url_to_bytes(
            DB.get(request["user_id"]["0"])["public_key"]
        ),
        credential_current_sign_count=0,
        require_user_verification=True,
    )
    return request


if __name__ == "__main__":
    uvicorn.run("server:app", port=7712, reload=True)
