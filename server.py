from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import sys
sys.path.append("./py_webauthn")
import json
import base64
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
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

import uvicorn

app = FastAPI()
origins=["localhost", "*"]
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
    raw_id = request["rawId"].replace("+","-").replace("/","_").replace("=", "")
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
        "Ig==" #base64.urlsafe_b64encode(b"\xcc")
    ),
    expected_origin="http://localhost:8080",
    expected_rp_id="localhost",
    require_user_verification=True,
    )
    print(bytes_to_base64url(registration_verification.credential_public_key))
    return request

@app.post("/auth")
def authenticate(request: dict):
    simple_authentication_options = generate_authentication_options(rp_id="example.com")
    raw_id = request["rawId"].replace("+","-").replace("/","_").replace("=", "")
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
        "Ig=="
    ),
    expected_rp_id="localhost",
    expected_origin="http://localhost:8080",
    credential_public_key=base64url_to_bytes(
        "pQECAyYgASFYID3iWL0N5MCdoDh5TBCRa9xH96QGEeyzBe1xHEgKiXaVIlggL08B6hOUUyUeUAZVCSSL1vVbi27PhPbKPL8GuvLdELU"
    ),
    credential_current_sign_count=0,
    require_user_verification=True,
    )
    return request

if __name__=="__main__":
    uvicorn.run("server:app", port=7712, reload=True)