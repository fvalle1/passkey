function _arrayBufferToBase64(buffer) {
        var binary = '';
        var bytes = new Uint8Array(buffer);
        var len = bytes.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }
    user_id = new Uint8Array([123]);

    const publicKeyCredentialCreationOptions = {
        challenge: new Uint8Array([3,1,4,1,5,9,2,42]),
        rp: {
            name: "Elemento",
            id: "localhost",
        },
        user: {
            id: user_id,
            name: "admin",
            displayName: "Admin",
        },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
        excludeCredentials: [
            //     {
            //     id: *****,
            //     type: 'public-key',
            //     transports: ['internal'],
            // }
        ],
        authenticatorSelection: {
            // authenticatorAttachment: "platform",
            userVerification: "preferred",
            requireResidentKey: true,
        },
        timeout: 30000
    };

    // Availability of `window.PublicKeyCredential` means WebAuthn is usable.
    if (window.PublicKeyCredential &&
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
        PublicKeyCredential.isConditionalMediationAvailable) {
        console.log("available")
        // Check if user verifying platform authenticator is available.
        Promise.all([
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
            PublicKeyCredential.isConditionalMediationAvailable(),
        ]).then(results => {
            if (results.every(r => r === true)) {
                // Call WebAuthn creation
            }
        });
    }


    function send(url, params) {
        fetch(url, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(params)
        })
            .then(response => response.json())
            .then(response => document.getElementById("response").innerText=JSON.stringify(response))
            .then(response => console.log(JSON.stringify(response)))
    }

    function create() {
        navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        }).then(credential => {
            send('http://localhost:7712/register/',
                {
                    "user_id": user_id,
                    "id": credential.id,
                    "rawId": _arrayBufferToBase64(credential.rawId),
                    "response": {
                        "attestationObject": _arrayBufferToBase64(credential.response.attestationObject),
                        "clientDataJSON": _arrayBufferToBase64(credential.response.clientDataJSON)
                    },
                    "type": credential.type
                });
        });
    }

    const abortController = new AbortController();

    const publicKeyCredentialRequestOptions = {
        // Server generated challenge
        challenge: new Uint8Array([3, 1, 4, 1, 5, 9, 2, 42]),
        // The same RP ID as used during registration
        rpId: 'localhost',
    };

    function authenticate(){
    navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
        signal: abortController.signal,
        // Specify 'conditional' to activate conditional UI
        mediation: 'conditional'
    }).then(credential => {
        console.log(credential);
        send('http://localhost:7712/auth/',
            {
                "user_id": user_id,
                "id": credential.id,
                "rawId": _arrayBufferToBase64(credential.rawId),
                "authenticatorAttachment": credential.authenticatorAttachment,
                "response": {
                    "authenticatorData": _arrayBufferToBase64(credential.response.authenticatorData),
                    "clientDataJSON": _arrayBufferToBase64(credential.response.clientDataJSON),
                    "signature": _arrayBufferToBase64(credential.response.signature),
                    "userHandle": _arrayBufferToBase64(credential.response.userHandle)
                },
                "type": credential.type
            });
    }
    );
}

