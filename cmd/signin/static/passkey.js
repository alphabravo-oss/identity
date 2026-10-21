'use strict';
const decode = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const encode = b => b == null ? null : btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
document.getElementById('passkey-button').addEventListener('click', async () => {
  try {
    const options = JSON.parse(document.getElementById('options').value);
    const publicKey = options.publicKey || options;
    publicKey.challenge = decode(publicKey.challenge);
    for (const credential of publicKey.allowCredentials || []) credential.id = decode(credential.id);
    const registration = document.getElementById('passkey').dataset.register === 'true';
    if (registration) {
      publicKey.user.id = decode(publicKey.user.id);
      for (const c of publicKey.excludeCredentials || []) c.id = decode(c.id);
    }
    const credential = registration ? await navigator.credentials.create({publicKey}) : await navigator.credentials.get({publicKey});
    const response = credential.response;
    const form = document.getElementById('passkey');
    form.elements.assertion.value = JSON.stringify({id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: {attestationObject: encode(response.attestationObject), authenticatorData: encode(response.authenticatorData), clientDataJSON: encode(response.clientDataJSON), signature: encode(response.signature), userHandle: encode(response.userHandle)}});
    form.submit();
  } catch (_) { document.getElementById('passkey-error').textContent = 'Passkey verification was cancelled or failed. Please try again.'; }
});
