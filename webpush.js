/*
 * Browser-based Web Push client for the application server piece.
 *
 * Uses the WebCrypto API.
 * Uses the fetch API.  Polyfill: https://github.com/github/fetch
 */

  'use strict';
  // Semi-handy variable defining the encryption data to be
  // Elliptical Curve (Diffie-Hellman) (ECDH) using the p256 curve.
  const P256DH = {
    name: 'ECDH',
    namedCurve: 'P-256'
  };

  // WebCrypto (defined by http://www.w3.org/TR/WebCryptoAPI/) is detailed
  // at https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
  //
  // this has the various encryption library helper functions for things like
  // EC crypto. It's very nice because it makes calls simple, unfortunately,
  // it also prevents some key auditing.
  //
  // It's worth noting that there's two parts to this. The first uses
  // ECDH to get "key agreement". This allows to parties to get a secure key
  // even over untrusted links.
  //
  // The second part is the actual message encryption using the agreed key
  // created by the ECDH dance.
  //
  try {
      if (webCrypto === undefined) {
          webCrypto = window.crypto.subtle;
      }
  } catch (e) {
      var webCrypto = window.crypto.subtle;
  }

  function ensureView(data) {
    /* Coerces data into a Uint8Array */
    if (typeof data === 'string') {
      return new TextEncoder('utf-8').encode(data);
    }
    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data);
    }
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer);
    }
    throw new Error('webpush() needs a string or BufferSource');
  }

  Promise.allMap = function(o) {
      // Resolve a list of promises
    var result = {};
    return Promise.all(
      Object.keys(o).map(
        k => Promise.resolve(o[k]).then(r => result[k] = r)
      )
    ).then(_ => result);
  };

  async function HKDF({ salt, ikm, info, length }) {
    return await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, [
        "deriveBits",
      ]),
      length * 8
    );
  }

  async function wp_encrypt(senderKey, sub, data, salt) {
    /* Encrypt the data using the temporary, locally generated key,
     * the remotely shared key, and a salt value
     *
     * @param senderKey     Locally generated key
     * @param sub           Subscription information object {endpoint, receiverKey, authKey}
     * @param data          The data to encrypt
     * @param salt          A random "salt" value for the encrypted data
     */
    console.debug("calling wp_encrypt(", senderKey, sub, salt, data, ")");
    if (!(data instanceof Uint8Array)) {
      throw new Error("Expecting Uint8Array for `data` parameter");
    }

    if (!(salt instanceof Uint8Array) || salt.length != 16) {
      throw new Error("Expecting Uint8Array[16] for `salt` parameter");
    }

    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", senderKey.publicKey));

    const body = await encrypt_with_params(data, {
      userAgentPublicKey: new Uint8Array(sub.receiverKey),
      appServer: {
        privateKey: senderKey.privateKey,
        publicKey,
      },
      salt,
      authSecret: sub.authKey,
    });

    const headers = {
      // https://datatracker.ietf.org/doc/html/rfc8291#section-4
      // The Content-Encoding header field therefore has exactly one value, which is "aes128gcm".
      'Content-Encoding': "aes128gcm",
      // https://datatracker.ietf.org/doc/html/rfc8030#section-5.2
      // An application server MUST include the TTL (Time-To-Live) header
      // field in its request for push message delivery.  The TTL header field
      // contains a value in seconds that suggests how long a push message is
      // retained by the push service.
      TTL: 15,
    };

    return {
      body,
      headers,
    }
  }

  // https://datatracker.ietf.org/doc/html/rfc8188#section-2.2
  // https://datatracker.ietf.org/doc/html/rfc8188#section-2.3
  async function deriveKeyAndNonce(header) {
    const { salt } = header;
    const ikm = await getInputKeyingMaterial(header);
    output('ikm', base64url.encode(ikm));

    // cek_info = "Content-Encoding: aes128gcm" || 0x00
    const cekInfo = new TextEncoder().encode("Content-Encoding: aes128gcm\0");
    // nonce_info = "Content-Encoding: nonce" || 0x00
    const nonceInfo = new TextEncoder().encode("Content-Encoding: nonce\0");

    // (The XOR SEQ is skipped as we only create single record here, thus becoming noop)
    return {
      // the length (L) parameter to HKDF is 16
      key: await HKDF({ salt, ikm, info: cekInfo, length: 16 }),
      // The length (L) parameter is 12 octets
      nonce: await HKDF({ salt, ikm, info: nonceInfo, length: 12 }),
    };
  }

  // https://datatracker.ietf.org/doc/html/rfc8291#section-3.3
  // https://datatracker.ietf.org/doc/html/rfc8291#section-3.4
  async function getInputKeyingMaterial(header) {
    // IKM:  the shared secret derived using ECDH
    // ecdh_secret = ECDH(as_private, ua_public)
    const ikm = await crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: await crypto.subtle.importKey(
          "raw",
          header.userAgentPublicKey,
          P256DH,
          true,
          []
        ),
      },
      header.appServer.privateKey,
      256
    );
    // key_info = "WebPush: info" || 0x00 || ua_public || as_public
    const keyInfo = new Uint8Array([
      ...new TextEncoder().encode("WebPush: info\0"),
      ...header.userAgentPublicKey,
      ...header.appServer.publicKey,
    ])
    return await HKDF({ salt: header.authSecret, ikm, info: keyInfo, length: 32 });
  }

  // https://datatracker.ietf.org/doc/html/rfc8188#section-2
  async function encryptRecord(key, nonce, data) {
    // add a delimiter octet (0x01 or 0x02)
    // The last record uses a padding delimiter octet set to the value 2
    //
    // (This implementation only creates a single record, thus always 2,
    // per https://datatracker.ietf.org/doc/html/rfc8291/#section-4:
    // An application server MUST encrypt a push message with a single
    // record.)
    const padded = new Uint8Array([...data, 2]);

    // encrypt with AEAD_AES_128_GCM
    return await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [
        "encrypt",
      ]),
      padded
    );
  }

  // https://datatracker.ietf.org/doc/html/rfc8188#section-2.1
  function writeHeader(header) {
    var dataView = new DataView(new ArrayBuffer(5));
    // https://codeberg.org/UnifiedPush/android-connector/issues/3
    // dataView.setUint32(0, header.recordSize);
    dataView.setUint32(0, 0x1000);
    dataView.setUint8(4, header.keyid.length);
    return new Uint8Array([
      ...header.salt,
      ...new Uint8Array(dataView.buffer),
      ...header.keyid,
    ]);
  }

  function validateParams(params) {
    const header = { ...params };
    if (!header.salt) {
      throw new Error("Must include a salt parameter");
    }
    if (header.salt.length !== 16) {
      // https://datatracker.ietf.org/doc/html/rfc8188#section-2.1
      // The "salt" parameter comprises the first 16 octets of the
      // "aes128gcm" content-coding header.
      throw new Error("The salt parameter must be 16 bytes");
    }
    if (header.appServer.publicKey.byteLength !== 65) {
      // https://datatracker.ietf.org/doc/html/rfc8291#section-4
      // A push message MUST include the application server ECDH public key in
      // the "keyid" parameter of the encrypted content coding header.  The
      // uncompressed point form defined in [X9.62] (that is, a 65-octet
      // sequence that starts with a 0x04 octet) forms the entirety of the
      // "keyid".
      throw new Error("The appServer.publicKey parameter must be 65 bytes");
    }
    if (!header.authSecret) {
      throw new Error("No authentication secret for webpush");
    }
    if (!header.userAgentPublicKey) {
      throw new Error("No user agent pubkey");
    }
    if (header.userAgentPublicKey.byteLength !== 65) {
      throw new Error("Wrong user agent pubkey length");
    }
    return header;
  }

  async function encrypt_with_params(data, params) {
    const header = validateParams(params);

    // https://datatracker.ietf.org/doc/html/rfc8291#section-2
    // The ECDH public key is encoded into the "keyid" parameter of the encrypted content coding header
    header.keyid = header.appServer.publicKey;
    header.recordSize = data.byteLength + 18 + 1;

    // https://datatracker.ietf.org/doc/html/rfc8188#section-2
    // The final encoding consists of a header (see Section 2.1) and zero or more
    // fixed-size encrypted records; the final record can be smaller than the record size.
    const saltedHeader = writeHeader(header);
    const { key, nonce } = await deriveKeyAndNonce(header);
    output('gcmB', base64url.encode(new Uint8Array(key)));
    output('nonce', base64url.encode(new Uint8Array(nonce)));

    const encrypt = await encryptRecord(key, nonce, data);
    return new Uint8Array([...saltedHeader, ...new Uint8Array(encrypt)]);
  }

  /*
   * Request push for a message.  This returns a promise that resolves when the
   * push has been delivered to the push service.
   *
   * @param subscription A PushSubscription that contains endpoint and p256dh
   *                     parameters.
   * @param data         The message to send.
   * @param salt         16 random bytes
   */
  function webpush(subscription, data, salt) {
    console.debug('data:', data);
    data = ensureView(data);

    if (salt == null) {
        console.info("Making new salt");
        salt = newSalt();
        output('salt', salt);
    }
    return webCrypto.generateKey(
            P256DH,
            true,          // false for production
            ['deriveBits'])
      .then(senderKey => {
        // Display the local key parts.
        // WebCrypto only allows you to export private keys as jwk.
        webCrypto.exportKey('jwk', senderKey.publicKey)
            .then(key=>{
                //output('senderKeyPub', base64url.encode(key))
                output('senderKey', mzcc.JWKToRaw(key));
                output('senderKeyPub', JSON.stringify(key));
            })
            .catch(x => console.error(x));
        // Dump the local private key
        webCrypto.exportKey('jwk', senderKey.privateKey)
            .then(key=> {
                console.debug("Private Key:", key)
                output('senderKeyPri', JSON.stringify(key))
            })
            .catch(x => {console.error(x);
                         output('senderKeyPri', "Could not display key: " + x);
            });
        console.debug("Sender Key", senderKey);
        // encode all the data as chunks
        return Promise.allMap({
          endpoint: subscription.endpoint,
          payload: wp_encrypt(senderKey,
                           subscription,
                           data,
                           salt),
          pubkey: webCrypto.exportKey('jwk', senderKey.publicKey)
        });
      })
  }

function send(options) {
    console.debug('payload', options.payload);
    let endpoint = options.endpoint;
    let send_options = {
        method: "POST",
        headers: options.payload.headers,
        body: options.payload.body,
        cache: "no-cache",
        referrer: "no-referrer",
    };
    // Note, fetch doesn't always seem to want to send the Headers.
    // Chances are VERY Good that if this returns an error, the headers
    // were not set. You can check the Network debug panel to see if
    // the request included the headers.
    console.debug("Fetching:", options.endpoint, send_options);
    let req = new Request(options.endpoint, send_options);
    console.debug("request:", req);
    return fetch(req)
        .then(response => {
            if (! response.ok) {
                if (response.status == 400) {
                    show_err("Server returned 400. Probably " +
                    "missing headers.<br>If refreshing doesn't work " +
                    "the 'curl' call below should still work fine.");
                    show_ok(false);
                    throw new Error("Server Returned 400");
                }
                throw new Error('Unable to deliver message: ',
                                JSON.stringify(response));
            } else {
                console.info("Message sent", response.status)
            }
            return true;
        })
        .catch(err =>{
             console.error("Send Failed: ", err);
             show_ok(false);
             return false;
        });
}

