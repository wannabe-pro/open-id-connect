<?php

namespace WannaBaPro\OpenIDConnect;

/**
 *
 * Please note this class stores nonces by default in $_SESSION['openid_connect_nonce']
 *
 */
class Client
{
    /**
     * @var string arbitrary id value
     */
    protected $clientID;

    /**
     * @var string arbitrary name value
     */
    protected $clientName;

    /**
     * @var string arbitrary secret value
     */
    protected $clientSecret;

    /**
     * @var array holds the provider configuration
     */
    protected $providerConfig = [];

    /**
     * @var string http proxy if necessary
     */
    protected $httpProxy;

    /**
     * @var string full system path to the SSL certificate
     */
    protected $certPath;

    /**
     * @var bool Verify SSL peer on transactions
     */
    protected $verifyPeer = true;

    /**
     * @var bool Verify peer hostname on transactions
     */
    protected $verifyHost = true;

    /**
     * @var string if we acquire an access token it will be stored here
     */
    protected $accessToken;

    /**
     * @var string if we acquire a refresh token it will be stored here
     */
    protected $refreshToken;

    /**
     * @var string if we acquire an id token it will be stored here
     */
    protected $idToken;

    /**
     * @var string stores the token response
     */
    protected $tokenResponse;

    /**
     * @var array holds scopes
     */
    protected $scopes = [];

    /**
     * @var int|null Response code from the server
     */
    protected $responseCode;

    /**
     * @var array holds response types
     */
    protected $responseTypes = [];

    /**
     * @var array holds a cache of info returned from the user info endpoint
     */
    protected $userInfo = [];

    /**
     * @var array holds authentication parameters
     */
    protected $authParams = [];

    /**
     * @var array holds additional registration parameters for example post_logout_redirect_uris
     */
    protected $registrationParams = [];

    /**
     * @var mixed holds well-known openid server properties
     */
    protected $wellKnown = false;

    /**
     * @var int timeout (seconds)
     */
    protected $timeOut = 60;

    /**
     * @var int leeway (seconds)
     */
    protected $leeway = 300;

    /**
     * @var array holds response types
     */
    protected $additionalJwks = [];

    /**
     * @var array holds verified jwt claims
     */
    protected $verifiedClaims = [];

    /**
     * @var callable validator function for issuer claim
     */
    protected $issuerValidator;

    /**
     * @var bool Allow OAuth 2 implicit flow; see http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
     */
    protected $allowImplicitFlow = false;

    /**
     * @var string
     */
    protected $redirectURL;

    protected $encType = PHP_QUERY_RFC1738;

    public $state;

    /**
     * @param ClientStateInterface $state
     * @param string|null $providerUrl optional
     * @param string|null $clientId optional
     * @param string|null $clientSecret optional
     * @param string|null $issuer
     */
    public function __construct($providerUrl = null, $clientId = null, $clientSecret = null, $issuer = null, ClientStateInterface $state = null)
    {
        if ($state === null) {
            $this->state = new ClientStateSession();
        } else {
            $this->state = $state;
        }


        $this->setProviderURL($providerUrl);
        if ($issuer === null) {
            $this->setIssuer($providerUrl);
        } else {
            $this->setIssuer($issuer);
        }

        $this->clientID = $clientId;
        $this->clientSecret = $clientSecret;

        $this->issuerValidator = function ($iss) {
            return $iss === $this->getIssuer() || $iss === $this->getWellKnownIssuer() || $iss === $this->getWellKnownIssuer(true);
        };
    }

    /**
     * @param $providerUrl
     */
    public function setProviderURL($providerUrl)
    {
        $this->providerConfig['providerUrl'] = $providerUrl;
    }

    /**
     * @param $issuer
     */
    public function setIssuer($issuer)
    {
        $this->providerConfig['issuer'] = $issuer;
    }

    /**
     * @param $responseTypes
     */
    public function setResponseTypes($responseTypes)
    {
        $this->responseTypes = array_merge($this->responseTypes, (array) $responseTypes);
    }

    /**
     * @param  array  $request
     *
     * @return bool
     * @throws ClientException
     */
    public function authenticate($request)
    {

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect
        if (isset($request['error'])) {
            $desc = isset($request['error_description']) ? ' Description: '.$request['error_description'] : '';
            throw new ClientException('Error: '.$request['error'].$desc);
        }

        // If we have an authorization code then proceed to request a token
        if (isset($request['code'])) {

            $code = $request['code'];
            $tokenJson = $this->requestTokens($code);

            // Throw an error if the server returns one
            if (isset($tokenJson['error'])) {
                if (isset($tokenJson['error_description'])) {
                    throw new ClientException($tokenJson['error_description']);
                }
                throw new ClientException('Got response: '.$tokenJson['error']);
            }

            // Do an OpenID Connect session check
            if ($request['state'] !== $this->getState()) {
                throw new ClientException('Unable to determine state');
            }

            // Cleanup state
            $this->unsetState();

            if (! array_key_exists('id_token', $tokenJson)) {
                throw new ClientException('User did not authorize openid scope.');
            }

            $claims = $this->decodeJWT($tokenJson['id_token'], 1);

            // Verify the signature
            if ($this->canVerifySignatures()) {
                if (! $this->getProviderConfigValue('jwks_uri')) {
                    throw new ClientException ('Unable to verify signature due to no jwks_uri being defined');
                }
                if (! $this->verifyJWTSignature($tokenJson['id_token'])) {
                    throw new ClientException ('Unable to verify signature');
                }
            } else {
                user_error('Warning: JWT signature verification unavailable.');
            }

            // If this is a valid claim
            if ($this->verifyJWTClaims($claims, $tokenJson['access_token'])) {

                // Clean up the session a little
                $this->unsetNonce();

                // Save the full response
                $this->tokenResponse = $tokenJson;

                // Save the id token
                $this->idToken = $tokenJson['id_token'];

                // Save the access token
                $this->accessToken = $tokenJson['access_token'];

                // Save the verified claims
                $this->verifiedClaims = $claims;

                // Save the refresh token, if we got one
                if (isset($tokenJson['refresh_token'])) {
                    $this->refreshToken = $tokenJson['refresh_token'];
                }

                // Success!
                return true;
            }

            throw new ClientException('Unable to verify JWT claims');
        }

        if ($this->allowImplicitFlow && isset($request['id_token'])) {
            // if we have no code but an id_token use that
            $idToken = $request['id_token'];

            $accessToken = null;
            if (isset($request['access_token'])) {
                $accessToken = $request['access_token'];
            }

            // Do an OpenID Connect session check
            if ($request['state'] !== $this->getState()) {
                throw new ClientException('Unable to determine state');
            }

            // Cleanup state
            $this->unsetState();

            $claims = $this->decodeJWT($idToken, 1);

            // Verify the signature
            if ($this->canVerifySignatures()) {
                if (! $this->getProviderConfigValue('jwks_uri')) {
                    throw new ClientException('Unable to verify signature due to no jwks_uri being defined');
                }
                if (! $this->verifyJWTSignature($idToken)) {
                    throw new ClientException('Unable to verify signature');
                }
            } else {
                user_error('Warning: JWT signature verification unavailable.');
            }

            // If this is a valid claim
            if ($this->verifyJWTClaims($claims, $accessToken)) {

                // Clean up the session a little
                $this->unsetNonce();

                // Save the id token
                $this->idToken = $idToken;

                // Save the verified claims
                $this->verifiedClaims = $claims;

                // Save the access token
                if ($accessToken) {
                    $this->accessToken = $accessToken;
                }

                // Success!
                return true;
            }

            throw new ClientException ('Unable to verify JWT claims');
        }

        $this->requestAuthorization();

        return false;
    }

    /**
     * It calls the end-session endpoint of the OpenID Connect provider to notify the OpenID
     * Connect provider that the end-user has logged out of the relying party site
     * (the client application).
     *
     * @param  string  $accessToken  ID token (obtained at login)
     * @param  string  $redirect  URL to which the RP is requesting that the End-User's User Agent
     * be redirected after a logout has been performed. The value MUST have been previously
     * registered with the OP. Value can be null.
     *
     * @throws ClientException
     */
    public function signOut($accessToken, $redirect)
    {
        $signoutEndpoint = $this->getProviderConfigValue('end_session_endpoint');

        $signoutParams = null;
        if ($redirect === null) {
            $signoutParams = ['id_token_hint' => $accessToken];
        } else {
            $signoutParams = [
                'id_token_hint' => $accessToken,
                'post_logout_redirect_uri' => $redirect,
            ];
        }

        $signoutEndpoint .= strpos($signoutEndpoint, '?') === false ? '?' : '&';
        $signoutEndpoint .= http_build_query($signoutParams, null, '&', $this->encType);
        $this->state->setRedirect($signoutEndpoint);
    }

    /**
     * @param  array  $scope  - example: openid, given_name, etc...
     */
    public function addScope($scope)
    {
        $this->scopes = array_merge($this->scopes, (array) $scope);
    }

    /**
     * @param  array  $param  - example: prompt=login
     */
    public function addAuthParam($param)
    {
        $this->authParams = array_merge($this->authParams, (array) $param);
    }

    /**
     * @param  array  $param  - example: post_logout_redirect_uris=[http://example.com/successful-logout]
     */
    public function addRegistrationParam($param)
    {
        $this->registrationParams = array_merge($this->registrationParams, (array) $param);
    }

    /**
     * @param $jwk array - example: (array) ['kid' => ..., 'nbf' => ..., 'use' => 'sig', 'kty' => 'RSA', 'e' => '', 'n' => '']
     */
    protected function addAdditionalJwk($jwk)
    {
        $this->additionalJwks[] = $jwk;
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param  string  $param
     * @param  string  $default  optional
     *
     * @return string
     *
     * @throws ClientException
     */
    protected function getProviderConfigValue($param, $default = null)
    {

        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto 'discovery'
        if (! isset($this->providerConfig[$param])) {
            $this->providerConfig[$param] = $this->getWellKnownConfigValue($param, $default);
        }

        return $this->providerConfig[$param];
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param  string  $param
     * @param  string  $default  optional
     *
     * @return string|array
     *
     * @throws ClientException
     */
    protected function getWellKnownConfigValue($param, $default = null)
    {

        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto 'discovery'
        if (! $this->wellKnown) {
            $wellKnownConfigUrl = rtrim($this->getProviderURL(), '/').'/.well-known/openid-configuration';
            $this->wellKnown = json_decode($this->fetchURL($wellKnownConfigUrl), true);
        }

        $value = false;
        if (isset($this->wellKnown[$param])) {
            $value = $this->wellKnown[$param];
        }

        if ($value) {
            return $value;
        }

        if (isset($default)) {
            // Uses default value if provided
            return $default;
        }

        throw new ClientException('The provider ' . $param . ' could not be fetched. Make sure your provider has a well known configuration available.');
    }

    /**
     * @param  string  $url  Sets redirect URL for auth flow
     */
    public function setRedirectURL($url)
    {
        if (parse_url($url, PHP_URL_HOST) !== false) {
            $this->redirectURL = $url;
        }
    }

    /**
     * Gets the URL of the current page we are on, encodes, and returns it
     *
     * @return string
     * @throws ClientException
     */
    public function getRedirectURL()
    {
        // If the redirect URL has been set then return it.
        if (property_exists($this, 'redirectURL') && $this->redirectURL) {
            return $this->redirectURL;
        }

        // Other-wise return the URL of the current page
        throw new ClientException('Invalid redirect URL');
    }

    /**
     * Used for arbitrary value generation for nonces and state
     *
     * @return string
     */
    protected function generateRandString()
    {
        return md5(uniqid(rand(), true));
    }

    /**
     * Start Here
     *
     * @return void
     * @throws ClientException
     */
    protected function requestAuthorization()
    {

        $authEndpoint = $this->getProviderConfigValue('authorization_endpoint');
        $responseType = 'code';

        // Generate and store a nonce in the session
        // The nonce is an arbitrary value
        $nonce = $this->setNonce($this->generateRandString());

        // State essentially acts as a session key for OIDC
        $state = $this->setState($this->generateRandString());

        $authParams = array_merge($this->authParams, [
            'response_type' => $responseType,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'nonce' => $nonce,
            'state' => $state,
            'scope' => 'openid',
        ]);

        // If the client has been registered with additional scopes
        if (count($this->scopes) > 0) {
            $authParams = array_merge($authParams, ['scope' => implode(' ', $this->scopes)]);
        }

        // If the client has been registered with additional response types
        if (count($this->responseTypes) > 0) {
            $authParams = array_merge($authParams, ['response_type' => implode(' ', $this->responseTypes)]);
        }

        $authEndpoint .= strpos($authEndpoint, '?') === false ? '?' : '&';
        $authEndpoint .= http_build_query($authParams, null, '&', $this->encType);

        $this->state->setRedirect($authEndpoint);
    }

    /**
     * Requests a client credentials token
     *
     * @throws ClientException
     */
    public function requestClientCredentialsToken()
    {
        $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');

        $headers = [];

        $grantType = 'client_credentials';

        $postData= [
            'grant_type' => $grantType,
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret,
            'scope' => implode(' ', $this->scopes),
        ];

        // Convert token params to string format
        $postParams = http_build_query($postData, null, '&', $this->encType);

        return json_decode($this->fetchURL($tokenEndpoint, $postParams, $headers), true);
    }

    /**
     * Requests a resource owner token
     * (Defined in https://tools.ietf.org/html/rfc6749#section-4.3)
     *
     * @param  boolean  $clientAuth  Indicates that the Client ID and Secret be used for client authentication
     *
     * @return mixed
     * @throws ClientException
     */
    public function requestResourceOwnerToken($clientAuth = false)
    {
        $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');

        $headers = [];

        $grantType = 'password';

        $postData = [
            'grant_type' => $grantType,
            'username' => $this->authParams['username'],
            'password' => $this->authParams['password'],
            'scope' => implode(' ', $this->scopes),
        ];

        //For client authentication include the client values
        if ($clientAuth) {
            $postData['client_id'] = $this->clientID;
            $postData['client_secret'] = $this->clientSecret;
        }

        // Convert token params to string format
        $postParams = http_build_query($postData, null, '&', $this->encType);

        return json_decode($this->fetchURL($tokenEndpoint, $postParams, $headers), true);
    }

    /**
     * Requests ID and Access tokens
     *
     * @param  string  $code
     *
     * @return mixed
     * @throws ClientException
     */
    protected function requestTokens($code)
    {
        $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');
        $tokenEndpointAuthMethodsSupported = $this->getProviderConfigValue(
            'token_endpoint_auth_methods_supported',
            ['client_secret_basic']
        );

        $headers = [];

        $grantType = 'authorization_code';

        $tokenParams = [
            'grant_type' => $grantType,
            'code' => $code,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id'  => $this->clientID,
            'client_secret' => $this->clientSecret,
        ];

        # Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $tokenEndpointAuthMethodsSupported, true)) {
            $headers = ['Authorization: Basic '.base64_encode($this->clientID.':'.$this->clientSecret)];
            unset($tokenParams['client_secret']);
        }

        // Convert token params to string format
        $tokenParams = http_build_query($tokenParams, null, '&', $this->encType);

        return json_decode($this->fetchURL($tokenEndpoint, $tokenParams, $headers), true);
    }

    /**
     * Requests Access token with refresh token
     *
     * @param  string  $refresh_token
     *
     * @return mixed
     * @throws ClientException
     */
    public function refreshToken($refresh_token)
    {
        $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');

        $grantType = 'refresh_token';

        $tokenParams = [
            'grant_type' => $grantType,
            'refresh_token' => $refresh_token,
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret,
        ];

        // Convert token params to string format
        $tokenParams = http_build_query($tokenParams, null, '&', $this->encType);

        $json = json_decode($this->fetchURL($tokenEndpoint, $tokenParams), true);

        if (isset($json['access_token'])) {
            $this->accessToken = $json['access_token'];
        }

        if (isset($json['refresh_token'])) {
            $this->refreshToken = $json['refresh_token'];
        }

        return $json;
    }

    /**
     * @param  array  $keys
     * @param  array  $header
     *
     * @return array
     * @throws ClientException
     */
    protected function getKeyForHeader($keys, $header)
    {
        $key = $this->eachKeyForHeader($keys, $header);
        if (isset($key)) {
            return $key;
        }
        if ($this->additionalJwks) {
            $key = $this->eachKeyForHeader($this->additionalJwks, $header);
            if (isset($key)) {
                return $key;
            }
        }
        if (isset($header['kid'])) {
            throw new ClientException('Unable to find a key for (algorithm, kid):' . $header['alg'] . ', ' . $header['kid'] . ')');
        }

        throw new ClientException('Unable to find a key for RSA');
    }

    protected function eachKeyForHeader($keys, $header)
    {
        foreach ($keys as $key) {
            if ($key['kty'] === 'RSA') {
                if (! isset($header['kid']) || $key['kid'] === $header['kid']) {
                    return $key;
                }
            } else {
                if (isset($key['alg']) && $key['alg'] === $header['alg'] && $key['kid'] === $header['kid']) {
                    return $key;
                }
            }
        }

        return null;
    }

    /**
     * @param  string  $hashType
     * @param  array  $key
     * @param $payload
     * @param $signature
     * @param $signatureType
     *
     * @return bool
     * @throws ClientException
     */
    protected function verifyRSAJWTSignature($hashType, $key, $payload, $signature, $signatureType)
    {
        if (! class_exists('\phpseclib\Crypt\RSA') && ! class_exists('Crypt_RSA')) {
            throw new ClientException('Crypt_RSA support unavailable.');
        }
        if (! (array_key_exists('n', $key) && array_key_exists('e', $key))) {
            throw new ClientException('Malformed key object');
        }

        /* We already have base64url-encoded data, so re-encode it as
           regular base64 and use the XML key format for simplicity.
        */
        $publicKeyXml = '<RSAKeyValue><Modulus>' . $this->b64url2b64($key['n']) . '</Modulus><Exponent>' . $this->b64url2b64($key['e']) . '</Exponent></RSAKeyValue>';
        if (class_exists('Crypt_RSA', false)) {
            $rsa = new Crypt_RSA();
            $rsa->setHash($hashType);
            if ($signatureType === 'PSS') {
                $rsa->setMGFHash($hashType);
            }
            $rsa->loadKey($publicKeyXml, Crypt_RSA::PUBLIC_FORMAT_XML);
            $rsa->signatureMode = $signatureType === 'PSS' ? Crypt_RSA::SIGNATURE_PSS : Crypt_RSA::SIGNATURE_PKCS1;
        } else {
            $rsa = new \phpseclib\Crypt\RSA();
            $rsa->setHash($hashType);
            if ($signatureType === 'PSS') {
                $rsa->setMGFHash($hashType);
            }
            $rsa->loadKey($publicKeyXml, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_XML);
            $rsa->signatureMode = $signatureType === 'PSS' ? \phpseclib\Crypt\RSA::SIGNATURE_PSS : \phpseclib\Crypt\RSA::SIGNATURE_PKCS1;
        }

        return $rsa->verify($payload, $signature);
    }

    /**
     * @param  string  $hashType
     * @param  array  $key
     * @param $payload
     * @param $signature
     *
     * @return bool
     * @throws ClientException
     */
    protected function verifyHMACJWTSignature($hashType, $key, $payload, $signature)
    {
        if (! function_exists('hash_hmac')) {
            throw new ClientException('hash_hmac support unavailable.');
        }

        $expected = hash_hmac($hashType, $payload, $key, true);

        if (function_exists('hash_equals')) {
            return hash_equals($signature, $expected);
        }

        return self::hashEquals($signature, $expected);
    }

    /**
     * @param  string  $jwt  encoded JWT
     *
     * @return bool
     * @throws ClientException
     */
    public function verifyJWTSignature($jwt)
    {
        if (! is_string($jwt)) {
            throw new ClientException('Error token is not a string');
        }
        $parts = explode('.', $jwt);
        if (! isset($parts[0])) {
            throw new ClientException('Error missing part 0 in token');
        }
        $signature = $this->base64urlDecode(array_pop($parts));
        if (false === $signature || '' === $signature) {
            throw new ClientException('Error decoding signature from token');
        }
        $header = json_decode($this->base64urlDecode($parts[0]), true);
        if (! is_array($header)) {
            throw new ClientException('Error decoding JSON from token header');
        }
        $payload = implode('.', $parts);
        $jwks = json_decode($this->fetchURL($this->getProviderConfigValue('jwks_uri')), true);
        if ($jwks === null) {
            throw new ClientException('Error decoding JSON from jwks_uri');
        }
        if (! isset($header['alg'])) {
            throw new ClientException('Error missing signature type in token header');
        }
        switch ($header['alg']) {
            case 'RS256':
            case 'PS256':
            case 'RS384':
            case 'RS512':
                $hashtype = 'sha' . substr($header['alg'], 2);
                $signatureType = $header['alg'] === 'PS256' ? 'PSS' : '';

                $verified = $this->verifyRSAJWTSignature(
                    $hashtype,
                    $this->getKeyForHeader($jwks['keys'], $header),
                    $payload,
                    $signature,
                    $signatureType
                );
                break;
            case 'HS256':
            case 'HS512':
            case 'HS384':
                $hashtype = 'SHA'.substr($header['alg'], 2);
                $verified = $this->verifyHMACJWTSignature($hashtype, $this->getClientSecret(), $payload, $signature);
                break;
            default:
                throw new ClientException('No support for signature type: '.$header['alg']);
        }

        return $verified;
    }

    /**
     * @param  array  $claims
     * @param  string|null  $accessToken
     *
     * @return bool
     * @throws ClientException
     */
    protected function verifyJWTClaims($claims, $accessToken = null)
    {
        if (isset($claims['at_hash']) && isset($accessToken)) {
            $accessTokenHeader = $this->getAccessTokenHeader();
            if (isset($accessTokenHeader['alg']) && $accessTokenHeader['alg'] !== 'none') {
                $bit = substr($accessTokenHeader['alg'], 2, 3);
            } else {
                $bit = '256';
            }
            $len = ((int) $bit) / 16;
            $expecteAtHash = $this->urlEncode(substr(hash('sha' . $bit, $accessToken, true), 0, $len));
        }

        return (($this->issuerValidator->__invoke($claims['iss']))
            && (($claims['aud'] === $this->clientID) || in_array($this->clientID, $claims['aud'], true))
            && ($claims['nonce'] === $this->getNonce())
            && (! isset($claims['exp']) || ((gettype($claims['exp']) === 'integer') && ($claims['exp'] >= time() - $this->leeway)))
            && (! isset($claims['nbf']) || ((gettype($claims['nbf']) === 'integer') && ($claims['nbf'] <= time() + $this->leeway)))
            && (! isset($claims['at_hash']) || $claims['at_hash'] === $expecteAtHash));
    }

    /**
     * @param  string  $str
     *
     * @return string
     */
    protected function urlEncode($str)
    {
        $enc = base64_encode($str);
        $enc = rtrim($enc, '=');
        $enc = strtr($enc, '+/', '-_');

        return $enc;
    }

    /**
     * @param  string  $jwt  encoded JWT
     * @param  int  $section  the section we would like to decode
     *
     * @return array
     */
    protected function decodeJWT($jwt, $section = 0)
    {
        $parts = explode('.', $jwt);

        return json_decode($this->base64urlDecode($parts[$section]), true);
    }

    /**
     *
     * @param  string  $attribute  optional
     *
     * Attribute        Type    Description
     * user_id            string    REQUIRED Identifier for the End-User at the Issuer.
     * name            string    End-User's full name in displayable form including all name parts, ordered according to End-User's locale and preferences.
     * given_name        string    Given name or first name of the End-User.
     * family_name        string    Surname or last name of the End-User.
     * middle_name        string    Middle name of the End-User.
     * nickname        string    Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
     * profile            string    URL of End-User's profile page.
     * picture            string    URL of the End-User's profile picture.
     * website            string    URL of End-User's web page or blog.
     * email            string    The End-User's preferred e-mail address.
     * verified        boolean    True if the End-User's e-mail address has been verified; otherwise false.
     * gender            string    The End-User's gender: Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
     * birthday        string    The End-User's birthday, represented as a date string in MM/DD/YYYY format. The year MAY be 0000, indicating that it is omitted.
     * zoneinfo        string    String from zoneinfo [zoneinfo] time zone database. For example, Europe/Paris or America/Los_Angeles.
     * locale            string    The End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Implementations MAY choose to accept this locale syntax as well.
     * phone_number    string    The End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim. For example, +1 (425) 555-1212 or +56 (2) 687 2400.
     * address            JSON object    The End-User's preferred address. The value of the address member is a JSON [RFC4627] structure containing some or all of the members defined in Section 2.4.2.1.
     * updated_time    string    Time the End-User's information was last updated, represented as a RFC 3339 [RFC3339] datetime. For example, 2011-01-03T23:58:42+0000.
     *
     * @return mixed
     *
     * @throws ClientException
     */
    public function requestUserInfo($attribute = null)
    {

        $userInfoEndpoint = $this->getProviderConfigValue('userinfo_endpoint');
        $schema = 'openid';

        $userInfoEndpoint .= '?schema=' . $schema;

        //The accessToken has to be sent in the Authorization header.
        // Accept json to indicate response type
        $headers = [
            'Authorization: Bearer ' . $this->accessToken,
            'Accept: application/json',
        ];

        $userJson = json_decode($this->fetchURL($userInfoEndpoint, null, $headers), true);

        $this->userInfo = $userJson;

        if ($attribute === null) {
            return $this->userInfo;
        }

        if (array_key_exists($attribute, $this->userInfo)) {
            return $this->userInfo[$attribute];
        }

        return null;
    }

    /**
     *
     * @param  string  $attribute  optional
     *
     * Attribute        Type    Description
     * exp            int    Expires at
     * nbf            int    Not before
     * ver        string    Version
     * iss        string    Issuer
     * sub        string    Subject
     * aud        string    Audience
     * nonce            string    nonce
     * iat            int    Issued At
     * auth_time            int    Authenatication time
     * oid            string    Object id
     *
     * @return mixed
     *
     */
    public function getVerifiedClaims($attribute = null)
    {
        if ($attribute === null) {
            return $this->verifiedClaims;
        }

        if (array_key_exists($attribute, $this->verifiedClaims)) {
            return $this->verifiedClaims[$attribute];
        }

        return null;
    }

    /**
     * @param  string  $url
     * @param  string | null  $postBody  string If this is set the post type will be POST
     * @param  array  $headers  Extra headers to be send with the request. Format as 'NameHeader: ValueHeader'
     * @param  string  $method
     *
     * @return mixed
     * @throws ClientException
     */
    protected function fetchURL($url, $postBody = null, $headers = [], $method = '')
    {
        // OK cool - then let's create a new cURL resource handle
        $ch = curl_init();
        
        // Determine whether this is a method
        if ($postBody !== null) {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, empty($method) ? 'POST' : $method);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);

            // Default content type is form encoded
            $content_type = 'application/x-www-form-urlencoded';

            // Determine if this is a JSON payload and add the appropriate content type
            if (is_array(json_decode($postBody, true))) {
                $content_type = 'application/json';
            }

            // Add POST-specific headers
            $headers[] = 'Content-Type: ' . $content_type;
            $headers[] = 'Content-Length: ' . strlen($postBody);
        } else if (! empty($method)) {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        }

        // If we set some headers include them
        if (count($headers) > 0) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        // Set URL to download
        curl_setopt($ch, CURLOPT_URL, $url);

        if (isset($this->httpProxy)) {
            curl_setopt($ch, CURLOPT_PROXY, $this->httpProxy);
        }

        // Include header in result? (0 = yes, 1 = no)
        curl_setopt($ch, CURLOPT_HEADER, 0);

        // Allows to follow redirect
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        /**
         * Set cert
         * Otherwise ignore SSL peer verification
         */
        if (isset($this->certPath)) {
            curl_setopt($ch, CURLOPT_CAINFO, $this->certPath);
        }

        if ($this->verifyHost) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }

        if ($this->verifyPeer) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        }

        // Should cURL return or print out the data? (true = return, false = print)
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        // Timeout in seconds
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeOut);

        // Download the given URL, and return output
        $output = curl_exec($ch);

        // HTTP Response code from server may be required from subclass
        $info = curl_getinfo($ch);
        $this->responseCode = $info['http_code'];

        if ($output === false) {
            throw new ClientException('Curl error: '.curl_error($ch));
        }

        // Close the cURL resource, and free system resources
        curl_close($ch);

        return $output;
    }

    /**
     * Метод для создания запроса к SSO
     *
     * @param $url
     * @param $accessToken
     * @param null $body
     * @param string $method
     *
     * @return mixed
     * @throws ClientException
     */
    public function request($url, $accessToken, $body = null, $method = 'POST')
    {
        // Маркер доступа должен быть отправлен в заголовке авторизации, поэтому мы создаем новый массив только с этим заголовком.
        $headers = ['Authorization: Bearer ' . $accessToken];
        $schema = strpos($url, '?') ? '&schema=openid' : '?schema=openid';

        return json_decode($this->fetchURL($url . $schema, $body, $headers, $method), true);
    }

    /**
     * @param  bool  $appendSlash
     *
     * @return string
     * @throws ClientException
     */
    public function getWellKnownIssuer($appendSlash = false)
    {
        return $this->getWellKnownConfigValue('issuer') . ($appendSlash ? '/' : '');
    }

    /**
     * @return string
     * @throws ClientException
     */
    public function getIssuer()
    {
        if (! isset($this->providerConfig['issuer'])) {
            throw new ClientException('The issuer has not been set');
        }

        return $this->providerConfig['issuer'];
    }

    /**
     * @return mixed
     * @throws ClientException
     */
    public function getProviderURL()
    {
        if (! isset($this->providerConfig['providerUrl'])) {
            throw new ClientException('The provider URL has not been set');
        }

        return $this->providerConfig['providerUrl'];
    }

    /**
     * @param  string  $httpProxy
     */
    public function setHttpProxy($httpProxy)
    {
        $this->httpProxy = $httpProxy;
    }

    /**
     * @param  string  $certPath
     */
    public function setCertPath($certPath)
    {
        $this->certPath = $certPath;
    }

    /**
     * @return string|null
     */
    public function getCertPath()
    {
        return $this->certPath;
    }

    /**
     * @param  bool  $verifyPeer
     */
    public function setVerifyPeer($verifyPeer)
    {
        $this->verifyPeer = $verifyPeer;
    }

    /**
     * @param  bool  $verifyHost
     */
    public function setVerifyHost($verifyHost)
    {
        $this->verifyHost = $verifyHost;
    }

    /**
     * @return bool
     */
    public function getVerifyHost()
    {
        return $this->verifyHost;
    }

    /**
     * @return bool
     */
    public function getVerifyPeer()
    {
        return $this->verifyPeer;
    }

    /**
     * Use this for custom issuer validation
     * The given function should accept the issuer string from the JWT claim as the only argument
     * and return true if the issuer is valid, otherwise return false
     *
     * @param  callable  $issuerValidator
     */
    public function setIssuerValidator($issuerValidator)
    {
        $this->issuerValidator = $issuerValidator;
    }

    /**
     * @param  bool  $allowImplicitFlow
     */
    public function setAllowImplicitFlow($allowImplicitFlow)
    {
        $this->allowImplicitFlow = $allowImplicitFlow;
    }

    /**
     * @return bool
     */
    public function getAllowImplicitFlow()
    {
        return $this->allowImplicitFlow;
    }

    /**
     *
     * Use this to alter a provider's endpoints and other attributes
     *
     * @param  array  $array
     *        simple key => value
     */
    public function providerConfigParam($array)
    {
        $this->providerConfig = array_merge($this->providerConfig, $array);
    }

    /**
     * @param  string  $clientSecret
     */
    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @param  string  $clientID
     */
    public function setClientID($clientID)
    {
        $this->clientID = $clientID;
    }

    /**
     * Dynamic registration
     *
     * @throws ClientException
     */
    public function register()
    {
        $registrationEndpoint = $this->getProviderConfigValue('registration_endpoint');

        $sendObject = array_merge($this->registrationParams, [
            'redirect_uris' => [$this->getRedirectURL()],
            'client_name' => $this->getClientName(),
        ]);

        $response = $this->fetchURL($registrationEndpoint, json_encode($sendObject));

        $jsonResponse = json_decode($response, true);

        // Throw some errors if we encounter them
        if ($jsonResponse === false) {
            throw new ClientException('Error registering: JSON response received from the server was invalid.');
        }

        if (isset($jsonResponse['error_description'])) {
            throw new ClientException($jsonResponse['error_description']);
        }

        $this->setClientID($jsonResponse['client_id']);

        // The OpenID Connect Dynamic registration protocol makes the client secret optional
        // and provides a registration access token and URI endpoint if it is not present
        if (isset($jsonResponse['client_secret'])) {
            $this->setClientSecret($jsonResponse['client_secret']);
        } else {
            throw new ClientException('Error registering: Please contact the OpenID Connect provider and obtain a Client ID and Secret directly from them');
        }
    }

    /**
     * Introspect a given token - either access token or refresh token.
     *
     * @see https://tools.ietf.org/html/rfc7662
     *
     * @param  string  $token
     * @param  string  $tokenTypeHint
     * @param  string|null  $clientId
     * @param  string|null  $clientSecret
     *
     * @return mixed
     * @throws ClientException
     */
    public function introspectToken($token, $tokenTypeHint = '', $clientId = null, $clientSecret = null)
    {
        $introspectionEndpoint = $this->getProviderConfigValue('introspection_endpoint');
        return $this->fetchToken($introspectionEndpoint, $token, $tokenTypeHint, $clientId, $clientSecret);
    }

    /**
     * Revoke a given token - either access token or refresh token.
     *
     * @see https://tools.ietf.org/html/rfc7009
     *
     * @param  string  $token
     * @param  string  $tokenTypeHint
     * @param  string|null  $clientId
     * @param  string|null  $clientSecret
     *
     * @return mixed
     * @throws ClientException
     */
    public function revokeToken($token, $tokenTypeHint = '', $clientId = null, $clientSecret = null)
    {
        $revocationEndpoint = $this->getProviderConfigValue('revocation_endpoint');
        return $this->fetchToken($revocationEndpoint, $token, $tokenTypeHint, $clientId, $clientSecret);
    }

    protected function fetchToken($endpoint, $token, $tokenTypeHint, $clientId, $clientSecret)
    {
        $postData = [
            'token' => $token,
        ];
        if ($tokenTypeHint) {
            $postData['token_type_hint'] = $tokenTypeHint;
        }
        $clientId = $clientId !== null ? $clientId : $this->clientID;
        $clientSecret = $clientSecret !== null ? $clientSecret : $this->clientSecret;

        // Convert token params to string format
        $postParams = http_build_query($postData, null, '&');
        $headers = [
            'Authorization: Basic ' . base64_encode($clientId . ':' . $clientSecret),
            'Accept: application/json',
        ];

        return json_decode($this->fetchURL($endpoint, $postParams, $headers), true);
    }

    /**
     * @return string
     */
    public function getClientName()
    {
        return $this->clientName;
    }

    /**
     * @param  string  $clientName
     */
    public function setClientName($clientName)
    {
        $this->clientName = $clientName;
    }

    /**
     * @return string
     */
    public function getClientID()
    {
        return $this->clientID;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @return bool
     */
    public function canVerifySignatures()
    {
        return class_exists('\phpseclib\Crypt\RSA') || class_exists('Crypt_RSA');
    }

    /**
     * Set the access token.
     *
     * May be required for subclasses of this Client.
     *
     * @param  string  $accessToken
     *
     * @return void
     */
    public function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * @return array
     */
    public function getAccessTokenHeader()
    {
        return $this->decodeJWT($this->accessToken);
    }

    /**
     * @return array
     */
    public function getAccessTokenPayload()
    {
        return $this->decodeJWT($this->accessToken, 1);
    }

    /**
     * @return array
     */
    public function getIdTokenHeader()
    {
        return $this->decodeJWT($this->idToken);
    }

    /**
     * @return array
     */
    public function getIdTokenPayload()
    {
        return $this->decodeJWT($this->idToken, 1);
    }

    /**
     * @return string
     */
    public function getTokenResponse()
    {
        return $this->tokenResponse;
    }

    /**
     * Stores nonce
     *
     * @param  string  $nonce
     *
     * @return string
     */
    protected function setNonce($nonce)
    {
        $this->state->setSessionKey('openid_connect_nonce', $nonce);

        return $nonce;
    }

    /**
     * Get stored nonce
     *
     * @return string
     */
    protected function getNonce()
    {
        return $this->state->getSessionKey('openid_connect_nonce');
    }

    /**
     * Cleanup nonce
     *
     * @return void
     */
    protected function unsetNonce()
    {
        $this->state->unsetSessionKey('openid_connect_nonce');
    }

    /**
     * Stores $state
     *
     * @param  string  $state
     *
     * @return string
     */
    protected function setState($state)
    {
        $this->state->setSessionKey('openid_connect_state', $state);

        return $state;
    }

    /**
     * Get stored state
     *
     * @return string
     */
    protected function getState()
    {
        return $this->state->getSessionKey('openid_connect_state');
    }

    /**
     * Cleanup state
     *
     * @return void
     */
    protected function unsetState()
    {
        $this->state->unsetSessionKey('openid_connect_state');
    }

    /**
     * Get the response code from last action/curl request.
     *
     * @return int
     */
    public function getResponseCode()
    {
        return $this->responseCode;
    }

    /**
     * Set timeout (seconds)
     *
     * @param  int  $timeout
     */
    public function setTimeout($timeout)
    {
        $this->timeOut = $timeout;
    }

    /**
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeOut;
    }

    /**
     * Safely calculate length of binary string
     *
     * @param  string  $str
     *
     * @return int
     */
    protected static function safeLength($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }

        return strlen($str);
    }

    /**
     * Where has_equals is not available, this provides a timing-attack safe string comparison
     *
     * @param  string  $str1
     * @param  string  $str2
     *
     * @return bool
     */
    protected static function hashEquals($str1, $str2)
    {
        $len1 = static::safeLength($str1);
        $len2 = static::safeLength($str2);

        //compare strings without any early abort...
        $len = min($len1, $len2);
        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= (ord($str1[$i]) ^ ord($str2[$i]));
        }
        //if strings were different lengths, we fail
        $status |= ($len1 ^ $len2);

        return ($status === 0);
    }

    public function setUrlEncoding($curEncoding)
    {
        switch ($curEncoding) {
            case PHP_QUERY_RFC1738:
                $this->encType = PHP_QUERY_RFC1738;
                break;

            case PHP_QUERY_RFC3986:
                $this->encType = PHP_QUERY_RFC3986;
                break;

            default:
                break;
        }
    }

    /**
     * A wrapper around base64_decode which decodes Base64URL-encoded data,
     * which is not the same alphabet as base64.
     *
     * @param  string  $base64url
     *
     * @return bool|string
     */
    function base64urlDecode($base64url)
    {
        return base64_decode($this->b64url2b64($base64url));
    }

    /**
     * Per RFC4648, 'base64 encoding with URL-safe and filename-safe
     * alphabet'.  This just replaces characters 62 and 63.  None of the
     * reference implementations seem to restore the padding if necessary,
     * but we'll do it anyway.
     *
     * @param  string  $base64url
     *
     * @return string
     */
    function b64url2b64($base64url)
    {
        // 'Shouldn't' be necessary, but why not
        $padding = strlen($base64url) % 4;
        if ($padding > 0) {
            $base64url .= str_repeat('=', 4 - $padding);
        }

        return strtr($base64url, '-_', '+/');
    }
}
