<?php

namespace WannaBaPro\OpenIDConnect;

/**
 * Interface client state.
 */
interface ClientStateInterface
{
    /**
     * Set redirect to auth-service URL.
     *
     * @param string $url
     */
    public function setRedirect($url);

    /**
     * Get client session key.
     *
     * @param string $key The key name.
     *
     * @return string
     */
    public function getSessionKey($key);

    /**
     * Set client session key.
     *
     * @param string $key The key name.
     * @param string $value The key value.
     */
    public function setSessionKey($key, $value);

    /**
     * Unset client session key.
     *
     * @param string $key
     */
    public function unsetSessionKey($key);
}
