<?php

namespace WannaBaPro\OpenIDConnect;

/**
 * Default client session state.
 */
class ClientStateSession implements ClientStateInterface
{
    /**
     * Begin session.
     */
    public function __construct()
    {
        session_start();
    }

    /**
     * {@inheritDoc}
     */
    public function setRedirect($url)
    {
        session_commit();
        header('Location: ' . $url);
        exit;
    }

    /**
     * {@inheritDoc}
     */
    public function getSessionKey($key)
    {
        return $_SESSION[$key];
    }

    /**
     * {@inheritDoc}
     */
    public function setSessionKey($key, $value)
    {
        $_SESSION[$key] = $value;
    }

    /**
     * {@inheritDoc}
     */
    public function unsetSessionKey($key)
    {
        unset($_SESSION[$key]);
    }
}
