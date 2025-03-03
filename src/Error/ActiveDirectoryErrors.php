<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Error;

use SimpleSAML\Error\ErrorCodes;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\core\Controller\Login;

class ActiveDirectoryErrors extends ErrorCodes
{
    public const RESETPASSWORD = 'RESETPASSWORD';
    public const RESETACCOUNT = 'RESETACCOUNT';
    public const LOGONRESTRICTION = 'LOGONRESTRICTION';

    public function __construct()
    {
        parent::__construct();
        Login::registerErrorCodeClass($this);
    }

    /**
     * Fetch all title translation strings for custom error codes.
     *
     * @return array A map from custom error code to error code title
     */
    public function getCustomTitles(): array
    {
        return array_merge(parent::getCustomTitles(), [
            self::RESETPASSWORD => Translate::noop('Password Reset Required'),
            self::RESETACCOUNT => Translate::noop('Account Reset Required'),
            self::LOGONRESTRICTION => Translate::noop('Logon Restriction Applied'),
        ]);
    }

    /**
     * Fetch all description translation strings for custom error codes.
     *
     * @return array A map from custom error code to error code description
     */
    public function getCustomDescriptions(): array
    {
        return array_merge(parent::getCustomDescriptions(), [
            self::RESETPASSWORD => Translate::noop(
                "Your password has expired or needs to be reset. Please follow the instructions " .
                "provided to reset your password and try again."
            ),
            self::RESETACCOUNT => Translate::noop(
                "Your account requires a full reset due to security policies or administrative action. " .
                "Please contact support or follow the reset procedure."
            ),
            self::LOGONRESTRICTION => Translate::noop(
                "Your account is currently restricted from logging in due to security measures or " .
                "policy enforcement. Please contact the administrator for assistance."
            ),
        ]);
    }
}