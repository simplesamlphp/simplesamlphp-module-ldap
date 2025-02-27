<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Error;

use SimpleSAML\Error\ErrorCodes;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\core\Controller\Login;


class ActiveDirectoryErrors extends ErrorCodes
{
    final public const RESETPASSWORD = 'RESETPASSWORD';
    final public const RESETACCOUNT = 'RESETACCOUNT';
    final public const LOGONRESTRICTION = 'LOGONRESTRICTION';

    public function __construct()
    {
        // Automatically register instances of subclasses with Login to allow
        // custom ErrorCodes to work in a redirect environment
        Login::registerErrorCodeClass($this);
    }

    public function getCustomTitles(): array
    {
        return [
            self::RESETPASSWORD => Translate::noop('Password Reset Required'),
            self::RESETACCOUNT => Translate::noop('Account Reset Required'),
            self::LOGONRESTRICTION => Translate::noop('Logon Restriction Applied'),
        ];
    }

    public function getCustomDescriptions(): array
    {
        return [
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
        ];
    }
}