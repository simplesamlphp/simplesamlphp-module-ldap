<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Connector;

use SimpleSAML\Module\ldap\Auth\InvalidCredentialResult;
use Symfony\Component\Ldap\Exception\InvalidCredentialsException;
use SimpleSAML\Locale\Translate;




use function ldap_get_option;

/**
 * Extends Ldap so that we can diagnose error messages from MS Active Directory
 */
class ActiveDirectory extends Ldap
{
    public const ERR_PASSWORD_RESET = 'RESETPASSWORD';
    public const ERR_ACCOUNT_RESET = 'RESETACCOUNT';
    public const ERR_LOGON_RESTRICTION = 'LOGONRESTRICTION';

    public const RESETPASSWORD = 'RESETPASSWORD';
    public const RESETACCOUNT = 'RESETACCOUNT';
    public const LOGONRESTRICTION = 'LOGONRESTRICTION';


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

    /**
     * Resolves the bind exception
     *
     * @return string
     */
    protected function resolveBindException(InvalidCredentialsException $e): string
    {
                
        ldap_get_option(
            $this->adapter->getConnection()->getResource(),
            LDAP_OPT_DIAGNOSTIC_MESSAGE,
            $message,
        );

        $result  = InvalidCredentialResult::fromDiagnosticMessage($message);
        if ($result->isInvalidCredential()) {
            return self::ERR_WRONG_PASS;
        } elseif ($result->isPasswordError()) {
            return self::ERR_PASSWORD_RESET;
        } elseif ($result->isAccountError()) {
            return self::ERR_ACCOUNT_RESET;
        } elseif ($result->isRestricted()) {
            return self::ERR_LOGON_RESTRICTION;
        }

        // default to the wrong user pass
        return self::ERR_WRONG_PASS;
    }
}
