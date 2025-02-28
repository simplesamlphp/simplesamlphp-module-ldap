<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Connector;

use SimpleSAML\Module\ldap\Auth\InvalidCredentialResult;
use Symfony\Component\Ldap\Exception\InvalidCredentialsException;
use SimpleSAML\Module\ldap\Error\ActiveDirectoryErrors;



use function ldap_get_option;

/**
 * Extends Ldap so that we can diagnose error messages from MS Active Directory
 */
class ActiveDirectory extends Ldap
{
    public const ERR_PASSWORD_RESET = 'RESETPASSWORD';
    public const ERR_ACCOUNT_RESET = 'RESETACCOUNT';
    public const ERR_LOGON_RESTRICTION = 'LOGONRESTRICTION';

    public function __construct()
    {
        parent::__construct();
        // Register the custom error codes
        new ActiveDirectoryErrors();
    }


    /**
     * Resolves the bind exception
     *
     * @return string
     */
    protected function resolveBindError(InvalidCredentialsException $e): string
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
