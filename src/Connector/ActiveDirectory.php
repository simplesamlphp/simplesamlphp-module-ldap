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

    public const RESETPASSWORD = 'RESETPASSWORD';
    public const RESETACCOUNT = 'RESETACCOUNT';
    public const LOGONRESTRICTION = 'LOGONRESTRICTION';

    public function __construct(
        string $connection_strings,
        string $encryption = 'ssl',
        int $version = 3,
        string $extension = 'ext_ldap',
        bool $debug = false,
        array $options = ['referrals' => false, 'network_timeout' => 3],
    ) {
        parent::__construct($connection_strings, $encryption, $version, $extension, $debug, $options);

        // Register ActiveDirectoryErrors
        new ActiveDirectoryErrors();
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
