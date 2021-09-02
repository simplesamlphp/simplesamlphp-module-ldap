<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Source;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\core\Auth\UserPassBase;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Ldap as LdapObject;
use Symfony\Component\Ldap\Adapter\ExtLdap\Query;

use function array_fill_keys;
use function array_keys;
use function array_map;
use function array_pop;
use function array_values;
use function count;
use function is_array;
use function sprintf;
use function strval;
use function str_replace;
use function var_export;

/**
 * LDAP authentication source.
 *
 * See the ldap-entry in config-templates/authsources.php for information about
 * configuration of this authentication source.
 *
 * @package simplesamlphp/simplesamlphp-module-ldap
 */

class Ldap extends UserPassBase
{
    /**
     * An LDAP configuration object.
     */
    private Configuration $ldapConfig;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $this->ldapConfig = Configuration::loadFromArray(
            $config,
            'authsources[' . var_export($this->authId, true) . ']'
        );
    }


    /**
     * Attempt to log in using the given username and password.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login(string $username, string $password): array
    {
        $encryption = $this->ldapConfig->getString('encryption', 'ssl');
        Assert::oneOf($encryption, ['none', 'ssl', 'tls']);

        foreach (explode(' ', $this->ldapConfig->getString('connection_string')) as $connection_string) {
            Assert::regex($connection_string, '#^ldap[s]?:\/\/#');

            $ldap = LdapObject::create(
                $this->ldapConfig->getString('extension', 'ext_ldap'),
                [
                    'connection_string' => $connection_string,
                    'encryption' => 'ssl',
                ]
            );
        }

        $searchScope = $this->ldapConfig->getString('search.scope', Query::SCOPE_SUB);
        Assert::oneOf($searchScope, [Query::SCOPE_BASE, Query::SCOPE_ONE, Query::SCOPE_SUB]);

        $referrals = $this->ldapConfig->getValue('referrals', Query::DEREF_NEVER);
        Assert::oneOf($referrals, [Query::DEREF_ALWAYS, Query::DEREF_NEVER, Query::DEREF_FINDING, Query::DEREF_SEARCHING]);

        $timeout = $this->ldapConfig->getString('timeout', 3);
        $searchBase = $this->ldapConfig->getArray('search.base');
        $options = [
            'scope' => $searchScope,
            'timeout' => $timeout,
            'deref' => $referrals,
        ];


        $searchEnable = $this->ldapConfig->getBoolean('search.enable', false);
        if ($searchEnable === false) {
            $dnPattern = $this->ldapConfig->getString('dnpattern');
            $dn = str_replace('%username%', $username, $dnPattern);

            $filter = '';
        } else {
            $searchUsername = $this->ldapConfig->getString('search.username');
            Assert::notWhitespaceOnly($searchUsername);

            $searchPassword = $this->ldapConfig->getString('search.password', null);
            Assert::nullOrnotWhitespaceOnly($searchPassword);

            $searchAttributes = $this->ldapConfig->getArray('search.attributes');
            $searchFilter = $this->ldapConfig->getString('search.filter', null);

            try {
                $ldap->bind($searchUsername, strval($searchPassword));
            } catch (ConnectionException $e) {
                $e = Error\Exception::fromException($e);
                throw $e;
            }

            $filter = '';
            foreach ($searchAttributes as $attr) {
                $filter .= '(' . $attr . '=' . $username . ')';
            }
            $filter = '(|' . $filter . ')';

            // Append LDAP filters if defined
            if ($searchFilter !== null) {
                $filter = "(&" . $filter . "" . $searchFilter . ")";
            }

            $entry = null;
            foreach ($searchBase as $base) {
                $query = $ldap->query($base, $filter, $options);
                $result = $query->execute();
                $result = is_array($result) ? $result : $result->toArray();

                if (count($result) > 1) {
                    throw new Error\Exception(
                        sprintf(
                            "Library - LDAP search(): Found %d entries searching base '%s' for '%s'",
                            count($result),
                            $base,
                            $filter,
                        )
                    );
                } elseif (count($result) === 1) {
                    $entry = array_pop($result);
                    break;
                } else {
                    Logger::debug(
                        sprintf(
                            "Library - LDAP search(): Found no entries searching base '%s' for '%s'",
                            count($result),
                            $base,
                            $filter,
                        )
                    );
                }
            }

            if ($entry === null) {
                throw new Error\UserNotFound("User not found");
            }

            $dn = $entry->getDn();
        }

        try {
            $ldap->bind($dn, strval($password));
        } catch (ConnectionException $e) {
            $e = Error\Exception::fromException($e);
            throw $e;
        }

        $entry = null;
        foreach ($searchBase as $base) {
            $query = $ldap->query($base, sprintf('(distinguishedName=%s)', $dn), $options);
            $result = $query->execute();
            $result = is_array($result) ? $result : $result->toArray();

            if (count($result) > 1) {
                throw new Error\Exception(
                    sprintf(
                        "Library - LDAP search(): Found %d entries searching base '%s' for '%s'",
                        count($result),
                        $base,
                        $filter,
                    )
                );
            } elseif (count($result) === 1) {
                $entry = array_pop($result);
                break;
            } else {
                Logger::debug(
                    sprintf(
                        "Library - LDAP search(): Found no entries searching base '%s' for '%s'",
                        count($result),
                        $base,
                        $filter,
                    )
                );
            }
        }

        if ($entry === null) {
            throw new Error\UserNotFound("User not found");
        }

        $attributes = $this->ldapConfig->getArray('attributes', []);
        if ($attributes === ['*']) {
            $result = $entry->getAttributes();
        } else {
            $result = array_intersect_key(
                $entry->getAttributes(),
                array_fill_keys(array_values($attributes), null)
            );
        }

        $binaries = array_intersect(
            array_keys($result),
            $this->ldapConfig->getArray('attributes.binary', []),
        );
        foreach ($binaries as $binary) {
            $result[$binary] = array_map('base64_encode', $result[$binary]);
        }

        return $result;
    }
}
