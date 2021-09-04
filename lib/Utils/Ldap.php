<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Utils;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Ldap as LdapObject;

use function array_pop;
use function count;
use function is_array;
use function sprintf;
use function strval;

/**
 * LDAP utilities
 *
 * @package simplesamlphp/simplesamlphp-module-ldap
 */

class Ldap
{
    /**
     * Create Ldap resource objects
     *
     * @param array $connection_strings
     * @param string $encryption
     * @param int $version
     * @param string $extension
     * @return \Symfony\Component\Ldap\Ldap[]
     */
    public function create(
        array $connection_strings,
        string $encryption = 'ssl',
        int $version = 3,
        string $extension = 'ext_ldap')
    : array {
        $ldapServers = [];

        foreach ($connection_strings as $connection_string) {
            Assert::regex($connection_string, '#^ldap[s]?:\/\/#');

            $ldapServers[] = LdapObject::create(
                $extension,
                [
                    'connection_string' => $connection_string,
                    'encryption' => $encryption,
                    'version' => $version,
                ]
            );
        }

        return $ldapServers;
    }


    /**
     * Bind to an LDAP-server
     *
     * @param \Symfony\Component\Ldap\Ldap[] $ldapServers
     * @param string $username
     * @param string|null $password  Null for passwordless logon
     * @throws \SimpleSAML\Error\Exception if none of the LDAP-servers could be contacted
     */
    public function bind(array $ldapServers, string $username, ?string $password): LdapObject
    {
        foreach ($ldapServers as $ldap) {
            try {
                $ldap->bind($username, strval($password));
                return $ldap;
            } catch (ConnectionException $e) {
                // Try next server
            }
        }

        throw new Error\Exception("Unable to bind to any of the configured LDAP servers.");
    }


    /**
     * Search the LDAP-directory for a specific DN
     *
     * @param \Symfony\Component\Ldap\Ldap $ldap
     * @param array $searchBase
     * @param string $filter
     * @param array $options
     * @param boolean $allowMissing
     * @return \Symfony\Component\Ldap\Entry|null The result of the search or null if none found
     * @throws \SimpleSAML\Error\Exception if more than one entry was found
     * @throws \SimpleSAML\Error\Exception if the object cannot be found using the given search base and filter
     */
    public function search(
        LdapObject $ldap,
        array $searchBase,
        string $filter,
        array $options,
        bool $allowMissing
    ): ?Entry {
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

        if ($entry === null && $allowMissing === false) {
            throw new Error\Exception(
                sprintf(
                    "Object not found using search base [%s] and filter '%s'",
                    implode(', ', $searchBase),
                    $filter
                )
            );
        }

        return $entry;
    }
}

