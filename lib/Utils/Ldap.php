<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Utils;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Utils;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Ldap as LdapObject;

use function array_pop;
use function count;
use function dechex;
use function is_array;
use function ord;
use function sprintf;
use function strlen;
use function strval;
use function substr;
use function str_replace;

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
     * @param bool $debug
     * @param array $options
     * @return \Symfony\Component\Ldap\Ldap[]
     */
    public function create(
        array $connection_strings,
        string $encryption = 'ssl',
        int $version = 3,
        string $extension = 'ext_ldap',
        bool $debug = false,
        array $options = ['referrals' => false, 'network_timeout' => 3]
    ): array {
        $ldapServers = [];

        foreach ($connection_strings as $connection_string) {
            Assert::regex($connection_string, '#^ldap[s]?:\/\/#');

            $ldapServers[] = LdapObject::create(
                $extension,
                [
                    'connection_string' => $connection_string,
                    'encryption' => $encryption,
                    'version' => $version,
                    'debug' => $debug,
                    'options' => $options,
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
     * Search the LDAP-directory for a specific object
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


    /**
     * Search the LDAP-directory for any object matching the search filter
     *
     * @param \Symfony\Component\Ldap\Ldap $ldap
     * @param array $searchBase
     * @param string $filter
     * @param array $options
     * @param boolean $allowMissing
     * @return \Symfony\Component\Ldap\Entry[] The result of the search
     * @throws \SimpleSAML\Error\Exception if more than one entry was found
     * @throws \SimpleSAML\Error\Exception if the object cannot be found using the given search base and filter
     */
    public function searchForMultiple(
        LdapObject $ldap,
        array $searchBase,
        string $filter,
        array $options,
        bool $allowMissing
    ): array {
        $entry = null;

        $results = [];
        foreach ($searchBase as $base) {
            $query = $ldap->query($base, $filter, $options);
            $result = $query->execute();
            $results = array_merge($results, is_array($result) ? $result : $result->toArray());

            sprintf(
                "Library - LDAP search(): Found %d entries searching base '%s' for '%s'",
                count($result),
                $base,
                $filter,
            );
        }

        if (empty($results) && ($allowMissing === false)) {
            throw new Error\Exception(
                sprintf(
                    "No Objects found using search base [%s] and filter '%s'",
                    implode(', ', $searchBase),
                    $filter
                )
            );
        }

        return $results;
    }


    /**
     * Escapes the given VALUES according to RFC 2254 so that they can be safely used in LDAP filters.
     *
     * Any control characters with an ACII code < 32 as well as the characters with special meaning in
     * LDAP filters "*", "(", ")", and "\" (the backslash) are converted into the representation of a
     * backslash followed by two hex digits representing the hexadecimal value of the character.
     *
     * @param string|array $values Array of values to escape
     * @param bool $singleValue
     * @return string|string[] Array $values, but escaped
     */
    public function escapeFilterValue($values = [], bool $singleValue = true)
    {
        // Parameter validation
        $arrayUtils = new Utils\Arrays();
        $values = $arrayUtils->arrayize($values);

        foreach ($values as $key => $val) {
            if ($val === null) {
                $val = '\0'; // apply escaped "null" if string is empty
            } else {
                // Escaping of filter meta characters
                $val = str_replace('\\', '\5c', $val);
                $val = str_replace('*', '\2a', $val);
                $val = str_replace('(', '\28', $val);
                $val = str_replace(')', '\29', $val);

                // ASCII < 32 escaping
                $val = $this->asc2hex32($val);
            }

            $values[$key] = $val;
        }

        if ($singleValue) {
            return $values[0];
        }

        return $values;
    }


    /**
     * Converts all ASCII chars < 32 to "\HEX"
     *
     * @param string $string String to convert
     * @return string
     */
    public function asc2hex32(string $string): string
    {
        for ($i = 0; $i < strlen($string); $i++) {
            $char = substr($string, $i, 1);

            if (ord($char) < 32) {
                $hex = dechex(ord($char));
                if (strlen($hex) == 1) {
                    $hex = '0' . $hex;
                }

                $string = str_replace($char, '\\' . $hex, $string);
            }
        }

        return $string;
    }
}
