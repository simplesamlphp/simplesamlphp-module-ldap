<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Utils;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Utils;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Exception\InvalidCredentialsException;
use Symfony\Component\Ldap\Ldap as LdapObject;

use function array_pop;
use function count;
use function dechex;
use function is_array;
use function is_iterable;
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
     * @param string $connection_strings
     * @param string $encryption
     * @param int $version
     * @param string $extension
     * @param bool $debug
     * @param array $options
     * @return \Symfony\Component\Ldap\Ldap
     */
    public function create(
        string $connection_strings,
        string $encryption = 'ssl',
        int $version = 3,
        string $extension = 'ext_ldap',
        bool $debug = false,
        array $options = ['referrals' => false, 'network_timeout' => 3]
    ): LdapObject {
        foreach (explode(' ', $connection_strings) as $connection_string) {
            Assert::regex($connection_string, '#^ldap[s]?:\/\/#');
        }

        Logger::debug(sprintf(
            "Setting up LDAP connection: host='%s', encryption=%s, version=%d, debug=%s, timeout=%d, referrals=%s.",
            $connection_strings,
            $encryption,
            $version,
            var_export($debug, true),
            $options['timeout'] ?? ini_get('default_socket_timeout'),
            var_export($options['referrals'] ?? false, true),
        ));

        return LdapObject::create(
            $extension,
            [
                'connection_string' => $connection_strings,
                'encryption' => $encryption,
                'version' => $version,
                'debug' => $debug,
                'options' => $options,
            ]
        );
    }


    /**
     * Bind to an LDAP-server
     *
     * @param \Symfony\Component\Ldap\Ldap $ldapObject
     * @param string $username
     * @param string|null $password  Null for passwordless logon
     * @throws \SimpleSAML\Error\Exception if none of the LDAP-servers could be contacted
     */
    public function bind(LdapObject $ldapObject, string $username, ?string $password): void
    {
        try {
            $ldapObject->bind($username, strval($password));
        } catch (InvalidCredentialsException $e) {
            throw new Error\Error('WRONGUSERPASS');
        }

        Logger::debug(sprintf("LDAP bind(): Bind successful for DN '%s'.", $username));
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
            $result = $query->execute()->toArray();

            if (count($result) > 1) {
                throw new Error\Exception(
                    sprintf(
                        "LDAP search(): Found %d entries searching base '%s' for '%s'",
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
                        "LDAP search(): Found no entries searching base '%s' for '%s'",
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
        $results = [];

        foreach ($searchBase as $base) {
            $query = $ldap->query($base, $filter, $options);
            $result = $query->execute()->toArray();
            $results = array_merge($results, $result);

            Logger::debug(sprintf(
                "Library - LDAP search(): Found %d entries searching base '%s' for '%s'",
                count($result),
                $base,
                $filter,
            ));
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
     * Any control characters with an ASCII code < 32 as well as the characters with special meaning in
     * LDAP filters "*", "(", ")", and "\" (the backslash) are converted into the representation of a
     * backslash followed by two hex digits representing the hexadecimal value of the character.
     *
     * @param string|string[] $values Array of values to escape
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
                $hex = str_pad(dechex(ord($char)), 2, '0', STR_PAD_LEFT);
                $string = str_replace($char, '\\' . $hex, $string);
            }
        }

        return $string;
    }
}
