<?php

/**
 * LDAP authentication source configuration parser.
 *
 * See the ldap-entry in config-templates/authsources.php for information about
 * configuration of these options.
 *
 * @package SimpleSAMLphp
 */

declare(strict_types=1);

namespace SimpleSAML\Module\ldap;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;

class ConfigHelper
{
    /**
     * String with the location of this configuration.
     * Used for error reporting.
     */
    protected string $location;

    /**
     * The hostname of the LDAP server.
     */
    protected string $hostname;

    /**
     * Whether we should use TLS/SSL when contacting the LDAP server.
     */
    protected bool $enableTLS;

    /**
     * Whether debug output is enabled.
     *
     * @var bool
     */
    protected bool $debug;

    /**
     * The timeout for accessing the LDAP server.
     *
     * @var int
     */
    protected int $timeout;

    /**
     * The port used when accessing the LDAP server.
     *
     * @var int
     */
    protected int $port;

    /**
     * Whether to follow referrals
     */
    protected bool $referrals;

    /**
     * Whether we need to search for the users DN.
     */
    protected bool $searchEnable;

    /**
     * The username we should bind with before we can search for the user.
     */
    protected ?string $searchUsername;

    /**
     * The password we should bind with before we can search for the user.
     */
    protected string $searchPassword;

    /**
     * Array with the base DN(s) for the search.
     */
    protected array $searchBase;

    /**
     * The scope of the search.
     */
    protected string $searchScope;

    /**
     * Additional LDAP filter fields for the search
     */
    protected ?string $searchFilter;

    /**
     * The attributes which should match the username.
     */
    protected array $searchAttributes;

    /**
     * The DN pattern we should use to create the DN from the username.
     */
    protected string $dnPattern;

    /**
     * The attributes we should fetch. Can be NULL in which case we will fetch all attributes.
     */
    protected ?array $attributes;

    /**
     * The attributes that are marked binary in the LDAP-schema. They will be base64 encoded.
     */
    protected array $binaryAttributes;

    /**
     * The user cannot get all attributes, privileged reader required
     */
    protected bool $privRead;

    /**
     * The DN we should bind with before we can get the attributes.
     */
    protected string $privUsername;

    /**
     * The password we should bind with before we can get the attributes.
     */
    protected string $privPassword;


    /**
     * Constructor for this configuration parser.
     *
     * @param array $config  Configuration.
     * @param string $location  The location of this configuration. Used for error reporting.
     */
    public function __construct(array $config, string $location)
    {
        $this->location = $location;

        // Parse configuration
        $config = Configuration::loadFromArray($config, $location);

        $this->hostname = $config->getString('hostname');
        $this->enableTLS = $config->getBoolean('enable_tls', false);
        $this->debug = $config->getBoolean('debug', false);
        $this->timeout = $config->getInteger('timeout', 0);
        $this->port = $config->getInteger('port', 389);
        $this->referrals = $config->getBoolean('referrals', true);
        $this->searchEnable = $config->getBoolean('search.enable', false);
        $this->privRead = $config->getBoolean('priv.read', false);

        if ($this->searchEnable) {
            $this->searchUsername = $config->getString('search.username', null);
            if ($this->searchUsername !== null) {
                $this->searchPassword = $config->getString('search.password');
            }

            $this->searchBase = $config->getArrayizeString('search.base');
            $this->searchScope = $config->getString('search.scope', 'subtree');
            $this->searchFilter = $config->getString('search.filter', null);
            $this->searchAttributes = $config->getArray('search.attributes');
        } else {
            $this->dnPattern = $config->getString('dnpattern');
        }

        // Are privs needed to get to the attributes?
        if ($this->privRead) {
            $this->privUsername = $config->getString('priv.username');
            $this->privPassword = $config->getString('priv.password');
        }

        $this->attributes = $config->getArray('attributes', null);
        $this->binaryAttributes = $config->getArray('attributes.binary', []);
    }


    /**
     * Attempt to log in using the given username and password.
     *
     * Will throw a \SimpleSAML\Error\Error('WRONGUSERPASS') if the username or password is wrong.
     * If there is a configuration problem, an Exception will be thrown.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @param array $sasl_args  Array of SASL options for LDAP bind.
     * @return array  Associative array with the users attributes.
     */
    public function login(string $username, string $password, array $sasl_args = null): array
    {
        if (empty($password)) {
            Logger::info($this->location . ': Login with empty password disallowed.');
            throw new Error\Error('WRONGUSERPASS');
        }

        $ldap = new Auth\Ldap(
            $this->hostname,
            $this->enableTLS,
            $this->debug,
            $this->timeout,
            $this->port,
            $this->referrals
        );

        if (!$this->searchEnable) {
            $ldapusername = addcslashes($username, ',+"\\<>;*');
            $dn = str_replace('%username%', $ldapusername, $this->dnPattern);
        } else {
            if ($this->searchUsername !== null) {
                if (!$ldap->bind($this->searchUsername, $this->searchPassword)) {
                    throw new Exception('Error authenticating using search username & password.');
                }
            }

            $dn = $ldap->searchfordn(
                $this->searchBase,
                $this->searchAttributes,
                $username,
                true,
                $this->searchFilter,
                $this->searchScope
            );

            if ($dn === null) {
                /* User not found with search. */
                Logger::info($this->location . ': Unable to find users DN. username=\'' . $username . '\'');
                throw new Error\Error('WRONGUSERPASS');
            }
        }

        if (!$ldap->bind($dn, $password, $sasl_args)) {
            Logger::info($this->location . ': ' . $username . ' failed to authenticate. DN=' . $dn);
            throw new Error\Error('WRONGUSERPASS');
        }

        // In case of SASL bind, authenticated and authorized DN may differ
        if (isset($sasl_args)) {
            foreach ($this->searchBase as $base) {
                try {
                    $dn = $ldap->whoami($base, $this->searchAttributes);
                } catch (Exception $e) {
                    continue;
                }
            }
        }

        // Are privs needed to get the attributes?
        if ($this->privRead) {
            // Yes, rebind with privs
            if (!$ldap->bind($this->privUsername, $this->privPassword)) {
                throw new Exception('Error authenticating using privileged DN & password.');
            }
        }

        return $ldap->getAttributes($dn, $this->attributes, $this->binaryAttributes);
    }


    /**
     * Search for a DN.
     *
     * @param string|array|null $attribute
     * The attribute name(s) searched for. If set to NULL, values from
     * configuration is used.
     * @param string $value
     * The attribute value searched for.
     * @param bool $allowZeroHits
     * Determines if the method will throw an exception if no
     * hits are found. Defaults to FALSE.
     * @return string|null
     * The DN of the matching element, if found. If no element was
     * found and $allowZeroHits is set to FALSE, an exception will
     * be thrown; otherwise NULL will be returned.
     * @throws \SimpleSAML\Error\AuthSource if:
     * - LDAP search encounter some problems when searching cataloge
     * - Not able to connect to LDAP server
     * @throws \SimpleSAML\Error\UserNotFound if:
     * - $allowZeroHits is FALSE and no result is found
     *
     */
    public function searchfordn($attribute, string $value, bool $allowZeroHits): ?string
    {
        $ldap = new Auth\Ldap(
            $this->hostname,
            $this->enableTLS,
            $this->debug,
            $this->timeout,
            $this->port,
            $this->referrals
        );

        if ($attribute === null) {
            $attribute = $this->searchAttributes;
        }

        if ($this->searchUsername !== null) {
            if (!$ldap->bind($this->searchUsername, $this->searchPassword)) {
                throw new Exception('Error authenticating using search username & password.');
            }
        }

        return $ldap->searchfordn(
            $this->searchBase,
            $attribute,
            $value,
            $allowZeroHits,
            $this->searchFilter,
            $this->searchScope
        );
    }


    /**
     * @param string $dn
     * @param array|null $attributes
     * @param array $binaryAttributes
     * @return array
     * @throws \Exception
     */
    public function getAttributes(string $dn, array $attributes = null, array $binaryAttributes = []): array
    {
        if ($attributes == null) {
            $attributes = $this->attributes;
        }

        $ldap = new Auth\Ldap(
            $this->hostname,
            $this->enableTLS,
            $this->debug,
            $this->timeout,
            $this->port,
            $this->referrals
        );

        // Are privs needed to get the attributes?
        if ($this->privRead) {
            // Yes, rebind with privs
            if (!$ldap->bind($this->privUsername, $this->privPassword)) {
                throw new Exception('Error authenticating using privileged DN & password.');
            }
        }
        return $ldap->getAttributes($dn, $attributes, $binaryAttributes);
    }
}
