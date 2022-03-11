<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Source;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Module\ldap\Connector;
use Symfony\Component\Ldap\Adapter\ExtLdap\Query;

use function array_fill_keys;
use function array_keys;
use function array_map;
use function array_values;
use function sprintf;
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
     * @var Connector\Connector
     */
    protected Connector\Connector $connector;

    /**
     * An LDAP configuration object.
     */
    protected Configuration $ldapConfig;

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
        $timeout = $this->ldapConfig->getInteger('timeout', 3);
        Assert::positiveInteger($timeout);

        $searchScope = $this->ldapConfig->getString('search.scope', Query::SCOPE_SUB);
        Assert::oneOf($searchScope, [Query::SCOPE_BASE, Query::SCOPE_ONE, Query::SCOPE_SUB]);

        $timeout = $this->ldapConfig->getInteger('timeout', 3);
        $searchBase = $this->ldapConfig->getArray('search.base');
        $options = [
            'scope' => $searchScope,
            'timeout' => $timeout,
        ];

        $connector = $this->resolveConnector();

        $searchEnable = $this->ldapConfig->getBoolean('search.enable', false);
        if ($searchEnable === false) {
            $dnPattern = $this->ldapConfig->getString('dnpattern');
            $dn = str_replace('%username%', $username, $dnPattern);
        } else {
            $searchUsername = $this->ldapConfig->getString('search.username');
            Assert::notWhitespaceOnly($searchUsername);

            $searchPassword = $this->ldapConfig->getString('search.password', null);
            Assert::nullOrnotWhitespaceOnly($searchPassword);

            $searchAttributes = $this->ldapConfig->getArray('search.attributes');
            $searchFilter = $this->ldapConfig->getString('search.filter', null);

            try {
                $connector->bind($searchUsername, $searchPassword);
            } catch (Error\Error $e) {
                throw new Error\Exception("Unable to bind using the configured search.username and search.password.");
            }

            $filter = '';
            foreach ($searchAttributes as $attr) {
                $filter .= '(' . $attr . '=' . $username . ')';
            }
            $filter = '(|' . $filter . ')';

            // Append LDAP filters if defined
            if ($searchFilter !== null) {
                $filter = "(&" . $filter . $searchFilter . ")";
            }

            try {
                /** @psalm-var \Symfony\Component\Ldap\Entry $entry */
                $entry = $connector->search($searchBase, $filter, $options, false);
                $dn = $entry->getDn();
            } catch (Error\Exception $e) {
                throw new Error\Error('WRONGUSERPASS');
            }
        }

        $connector->bind($dn, $password);
        $filter = sprintf('(distinguishedName=%s)', $dn);

        /** @psalm-var \Symfony\Component\Ldap\Entry $entry */
        $entry = $connector->search($searchBase, $filter, $options, false);

        $attributes = $this->ldapConfig->getValue('attributes', []);
        if ($attributes === null) {
            $result = $entry->getAttributes();
        } else {
            Assert::isArray($attributes);
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

    /**
     * Resolve the connector
     *
     * @return Connector\Connector
     * @throws \Exception
     */
    protected function resolveConnector(): Connector\Connector
    {
        if ($this->connector) {
            return $this->connector;
        }

        $encryption = $this->ldapConfig->getString('encryption', 'ssl');
        Assert::oneOf($encryption, ['none', 'ssl', 'tls']);

        $version = $this->ldapConfig->getInteger('version', 3);
        Assert::positiveInteger($version);

        $class = $this->ldapConfig->getString('connector', Connector\Ldap::class);
        Assert::classExists($class);

        return $this->connector = new $class(
            $this->ldapConfig->getString('connection_string'),
            $encryption,
            $version,
            $this->ldapConfig->getString('extension', 'ext_ldap'),
            $this->ldapConfig->getBoolean('debug', false),
            $this->ldapConfig->getArray('options', []),
        );
    }
}
