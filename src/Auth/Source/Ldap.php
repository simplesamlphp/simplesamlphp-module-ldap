<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Source;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Module\ldap\ConnectorFactory;
use SimpleSAML\Module\ldap\ConnectorInterface;
use Symfony\Component\Ldap\Adapter\ExtLdap\Query;
use Symfony\Component\Ldap\Entry;

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
     * @var \SimpleSAML\Module\ldap\ConnectorInterface
     */
    protected ConnectorInterface $connector;

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

        $this->connector = ConnectorFactory::fromAuthSource($this->authId);
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
        $searchScope = $this->ldapConfig->getOptionalString('search.scope', Query::SCOPE_SUB);
        Assert::oneOf($searchScope, [Query::SCOPE_BASE, Query::SCOPE_ONE, Query::SCOPE_SUB]);

        $timeout = $this->ldapConfig->getOptionalInteger('timeout', 3);
        Assert::natural($timeout);

        $searchBase = $this->ldapConfig->getArray('search.base');
        $options = [
            'scope' => $searchScope,
            'timeout' => $timeout,
        ];

        $searchEnable = $this->ldapConfig->getOptionalBoolean('search.enable', false);
        if ($searchEnable === false) {
            $dnPattern = $this->ldapConfig->getString('dnpattern');
            $dn = str_replace('%username%', $username, $dnPattern);
        } else {
            $searchUsername = $this->ldapConfig->getString('search.username');
            Assert::notWhitespaceOnly($searchUsername);

            $searchPassword = $this->ldapConfig->getOptionalString('search.password', null);
            Assert::nullOrnotWhitespaceOnly($searchPassword);

            $searchAttributes = $this->ldapConfig->getArray('search.attributes');
            $searchFilter = $this->ldapConfig->getOptionalString('search.filter', null);

            try {
                $this->connector->bind($searchUsername, $searchPassword);
            } catch (Error\Error $e) {
                throw new Error\Exception("Unable to bind using the configured search.username and search.password.");
            }

            $filter = $this->buildSearchFilter($username);

            try {
                /** @psalm-var \Symfony\Component\Ldap\Entry $entry */
                $entry = $this->connector->search($searchBase, $filter, $options, false);
                $dn = $entry->getDn();
            } catch (Error\Exception $e) {
                throw new Error\Error('WRONGUSERPASS');
            }
        }

        $this->connector->bind($dn, $password);

        $options['scope'] = Query::SCOPE_BASE;
        $filter = '(objectClass=*)';

        /** @psalm-var \Symfony\Component\Ldap\Entry $entry */
        $entry = $this->connector->search([$dn], $filter, $options, false);

        return $this->processAttributes($entry);
    }


    /**
     * Attempt to find a user's attributes given its username.
     *
     * @param string $username  The username who's attributes we want.
     * @return array  Associative array with the users attributes.
     */
    public function getAttributes(string $username): array
    {
        $searchUsername = $this->ldapConfig->getString('search.username');
        Assert::notWhitespaceOnly($searchUsername);

        $searchPassword = $this->ldapConfig->getOptionalString('search.password', null);
        Assert::nullOrnotWhitespaceOnly($searchPassword);

        try {
            $this->connector->bind($searchUsername, $searchPassword);
        } catch (Error\Error $e) {
            throw new Error\Exception("Unable to bind using the configured search.username and search.password.");
        }

        $searchEnable = $this->ldapConfig->getOptionalBoolean('search.enable', false);
        if ($searchEnable === false) {
            $dnPattern = $this->ldapConfig->getString('dnpattern');
            $filter = '(' . str_replace('%username%', $username, $dnPattern) . ')';
        } else {
            $filter = $this->buildSearchFilter($username);
        }

        $searchScope = $this->ldapConfig->getOptionalString('search.scope', Query::SCOPE_SUB);
        Assert::oneOf($searchScope, [Query::SCOPE_BASE, Query::SCOPE_ONE, Query::SCOPE_SUB]);

        $timeout = $this->ldapConfig->getOptionalInteger('timeout', 3);
        Assert::natural($timeout);

        $searchBase = $this->ldapConfig->getArray('search.base');
        $options = [
            'scope' => $searchScope,
            'timeout' => $timeout,
        ];

        try {
            /** @psalm-var \Symfony\Component\Ldap\Entry $entry */
            $entry = $this->connector->search($searchBase, $filter, $options, false);
        } catch (Error\Exception $e) {
            throw new Error\Error('WRONGUSERPASS');
        }

        return $this->processAttributes($entry);
    }


    /**
     * @param \Symfony\Component\Ldap\Entry $entry
     * @return array
     */
    private function processAttributes(Entry $entry): array
    {
        $attributes = $this->ldapConfig->getOptionalValue('attributes', []);
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
            $this->ldapConfig->getOptionalArray('attributes.binary', []),
        );
        foreach ($binaries as $binary) {
            $result[$binary] = array_map('base64_encode', $result[$binary]);
        }

        return $result;
    }


    /**
     * @param string $username
     * @return string
     */
    private function buildSearchFilter(string $username): string
    {
        $searchAttributes = $this->ldapConfig->getArray('search.attributes');
        /** @psalm-var string|null $searchFilter */
        $searchFilter = $this->ldapConfig->getOptionalString('search.filter', null);

        $filter = '';
        foreach ($searchAttributes as $attr) {
            $filter .= '(' . $attr . '=' . $username . ')';
        }
        $filter = '(|' . $filter . ')';

        // Append LDAP filters if defined
        if ($searchFilter !== null) {
            $filter = "(&" . $filter . $searchFilter . ")";
        }

        return $filter;
    }
}
