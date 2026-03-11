<?php

/**
 * LDAP authentication source.
 *
 * See the ldap-entry in config-templates/authsources.php for information about
 * configuration of this authentication source.
 *
 * This class is based on www/auth/login.php.
 *
 * @package simplesamlphp/simplesamlphp-module-ldap
 */

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Source;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\core\Auth\UserPassOrgBase;

use function array_change_key_case;
use function array_key_exists;
use function strtolower;
use function var_export;

class LdapMulti extends UserPassOrgBase
{
    /**
     * The key of the OrgId field in the state, identifies which org was selected.
     */
    public const string SOURCEID = '\SimpleSAML\Module\ldap\Auth\LdapMulti.SelectedSource';


    /**
     * An LDAP configuration object.
     */
    private Configuration $ldapConfig;

    /**
     * An array with mappings for organization => authsource.
     *
     * @var array<mixed>
     */
    private array $mapping;

    /**
     * An array with descriptions for organizations.
     *
     * @var array<mixed>
     */
    private array $orgs;

    /**
     * An array of organization IDs to LDAP configuration objects.
     *
     * @var array<mixed>
     */
    private array $ldapOrgs;

    /**
     * Whether we should include the organization as part of the username.
     */
    private bool $includeOrgInUsername;


    /**
     * Constructor for this authentication source.
     *
     * @param array<mixed> $info  Information about this authentication source.
     * @param array<mixed> $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $this->ldapConfig = Configuration::loadFromArray(
            $config,
            'authsources[' . var_export($this->authId, true) . ']',
        );

        $usernameOrgMethod = $this->ldapConfig->getValueValidate(
            'username_organization_method',
            ['none', 'allow', 'force'],
        );
        $this->setUsernameOrgMethod($usernameOrgMethod);

        $this->includeOrgInUsername = $this->ldapConfig->getOptionalBoolean(
            'include_organization_in_username',
            false,
        );

        $this->mapping = array_change_key_case($this->ldapConfig->getArray('mapping'));
        Assert::notEmpty($this->mapping);

        $organizations = array_keys($this->mapping);
        $authsources = Configuration::getConfig('authsources.php');

        foreach ($organizations as $organization) {
            Assert::keyExists($this->mapping[$organization], 'authsource');
            $authsource = $this->mapping[$organization]['authsource'];
            Assert::notNull(Auth\Source::getById($authsource, Ldap::class));

            if (array_key_exists('description', $this->mapping[$organization])) {
                $this->orgs[$organization] = $this->mapping[$organization]['description'];
            } else {
                $this->orgs[$organization] = $organization;
            }

            $this->ldapOrgs[$organization] = Configuration::loadFromArray(
                $authsources->getValue($authsource),
                'authsources[' . var_export($this->authId, true) . '][' . var_export($organization, true) . ']',
            );
        }
    }


    /**
     * Attempt to log in using SASL and the given username and password.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @param string $organization  The organization the user chose.
     * @param array<mixed> $sasl_args SASL options
     * @return array<mixed> Associative array with the users attributes.
     */
    protected function loginSasl(
        string $username,
        #[\SensitiveParameter]string $password,
        string $organization,
        array $sasl_args = [],
    ): array {
        $organization = strtolower($organization);
        if ($this->includeOrgInUsername) {
            $username = $username . '@' . $organization;
        }

        $authsource = $this->mapping[$organization]['authsource'];

        if (!array_key_exists($organization, $this->ldapOrgs)) {
            // The organization is unknown to us.
            throw new Error\Error('WRONGUSERPASS');
        }

        $sourceConfig = $this->ldapOrgs[$organization];

        $ldap = new class (['AuthId' => $authsource], $sourceConfig->toArray()) extends Ldap
        {
            /**
             * @param array<mixed> $sasl_args
             * @return array<mixed>
             */
            public function loginOverload(
                string $username,
                #[\SensitiveParameter]string $password,
                array $sasl_args,
            ): array {
                return $this->loginSasl($username, $password, $sasl_args);
            }
        };

        return $ldap->loginOverload($username, $password, $sasl_args);
    }


    /**
     * Handle login request.
     *
     * This function is used by the login form (core/loginuserpassorg) when the user
     * enters a username and password. On success, it will not return. On wrong
     * username/password failure, and other errors, it will throw an exception.
     *
     * @param string $authStateId  The identifier of the authentication state.
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @param string $organization  The id of the organization the user chose.
     */
    public static function handleLogin(
        string $authStateId,
        string $username,
        string $password,
        string $organization,
    ): void {
        /* Retrieve the authentication state. */
        $state = Auth\State::loadState($authStateId, self::STAGEID);

        /* Find authentication source. */
        Assert::keyExists($state, self::AUTHID);

        /** @var \SimpleSAML\Module\ldap\Auth\Source\LdapMulti|null $source */
        $source = Auth\Source::getById($state[self::AUTHID]);
        if ($source === null) {
            throw new \Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        $orgMethod = $source->getUsernameOrgMethod();
        if ($orgMethod !== 'none') {
            $tmp = explode('@', $username, 2);
            if (count($tmp) === 2) {
                $username = $tmp[0];
                $organization = $tmp[1];
            } else {
                if ($orgMethod === 'force') {
                    /* The organization should be a part of the username, but isn't. */
                    throw new Error\Error(Error\ErrorCodes::WRONGUSERPASS);
                }
            }
        }

        /* Attempt to log in. */
        try {
            $attributes = $source->login($username, $password, $organization);
        } catch (\Exception $e) {
            Logger::stats('Unsuccessful login attempt from ' . $_SERVER['REMOTE_ADDR'] . '.');
            throw $e;
        }

        Logger::stats(
            'User \'' . $username . '\' at \'' . $organization
            . '\' successfully authenticated from ' . $_SERVER['REMOTE_ADDR'],
        );

        // Add the selected Org to the state
        $mapping = $source->getMapping();
        $state[self::SOURCEID] = $mapping[$organization]['authsource'];
        $state[self::ORGID] = $organization;
        $state['PersistentAuthData'][] = self::ORGID;

        $state['Attributes'] = $attributes;
        Auth\Source::completeAuth($state);


        // Save the $state-array, so that we can restore it after a redirect
        $authStateId = Auth\State::saveState($state, self::STAGEID);

        parent::handleLogin($authStateId, $username, $password, $organization);
    }


    /**
     * Attempt to log in using the given username and password.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @param string $organization  The organization the user chose.
     * @return array<mixed> Associative array with the users attributes.
     */
    protected function login(string $username, #[\SensitiveParameter]string $password, string $organization): array
    {
        return $this->loginSasl($username, $password, $organization);
    }


    /**
     * Retrieve list of organizations.
     *
     * @return array<mixed> Associative array with the organizations.
     */
    protected function getOrganizations(): array
    {
        return $this->orgs;
    }


    /**
     * Retrieve the mapping
     *
     * @return array<mixed> Associative array with the organization/authsource mapping.
     */
    protected function getMapping(): array
    {
        return $this->mapping;
    }
}
