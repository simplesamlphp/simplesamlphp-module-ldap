<?php

/**
 * LDAP authentication source.
 *
 * See the ldap-entry in config-templates/authsources.php for information about
 * configuration of this authentication source.
 *
 * This class is based on www/auth/login.php.
 *
 * @package SimpleSAMLphp
 */

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Source;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\ldap\ConfigHelper;

class LdapMulti extends \SimpleSAML\Module\core\Auth\UserPassOrgBase
{
    /**
     * An array with descriptions for organizations.
     */
    private array $orgs;

    /**
     * An array of organization IDs to LDAP configuration objects.
     */
    private array $ldapOrgs;

    /**
     * Whether we should include the organization as part of the username.
     */
    private bool $includeOrgInUsername;


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

        $cfgHelper = Configuration::loadFromArray(
            $config,
            'Authentication source ' . var_export($this->authId, true)
        );


        $this->orgs = [];
        $this->ldapOrgs = [];
        foreach ($config as $name => $value) {
            if ($name === 'username_organization_method') {
                $usernameOrgMethod = $cfgHelper->getValueValidate(
                    'username_organization_method',
                    ['none', 'allow', 'force']
                );
                $this->setUsernameOrgMethod($usernameOrgMethod);
                continue;
            }

            if ($name === 'include_organization_in_username') {
                $this->includeOrgInUsername = $cfgHelper->getBoolean(
                    'include_organization_in_username',
                    false
                );
                continue;
            }

            $orgCfg = $cfgHelper->getArray($name);
            $orgId = $name;

            if (array_key_exists('description', $orgCfg)) {
                $this->orgs[$orgId] = $orgCfg['description'];
            } else {
                $this->orgs[$orgId] = $orgId;
            }

            $orgCfg = new ConfigHelper(
                $orgCfg,
                'Authentication source ' . var_export($this->authId, true) .
                    ', organization ' . var_export($orgId, true)
            );
            $this->ldapOrgs[$orgId] = $orgCfg;
        }
    }


    /**
     * Attempt to log in using the given username and password.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @param string $organization  The organization the user chose.
     * @return array  Associative array with the users attributes.
     */
    protected function login(string $username, string $password, string $organization, array $sasl_args = null): array
    {
        if (!array_key_exists($organization, $this->ldapOrgs)) {
            // The user has selected an organization which doesn't exist anymore.
            Logger::warning('Authentication source ' . var_export($this->authId, true) .
                ': Organization seems to have disappeared while the user logged in.' .
                ' Organization was ' . var_export($organization, true));
            throw new Error\Error('WRONGUSERPASS');
        }

        if ($this->includeOrgInUsername) {
            $username = $username . '@' . $organization;
        }

        return $this->ldapOrgs[$organization]->login($username, $password, $sasl_args);
    }


    /**
     * Retrieve list of organizations.
     *
     * @return array  Associative array with the organizations.
     */
    protected function getOrganizations(): array
    {
        return $this->orgs;
    }
}
