<?php

/**
 * This base LDAP filter class can be extended to enable real
 * filter classes direct access to the authsource ldap config
 * and connects to the ldap server.
 *
 * Updated: 20161223 Remy Blom
 *          - Wrapped the building of authsource config with issets
 *
 * @package SimpleSAMLphp
 */

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Process;

use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\ldap\Auth\Ldap;

abstract class BaseFilter extends \SimpleSAML\Auth\ProcessingFilter
{
    // TODO: Support ldap:LDAPMulti, if possible
    protected static array $ldapsources = ['ldap:Ldap', 'authX509:X509userCert'];

    /**
     * List of attribute "alias's" linked to the real attribute
     * name. Used for abstraction / configuration of the LDAP
     * attribute names, which may change between dir service.
     *
     * @var array
     */
    protected array $attribute_map;

    /**
     * The base DN of the LDAP connection. Used when searching
     * the LDAP server.
     *
     * @var string|array
     */
    protected $base_dn;

    /**
     * The construct method will change the filter config into
     * a \SimpleSAML\Configuration object and store it here for
     * later use, if needed.
     *
     * @var \SimpleSAML\Configuration
     */
    protected Configuration $config;

    /**
     * Instance, object of the ldap connection. Stored here to
     * be access later during processing.
     *
     * @var \SimpleSAML\Module\ldap\Auth\Ldap
     */
    private Ldap $ldap;

    /**
     * Many times a LDAP product specific query can be used to
     * speed up or reduce the filter process. This helps the
     * child classes determine the product used to optimize
     * those queries.
     *
     * @var string
     */
    protected string $product;

    /**
     * The class "title" used in logging and exception messages.
     * This should be prepended to the beginning of the message.
     *
     * @var string
     */
    protected string $title = 'ldap:BaseFilter : ';

    /**
     * List of LDAP object types, used to determine the type of
     * object that a DN references.
     *
     * @var array
     */
    protected array $type_map;


    /**
     * Checks the authsource, if defined, for configuration values
     * to the LDAP server. Then sets up the LDAP connection for the
     * instance/object and stores everything in class members.
     *
     * @throws \SimpleSAML\Error\Exception
     * @param array &$config
     * @param mixed $reserved
     */
    public function __construct(array &$config, $reserved)
    {
        parent::__construct($config, $reserved);

        // Change the class $title to match it's true name
        // This way if the class is extended the proper name is used
        $classname = get_class($this);
        $classname = explode('_', $classname);
        $this->title = 'ldap:' . end($classname) . ' : ';

        // Log the construction
        Logger::debug($this->title . 'Creating and configuring the filter.');

        // If an authsource was defined (an not empty string)...
        if (isset($config['authsource']) && $config['authsource'] !== '') {
            $authconfig = $this->parseAuthSourceConfig($config['authsource']);

            // Merge the authsource config with the filter config,
            // but have the filter config override the authsource config
            $config = array_merge($authconfig, $config);

            // Authsource complete
            Logger::debug(
                $this->title . 'Retrieved authsource [' . $config['authsource'] .
                '] configuration values: ' . $this->varExport($authconfig)
            );
        }

        // Convert the config array to a config class,
        // that way we can verify type and define defaults.
        // Store in the instance in-case needed later, by a child class.
        $this->config = Configuration::loadFromArray($config, 'ldap:AuthProcess');

        // Initialize the Ldap-object
        $this->initializeLdap();

        // Set all the filter values, setting defaults if needed
        $this->base_dn = $this->config->getArrayizeString('ldap.basedn', '');
        $this->product = $this->config->getString('ldap.product', '');

        // Cleanup the directory service, so that it is easier for
        // child classes to determine service name consistently
        $this->product = trim($this->product);
        $this->product = strtoupper($this->product);

        // Log the member values retrieved above
        Logger::debug(
            $this->title . 'Configuration values retrieved;' .
            ' BaseDN: ' . $this->varExport($this->base_dn) .
            ' Product: ' . $this->varExport($this->product)
        );

        // Setup the attribute map which will be used to search LDAP
        $this->attribute_map = [
            'dn'       => $this->config->getString('attribute.dn', 'distinguishedName'),
            'groups'   => $this->config->getString('attribute.groups', 'groups'),
            'member'   => $this->config->getString('attribute.member', 'member'),
            'memberof' => $this->config->getString('attribute.memberof', 'memberOf'),
            'name'     => $this->config->getString('attribute.groupname', 'name'),
            'return'   => $this->config->getString('attribute.return', 'distinguishedName'),
            'type'     => $this->config->getString('attribute.type', 'objectClass'),
            'username' => $this->config->getString('attribute.username', 'sAMAccountName')
        ];

        // Log the attribute map
        Logger::debug(
            $this->title . 'Attribute map created: ' . $this->varExport($this->attribute_map)
        );

        // Setup the object type map which is used to determine a DNs' type
        $this->type_map = [
            'group' => $this->config->getString('type.group', 'group'),
            'user'  => $this->config->getString('type.user', 'user')
        ];

        // Log the type map
        Logger::debug(
            $this->title . 'Type map created: ' . $this->varExport($this->type_map)
        );
    }


    /**
     * Parse authsource config
     *
     * @param string $as The name of the authsource
     */
    private function parseAuthSourceConfig(string $as) : array
    {
        // Log the authsource request
        Logger::debug(
            $this->title . 'Attempting to get configuration values from authsource [' . $as . ']'
        );

        // Get the authsources file, which should contain the config
        $authsources = Configuration::getConfig('authsources.php');

        // Verify that the authsource config exists
        if (!$authsources->hasValue($as)) {
            throw new Error\Exception(
                $this->title . 'Authsource [' . $as . '] defined in filter parameters not found in authsources.php'
            );
        }

        // Get just the specified authsource config values
        $authsource = $authsources->getArray($as);

        // Make sure it is an ldap source
        if (isset($authsource[0]) && !in_array($authsource[0], self::$ldapsources)) {
            throw new Error\Exception(
                $this->title . 'Authsource [' . $as . '] specified in filter parameters is not an ldap:LDAP type'
            );
        }

        // Build the authsource config
        $authconfig = [];
        if (isset($authsource['hostname'])) {
            $authconfig['ldap.hostname']   = $authsource['hostname'];
        }
        if (isset($authsource['enable_tls'])) {
            $authconfig['ldap.enable_tls'] = $authsource['enable_tls'];
        }
        if (isset($authsource['port'])) {
            $authconfig['ldap.port']       = $authsource['port'];
        }
        if (isset($authsource['timeout'])) {
            $authconfig['ldap.timeout']    = $authsource['timeout'];
        }
        if (isset($authsource['debug'])) {
            $authconfig['ldap.debug']      = $authsource['debug'];
        }
        if (isset($authsource['referrals'])) {
            $authconfig['ldap.referrals']  = $authsource['referrals'];
        }

        // only set when search.enabled = true
        if (isset($authsource['search.enable']) && $authsource['search.enable']) {
            if (isset($authsource['search.base'])) {
                $authconfig['ldap.basedn'] = $authsource['search.base'];
            }
            if (isset($authsource['search.scope'])) {
                $authconfig['ldap.scope'] = $authsource['search.scope'];
            }
            if (isset($authsource['search.username'])) {
                $authconfig['ldap.username']   = $authsource['search.username'];
            }
            if (isset($authsource['search.password'])) {
                $authconfig['ldap.password']   = $authsource['search.password'];
            }

            // Only set the username attribute if the authsource specifies one attribute
            if (
                isset($authsource['search.attributes'])
                && is_array($authsource['search.attributes'])
                && count($authsource['search.attributes']) == 1
            ) {
                $authconfig['attribute.username'] = reset($authsource['search.attributes']);
            }
        }

        // only set when priv.read = true
        if (isset($authsource['priv.read']) && $authsource['priv.read']) {
            if (isset($authsource['priv.username'])) {
                $authconfig['ldap.username'] = $authsource['priv.username'];
            }
            if (isset($authsource['priv.password'])) {
                $authconfig['ldap.password'] = $authsource['priv.password'];
            }
        }

        return $authconfig;
    }


    /**
     * Getter for the LDAP connection object. Created this getter
     * rather than setting in the constructor to avoid unnecessarily
     * connecting to LDAP when it might not be needed.
     *
     * @return \SimpleSAML\Module\ldap\Auth\Ldap
     */
    protected function getLdap(): Ldap
    {
        // Get the connection specific options
        $hostname   = $this->config->getString('ldap.hostname');
        $port       = $this->config->getInteger('ldap.port', 389);
        $enable_tls = $this->config->getBoolean('ldap.enable_tls', false);
        $debug      = $this->config->getBoolean('ldap.debug', false);
        $referrals  = $this->config->getBoolean('ldap.referrals', true);
        $timeout    = $this->config->getInteger('ldap.timeout', 0);
        $username   = $this->config->getString('ldap.username', null);
        $password   = $this->config->getString('ldap.password', null);

        // Log the LDAP connection
        Logger::debug(
            $this->title . 'Connecting to LDAP server;' .
            ' Hostname: ' . $hostname .
            ' Port: ' . $port .
            ' Enable TLS: ' . ($enable_tls ? 'Yes' : 'No') .
            ' Debug: ' . ($debug ? 'Yes' : 'No') .
            ' Referrals: ' . ($referrals ? 'Yes' : 'No') .
            ' Timeout: ' . $timeout .
            ' Username: ' . $username .
            ' Password: ' . (empty($password) ? '' : '********')
        );

        $this->ldap->bind($username, $password);

        // All done
        return $this->ldap;
    }


    /**
     * Initialize the Ldap-object
     *
     * @return void
     */
    private function initializeLdap(): void
    {
        // Get the connection specific options
        $hostname   = $this->config->getString('ldap.hostname');
        $port       = $this->config->getInteger('ldap.port', 389);
        $enable_tls = $this->config->getBoolean('ldap.enable_tls', false);
        $debug      = $this->config->getBoolean('ldap.debug', false);
        $referrals  = $this->config->getBoolean('ldap.referrals', true);
        $timeout    = $this->config->getInteger('ldap.timeout', 0);

        // Connect to the LDAP server to be queried during processing
        $this->ldap = new Ldap($hostname, $enable_tls, $debug, $timeout, $port, $referrals);
    }


    /**
     * Local utility function to get details about a variable,
     * basically converting it to a string to be used in a log
     * message. The var_export() function returns several lines
     * so this will remove the new lines and trim each line.
     *
     * @param mixed $value
     * @return string
     */
    protected function varExport($value): string
    {
        if (is_array($value)) {
            // remove sensitive data
            foreach ($value as $key => &$val) {
                if ($key === 'ldap.password') {
                    $val = empty($val) ? '' : '********';
                }
            }
            unset($val);
        }

        $export = var_export($value, true);
        $lines = explode("\n", $export);
        foreach ($lines as &$line) {
            $line = trim($line);
        }
        return implode(' ', $lines);
    }
}
