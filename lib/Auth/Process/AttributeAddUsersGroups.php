<?php

/**
 * Does a reverse membership lookup on the logged in user,
 * looking for groups it is a member of and adds them to
 * a defined attribute, in DN format.
 *
 * @package SimpleSAMLphp
 */

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Process;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Utils;

class AttributeAddUsersGroups extends BaseFilter
{
    /**
     * LDAP search filters to be added to the base filters for this authproc-filter.
     * It's an array of key => value pairs that will be translated to (key=value) in the ldap query.
     *
     * @var array
     */
    protected array $additional_filters;


    /**
     * This is run when the filter is processed by SimpleSAML.
     * It will attempt to find the current users groups using
     * the best method possible for the LDAP product. The groups
     * are then added to the request attributes.
     *
     * @throws \SimpleSAML\Error\Exception
     * @param array $request
     */
    public function process(array &$request): void
    {
        Assert::keyExists($request, 'Attributes');

        // Log the process
        Logger::debug(
            $this->title . 'Attempting to get the users groups...'
        );

        $this->additional_filters = $this->config->getArray('additional_filters', []);

        // Reference the attributes, just to make the names shorter
        $attributes = &$request['Attributes'];
        $map = &$this->attribute_map;

        // Get the users groups from LDAP
        $groups = $this->getGroups($attributes);

        // If there are none, do not proceed
        if (empty($groups)) {
            return;
        }

        // Make the array if it is not set already
        if (!isset($attributes[$map['groups']])) {
            $attributes[$map['groups']] = [];
        }

        // Must be an array, else cannot merge groups
        if (!is_array($attributes[$map['groups']])) {
            throw new Error\Exception(
                $this->title . 'The group attribute [' . $map['groups'] .
                '] is not an array of group DNs. ' . $this->varExport($attributes[$map['groups']])
            );
        }

        // Add the users group(s)
        $group_attribute = &$attributes[$map['groups']];
        $group_attribute = array_merge($group_attribute, $groups);
        $group_attribute = array_unique($group_attribute);

        // All done
        Logger::debug(
            $this->title . 'Added users groups to the group attribute [' .
            $map['groups'] . ']: ' . implode('; ', $groups)
        );
    }


    /**
     * This section of code was broken out because the child
     * filter AuthorizeByGroup can use this method as well.
     * Based on the LDAP product, it will do an optimized search
     * using the required attribute values from the user to
     * get their group membership, recursively.
     *
     * @throws \SimpleSAML\Error\Exception
     * @param array $attributes
     * @return array
     */
    protected function getGroups(array $attributes): array
    {
        // Log the request
        Logger::debug(
            $this->title . 'Checking for groups based on the best method for the LDAP product.'
        );

        // Based on the directory service, search LDAP for groups
        // If any attributes are needed, prepare them before calling search method
        switch ($this->product) {
            case 'ACTIVEDIRECTORY':
                $groups = $this->getGroupsActiveDirectory($attributes);
                break;
            case 'OPENLDAP':
                $groups = $this->getGroupsOpenLdap($attributes);
                break;
            default:
                // Reference the map, just to make the name shorter
                $map = &$this->attribute_map;

                // Log the general search
                Logger::debug(
                    $this->title . 'Searching LDAP using the default search method.'
                );

                // Make sure the defined memberOf attribute exists
                if (!isset($attributes[$map['memberof']])) {
                    throw new Error\Exception(
                        $this->title . 'The memberof attribute [' . $map['memberof'] .
                        '] is not defined in the user\'s Attributes: ' . implode(', ', array_keys($attributes))
                    );
                }

                // MemberOf must be an array of group DN's
                if (!is_array($attributes[$map['memberof']])) {
                    throw new Error\Exception(
                        $this->title . 'The memberof attribute [' . $map['memberof'] .
                        '] is not an array of group DNs. ' . $this->varExport($attributes[$map['memberof']])
                    );
                }

                // Search for the users group membership, recursively
                $groups = $this->search($attributes[$map['memberof']]);
        }

        // All done
        Logger::debug(
            $this->title . 'User found to be a member of the groups:' . implode('; ', $groups)
        );
        return $groups;
    }


    /**
     * OpenLDAP optimized search
     * using the required attribute values from the user to
     * get their group membership, recursively.
     *
     * @throws \SimpleSAML\Error\Exception
     * @param array $attributes
     * @return array
     */
    protected function getGroupsOpenLdap(array $attributes): array
    {
        // Log the OpenLDAP specific search
        Logger::debug(
            $this->title . 'Searching LDAP using OpenLDAP specific method.'
        );

        // Reference the map, just to make the name shorter
        $map = &$this->attribute_map;

        // Print group search string and search for all group names
        $openldap_base = $this->config->getString('ldap.basedn', 'ou=groups,dc=example,dc=com');
        Logger::debug(
            $this->title . "Searching for groups in ldap.basedn " . $openldap_base . " with filter (" .
            $map['memberof'] . "=" . $attributes[$map['username']][0] . ") and attributes " . $map['member']
        );

        $groups = [];
        try {
            /* Intention is to filter in 'ou=groups,dc=example,dc=com' for
             * '(memberUid = <value of attribute.username>)' and take only the attributes 'cn' (=name of the group)
             */
            $all_groups = $this->getLdap()->searchformultiple(
                $openldap_base,
                array_merge(
                    [
                        $map['memberof'] => $attributes[$map['username']][0]
                    ],
                    $this->additional_filters
                ),
                [$map['return']]
            );
        } catch (Error\UserNotFound $e) {
            return $groups; // if no groups found return with empty (still just initialized) groups array
        }

        // run through all groups and add each to our groups array
        foreach ($all_groups as $group_entry) {
            $groups[] = $group_entry[$map['return']][0];
        }

        return $groups;
    }


    /**
     * Active Directory optimized search
     * using the required attribute values from the user to
     * get their group membership, recursively.
     *
     * @throws \SimpleSAML\Error\Exception
     * @param array $attributes
     * @return array
     */
    protected function getGroupsActiveDirectory(array $attributes): array
    {
        // Log the AD specific search
        Logger::debug(
            $this->title . 'Searching LDAP using ActiveDirectory specific method.'
        );

        // Reference the map, just to make the name shorter
        $map = &$this->attribute_map;

        // Make sure the defined dn attribute exists
        if (!isset($attributes[$map['dn']])) {
            throw new Error\Exception(
                $this->title . 'The DN attribute [' . $map['dn'] .
                '] is not defined in the user\'s Attributes: ' . implode(', ', array_keys($attributes))
            );
        }

        // DN attribute must have a value
        if (!isset($attributes[$map['dn']][0]) || !$attributes[$map['dn']][0]) {
            throw new Error\Exception(
                $this->title . 'The DN attribute [' . $map['dn'] .
                '] does not have a [0] value defined. ' . $this->varExport($attributes[$map['dn']])
            );
        }

        // Pass to the AD specific search
        return $this->searchActiveDirectory($attributes[$map['dn']][0]);
    }


    /**
     * Looks for groups from the list of DN's passed. Also
     * recursively searches groups for further membership.
     * Avoids loops by only searching a DN once. Returns
     * the list of groups found.
     *
     * @param array $memberof
     * @return array
     */
    protected function search(array $memberof): array
    {
        // Used to determine what DN's have already been searched
        static $searched = [];

        // Init the groups variable
        $groups = [];

        // Shorten the variable name
        $map = &$this->attribute_map;

        // Log the search
        Logger::debug(
            $this->title . 'Checking DNs for groups.' .
            ' DNs: ' . implode('; ', $memberof) .
            ' Attributes: ' . $map['memberof'] . ', ' . $map['type'] .
            ' Group Type: ' . $this->type_map['group']
        );

        // Work out what attributes to get for a group
        $use_group_name = false;
        $get_attributes = [$map['memberof'], $map['type']];
        if (isset($map['name']) && $map['name']) {
            $get_attributes[] = $map['name'];
            $use_group_name = true;
        }

        // Check each DN of the passed memberOf
        foreach ($memberof as $dn) {
            // Avoid infinite loops, only need to check a DN once
            if (isset($searched[$dn])) {
                continue;
            }

            // Track all DN's that are searched
            // Use DN for key as well, isset() is faster than in_array()
            $searched[$dn] = $dn;

            // Query LDAP for the attribute values for the DN
            try {
                $attributes = $this->getLdap()->getAttributes($dn, $get_attributes);
            } catch (Error\AuthSource $e) {
                continue; // DN must not exist, just continue. Logged by the LDAP object
            }

            // Only look for groups
            if (!in_array($this->type_map['group'], $attributes[$map['type']], true)) {
                continue;
            }

            // Add to found groups array
            if ($use_group_name && isset($attributes[$map['name']]) && is_array($attributes[$map['name']])) {
                $groups[] = $attributes[$map['name']][0];
            } else {
                $groups[] = $dn;
            }

            // Recursively search "sub" groups
            if (!empty($attributes[$map['memberof']])) {
                $groups = array_merge($groups, $this->search($attributes[$map['memberof']]));
            }
        }

        // Return only the unique group names
        return array_unique($groups);
    }


    /**
     * Searches LDAP using a ActiveDirectory specific filter,
     * looking for group membership for the users DN. Returns
     * the list of group DNs retrieved.
     *
     * @param string $dn
     * @return array
     */
    protected function searchActiveDirectory(string $dn): array
    {
        $arrayUtils = new Utils\Arrays();

        // Shorten the variable name
        $map = &$this->attribute_map;

        // Log the search
        Logger::debug(
            $this->title . 'Searching ActiveDirectory group membership.' .
            ' DN: ' . $dn .
            ' DN Attribute: ' . $map['dn'] .
            ' Return Attribute: ' . $map['return'] .
            ' Member Attribute: ' . $map['member'] .
            ' Type Attribute: ' . $map['type'] .
            ' Type Value: ' . $this->type_map['group'] .
            ' Base: ' . implode('; ', $arrayUtils->arrayize($this->base_dn))
        );

        // AD connections should have this set
        $this->getLdap()->setOption(LDAP_OPT_REFERRALS, 0);

        // Search AD with the specific recursive flag
        try {
            $entries = $this->getLdap()->searchformultiple(
                $this->base_dn,
                array_merge(
                    [
                        $map['type'] => $this->type_map['group'],
                        $map['member'] . ':1.2.840.113556.1.4.1941:' => $dn
                    ],
                    $this->additional_filters
                ),
                [$map['return']]
            );

        // The search may throw an exception if no entries
        // are found, unlikely but possible.
        } catch (Error\UserNotFound $e) {
            return [];
        }

        //Init the groups
        $groups = [];

        // Check each entry..
        foreach ($entries as $entry) {
            // Check for the DN using the original attribute name
            if (isset($entry[$map['return']][0])) {
                $groups[] = $entry[$map['return']][0];
                continue;
            }

            // Sometimes the returned attribute names are lowercase
            if (isset($entry[strtolower($map['return'])][0])) {
                $groups[] = $entry[strtolower($map['return'])][0];
                continue;
            }

            // AD queries also seem to return the objects dn by default
            if (isset($entry['return'])) {
                $groups[] = $entry['return'];
                continue;
            }

            // Could not find DN, log and continue
            Logger::notice(
                $this->title . 'The return attribute [' .
                implode(', ', [$map['return'], strtolower($map['return'])]) .
                '] could not be found in the entry. ' . $this->varExport($entry)
            );
        }

        // All done
        return $groups;
    }
}
