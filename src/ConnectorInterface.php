<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap;

use Symfony\Component\Ldap\Adapter\AdapterInterface;
use Symfony\Component\Ldap\Entry;

interface ConnectorInterface
{
    public const ERR_WRONG_PASS = 'WRONGUSERPASS';


    /**
     * Bind to an LDAP-server
     *
     * @param string|null $username
     * @param string|null $password Null for passwordless logon
     * @return void
     *
     * @throws \SimpleSAML\Error\Exception if none of the LDAP-servers could be contacted
     */
    public function bind(
        ?string $username,
        #[\SensitiveParameter]
        ?string $password,
    ): void;


    /**
     * Bind to an LDAP-server using SASL
     *
     * @param string|null $username
     * @param string|null $password Null for passwordless logon
     * @param string|null $mech
     * @param string|null $realm
     * @param string|null $authcId
     * @param string|null $authzId
     * @param string|null $props
     * @return void
     *
     * @throws \SimpleSAML\Error\Exception if none of the LDAP-servers could be contacted
     */
    public function saslBind(
        ?string $username,
        ?string $password,
        ?string $mech,
        ?string $realm,
        ?string $authcId,
        ?string $authzId,
        ?string $props,
    ): void;


    /**
     * Return the authenticated DN
     *
     * @return string
     */
    public function whoami(): string;


    /**
     * Search the LDAP-directory for a specific object
     *
     * @param string[] $searchBase
     * @param string $filter
     * @param array<mixed> $options
     * @param boolean $allowMissing
     * @return \Symfony\Component\Ldap\Entry|null The result of the search or null if none found
     * @psalm-return ($allowMissing is true ? \Symfony\Component\Ldap\Entry|null : \Symfony\Component\Ldap\Entry)
     *
     * @throws \SimpleSAML\Error\Exception if more than one entry was found
     * @throws \SimpleSAML\Error\Exception if the object cannot be found using the given search base and filter
     */
    public function search(
        array $searchBase,
        string $filter,
        array $options,
        bool $allowMissing,
    ): ?Entry;


    /**
     * Search the LDAP-directory for any object matching the search filter
     *
     * @param string[] $searchBase
     * @param string $filter
     * @param array<mixed> $options
     * @param boolean $allowMissing
     * @return \Symfony\Component\Ldap\Entry[] The result of the search
     *
     * @throws \SimpleSAML\Error\Exception if more than one entry was found
     * @throws \SimpleSAML\Error\Exception if the object cannot be found using the given search base and filter
     */
    public function searchForMultiple(
        array $searchBase,
        string $filter,
        array $options,
        bool $allowMissing,
    ): array;


    /**
     * @return \Symfony\Component\Ldap\Adapter\AdapterInterface
     */
    public function getAdapter(): AdapterInterface;
}
