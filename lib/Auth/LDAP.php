<?php

namespace SimpleSAML\Module\ldap\Auth;

@trigger_error(sprintf('Using the "SimpleSAML\Module\ldap\Auth\LDAP" class is deprecated, use "SimpleSAML\Module\ldap\Auth\Ldap" instead.'), E_USER_DEPRECATED);

/**
 * @deprecated To be removed in a next major release
 */
if (!class_exists('LDAP')) {
    class LDAP extends Ldap
    {
    }
} else {
    require_once('Ldap.php');
}
