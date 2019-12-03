<?php

use SimpleSAML\Module;

/**
 * Autoload function for SimpleSAMLphp modules following PSR-4.
 *
 * @param string $className Name of the class.
 */
function sspmodAutoloadPSR4($className)
{
    $renamed = [
        'SimpleSAML\\Auth\\LDAP' => 'SimpleSAML\\Module\\ldap\\Auth\\Ldap'
    ];

    if (array_key_exists($class, $renamed)) {
        // the class has been renamed, try to load it and create an alias
        $class = $renamed[$class];
    }

    $elements = explode('\\', $className);

    $file = Module::getModuleDir('ldap') . '/lib/' . implode('/', $elements) . '.php';
    if (file_exists($file)) {
        require_once($file);
    }
}

spl_autoload_register('sspmodAutoloadPSR4');
