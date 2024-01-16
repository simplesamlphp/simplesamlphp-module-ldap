<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\ldap\Connector;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Assert\AssertionFailedException;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\ldap\Connector;
use SimpleSAML\Module\ldap\ConnectorFactory;

/**
 * @covers \SimpleSAML\Module\ldap\Connector\ActiveDirectory
 * @covers \SimpleSAML\Module\ldap\Connector\Ldap
 * @covers \SimpleSAML\Module\ldap\ConnectorFactory
 */
class ConnectorFactoryTest extends TestCase
{
    /**
     */
    public static function setUpBeforeClass(): void
    {
        $config = Configuration::loadFromArray(
            ['module.enable' => ['ldap' => true]],
            '[ARRAY]',
            'simplesaml'
        );
        Configuration::setPreLoadedConfig($config, 'config.php');

        $sourceConfig = Configuration::loadFromArray([
            'some' => [
                'ldap:Ldap',
                'connection_string' => 'ldaps://example.org:636',
            ],

            'other' => [
                'ldap:Ldap',
                'connection_string' => 'ldaps://example.org:636',
                'connector' => '\SimpleSAML\Module\ldap\Connector\ActiveDirectory',
            ],

            'wrong' => [
                'core:AdminPassword',
                'connection_string' => 'ldaps://example.org:636', // Mimic an ldap-source with minimal settings
            ],
        ]);
        Configuration::setPreLoadedConfig($sourceConfig, 'authsources.php');
    }


    /**
     * Test that fromAuthSource with a non-existing source throws an exception
     */
    public function testFromAuthSourceNonExisting(): void
    {
        $this->expectException(Error\Exception::class);
        ConnectorFactory::fromAuthSource('doesNotExist');
    }


    /**
     * Test that fromAuthSource with a wrong type of source throws an exception
     */
    public function testFromAuthSourceWrongType(): void
    {
        $this->expectException(AssertionFailedException::class);
        ConnectorFactory::fromAuthSource('wrong');
    }


    /**
     * Test that fromAuthSource with a correct source returns a Connector
     */
    public function testFromAuthSourceCorrect(): void
    {
        $connector = ConnectorFactory::fromAuthSource('some');
        $this->assertInstanceOf(Connector\Ldap::class, $connector);

        $connector = ConnectorFactory::fromAuthSource('other');
        $this->assertInstanceOf(Connector\ActiveDirectory::class, $connector);
    }
}
