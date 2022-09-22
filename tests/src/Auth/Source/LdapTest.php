<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Source;

use PHPUnit\Framework\TestCase;
use SAML2\Constants;
use SimpleSAML\Configuration;
use SimpleSAML\Module\ldap\ConnectorInterface;
use Symfony\Component\Ldap\Entry;

class LdapTest extends TestCase
{
    /**
     * @var Ldap
     */
    protected $connector;

    /**
     */
    protected function setUp(): void
    {
        parent::setUp();

        $sourceConfig = Configuration::loadFromArray([
            'ldap_login' => [
                'ldap:Ldap',

                 'connection_string' => 'ldaps://ldap.example.org',
            ],
        ]);

        Configuration::setPreLoadedConfig($sourceConfig, 'authsources.php');
    }

    public function buildSourceMock(): Ldap
    {
        $mb = $this->getMockBuilder(ConnectorInterface::class);
        $s  = $mb->getMock();

        return new class ($s) extends Ldap {
            public ConnectorInterface $connector;

            public function __construct(ConnectorInterface $connector)
            {
                $this->connector = $connector;
                parent::__construct(
                    ['AuthId' => 'ldap_login'],
                    [
                        'attributes'  => null,
                        'search.base' => ['DC=example,DC=com'],
                        'dnpattern'   => '%username%@example.com'
                    ]
                );
            }
        };
    }

    public function testLogin(): void
    {
        $source = $this->buildSourceMock();
        $source->connector->method('search')->willReturn(
            new Entry('test', ['test' => ['test']])
        );

        // This forces the login flow through the ECP processing
        $ary                      = [
            'saml:Binding' => Constants::BINDING_PAOS
        ];
        $_SERVER['PHP_AUTH_USER'] = 'test';
        $_SERVER['PHP_AUTH_PW']   = 'test';
        $source->authenticate($ary);

        $this->assertEquals(['test' => ['test']], $ary['Attributes']);
    }
}
