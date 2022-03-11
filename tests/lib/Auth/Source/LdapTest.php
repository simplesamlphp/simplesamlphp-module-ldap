<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\Auth\Source;

use PHPUnit\Framework\TestCase;
use SAML2\Constants;
use SimpleSAML\Module\ldap\Connector\Connector;
use Symfony\Component\Ldap\Entry;

class LdapTest extends TestCase
{
    /**
     * @var Ldap
     */
    protected $connector;

    public function buildSourceMock(): Ldap
    {
        $mb = $this->getMockBuilder(Connector::class);
        $s  = $mb->getMock();

        return new class($s) extends Ldap {
            public Connector $connector;

            public function __construct(Connector $connector)
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

    public function testLogin()
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

        self::assertEquals(['test' => ['test']], $ary['Attributes']);
    }
}