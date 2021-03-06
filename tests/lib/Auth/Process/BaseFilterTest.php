<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\ldap\Auth\Process;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\ldap\Auth\Process\BaseFilter;

class BaseFilterTest extends TestCase
{
    /**
     */
    public function testVarExportHidesLdapPassword(): void
    {
        $stub = $this->getMockBuilder(BaseFilter::class)
            ->disableOriginalConstructor()
            ->getMockForAbstractClass();
        $class = new \ReflectionClass($stub);
        $method = $class->getMethod('varExport');
        $method->setAccessible(true);

        $this->assertEquals(
            "array ( 'ldap.hostname' => 'ldap://172.17.101.32', 'ldap.port' => 389, 'ldap.password' => '********', )",
            $method->invokeArgs($stub, [[
                'ldap.hostname' => 'ldap://172.17.101.32',
                'ldap.port' => 389,
                'ldap.password' => 'password',
            ]])
        );
    }
}
