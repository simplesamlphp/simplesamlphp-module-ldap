<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\ldap\Auth\Process;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SimpleSAML\Module\ldap\Auth\Process\BaseFilter;

final class BaseFilterTest extends TestCase
{
    /**
     */
    public function testVarExportHidesLdapPassword(): void
    {
        $stub = $this->createStub(BaseFilter::class);
        $class = new ReflectionClass($stub);
        $method = $class->getMethod('varExport');
        $method->setAccessible(true);

        $this->assertEquals(
            "array ( 'connection_string' => 'ldap://172.17.101.32:389', 'search.password' => '********', )",
            $method->invokeArgs($stub, [[
                'connection_string' => 'ldap://172.17.101.32:389',
                'search.password' => 'password',
            ]]),
        );
    }
}
