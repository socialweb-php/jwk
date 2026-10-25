<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use SocialWeb\Jwk\Example;

class ExampleTest extends TestCase
{
    public function testGreet(): void
    {
        $example = new Example();

        $this->assertSame('Hello, Friends!', $example->greet('Friends'));
    }
}
