<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use RuntimeException;
use SocialWeb\Jwk\Exception\InvalidJwkSet;
use SocialWeb\Jwk\Exception\JwkException;
use SocialWeb\Test\Jwk\TestCase;
use UnexpectedValueException;

class InvalidJwkSetTest extends TestCase
{
    public function testCanBeCaughtAsAJwkException(): void
    {
        $this->expectException(JwkException::class);

        throw new InvalidJwkSet('The "keys" member is required');
    }

    public function testCanBeCaughtAsAnUnexpectedValueException(): void
    {
        $this->expectException(UnexpectedValueException::class);

        throw new InvalidJwkSet('The "keys" member is required');
    }

    public function testHasTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new InvalidJwkSet('The "keys" member is required', 0, $previous);

        $this->assertSame('The "keys" member is required', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
