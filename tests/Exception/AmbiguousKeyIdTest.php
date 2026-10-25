<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use RuntimeException;
use SocialWeb\Jwk\Exception\AmbiguousKeyId;
use SocialWeb\Jwk\Exception\JwkException;
use SocialWeb\Test\Jwk\TestCase;

class AmbiguousKeyIdTest extends TestCase
{
    public function testCanBeCaughtAsAJwkException(): void
    {
        $this->expectException(JwkException::class);

        throw new AmbiguousKeyId('Two keys have the identifier "1"');
    }

    public function testCanBeCaughtAsARuntimeException(): void
    {
        $this->expectException(RuntimeException::class);

        throw new AmbiguousKeyId('Two keys have the identifier "1"');
    }

    public function testHasTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new AmbiguousKeyId('Two keys have the identifier "1"', 0, $previous);

        $this->assertSame('Two keys have the identifier "1"', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
