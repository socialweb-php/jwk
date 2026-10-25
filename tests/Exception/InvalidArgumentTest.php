<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use InvalidArgumentException;
use RuntimeException;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\JwkException;
use SocialWeb\Test\Jwk\TestCase;

class InvalidArgumentTest extends TestCase
{
    public function testCanBeCaughtAsAJwkException(): void
    {
        $this->expectException(JwkException::class);

        throw new InvalidArgument('bad input');
    }

    public function testCanBeCaughtAsAnInvalidArgumentException(): void
    {
        $this->expectException(InvalidArgumentException::class);

        throw new InvalidArgument('bad input');
    }

    public function testHasTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new InvalidArgument('bad input', 0, $previous);

        $this->assertSame('bad input', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
