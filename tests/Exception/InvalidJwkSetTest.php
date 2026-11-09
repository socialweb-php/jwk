<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use RuntimeException;
use SocialWeb\Jwk\Exception\InvalidJwkSet;
use SocialWeb\Jwk\Exception\InvalidJwkSetReason;
use SocialWeb\Jwk\Exception\JwkException;
use SocialWeb\Test\Jwk\TestCase;
use UnexpectedValueException;

final class InvalidJwkSetTest extends TestCase
{
    public function testCanBeCaughtAsAJwkException(): void
    {
        $this->expectException(JwkException::class);

        throw new InvalidJwkSet(InvalidJwkSetReason::MissingKeysMember, 'The "keys" member is required');
    }

    public function testCanBeCaughtAsAnUnexpectedValueException(): void
    {
        $this->expectException(UnexpectedValueException::class);

        throw new InvalidJwkSet(InvalidJwkSetReason::MissingKeysMember, 'The "keys" member is required');
    }

    public function testHasTheReasonTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new InvalidJwkSet(InvalidJwkSetReason::MalformedJson, 'The JSON text does not parse', $previous);

        $this->assertSame(InvalidJwkSetReason::MalformedJson, $exception->reason);
        $this->assertSame('The JSON text does not parse', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
        $this->assertSame(0, $exception->getCode());
    }

    public function testThePreviousIsOptional(): void
    {
        $exception = new InvalidJwkSet(InvalidJwkSetReason::NotAnObject, 'The JSON value is not an object');

        $this->assertNull($exception->getPrevious());
    }
}
