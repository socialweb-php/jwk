<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use RuntimeException;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Exception\JwkException;
use SocialWeb\Test\Jwk\TestCase;
use UnexpectedValueException;

class InvalidJwkTest extends TestCase
{
    public function testCanBeCaughtAsAJwkException(): void
    {
        $this->expectException(JwkException::class);

        throw new InvalidJwk(InvalidJwkReason::MissingMember, 'The "kty" member is required', 'kty');
    }

    public function testCanBeCaughtAsAnUnexpectedValueException(): void
    {
        $this->expectException(UnexpectedValueException::class);

        throw new InvalidJwk(InvalidJwkReason::MissingMember, 'The "kty" member is required', 'kty');
    }

    public function testHasTheReasonTheMemberTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new InvalidJwk(InvalidJwkReason::WrongType, 'The "n" member must be a string', 'n', $previous);

        $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
        $this->assertSame('n', $exception->member);
        $this->assertSame('The "n" member must be a string', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
        $this->assertSame(0, $exception->getCode());
    }

    public function testTheMemberIsOptional(): void
    {
        $exception = new InvalidJwk(InvalidJwkReason::NotAnObject, 'The JSON value is not an object');

        $this->assertNull($exception->member);
        $this->assertNull($exception->getPrevious());
    }
}
