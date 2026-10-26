<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\SkippedKey;

class SkippedKeyTest extends TestCase
{
    public function testHoldsThePositionAndTheCause(): void
    {
        $cause = new InvalidJwk(InvalidJwkReason::MissingMember, 'The "kty" member is required', 'kty');
        $skipped = new SkippedKey(2, $cause);

        $this->assertSame(2, $skipped->index);
        $this->assertSame($cause, $skipped->cause);
        $this->assertSame(InvalidJwkReason::MissingMember, $skipped->cause->reason);
    }

    public function testAcceptsIndexZero(): void
    {
        $skipped = new SkippedKey(0, new InvalidJwk(InvalidJwkReason::NotAnObject, 'Not an object'));

        $this->assertSame(0, $skipped->index);
    }

    public function testRefusesANegativeIndex(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('The index is a position in the "keys" array and cannot be negative');

        new SkippedKey(-1, new InvalidJwk(InvalidJwkReason::NotAnObject, 'Not an object'));
    }
}
