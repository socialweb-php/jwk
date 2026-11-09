<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use SocialWeb\Jwk\Exception\InvalidJwkSetReason;
use SocialWeb\Test\Jwk\TestCase;

use function array_map;

final class InvalidJwkSetReasonTest extends TestCase
{
    public function testHasAReasonForEachWayASetObjectFails(): void
    {
        $this->assertSame(
            ['MalformedJson', 'NotAnObject', 'MissingKeysMember', 'KeysNotAnArray'],
            array_map(static fn (InvalidJwkSetReason $reason): string => $reason->name, InvalidJwkSetReason::cases()),
        );
    }
}
