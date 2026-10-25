<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use SocialWeb\Jwk\Exception\ConversionFailedReason;
use SocialWeb\Test\Jwk\TestCase;

use function array_map;

class ConversionFailedReasonTest extends TestCase
{
    public function testHasTheReasonsOfTheDesign(): void
    {
        $this->assertSame(
            ['UnreadablePem', 'UnsupportedKey', 'SymmetricKey', 'NotAPrivateKey', 'MissingCrtMembers', 'MultiPrimeKey'],
            array_map(
                static fn (ConversionFailedReason $reason): string => $reason->name,
                ConversionFailedReason::cases(),
            ),
        );
    }
}
