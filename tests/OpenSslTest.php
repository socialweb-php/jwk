<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\OpenSsl;

use function openssl_error_string;
use function openssl_pkey_get_public;

use const OPENSSL_KEYTYPE_ED25519;

class OpenSslTest extends TestCase
{
    public function testBuildsAKeyFromItsMembers(): void
    {
        $publicKey = self::hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
        $key = OpenSsl::build(['ed25519' => ['pub_key' => $publicKey]], InvalidJwkReason::InvalidValue, 'x', 'unused');

        /** @var array{type: int, ed25519: array{pub_key: string}} $details */
        $details = OpenSsl::details($key);

        $this->assertSame(OPENSSL_KEYTYPE_ED25519, $details['type']);
        $this->assertSame($publicKey, $details['ed25519']['pub_key']);
    }

    public function testThrowsTheGivenReasonWhenOpenSslRefusesAndLeavesNoErrorBehind(): void
    {
        try {
            OpenSsl::build(['ed25519' => ['pub_key' => 'short']], InvalidJwkReason::InvalidValue, 'x', 'Could not');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('x', $exception->member);
            $this->assertSame('Could not', $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testAppendsOpenSslsErrorTextWhenThereIsAny(): void
    {
        $x = self::hex('302bf68d4c2d124a2c7f5aa4fd3ab5a1c4c1c4ac1c4a1c4ac1c4a1c4ac1c4a1c');

        try {
            OpenSsl::build(
                ['ec' => ['curve_name' => 'prime256v1', 'x' => $x, 'y' => $x]],
                InvalidJwkReason::PointNotOnCurve,
                'x',
                'Not a point',
            );
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::PointNotOnCurve, $exception->reason);
            $this->assertStringStartsWith('Not a point: error:', $exception->getMessage());
            $this->assertStringContainsString('point is not on curve', $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testDrainsStaleErrorsBeforeBuilding(): void
    {
        @openssl_pkey_get_public('not a key');
        $publicKey = self::hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');

        OpenSsl::build(['ed25519' => ['pub_key' => $publicKey]], InvalidJwkReason::InvalidValue, 'x', 'unused');

        $this->assertFalse(openssl_error_string());
    }

    public function testDrainsTheErrorQueueIntoOneMessage(): void
    {
        @openssl_pkey_get_public('not a key');

        $errors = OpenSsl::drainErrors();

        $this->assertStringContainsString('error:', $errors);
        $this->assertSame('', OpenSsl::drainErrors());
    }

    public function testPadsOnTheLeftWithZeroBytes(): void
    {
        $this->assertSame("\x00\x00\x01", OpenSsl::padLeft("\x01", 3));
        $this->assertSame("\x01\x02\x03", OpenSsl::padLeft("\x01\x02\x03", 3));
        $this->assertSame("\x01\x02\x03\x04", OpenSsl::padLeft("\x01\x02\x03\x04", 3));
    }
}
