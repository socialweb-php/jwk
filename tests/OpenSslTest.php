<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\OpenSsl;

use function openssl_error_string;
use function openssl_pkey_get_public;
use function str_repeat;

use const OPENSSL_KEYTYPE_EC;
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

    /**
     * @return iterable<string, array{array<string, array<string, string>>}>
     */
    public static function malformedMembersProvider(): iterable
    {
        yield 'no entry' => [[]];
        yield 'two entries' => [['ed25519' => ['pub_key' => 'a'], 'x25519' => ['pub_key' => 'b']]];
        yield 'an unknown entry name' => [['foo' => ['pub_key' => 'a']]];
        yield 'an empty entry' => [['ed25519' => []]];
        yield 'an ec entry with only the curve name' => [['ec' => ['curve_name' => 'prime256v1']]];
    }

    /**
     * @param array<string, array<string, string>> $members
     */
    #[DataProvider('malformedMembersProvider')]
    public function testRefusesMembersThatDescribeNoKey(array $members): void
    {
        $this->expectException(InvalidArgument::class);

        OpenSsl::build($members, InvalidJwkReason::InvalidValue, 'x', 'unused');
    }

    /**
     * @return iterable<string, array{array<string, array<string, string>>, string}>
     */
    public static function unreadMembersProvider(): iterable
    {
        $scalar = str_repeat("\x01", 32);

        yield 'an rsa member OpenSSL does not read' => [
            ['rsa' => ['n' => "\xc3", 'e' => "\x03", 'd' => "\x01", 'foo' => 'x']],
            'The "rsa" entry has the member "foo", which OpenSSL does not read for it',
        ];
        yield 'an ec member OpenSSL does not read' => [
            ['ec' => ['curve_name' => 'prime256v1', 'd' => $scalar, 'pub_key' => 'x']],
            'The "ec" entry has the member "pub_key", which OpenSSL does not read for it',
        ];
        yield 'an ed25519 member OpenSSL does not read' => [
            ['ed25519' => ['x' => $scalar]],
            'The "ed25519" entry has the member "x", which OpenSSL does not read for it',
        ];
        yield 'an x448 member OpenSSL does not read' => [
            ['x448' => ['d' => $scalar]],
            'The "x448" entry has the member "d", which OpenSSL does not read for it',
        ];
        yield 'an ec entry without a curve name' => [
            ['ec' => ['d' => $scalar]],
            'The "ec" entry must hold a "curve_name" member',
        ];
        yield 'an ec entry with a curve name OpenSSL does not know' => [
            ['ec' => ['curve_name' => 'P-256', 'd' => $scalar]],
            'The curve name "P-256" is not one OpenSSL knows',
        ];
    }

    /**
     * @param array<string, array<string, string>> $members
     */
    #[DataProvider('unreadMembersProvider')]
    public function testRefusesMembersOpenSslDoesNotRead(array $members, string $message): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains($message);

        OpenSsl::build($members, InvalidJwkReason::InvalidValue, 'x', 'unused');
    }

    public function testBuildsFromEveryMemberOpenSslReadsForAnRsaKey(): void
    {
        $fixture = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);
        $names = [
            'n' => 'n',
            'e' => 'e',
            'd' => 'd',
            'p' => 'p',
            'q' => 'q',
            'dmp1' => 'dp',
            'dmq1' => 'dq',
            'iqmp' => 'qi',
        ];
        $members = [];

        foreach ($names as $name => $member) {
            $members[$name] = Base64Url::decode(self::fixtureString($fixture, $member));
        }

        $key = OpenSsl::build(['rsa' => $members], InvalidJwkReason::InvalidValue, 'n', 'unused');

        /** @var array{rsa: array<string, string>} $details */
        $details = OpenSsl::details($key);

        $this->assertSame($members['iqmp'], $details['rsa']['iqmp']);
    }

    public function testBuildsFromEveryMemberOpenSslReadsForOkpKeys(): void
    {
        $privateKey = self::hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
        $key = OpenSsl::build(
            ['ed25519' => ['priv_key' => $privateKey]],
            InvalidJwkReason::InvalidValue,
            'd',
            'unused',
        );

        /** @var array{ed25519: array{priv_key: string}} $details */
        $details = OpenSsl::details($key);
        $this->assertSame($privateKey, $details['ed25519']['priv_key']);

        foreach (['ed448' => 57, 'x25519' => 32, 'x448' => 56] as $type => $length) {
            $publicKey = str_repeat("\x09", $length);
            $key = OpenSsl::build(
                [$type => ['pub_key' => $publicKey]],
                InvalidJwkReason::InvalidValue,
                'x',
                'unused',
            );

            /** @var array<string, array{pub_key: string}> $details */
            $details = OpenSsl::details($key);
            $this->assertSame($publicKey, $details[$type]['pub_key']);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function badScalarProvider(): iterable
    {
        yield 'zero' => [self::hex('00000000000000000000000000000000' . '00000000000000000000000000000000')];
        yield 'the order of the curve' => [
            self::hex('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
        ];
    }

    #[DataProvider('badScalarProvider')]
    public function testRefusesAnEcScalarThatOpenSslReplacesWithAGeneratedKey(string $scalar): void
    {
        $fixture = self::fixtureSetMember('rfc7517/appendix-a2.json', 0);
        $members = [
            'ec' => [
                'curve_name' => 'prime256v1',
                'x' => Base64Url::decode(self::fixtureString($fixture, 'x')),
                'y' => Base64Url::decode(self::fixtureString($fixture, 'y')),
                'd' => $scalar,
            ],
        ];

        try {
            OpenSsl::build($members, InvalidJwkReason::InvalidValue, 'd', 'Bad scalar');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('d', $exception->member);
            $this->assertStringStartsWith('Bad scalar', $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testAnEcPublicBuildLeavesNoErrorBehind(): void
    {
        $fixture = self::fixtureSetMember('rfc7517/appendix-a2.json', 0);
        $key = OpenSsl::build(
            [
                'ec' => [
                    'curve_name' => 'prime256v1',
                    'x' => Base64Url::decode(self::fixtureString($fixture, 'x')),
                    'y' => Base64Url::decode(self::fixtureString($fixture, 'y')),
                ],
            ],
            InvalidJwkReason::PointNotOnCurve,
            'x',
            'unused',
        );

        $this->assertSame(OPENSSL_KEYTYPE_EC, OpenSsl::details($key)['type']);
        $this->assertFalse(openssl_error_string());
    }

    public function testBuildsFromCoordinatesWithALeadingZeroByte(): void
    {
        // No fixture has a coordinate with a leading zero byte, so the
        // RFC 7517 appendix A.2 coordinates are given with one added, which
        // OpenSSL reports back without it.
        $fixture = self::fixtureSetMember('rfc7517/appendix-a2.json', 0);
        $x = Base64Url::decode(self::fixtureString($fixture, 'x'));
        $y = Base64Url::decode(self::fixtureString($fixture, 'y'));

        $key = OpenSsl::build(
            ['ec' => ['curve_name' => 'prime256v1', 'x' => "\0" . $x, 'y' => "\0" . $y]],
            InvalidJwkReason::PointNotOnCurve,
            'x',
            'unused',
        );

        /** @var array{ec: array{x: string, y: string}} $details */
        $details = OpenSsl::details($key);

        $this->assertSame($x, $details['ec']['x']);
        $this->assertSame($y, $details['ec']['y']);
    }

    public function testKeepsLeadingZeroBytesOfAValueOpenSslReportsInFull(): void
    {
        $publicKey = "\0" . str_repeat("\x07", 31);
        $key = OpenSsl::build(['x25519' => ['pub_key' => $publicKey]], InvalidJwkReason::InvalidValue, 'x', 'unused');

        /** @var array{x25519: array{pub_key: string}} $details */
        $details = OpenSsl::details($key);

        $this->assertSame($publicKey, $details['x25519']['pub_key']);
    }

    public function testErrorsLeftByEarlierCallsDoNotReachTheMessage(): void
    {
        $scalar = str_repeat("\0", 32);
        $fixture = self::fixtureSetMember('rfc7517/appendix-a2.json', 0);
        $members = [
            'ec' => [
                'curve_name' => 'prime256v1',
                'x' => Base64Url::decode(self::fixtureString($fixture, 'x')),
                'y' => Base64Url::decode(self::fixtureString($fixture, 'y')),
                'd' => $scalar,
            ],
        ];

        $clean = '';

        try {
            OpenSsl::build($members, InvalidJwkReason::InvalidValue, 'd', 'Bad scalar');
        } catch (InvalidJwk $exception) {
            $clean = $exception->getMessage();
        }

        @openssl_pkey_get_public('not a key');

        try {
            OpenSsl::build($members, InvalidJwkReason::InvalidValue, 'd', 'Bad scalar');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame($clean, $exception->getMessage());
        }
    }
}
