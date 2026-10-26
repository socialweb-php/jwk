<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\Exception\ConversionFailed;
use SocialWeb\Jwk\Exception\ConversionFailedReason;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\OpenSsl;

use function array_slice;
use function base64_decode;
use function chunk_split;
use function explode;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_pkey_new;
use function openssl_x509_read;
use function preg_replace;
use function str_contains;
use function str_ends_with;
use function str_repeat;
use function str_replace;
use function strlen;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;
use const OPENSSL_KEYTYPE_RSA;

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

    public function testReadsAPrivatePemAndAPublicPem(): void
    {
        $private = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ed25519.private.pem'), null);
        $public = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ed25519.public.pem'), null);

        /** @var array{type: int, ed25519: array<string, string>} $privateDetails */
        $privateDetails = OpenSsl::details($private);
        /** @var array{type: int, ed25519: array<string, string>} $publicDetails */
        $publicDetails = OpenSsl::details($public);

        $this->assertSame(OPENSSL_KEYTYPE_ED25519, $privateDetails['type']);
        $this->assertArrayHasKey('priv_key', $privateDetails['ed25519']);
        $this->assertSame(OPENSSL_KEYTYPE_ED25519, $publicDetails['type']);
        $this->assertArrayNotHasKey('priv_key', $publicDetails['ed25519']);
        $this->assertSame($privateDetails['ed25519']['pub_key'], $publicDetails['ed25519']['pub_key']);
        $this->assertFalse(openssl_error_string());
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function pemFormProvider(): iterable
    {
        yield 'PKCS #1 RSA PRIVATE KEY' => ['rfc9421/test-key-rsa.private.pem', OPENSSL_KEYTYPE_RSA];
        yield 'PKCS #1 RSA PUBLIC KEY' => ['rfc9421/test-key-rsa.public.pem', OPENSSL_KEYTYPE_RSA];
        yield 'PKCS #8 RSA PRIVATE KEY' => ['rfc9421/test-key-rsa.private.pkcs8.pem', OPENSSL_KEYTYPE_RSA];
        yield 'RSA SubjectPublicKeyInfo' => ['rfc9421/test-key-rsa.public.spki.pem', OPENSSL_KEYTYPE_RSA];
        yield 'SEC 1 EC PRIVATE KEY' => ['rfc9421/test-key-ecc-p256.private.pem', OPENSSL_KEYTYPE_EC];
        yield 'PKCS #8 EC PRIVATE KEY' => ['rfc9421/test-key-ecc-p256.private.pkcs8.pem', OPENSSL_KEYTYPE_EC];
        yield 'EC SubjectPublicKeyInfo' => ['rfc9421/test-key-ecc-p256.public.pem', OPENSSL_KEYTYPE_EC];
        yield 'PKCS #8 Ed25519 PRIVATE KEY' => ['rfc9421/test-key-ed25519.private.pem', OPENSSL_KEYTYPE_ED25519];
        yield 'Ed25519 SubjectPublicKeyInfo' => ['rfc9421/test-key-ed25519.public.pem', OPENSSL_KEYTYPE_ED25519];
    }

    #[DataProvider('pemFormProvider')]
    public function testReadsEveryPemFormOpenSslWrites(string $file, int $type): void
    {
        $key = OpenSsl::readPem(self::fixturePem($file), null);

        $this->assertSame($type, OpenSsl::details($key)['type']);
        $this->assertFalse(openssl_error_string());
    }

    public function testReadsThePublicKeyOfACertificatePem(): void
    {
        $fixture = self::fixture('rfc7517/appendix-b.json');
        /** @var list<string> $chain */
        $chain = $fixture['x5c'];
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split($chain[0], 64, "\n") . "-----END CERTIFICATE-----\n";

        $key = OpenSsl::readPem($pem, null);

        $this->assertSame(OPENSSL_KEYTYPE_RSA, OpenSsl::details($key)['type']);
        $this->assertSame(OpenSsl::publicPem(Jwk::fromJson($fixture)->toOpenSslKey()), OpenSsl::publicPem($key));
    }

    public function testReadsAnEncryptedPemWithItsPassphraseOnly(): void
    {
        $key = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ecc-p256.private.pem'), null);
        $encrypted = OpenSsl::privatePem($key, 'secret');

        $read = OpenSsl::readPem($encrypted, 'secret');
        $this->assertSame(OpenSsl::publicPem($key), OpenSsl::publicPem($read));
        $this->assertFalse(openssl_error_string());

        foreach ([null, 'wrong', ''] as $passphrase) {
            try {
                OpenSsl::readPem($encrypted, $passphrase);
                $this->fail('Expected ConversionFailed');
            } catch (ConversionFailed $exception) {
                $this->assertSame(ConversionFailedReason::UnreadablePem, $exception->reason);
                $this->assertStringStartsWith(
                    'OpenSSL could not read a key from the PEM text: error:',
                    $exception->getMessage(),
                );
                $this->assertStringContainsString('bad decrypt', $exception->getMessage());
            }

            $this->assertFalse(openssl_error_string());
        }
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function bundleOrderProvider(): iterable
    {
        yield 'the certificate first' => [true];
        yield 'the key first' => [false];
    }

    #[DataProvider('bundleOrderProvider')]
    public function testRefusesAnEncryptedKeyBesideACertificateWithoutItsPassphrase(bool $certificateFirst): void
    {
        /** @var list<string> $chain */
        $chain = self::fixture('rfc7517/appendix-b.json')['x5c'];
        $certificate = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split($chain[0], 64, "\n")
            . "-----END CERTIFICATE-----\n";
        $key = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ecc-p256.private.pem'), null);
        $encrypted = OpenSsl::privatePem($key, 'secret');
        $bundle = $certificateFirst ? $certificate . $encrypted : $encrypted . $certificate;

        $read = OpenSsl::readPem($bundle, 'secret');
        $this->assertSame(OpenSsl::privatePem($key, null), OpenSsl::privatePem($read, null));
        $this->assertFalse(openssl_error_string());

        foreach ([null, 'wrong', ''] as $passphrase) {
            try {
                OpenSsl::readPem($bundle, $passphrase);
                $this->fail('Expected ConversionFailed');
            } catch (ConversionFailed $exception) {
                $this->assertSame(ConversionFailedReason::UnreadablePem, $exception->reason);
                $this->assertStringStartsWith(
                    'OpenSSL could not read a key from the PEM text: error:',
                    $exception->getMessage(),
                );
                $this->assertStringContainsString('bad decrypt', $exception->getMessage());
            }

            $this->assertFalse(openssl_error_string());
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function privateKeyLabelProvider(): iterable
    {
        yield 'PKCS #8' => ['PRIVATE KEY'];
        yield 'PKCS #8 encrypted' => ['ENCRYPTED PRIVATE KEY'];
        yield 'PKCS #1' => ['RSA PRIVATE KEY'];
        yield 'SEC 1' => ['EC PRIVATE KEY'];
    }

    #[DataProvider('privateKeyLabelProvider')]
    public function testDoesNotReadTheCertificateBesideAPrivateKeyThatDoesNotRead(string $label): void
    {
        /** @var list<string> $chain */
        $chain = self::fixture('rfc7517/appendix-b.json')['x5c'];
        $certificate = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split($chain[0], 64, "\n")
            . "-----END CERTIFICATE-----\n";
        $bundle = $certificate . "-----BEGIN {$label}-----\nAAAA\n-----END {$label}-----\n";

        try {
            OpenSsl::readPem($bundle, null);
            $this->fail('Expected ConversionFailed');
        } catch (ConversionFailed $exception) {
            $this->assertSame(ConversionFailedReason::UnreadablePem, $exception->reason);
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testIgnoresAPassphraseGivenForAnUnencryptedPem(): void
    {
        $pem = self::fixturePem('rfc9421/test-key-ed25519.private.pem');
        $expected = OpenSsl::publicPem(OpenSsl::readPem($pem, null));

        $this->assertSame($expected, OpenSsl::publicPem(OpenSsl::readPem($pem, 'unused')));
        $this->assertSame(
            $expected,
            OpenSsl::publicPem(OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ed25519.public.pem'), 'unused')),
        );
    }

    public function testRefusesAFilePathBeforeOpenSslSeesIt(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('A key must be given as PEM text, not as a file path');

        OpenSsl::readPem('file:///etc/hosts', null);
    }

    public function testRefusesTextThatIsNotAPemAndLeavesNoErrorBehind(): void
    {
        try {
            OpenSsl::readPem('not a pem', null);
            $this->fail('Expected ConversionFailed');
        } catch (ConversionFailed $exception) {
            $this->assertSame(ConversionFailedReason::UnreadablePem, $exception->reason);
            $this->assertStringStartsWith(
                'OpenSSL could not read a key from the PEM text: error:',
                $exception->getMessage(),
            );
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testDrainsStaleErrorsBeforeReadingAPem(): void
    {
        @openssl_pkey_get_public('not a key');

        OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ed25519.public.pem'), null);

        $this->assertFalse(openssl_error_string());
    }

    public function testStaleErrorsDoNotReachTheMessageOfAnUnreadablePem(): void
    {
        @openssl_x509_read('not a certificate');

        try {
            OpenSsl::readPem('not a pem', null);
            $this->fail('Expected ConversionFailed');
        } catch (ConversionFailed $exception) {
            $this->assertStringNotContainsString('no start line', $exception->getMessage());
        }
    }

    public function testReadsAPemWithTextBeforeItAndCrlfLineEndings(): void
    {
        $pem = self::fixturePem('rfc9421/test-key-ecc-p256.public.pem');
        $key = OpenSsl::readPem("Subject: test\r\n" . str_replace("\n", "\r\n", $pem), null);

        $this->assertSame($pem, OpenSsl::publicPem($key));
    }

    public function testWritesThePublicPemOfAPrivateKeyInTheStrictForm(): void
    {
        $key = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-rsa.private.pem'), null);
        $pem = OpenSsl::publicPem($key);

        $this->assertSame(self::fixturePem('rfc9421/test-key-rsa.public.spki.pem'), $pem);
        $this->assertTrue(str_ends_with($pem, "-----END PUBLIC KEY-----\n"));
        $this->assertFalse(str_contains($pem, "\r"));

        $lines = explode("\n", $pem);

        foreach (array_slice($lines, 1, -3) as $line) {
            $this->assertSame(64, strlen($line));
        }
    }

    public function testWritesThePrivatePemAsUnencryptedPkcs8(): void
    {
        $key = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ecc-p256.private.pem'), null);

        $this->assertSame(
            self::fixturePem('rfc9421/test-key-ecc-p256.private.pkcs8.pem'),
            OpenSsl::privatePem($key, null),
        );
        $this->assertFalse(openssl_error_string());
    }

    public function testEncryptsThePrivatePemWithAes256CbcAndNotTripleDes(): void
    {
        $key = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ecc-p256.private.pem'), null);
        $pem = OpenSsl::privatePem($key, 'secret');

        $this->assertStringStartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", $pem);
        $this->assertTrue(str_ends_with($pem, "-----END ENCRYPTED PRIVATE KEY-----\n"));

        $der = base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $pem), true);
        $this->assertIsString($der);
        // The PBES2 scheme names its cipher by object identifier: aes256-CBC
        // is 2.16.840.1.101.3.4.1.42 and des-ede3-cbc is 1.2.840.113549.3.7.
        $this->assertTrue(str_contains($der, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2a"));
        $this->assertFalse(str_contains($der, "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x07"));
        $this->assertSame(OpenSsl::publicPem($key), OpenSsl::publicPem(OpenSsl::readPem($pem, 'secret')));
    }

    public function testPrivatePemRefusesAnEmptyPassphrase(): void
    {
        $key = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ed25519.private.pem'), null);

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('The passphrase must not be empty; pass null for an unencrypted PEM');

        OpenSsl::privatePem($key, '');
    }

    public function testPrivatePemThrowsWhenOpenSslDoesNotExportTheKey(): void
    {
        $key = OpenSsl::readPem(self::fixturePem('rfc9421/test-key-ed25519.public.pem'), null);
        @openssl_x509_read('not a certificate');

        try {
            OpenSsl::privatePem($key, null);
            $this->fail('Expected LogicException');
        } catch (LogicException $exception) {
            $this->assertSame('OpenSSL could not export the private key', $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testPrivatePemAppendsOpenSslsErrorTextWhenThereIsAny(): void
    {
        $fixture = self::fixture('rfc9421/test-key-rsa.json');
        $members = [];

        foreach (['n', 'e', 'd'] as $name) {
            $members[$name] = Base64Url::decode(self::fixtureString($fixture, $name));
        }

        $key = openssl_pkey_new(['rsa' => $members]);
        $this->assertNotFalse($key);

        try {
            OpenSsl::privatePem($key, null);
            $this->fail('Expected LogicException');
        } catch (LogicException $exception) {
            $this->assertStringStartsWith('OpenSSL could not export the private key: error:', $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testReadsThePublicKeyOfADerCertificate(): void
    {
        $fixture = self::fixture('rfc7517/appendix-b.json');
        /** @var list<string> $chain */
        $chain = $fixture['x5c'];
        $der = base64_decode($chain[0], true);
        $this->assertIsString($der);

        $key = OpenSsl::certificatePublicKey($der, 'unused', 'x5c');

        $this->assertSame(OpenSsl::publicPem(Jwk::fromJson($fixture)->toOpenSslKey()), OpenSsl::publicPem($key));
        $this->assertFalse(openssl_error_string());
    }

    public function testRefusesBytesThatAreNotACertificate(): void
    {
        @openssl_pkey_get_public('not a key');

        try {
            OpenSsl::certificatePublicKey("\x30\x03\x02\x01\x01", 'Not a certificate', 'x5c');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidCertificate, $exception->reason);
            $this->assertSame('x5c', $exception->member);
            $this->assertStringStartsWith('Not a certificate: error:', $exception->getMessage());
            $this->assertStringNotContainsString('DECODER', $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());
    }
}
