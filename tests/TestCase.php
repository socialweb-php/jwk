<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase as BaseTestCase;
use RuntimeException;

use function file_get_contents;
use function hex2bin;
use function is_array;
use function is_string;
use function json_decode;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_sign;
use function preg_replace;

use const JSON_THROW_ON_ERROR;

/**
 * A base test case for common test functionality
 */
class TestCase extends BaseTestCase
{
    /**
     * Returns the JSON text of a fixture under `tests/fixtures/`, such as
     * `rfc7517/appendix-a1.json`
     */
    protected static function fixtureJson(string $file): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $file);

        if ($contents === false) {
            throw new RuntimeException('Cannot read the fixture ' . $file);
        }

        return $contents;
    }

    /**
     * Returns the text of a PEM fixture under `tests/fixtures/`, such as
     * `rfc8410/section-10.1-public.pem`
     */
    protected static function fixturePem(string $file): string
    {
        return self::fixtureJson($file);
    }

    /**
     * Returns a fixture decoded to an array
     *
     * @return array<string, mixed>
     */
    protected static function fixture(string $file): array
    {
        /** @var mixed $decoded */
        $decoded = json_decode(self::fixtureJson($file), true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($decoded)) {
            throw new RuntimeException('The fixture ' . $file . ' is not a JSON object');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * Returns one member of a fixture JWK Set, decoded
     *
     * @return array<string, mixed>
     */
    protected static function fixtureSetMember(string $file, int $index): array
    {
        /** @var array{keys: list<array<string, mixed>>} $set */
        $set = self::fixture($file);

        return $set['keys'][$index];
    }

    /**
     * Returns a string member of a decoded fixture
     *
     * @param array<string, mixed> $fixture
     */
    protected static function fixtureString(array $fixture, string $member): string
    {
        $value = $fixture[$member] ?? null;

        if (!is_string($value)) {
            throw new RuntimeException('The fixture member ' . $member . ' is not a string');
        }

        return $value;
    }

    /**
     * Signs a fixed message with the key through OpenSSL and returns the
     * signature, so that a test can verify it with another key
     */
    protected static function sign(OpenSSLAsymmetricKey $key, int | string $algorithm): string
    {
        $signature = '';

        if (!openssl_sign('message', $signature, $key, $algorithm) || !is_string($signature)) {
            throw new RuntimeException('OpenSSL could not sign');
        }

        return $signature;
    }

    /**
     * Returns the private key as the PKCS #8 PEM `openssl_pkey_export()`
     * writes
     */
    protected static function exportPrivatePem(OpenSSLAsymmetricKey $key): string
    {
        $pem = '';

        if (!openssl_pkey_export($key, $pem) || !is_string($pem)) {
            throw new RuntimeException('OpenSSL could not export the key');
        }

        return $pem;
    }

    /**
     * Returns the public key as the SubjectPublicKeyInfo PEM in the `key`
     * entry of `openssl_pkey_get_details()`
     */
    protected static function exportPublicPem(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);
        $pem = $details === false ? null : $details['key'];

        if (!is_string($pem)) {
            throw new RuntimeException('OpenSSL reported no public key PEM');
        }

        return $pem;
    }

    /**
     * Returns the bytes of a hexadecimal string, with any spaces and line
     * breaks ignored, as the RFC test vectors print them
     */
    protected static function hex(string $hex): string
    {
        $bytes = hex2bin((string) preg_replace('/\s+/', '', $hex));

        if ($bytes === false) {
            throw new RuntimeException('The string is not hexadecimal');
        }

        return $bytes;
    }
}
