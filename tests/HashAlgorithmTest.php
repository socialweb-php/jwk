<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\HashAlgorithm;

use function hash;
use function strlen;

class HashAlgorithmTest extends TestCase
{
    /**
     * @return iterable<string, array{HashAlgorithm, string, string, int}>
     */
    public static function algorithmProvider(): iterable
    {
        yield 'SHA-256' => [HashAlgorithm::Sha256, 'sha-256', 'sha256', 32];
        yield 'SHA-384' => [HashAlgorithm::Sha384, 'sha-384', 'sha384', 48];
        yield 'SHA-512' => [HashAlgorithm::Sha512, 'sha-512', 'sha512', 64];
    }

    #[DataProvider('algorithmProvider')]
    public function testNamesTheFunctionForTheRegistryAndForHash(
        HashAlgorithm $algorithm,
        string $registryName,
        string $hashName,
        int $digestLength,
    ): void {
        $this->assertSame($registryName, $algorithm->value);
        $this->assertSame($hashName, $algorithm->hashName());
        $this->assertSame($digestLength, $algorithm->digestLength());
        $this->assertSame($digestLength, strlen(hash($algorithm->hashName(), '', true)));
    }
}
