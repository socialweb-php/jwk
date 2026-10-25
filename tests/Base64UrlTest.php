<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\Exception\InvalidArgument;

use function random_bytes;
use function random_int;

class Base64UrlTest extends TestCase
{
    public function testEncodesTheRfc7515AppendixCExample(): void
    {
        $this->assertSame('A-z_4ME', Base64Url::encode("\x03\xec\xff\xe0\xc1"));
    }

    public function testDecodesTheRfc7515AppendixCExample(): void
    {
        $this->assertSame("\x03\xec\xff\xe0\xc1", Base64Url::decode('A-z_4ME'));
    }

    public function testTheEmptyStringEncodesToTheEmptyString(): void
    {
        $this->assertSame('', Base64Url::encode(''));
        $this->assertSame('', Base64Url::decode(''));
    }

    public function testEveryLengthRoundTrips(): void
    {
        for ($length = 1; $length <= 70; $length++) {
            $bytes = random_bytes($length);
            $text = Base64Url::encode($bytes);

            $this->assertSame($bytes, Base64Url::decode($text));
            $this->assertStringNotContainsString('=', $text);
            $this->assertStringNotContainsString('+', $text);
            $this->assertStringNotContainsString('/', $text);
        }
    }

    public function testEncodesTheBase64urlUIntOf65537AsAqab(): void
    {
        $this->assertSame('AQAB', Base64Url::encode("\x01\x00\x01"));
        $this->assertSame("\x01\x00\x01", Base64Url::decode('AQAB'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refusedProvider(): iterable
    {
        yield 'padding' => ['AQAB==', 'The text has a character outside the base64url alphabet'];
        yield 'the standard alphabet plus' => ['A+z/4ME', 'The text has a character outside the base64url alphabet'];
        yield 'the standard alphabet slash' => ['A-z/4ME', 'The text has a character outside the base64url alphabet'];
        yield 'a space' => ['AQ AB', 'The text has a character outside the base64url alphabet'];
        yield 'a line break' => ["AQAB\n", 'The text has a character outside the base64url alphabet'];
        yield 'one character' => ['A', 'The text has a length no byte sequence encodes in base64url'];
        yield 'five characters' => ['AQABA', 'The text has a length no byte sequence encodes in base64url'];
        yield 'stray bits in the last of two characters' => [
            'AB',
            'The text is not the canonical base64url encoding of its bytes',
        ];
        yield 'stray bits in the last of three characters' => [
            'AAB',
            'The text is not the canonical base64url encoding of its bytes',
        ];
        yield 'stray bits after a valid prefix' => [
            'A-z_4MF',
            'The text is not the canonical base64url encoding of its bytes',
        ];
    }

    #[DataProvider('refusedProvider')]
    public function testRefusesTextThatIsNotCanonicalBase64Url(string $text, string $message): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains($message);

        Base64Url::decode($text);
    }

    public function testACanonicalEncodingDecodesWhenTheStrayBitsAreZero(): void
    {
        $this->assertSame("\x00", Base64Url::decode('AA'));
        $this->assertSame("\x00\x00", Base64Url::decode('AAA'));
        $this->assertSame("\xff", Base64Url::decode('_w'));
        $this->assertSame("\xff\xff", Base64Url::decode('__8'));
    }

    public function testDecodingIsTheInverseOfEncodingForRandomInput(): void
    {
        $bytes = random_bytes(random_int(1, 200));

        $this->assertSame($bytes, Base64Url::decode(Base64Url::encode($bytes)));
    }
}
