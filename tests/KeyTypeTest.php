<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\KeyType;

class KeyTypeTest extends TestCase
{
    public function testIsBackedByTheRegisteredKtyValues(): void
    {
        $this->assertSame('RSA', KeyType::Rsa->value);
        $this->assertSame('EC', KeyType::Ec->value);
        $this->assertSame('OKP', KeyType::Okp->value);
        $this->assertSame('oct', KeyType::Oct->value);
        $this->assertNull(KeyType::tryFrom('rsa'));
        $this->assertNull(KeyType::tryFrom('OCT'));
    }

    /**
     * @return iterable<string, array{KeyType, non-empty-list<string>}>
     */
    public static function privateMemberNamesProvider(): iterable
    {
        yield 'RSA' => [KeyType::Rsa, ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']];
        yield 'EC' => [KeyType::Ec, ['d']];
        yield 'OKP' => [KeyType::Okp, ['d']];
        yield 'oct' => [KeyType::Oct, ['k']];
    }

    /**
     * @param non-empty-list<string> $expected
     */
    #[DataProvider('privateMemberNamesProvider')]
    public function testNamesThePrivateMembers(KeyType $type, array $expected): void
    {
        $this->assertSame($expected, $type->privateMemberNames());
    }
}
