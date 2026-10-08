<?php

namespace PublishPressPhpcsStandards\Tests;

final class RequireDirectAccessGuardSniffTest extends PhpcsTestCase
{
    /**
     * @var string
     */
    private $sniff = 'PublishPressStandards.Security.RequireDirectAccessGuard';

    /**
     * @return string[]
     */
    public function validFixtureProvider()
    {
        return [
            ['RequireDirectAccessGuard/valid-oneliner.php'],
            ['RequireDirectAccessGuard/valid-no-comment.php'],
            ['RequireDirectAccessGuard/valid-declare-namespace-use.php'],
            ['RequireDirectAccessGuard/valid-braced-namespace.php'],
            ['RequireDirectAccessGuard/valid-closure-use.php'],
            ['RequireDirectAccessGuard/valid-guard-above-class-docblock.php'],
            ['RequireDirectAccessGuard/valid-file-docblock.php'],
            ['RequireDirectAccessGuard/valid-use-function-defined.php'],
        ];
    }

    /**
     * @dataProvider validFixtureProvider
     *
     * @param string $fixtureRelativePath
     */
    public function testAllowsValidDirectAccessGuards($fixtureRelativePath)
    {
        $fixture = $this->fixturePath($fixtureRelativePath);
        $report  = $this->runPhpcsOnFixture($fixtureRelativePath, [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);

        if (isset($report['files'][$fixture])) {
            $this->assertSame([], $report['files'][$fixture]['messages']);
        }
    }

    public function testFlagsMissingGuardAsFixable()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/missing-guard.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/missing-guard.php', [$this->sniff]);

        $this->assertSame(1, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.Missing', $messages[0]['source']);
    }

    public function testPhpcbfInsertsMissingGuard()
    {
        $fixedFixture = $this->fixturePath('RequireDirectAccessGuard/missing-guard-fixed.php');
        $target       = $this->runPhpcbfOnFixtureCopy('RequireDirectAccessGuard/missing-guard.php', [$this->sniff]);

        $this->assertFileEquals($fixedFixture, $target);

        unlink($target);
    }

    public function testPhpcbfInsertsGuardAboveClassDocblock()
    {
        $fixedFixture = $this->fixturePath('RequireDirectAccessGuard/missing-guard-class-docblock-fixed.php');
        $target       = $this->runPhpcbfOnFixtureCopy(
            'RequireDirectAccessGuard/missing-guard-class-docblock.php',
            [$this->sniff]
        );

        $this->assertFileEquals($fixedFixture, $target);

        unlink($target);
    }

    public function testPhpcbfKeepsFileDocblockAboveGuard()
    {
        $fixedFixture = $this->fixturePath('RequireDirectAccessGuard/missing-guard-file-docblock-fixed.php');
        $target       = $this->runPhpcbfOnFixtureCopy(
            'RequireDirectAccessGuard/missing-guard-file-docblock.php',
            [$this->sniff]
        );

        $this->assertFileEquals($fixedFixture, $target);

        unlink($target);
    }

    public function testPhpcbfMovesGuardAboveClassDocblock()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/guard-splits-class-docblock.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/guard-splits-class-docblock.php', [$this->sniff]);

        $this->assertSame(1, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.SplitsDocblock', $messages[0]['source']);

        $fixedFixture = $this->fixturePath('RequireDirectAccessGuard/guard-splits-class-docblock-fixed.php');
        $target       = $this->runPhpcbfOnFixtureCopy(
            'RequireDirectAccessGuard/guard-splits-class-docblock.php',
            [$this->sniff]
        );

        $this->assertFileEquals($fixedFixture, $target);

        unlink($target);
    }

    public function testFlagsHtmlFirstFileAsFixableMissing()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/html-first.html.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/html-first.html.php', [$this->sniff]);

        $this->assertSame(1, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.Missing', $messages[0]['source']);
    }

    public function testPhpcbfPrependsGuardToHtmlFirstFile()
    {
        $fixedFixture = $this->fixturePath('RequireDirectAccessGuard/html-first-fixed.html.php');
        $target       = $this->runPhpcbfOnFixtureCopy('RequireDirectAccessGuard/html-first.html.php', [$this->sniff]);

        $this->assertFileEquals($fixedFixture, $target);

        unlink($target);
    }

    public function testWarnsOnLegacyDefinedOrDieWithoutAutofix()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/legacy-defined-or-die.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/legacy-defined-or-die.php', [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['warnings']);
        $this->assertSame(0, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame('WARNING', $messages[0]['type']);
        $this->assertSame($this->sniff . '.NonStandardSyntax', $messages[0]['source']);
    }

    public function testPhpcbfDoesNotModifyLegacyDefinedOrDieGuard()
    {
        $source = $this->fixturePath('RequireDirectAccessGuard/legacy-defined-or-die.php');
        $target = $this->runPhpcbfOnFixtureCopy('RequireDirectAccessGuard/legacy-defined-or-die.php', [$this->sniff]);

        $this->assertFileEquals($source, $target);

        unlink($target);
    }

    public function testWarnsWhenIfDieGuardAppearsBeforeUseStatements()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/missing-not-fixable.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/missing-not-fixable.php', [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['warnings']);
        $this->assertSame(0, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.NonStandardSyntax', $messages[0]['source']);
    }

    public function testWarnsOnLegacyDefinedBooleanOr()
    {
        $report = $this->runPhpcsOnFixture('RequireDirectAccessGuard/legacy-defined-boolean-or.php', [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['warnings']);
    }

    public function testWarnsOnLegacyIfDieWithoutAutofix()
    {
        $source = $this->fixturePath('RequireDirectAccessGuard/legacy-if-die.php');
        $report = $this->runPhpcsOnFixture('RequireDirectAccessGuard/legacy-if-die.php', [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['warnings']);

        $target = $this->runPhpcbfOnFixtureCopy('RequireDirectAccessGuard/legacy-if-die.php', [$this->sniff]);
        $this->assertFileEquals($source, $target);
        unlink($target);
    }

    public function testFlagsMissingGuardWhenLegacyAppearsOnlyInsideFunction()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/legacy-in-function-missing.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/legacy-in-function-missing.php', [$this->sniff]);

        $this->assertSame(1, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['fixable']);
        $this->assertSame(0, $report['totals']['warnings']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.Missing', $messages[0]['source']);
    }

    public function testFlagsHtmlFirstMissingWhenLegacyIsOnlyInEmbeddedPhp()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/html-first-legacy-in-embedded-php.html.php');
        $report  = $this->runPhpcsOnFixture(
            'RequireDirectAccessGuard/html-first-legacy-in-embedded-php.html.php',
            [$this->sniff]
        );

        $this->assertSame(1, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['fixable']);
        $this->assertSame(0, $report['totals']['warnings']);
    }

    public function testFlagsWrongPositionWhenGuardAppearsAfterClass()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/wrong-position-after-class.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/wrong-position-after-class.php', [$this->sniff]);

        $this->assertSame(1, $report['totals']['errors']);
        $this->assertSame(0, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.WrongPosition', $messages[0]['source']);
    }

    public function testWarnsOnIfStyleDirectAccessGuard()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/non-standard-if-braced.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/non-standard-if-braced.php', [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['warnings']);
        $this->assertSame(0, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.NonStandardSyntax', $messages[0]['source']);
    }

    public function testWarnsWhenNamespacedFileUsesDefinedWithoutBackslash()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/non-standard-defined-no-backslash.php');
        $report  = $this->runPhpcsOnFixture(
            'RequireDirectAccessGuard/non-standard-defined-no-backslash.php',
            [$this->sniff]
        );

        $this->assertSame(0, $report['totals']['errors']);
        $this->assertSame(1, $report['totals']['warnings']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.NonStandardSyntax', $messages[0]['source']);
    }

    public function testFlagsWrongPositionWhenGuardAppearsBeforeUse()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/wrong-position-before-use.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/wrong-position-before-use.php', [$this->sniff]);

        $this->assertSame(1, $report['totals']['errors']);
        $this->assertSame(0, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.WrongPosition', $messages[0]['source']);
    }

    public function testSkipsVendorPaths()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/vendor/example.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/vendor/example.php', [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);

        if (isset($report['files'][$fixture])) {
            $this->assertSame([], $report['files'][$fixture]['messages']);
        }
    }

    public function testSkipsShebangCliScripts()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/shebang-cli.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/shebang-cli.php', [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);

        if (isset($report['files'][$fixture])) {
            $this->assertSame([], $report['files'][$fixture]['messages']);
        }
    }
}
