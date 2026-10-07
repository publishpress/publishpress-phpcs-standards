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
            ['RequireDirectAccessGuard/valid-braced.php'],
            ['RequireDirectAccessGuard/valid-declare-namespace-use.php'],
            ['RequireDirectAccessGuard/valid-braced-namespace.php'],
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

    public function testFlagsMissingGuardAsNotFixableWhenUsesFollowInvalidGuard()
    {
        $fixture = $this->fixturePath('RequireDirectAccessGuard/missing-not-fixable.php');
        $report  = $this->runPhpcsOnFixture('RequireDirectAccessGuard/missing-not-fixable.php', [$this->sniff]);

        $this->assertSame(1, $report['totals']['errors']);
        $this->assertSame(0, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.Missing', $messages[0]['source']);
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
