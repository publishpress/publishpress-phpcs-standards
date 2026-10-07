<?php

namespace PublishPressPhpcsStandards\Tests;

final class DisallowDirectAutoloadSniffTest extends PhpcsTestCase
{
    /**
     * @var string
     */
    private $sniff = 'PublishPressStandards.Libraries.DisallowDirectAutoload';

    public function testFlagsDirectPublishpressLibraryAutoloadPaths()
    {
        $fixture = $this->fixturePath('DisallowDirectAutoload/invalid-autoload.php');
        $report  = $this->runPhpcsOnFixture('DisallowDirectAutoload/invalid-autoload.php', [$this->sniff]);

        $this->assertSame(4, $report['totals']['errors']);
        $this->assertSame(4, $report['totals']['fixable']);

        $messages = $this->messagesForFixture($report, $fixture);
        $lines    = array_column($messages, 'line');

        $this->assertSame([5, 6, 7, 8], $lines);

        foreach ($messages as $message) {
            $this->assertSame('ERROR', $message['type']);
            $this->assertSame($this->sniff . '.Found', $message['source']);
        }
    }

    public function testAllowsIncludePhpAndUnrelatedAutoloadPaths()
    {
        $fixture = $this->fixturePath('DisallowDirectAutoload/valid-loads.php');
        $report  = $this->runPhpcsOnFixture('DisallowDirectAutoload/valid-loads.php', [$this->sniff]);

        $this->assertSame(0, $report['totals']['errors']);

        if (isset($report['files'][$fixture])) {
            $this->assertSame([], $report['files'][$fixture]['messages']);
        }
    }

    public function testPhpcbfRewritesAutoloadPathsToIncludePhp()
    {
        $fixedFixture = $this->fixturePath('DisallowDirectAutoload/invalid-autoload-fixed.php');
        $target       = $this->runPhpcbfOnFixtureCopy('DisallowDirectAutoload/invalid-autoload.php', [$this->sniff]);

        $this->assertFileEquals($fixedFixture, $target);

        unlink($target);
    }
}
