<?php

namespace PublishPressPhpcsStandards\Tests;

final class RequirePluginExtraSniffTest extends PhpcsTestCase
{
    /**
     * @var string
     */
    private $sniff = 'PublishPressStandards.Composer.RequirePluginExtra';

    public function testAllowsCompleteExtraMetadata()
    {
        $fixture = $this->fixturePath('RequirePluginExtra/valid/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequirePluginExtra/valid/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertSame(0, $report['totals']['warnings']);

        if (isset($report['files'][$fixture])) {
            $this->assertSame([], $report['files'][$fixture]['messages']);
        }
    }

    public function testWarnsWhenComposerJsonIsMissing()
    {
        $fixture = $this->fixturePath('RequirePluginExtra/missing-composer-json/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequirePluginExtra/missing-composer-json/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertSame(1, $report['totals']['warnings']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.MissingFile', $messages[0]['source']);
    }

    public function testWarnsForEachRequiredKeyWhenExtraObjectIsMissing()
    {
        $fixture = $this->fixturePath('RequirePluginExtra/missing-extra/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequirePluginExtra/missing-extra/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertSame(7, $report['totals']['warnings']);

        $messages = $this->messagesForFixture($report, $fixture);
        $sources  = array_column($messages, 'source');

        foreach ($sources as $source) {
            $this->assertSame($this->sniff . '.Missing', $source);
        }
    }

    public function testWarnsForMissingKeysInPlannerShapedExtra()
    {
        $fixture = $this->fixturePath('RequirePluginExtra/partial-extra/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequirePluginExtra/partial-extra/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertSame(4, $report['totals']['warnings']);

        $messages = $this->messagesForFixture($report, $fixture);
        $bodies   = array_column($messages, 'message');

        $this->assertTrue(
            (bool) preg_grep('/version-constant/', $bodies),
            'Expected a warning for version-constant.'
        );
        $this->assertTrue(
            (bool) preg_grep('/plugin-lang-domain/', $bodies),
            'Expected a warning for plugin-lang-domain.'
        );
        $this->assertTrue(
            (bool) preg_grep('/plugin-github-repo/', $bodies),
            'Expected a warning for plugin-github-repo.'
        );
        $this->assertTrue(
            (bool) preg_grep('/plugin-composer-package/', $bodies),
            'Expected a warning for plugin-composer-package.'
        );
    }

    public function testWarnsWhenExtraValueIsEmptyString()
    {
        $fixture = $this->fixturePath('RequirePluginExtra/empty-value/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequirePluginExtra/empty-value/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertSame(1, $report['totals']['warnings']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.Missing', $messages[0]['source']);
        $this->assertStringContainsString('version-constant', $messages[0]['message']);
    }

    public function testSkipsFilesWithoutPluginHeader()
    {
        $fixture = $this->fixturePath('RequirePluginExtra/no-plugin-header/helper.php');
        $report  = $this->runPhpcsOnFixture(
            'RequirePluginExtra/no-plugin-header/helper.php',
            [$this->sniff]
        );

        $this->assertSame(0, $report['totals']['warnings']);

        if (isset($report['files'][$fixture])) {
            $this->assertSame([], $report['files'][$fixture]['messages']);
        }
    }
}
