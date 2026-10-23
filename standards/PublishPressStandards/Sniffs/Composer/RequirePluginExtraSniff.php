<?php

namespace PublishPressStandards\Sniffs\Composer;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

class RequirePluginExtraSniff implements Sniff
{
    /**
     * Keys required by dev-workspace pack.sh plus version-constant for release checks.
     *
     * @var string[]
     */
    public $requiredExtraKeys = [
        'plugin-name',
        'plugin-slug',
        'plugin-folder',
        'version-constant',
        'plugin-lang-domain',
        'plugin-github-repo',
        'plugin-composer-package',
    ];

    /**
     * @return int[]
     */
    public function register()
    {
        return [T_OPEN_TAG];
    }

    /**
     * @param \PHP_CodeSniffer\Files\File $phpcsFile
     * @param int                         $stackPtr
     *
     * @return void|int
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $filePath = $phpcsFile->getFilename();

        if ($this->isUnderExcludedPath($filePath)) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if (!$this->isPluginMainFile($phpcsFile)) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        $pluginRoot = dirname($filePath);
        $composerPath = $pluginRoot . DIRECTORY_SEPARATOR . 'composer.json';

        if (!is_file($composerPath)) {
            $phpcsFile->addWarning(
                'Plugin root is missing composer.json required for dev-workspace builder metadata.',
                $stackPtr,
                'MissingFile'
            );

            return (count($phpcsFile->getTokens()) + 1);
        }

        $contents = file_get_contents($composerPath);

        if ($contents === false) {
            $phpcsFile->addWarning(
                'Could not read composer.json in the plugin root.',
                $stackPtr,
                'InvalidJson'
            );

            return (count($phpcsFile->getTokens()) + 1);
        }

        $decoded = json_decode($contents);

        if (!is_object($decoded)) {
            $phpcsFile->addWarning(
                'composer.json in the plugin root is not valid JSON.',
                $stackPtr,
                'InvalidJson'
            );

            return (count($phpcsFile->getTokens()) + 1);
        }

        $extra = isset($decoded->extra) ? $decoded->extra : null;

        foreach ($this->requiredExtraKeys as $key) {
            if (!$this->hasNonEmptyStringExtra($extra, $key)) {
                $phpcsFile->addWarning(
                    'composer.json extra.%s is missing or empty; dev-workspace scripts require it.',
                    $stackPtr,
                    'Missing',
                    [$key]
                );
            }
        }

        return (count($phpcsFile->getTokens()) + 1);
    }

    /**
     * @param string $filePath
     *
     * @return bool
     */
    private function isUnderExcludedPath($filePath)
    {
        $normalized = str_replace('\\', '/', $filePath);

        return (strpos($normalized, '/vendor/') !== false
            || strpos($normalized, '/node_modules/') !== false);
    }

    /**
     * @param \PHP_CodeSniffer\Files\File $phpcsFile
     *
     * @return bool
     */
    private function isPluginMainFile(File $phpcsFile)
    {
        $header = $phpcsFile->getTokensAsString(0, min(50, count($phpcsFile->getTokens())));

        return (strpos($header, 'Plugin Name:') !== false);
    }

    /**
     * @param mixed  $extra
     * @param string $key
     *
     * @return bool
     */
    private function hasNonEmptyStringExtra($extra, $key)
    {
        if (!is_object($extra) || !isset($extra->{$key})) {
            return false;
        }

        $value = $extra->{$key};

        if (!is_string($value)) {
            return false;
        }

        return trim($value) !== '';
    }
}
