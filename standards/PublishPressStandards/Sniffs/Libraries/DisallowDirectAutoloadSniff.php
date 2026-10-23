<?php

namespace PublishPressStandards\Sniffs\Libraries;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

class DisallowDirectAutoloadSniff implements Sniff
{
    /**
     * PublishPress shared library paths must use include.php, not autoload.php.
     *
     * @var string
     */
    private $disallowedPathPattern = '(^|/)publishpress/[^/]+/lib/autoload\.php$';

    /**
     * @return int[]
     */
    public function register()
    {
        return [
            T_REQUIRE,
            T_REQUIRE_ONCE,
            T_INCLUDE,
            T_INCLUDE_ONCE,
        ];
    }

    /**
     * @param \PHP_CodeSniffer\Files\File $phpcsFile
     * @param int                         $stackPtr
     *
     * @return void
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $semicolon = $phpcsFile->findNext(T_SEMICOLON, ($stackPtr + 1));

        if ($semicolon === false) {
            return;
        }

        for ($i = ($stackPtr + 1); $i < $semicolon; $i++) {
            if ($tokens[$i]['code'] !== T_CONSTANT_ENCAPSED_STRING
                && $tokens[$i]['code'] !== T_DOUBLE_QUOTED_STRING
            ) {
                continue;
            }

            $path = $this->stripQuotes($tokens[$i]['content']);

            if (preg_match('#' . $this->disallowedPathPattern . '#', $path) !== 1) {
                continue;
            }

            $error = 'PublishPress shared libraries must be loaded via include.php, not autoload.php. Found "%s"';
            $data  = [$path];
            $fix   = $phpcsFile->addFixableError($error, $i, 'Found', $data);

            if ($fix === true) {
                $replacement = str_replace('autoload.php', 'include.php', $tokens[$i]['content']);
                $phpcsFile->fixer->replaceToken($i, $replacement);
            }
        }
    }

    /**
     * @param string $quoted
     *
     * @return string
     */
    private function stripQuotes($quoted)
    {
        return substr($quoted, 1, -1);
    }
}
