<?php

namespace PublishPressStandards\Sniffs\Security;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;

class RequireDirectAccessGuardSniff implements Sniff
{
    /**
     * @var string
     */
    private $processedFile = '';

    /**
     * @return int[]
     */
    public function register()
    {
        return [
            T_OPEN_TAG,
            T_INLINE_HTML,
        ];
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

        if ($this->processedFile === $filePath) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($stackPtr !== 0) {
            return;
        }

        $this->processedFile = $filePath;

        if ($this->isUnderExcludedPath($filePath)) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($this->fileStartsWithShebang($filePath)) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        $tokens = $phpcsFile->getTokens();

        $analysis = $this->analyzeFile($tokens);

        if ($analysis === null) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($analysis['valid_guard_at_expected']) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($analysis['guard_splits_docblock']) {
            $fix = $phpcsFile->addFixableError(
                'Direct-access guard must appear before the class, interface, trait, or function docblock.',
                $analysis['split_guard_ptr'],
                'SplitsDocblock'
            );

            if ($fix === true) {
                $this->relocateGuardBeforeDocblock(
                    $phpcsFile,
                    $analysis['split_guard_ptr'],
                    $analysis['insert_before_ptr']
                );
            }

            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($analysis['valid_guard_ptr'] !== null && !$analysis['valid_guard_at_expected']) {
            $relocate = $analysis['wrong_position_relocate'];

            if ($relocate !== null) {
                $fix = $phpcsFile->addFixableError(
                    'Direct-access guard must appear immediately after namespace and use statements, before any other code.',
                    $analysis['valid_guard_ptr'],
                    'WrongPosition'
                );

                if ($fix === true) {
                    $this->relocateGuardAfterUses(
                        $phpcsFile,
                        $relocate['guard_ptr'],
                        $relocate['insert_ptr']
                    );
                }
            } else {
                $phpcsFile->addError(
                    'Direct-access guard must appear immediately after namespace and use statements, before any other code.',
                    $analysis['valid_guard_ptr'],
                    'WrongPosition'
                );
            }

            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($analysis['non_standard_guard_ptr'] !== null) {
            if ($this->isFullyQualifiedDefinedAfterImport(
                $tokens,
                $analysis['non_standard_guard_ptr'],
                $analysis['guard_context']
            )) {
                $phpcsFile->addWarning(
                    'use function defined already imports the global function; call it as '
                    . $this->formatStandardGuardExample($analysis['guard_context'])
                    . ' instead of \\defined.',
                    $analysis['non_standard_guard_ptr'],
                    'FullyQualifiedAfterFunctionImport'
                );
            } else {
                $phpcsFile->addWarning(
                    'Direct-access guard uses non-standard syntax; use '
                    . $this->formatStandardGuardExample($analysis['guard_context'])
                    . ' instead.',
                    $analysis['non_standard_guard_ptr'],
                    'NonStandardSyntax'
                );
            }

            return (count($phpcsFile->getTokens()) + 1);
        }

        $errorPtr = $analysis['expected_guard_ptr'];

        if ($errorPtr === false || !isset($tokens[$errorPtr])) {
            $errorPtr = $stackPtr;
        }

        if ($analysis['fixable']) {
            $guardLine = $this->buildGuardLine($analysis['guard_context']);
            $fix = $phpcsFile->addFixableError(
                'PHP file is missing a direct-access guard ('
                . $this->formatStandardGuardExample($analysis['guard_context'])
                . ').',
                $errorPtr,
                'Missing'
            );

            if ($fix === true) {
                if ($analysis['html_first']) {
                    $phpcsFile->fixer->addContentBefore(
                        $stackPtr,
                        $this->buildHtmlFirstGuard($analysis['guard_context'])
                    );
                } elseif ($this->shouldInsertGuardAfterOpenTag($tokens, $analysis['insert_before_ptr'])) {
                    $openTagPtr = $this->findFirstOpenTag($tokens, 0);
                    $phpcsFile->fixer->addContent(
                        $openTagPtr,
                        $phpcsFile->eolChar . $guardLine . $phpcsFile->eolChar
                    );
                } else {
                    $phpcsFile->fixer->addContentBefore(
                        $analysis['insert_before_ptr'],
                        $guardLine . $phpcsFile->eolChar . $phpcsFile->eolChar
                    );
                }
            }
        } else {
            $phpcsFile->addError(
                'PHP file is missing a direct-access guard ('
                . $this->formatStandardGuardExample($analysis['guard_context'])
                . ').',
                $errorPtr,
                'Missing'
            );
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
     * @param string $filePath
     *
     * @return bool
     */
    private function fileStartsWithShebang($filePath)
    {
        $handle = fopen($filePath, 'rb');

        if ($handle === false) {
            return false;
        }

        $firstLine = fgets($handle);
        fclose($handle);

        if ($firstLine === false) {
            return false;
        }

        return (strpos($firstLine, '#!') === 0);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     *
     * @return array<string, mixed>|null
     */
    private function analyzeFile(array $tokens)
    {
        $count = count($tokens);

        if ($count === 0) {
            return null;
        }

        $htmlFirst = ($tokens[0]['code'] === T_INLINE_HTML);
        $ptr = 0;
        $guardContext = $this->buildGuardContext($tokens);

        if ($htmlFirst) {
            $nonStandardGuardPtr = null;

            if ($tokens[0]['code'] === T_OPEN_TAG) {
                $firstPhpBlockEnd = $this->findFirstPhpBlockEnd($tokens, 0);
                $nonStandardGuardPtr = $this->findNonStandardGuardBetween(
                    $tokens,
                    1,
                    $firstPhpBlockEnd,
                    $guardContext
                );
            }

            return [
                'html_first' => true,
                'expected_guard_ptr' => 0,
                'insert_before_ptr' => 0,
                'valid_guard_ptr' => null,
                'non_standard_guard_ptr' => $nonStandardGuardPtr,
                'valid_guard_at_expected' => false,
                'guard_splits_docblock' => false,
                'split_guard_ptr' => null,
                'fixable' => ($nonStandardGuardPtr === null),
                'guard_context' => $guardContext,
            ];
        }

        $ptr = $this->findFirstOpenTag($tokens, $ptr);

        if ($ptr === false) {
            return null;
        }

        $ptr++;

        $ptr = $this->skipIgnorable($tokens, $ptr);

        while ($ptr < $count) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $count) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_DECLARE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($this->isDocblockOpen($tokens, $ptr)) {
                if ($this->isStructureDocblock($tokens, $ptr)) {
                    break;
                }

                $ptr = $this->docblockEnd($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_NAMESPACE) {
                $ptr = $this->skipNamespaceStatement($tokens, $ptr);
                continue;
            }

            if ($this->isStructureKeyword($tokens, $ptr)
                || $this->tokenIsStructureDeclaration($tokens, $ptr)
            ) {
                $ptr = $this->rewindToStructureDocblockIfNeeded($tokens, $ptr);
                break;
            }

            break;
        }

        $ptr = $this->rewindToStructureDocblockIfNeeded($tokens, $ptr);

        $preambleStart = $ptr;
        $lastUseEnd = $ptr;
        $nonStandardGuardPtr = null;
        $stopCodes = $this->scopeStopCodes();

        while ($ptr < $count) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $count) {
                break;
            }

            if (in_array($tokens[$ptr]['code'], $stopCodes, true)) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_USE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                $lastUseEnd = $ptr;
                continue;
            }

            if ($tokens[$ptr]['code'] === T_IF) {
                if ($nonStandardGuardPtr === null
                    && $this->isAbspathProtectionIfAt($tokens, $ptr)
                ) {
                    $nonStandardGuardPtr = $this->skipIgnorable($tokens, $ptr);
                }

                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($this->tokenIsDefinedFunction($tokens, $ptr)) {
                if ($nonStandardGuardPtr === null
                    && !$this->isStandardDirectAccessGuardAt($tokens, $ptr, $guardContext)
                    && $this->isNonStandardShortCircuitGuardAt($tokens, $ptr, $guardContext)
                ) {
                    $nonStandardGuardPtr = $this->skipIgnorable($tokens, $ptr);
                }

                if ($nonStandardGuardPtr === null
                    && $this->isLegacyDirectAccessGuardAt($tokens, $ptr)
                ) {
                    $nonStandardGuardPtr = $this->skipIgnorable($tokens, $ptr);
                }

                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_COMMENT) {
                $ptr++;
                continue;
            }

            if ($this->isDocblockOpen($tokens, $ptr)) {
                if ($this->isFileHeaderDocblock($tokens, $ptr)) {
                    $ptr = $this->docblockEnd($tokens, $ptr);
                    continue;
                }

                break;
            }

            break;
        }

        $insertBefore = $this->findGuardInsertPtr($tokens, $lastUseEnd);
        $guardAfterUses = $this->findGuardAtExpectedPosition($tokens, $lastUseEnd, $guardContext);
        $validGuardPtr = $this->findValidGuardInFile($tokens, $guardContext);
        $validAtExpected = ($guardAfterUses !== null
            && !$this->hasUseAfterGuard($tokens, $guardAfterUses));
        $splitGuardPtr = $this->findGuardSplittingDocblock($tokens, $insertBefore, $guardContext);
        $wrongPositionRelocate = null;

        if ($validGuardPtr !== null
            && !$validAtExpected
            && $this->hasUseAfterGuard($tokens, $validGuardPtr)
            && $this->isStandardDirectAccessGuardAt($tokens, $validGuardPtr, $guardContext)
        ) {
            $wrongPositionRelocate = [
                'guard_ptr' => $validGuardPtr,
                'insert_ptr' => $insertBefore,
            ];
        }

        $fixable = ($validGuardPtr === null
            && $nonStandardGuardPtr === null
            && !$this->hasNonPreambleBetween($tokens, $preambleStart, $lastUseEnd));

        return [
            'html_first' => false,
            'expected_guard_ptr' => $insertBefore,
            'insert_before_ptr' => $insertBefore,
            'valid_guard_ptr' => $validGuardPtr,
            'non_standard_guard_ptr' => $nonStandardGuardPtr,
            'valid_guard_at_expected' => $validAtExpected,
            'guard_splits_docblock' => ($splitGuardPtr !== null),
            'split_guard_ptr' => $splitGuardPtr,
            'wrong_position_relocate' => $wrongPositionRelocate,
            'fixable' => $fixable,
            'guard_context' => $guardContext,
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     *
     * @return array<string, bool>
     */
    private function buildGuardContext(array $tokens)
    {
        $importsFunctionDefined = $this->preambleImportsFunctionDefined($tokens);

        return [
            'requires_backslash_defined' => ($this->fileHasNamespace($tokens)
                && !$importsFunctionDefined),
            'imports_function_defined' => $importsFunctionDefined,
        ];
    }

    /**
     * @param array<string, bool> $context
     *
     * @return string
     */
    private function buildGuardLine(array $context)
    {
        $defined = $this->definedFunctionNameForContext($context);

        return $defined . "('ABSPATH') || exit;";
    }

    /**
     * @param array<string, bool> $context
     *
     * @return string
     */
    private function buildHtmlFirstGuard(array $context)
    {
        return '<?php ' . $this->buildGuardLine($context) . "\n?>\n";
    }

    /**
     * @param array<string, bool> $context
     *
     * @return string
     */
    private function formatStandardGuardExample(array $context)
    {
        return $this->buildGuardLine($context);
    }

    /**
     * @param array<string, bool> $context
     *
     * @return string
     */
    private function definedFunctionNameForContext(array $context)
    {
        if (!empty($context['requires_backslash_defined'])) {
            return '\\defined';
        }

        return 'defined';
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     *
     * @return bool
     */
    private function fileHasNamespace(array $tokens)
    {
        $count = count($tokens);
        $ptr = $this->findFirstOpenTag($tokens, 0);

        if ($ptr === false) {
            return false;
        }

        $ptr++;
        $ptr = $this->skipIgnorable($tokens, $ptr);
        $stopCodes = $this->scopeStopCodes();

        while ($ptr < $count) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $count) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_NAMESPACE) {
                return true;
            }

            if ($tokens[$ptr]['code'] === T_DECLARE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($this->isDocblockOpen($tokens, $ptr)) {
                $ptr = $this->docblockEnd($tokens, $ptr);
                continue;
            }

            if (in_array($tokens[$ptr]['code'], $stopCodes, true)) {
                break;
            }

            break;
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     *
     * @return bool
     */
    private function preambleImportsFunctionDefined(array $tokens)
    {
        $count = count($tokens);
        $ptr = $this->findFirstOpenTag($tokens, 0);

        if ($ptr === false) {
            return false;
        }

        $ptr++;
        $ptr = $this->skipIgnorable($tokens, $ptr);
        $stopCodes = $this->scopeStopCodes();

        while ($ptr < $count) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $count) {
                break;
            }

            if (in_array($tokens[$ptr]['code'], $stopCodes, true)) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_DECLARE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_NAMESPACE) {
                $ptr = $this->skipNamespaceStatement($tokens, $ptr);
                continue;
            }

            if ($this->isDocblockOpen($tokens, $ptr)) {
                $ptr = $this->docblockEnd($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_USE) {
                if ($this->useStatementImportsFunctionDefined($tokens, $ptr)) {
                    return true;
                }

                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            break;
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $usePtr
     *
     * @return bool
     */
    private function useStatementImportsFunctionDefined(array $tokens, $usePtr)
    {
        if (!isset($tokens[$usePtr]) || $tokens[$usePtr]['code'] !== T_USE) {
            return false;
        }

        $end = $this->skipStatement($tokens, $usePtr);
        $statement = '';

        for ($i = $usePtr; $i < $end; $i++) {
            $statement .= $tokens[$i]['content'];
        }

        return (preg_match('/\bfunction\s+defined\b/i', $statement) === 1);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $openTagPtr
     *
     * @return int
     */
    private function findFirstPhpBlockEnd(array $tokens, $openTagPtr)
    {
        $count = count($tokens);

        for ($i = ($openTagPtr + 1); $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_INLINE_HTML) {
                return $i;
            }
        }

        return $count;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $start
     * @param int                              $limit
     *
     * @return int|null
     */
    private function findNonStandardGuardBetween(array $tokens, $start, $limit, array $guardContext)
    {
        $ptr = $start;
        $limit = min($limit, count($tokens));
        $stopCodes = $this->scopeStopCodes();

        while ($ptr < $limit) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $limit) {
                break;
            }

            if (in_array($tokens[$ptr]['code'], $stopCodes, true)) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_USE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_IF
                && $this->isAbspathProtectionIfAt($tokens, $ptr)
            ) {
                return $this->skipIgnorable($tokens, $ptr);
            }

            if ($this->tokenIsDefinedFunction($tokens, $ptr)) {
                if (!$this->isStandardDirectAccessGuardAt($tokens, $ptr, $guardContext)
                    && ($this->isNonStandardShortCircuitGuardAt($tokens, $ptr, $guardContext)
                        || $this->isLegacyDirectAccessGuardAt($tokens, $ptr))
                ) {
                    return $this->skipIgnorable($tokens, $ptr);
                }

                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_INLINE_HTML) {
                break;
            }

            break;
        }

        return null;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $start
     *
     * @return int|false
     */
    private function findFirstOpenTag(array $tokens, $start)
    {
        $count = count($tokens);

        for ($i = $start; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_OPEN_TAG) {
                return $i;
            }
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isAbspathProtectionIfAt(array $tokens, $ptr)
    {
        return ($this->isIfStyleDirectAccessGuardAt($tokens, $ptr)
            || $this->isIfWithAbspathAndDieOrExit($tokens, $ptr));
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isIfWithAbspathAndDieOrExit(array $tokens, $ptr)
    {
        $startPtr = $this->skipIgnorable($tokens, $ptr);

        if (!isset($tokens[$startPtr]) || $tokens[$startPtr]['code'] !== T_IF) {
            return false;
        }

        $openParen = $this->skipIgnorable($tokens, $startPtr + 1);

        if (!isset($tokens[$openParen]) || $tokens[$openParen]['code'] !== T_OPEN_PARENTHESIS) {
            return false;
        }

        $conditionEnd = $this->findMatchingParenthesisEnd($tokens, $openParen);

        if ($conditionEnd === false) {
            return false;
        }

        if (!$this->isAbspathUndefinedCondition($tokens, $openParen, $conditionEnd)) {
            return false;
        }

        $bodyPtr = $this->skipIgnorable($tokens, $conditionEnd + 1);

        return $this->isDieOrExitInvocation($tokens, $bodyPtr);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     * @param array<string, bool>              $guardContext
     *
     * @return bool
     */
    private function isStandardDirectAccessGuardAt(array $tokens, $ptr, array $guardContext)
    {
        $definedPtr = $this->resolveDefinedFunctionPtr($tokens, $ptr);

        if ($definedPtr === false) {
            return false;
        }

        $afterDefined = $this->skipDefinedAbspathCall($tokens, $definedPtr);

        if ($afterDefined === false) {
            return false;
        }

        $operatorPtr = $this->skipIgnorable($tokens, $afterDefined);

        if (!isset($tokens[$operatorPtr]) || $tokens[$operatorPtr]['code'] !== T_BOOLEAN_OR) {
            return false;
        }

        $afterOperator = $this->skipIgnorable($tokens, $operatorPtr + 1);

        if (!$this->isBareExitStatement($tokens, $afterOperator)) {
            return false;
        }

        return $this->definedCallMatchesContext($tokens, $definedPtr, $guardContext);
    }

    /**
     * `\defined('ABSPATH') || exit` when `use function defined` is already imported.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     * @param array<string, bool>              $guardContext
     *
     * @return bool
     */
    private function isFullyQualifiedDefinedAfterImport(array $tokens, $ptr, array $guardContext)
    {
        if (empty($guardContext['imports_function_defined'])) {
            return false;
        }

        $qualifiedContext = $guardContext;
        $qualifiedContext['requires_backslash_defined'] = true;

        return $this->isStandardDirectAccessGuardAt($tokens, $ptr, $qualifiedContext);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     * @param array<string, bool>              $guardContext
     *
     * @return bool
     */
    private function isNonStandardShortCircuitGuardAt(array $tokens, $ptr, array $guardContext)
    {
        if ($this->isStandardDirectAccessGuardAt($tokens, $ptr, $guardContext)) {
            return false;
        }

        $definedPtr = $this->resolveDefinedFunctionPtr($tokens, $ptr);

        if ($definedPtr === false) {
            return false;
        }

        $afterDefined = $this->skipDefinedAbspathCall($tokens, $definedPtr);

        if ($afterDefined === false) {
            return false;
        }

        $operatorPtr = $this->skipIgnorable($tokens, $afterDefined);

        if (!isset($tokens[$operatorPtr]) || !$this->tokenIsLogicalOr($tokens[$operatorPtr])) {
            return false;
        }

        $afterOperator = $this->skipIgnorable($tokens, $operatorPtr + 1);

        return ($this->tokenIsDieOrExitCall($tokens, $afterOperator)
            || $this->isBareExitStatement($tokens, $afterOperator));
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $definedPtr
     * @param array<string, bool>              $guardContext
     *
     * @return bool
     */
    private function definedCallMatchesContext(array $tokens, $definedPtr, array $guardContext)
    {
        $usesGlobalDefined = $this->definedCallUsesGlobalNamespace($tokens, $definedPtr);

        if (!empty($guardContext['requires_backslash_defined'])) {
            return $usesGlobalDefined;
        }

        return !$usesGlobalDefined;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isLegacyDirectAccessGuardAt(array $tokens, $ptr)
    {
        $definedPtr = $this->resolveDefinedFunctionPtr($tokens, $ptr);

        if ($definedPtr === false) {
            return false;
        }

        $afterDefined = $this->skipDefinedAbspathCall($tokens, $definedPtr);

        if ($afterDefined === false) {
            return false;
        }

        $operatorPtr = $this->skipIgnorable($tokens, $afterDefined);

        if (!isset($tokens[$operatorPtr]) || !$this->tokenIsLogicalOr($tokens[$operatorPtr])) {
            return false;
        }

        $afterOperator = $this->skipIgnorable($tokens, $operatorPtr + 1);

        return $this->tokenIsDieOrExitCall($tokens, $afterOperator);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function tokenIsDefinedFunction(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        if (!$this->isStatementLevelExpressionStart($tokens, $ptr)) {
            return false;
        }

        return ($this->resolveDefinedFunctionPtr($tokens, $ptr) !== false);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int|false
     */
    private function resolveDefinedFunctionPtr(array $tokens, $ptr)
    {
        $ptr = $this->skipIgnorable($tokens, $ptr);

        if (!isset($tokens[$ptr])) {
            return false;
        }

        if ($tokens[$ptr]['code'] === T_NAME_FULLY_QUALIFIED
            && preg_match('/^\\\\?defined$/i', $tokens[$ptr]['content']) === 1
        ) {
            return $ptr;
        }

        if ($tokens[$ptr]['code'] === T_NS_SEPARATOR) {
            $next = $this->skipIgnorable($tokens, $ptr + 1);

            if (isset($tokens[$next])
                && $tokens[$next]['code'] === T_STRING
                && strtolower($tokens[$next]['content']) === 'defined'
            ) {
                return $next;
            }

            return false;
        }

        if ($tokens[$ptr]['code'] === T_STRING
            && strtolower($tokens[$ptr]['content']) === 'defined'
        ) {
            return $ptr;
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $definedPtr
     *
     * @return bool
     */
    private function definedCallUsesGlobalNamespace(array $tokens, $definedPtr)
    {
        if ($tokens[$definedPtr]['code'] === T_NAME_FULLY_QUALIFIED) {
            return (strpos($tokens[$definedPtr]['content'], '\\') === 0);
        }

        $previous = ($definedPtr - 1);

        while ($previous >= 0 && isset(Tokens::$emptyTokens[$tokens[$previous]['code']])) {
            $previous--;
        }

        return ($previous >= 0 && $tokens[$previous]['code'] === T_NS_SEPARATOR);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $definedPtr
     *
     * @return int|false
     */
    private function skipDefinedAbspathCall(array $tokens, $definedPtr)
    {
        $openParen = $this->skipIgnorable($tokens, $definedPtr + 1);

        if (!isset($tokens[$openParen]) || $tokens[$openParen]['code'] !== T_OPEN_PARENTHESIS) {
            return false;
        }

        $closeParen = $this->findMatchingParenthesisEnd($tokens, $openParen);

        if ($closeParen === false) {
            return false;
        }

        $argument = '';

        for ($i = ($openParen + 1); $i < $closeParen; $i++) {
            $argument .= $tokens[$i]['content'];
        }

        $normalized = preg_replace('/\s+/', '', $argument);

        if (!preg_match('/^[\'"]ABSPATH[\'"]$/', $normalized)) {
            return false;
        }

        return $closeParen + 1;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isStatementLevelExpressionStart(array $tokens, $ptr)
    {
        $previous = ($ptr - 1);

        while ($previous >= 0) {
            if (isset(Tokens::$emptyTokens[$tokens[$previous]['code']])) {
                $previous--;
                continue;
            }

            break;
        }

        if ($previous < 0) {
            return true;
        }

        return !in_array($tokens[$previous]['code'], [T_OBJECT_OPERATOR, T_DOUBLE_COLON], true);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isDieOrExitInvocation(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        if ($tokens[$ptr]['code'] === T_EXIT) {
            return true;
        }

        if ($tokens[$ptr]['code'] === T_STRING
            && strtolower($tokens[$ptr]['content']) === 'die'
        ) {
            return true;
        }

        if ($tokens[$ptr]['code'] !== T_OPEN_CURLY_BRACKET) {
            return false;
        }

        $inner = $this->skipIgnorable($tokens, $ptr + 1);

        if (!isset($tokens[$inner])) {
            return false;
        }

        if ($tokens[$inner]['code'] === T_EXIT) {
            return true;
        }

        return ($tokens[$inner]['code'] === T_STRING
            && strtolower($tokens[$inner]['content']) === 'die');
    }

    /**
     * @param array<int, array<string, mixed>> $token
     *
     * @return bool
     */
    private function tokenIsLogicalOr(array $token)
    {
        return ($token['code'] === T_LOGICAL_OR || $token['code'] === T_BOOLEAN_OR);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function tokenIsDieOrExitCall(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        if ($tokens[$ptr]['code'] === T_EXIT) {
            return true;
        }

        return ($tokens[$ptr]['code'] === T_STRING
            && strtolower($tokens[$ptr]['content']) === 'die');
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int|null
     */
    private function findValidGuardInFile(array $tokens, array $guardContext)
    {
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            if ($this->tokenIsDefinedFunction($tokens, $i)
                && $this->isStandardDirectAccessGuardAt($tokens, $i, $guardContext)
            ) {
                return $i;
            }
        }

        return null;
    }

    /**
     * Where a missing guard is inserted.
     *
     * The file header docblock stays above the guard. A docblock on the next
     * class, interface, trait, or function stays below it.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $lastUseEnd
     *
     * @return int
     */
    private function findGuardInsertPtr(array $tokens, $lastUseEnd)
    {
        $count = count($tokens);
        $ptr = $this->skipWhitespaceAndInlineComments($tokens, $lastUseEnd);
        $ptr = $this->rewindToStructureDocblockIfNeeded($tokens, $ptr);

        while ($ptr < $count && $this->isDocblockOpen($tokens, $ptr)) {
            if ($this->isStructureDocblock($tokens, $ptr) && !$this->isFileHeaderDocblock($tokens, $ptr)) {
                return $ptr;
            }

            $ptr = $this->docblockEnd($tokens, $ptr);
            $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);
        }

        if ($this->isStructureKeyword($tokens, $ptr)
            || $this->tokenIsStructureDeclaration($tokens, $ptr)
        ) {
            $docblockPtr = $this->findStructureDocblockImmediatelyBefore($tokens, $ptr);

            if ($docblockPtr !== null && !$this->isFileHeaderDocblock($tokens, $docblockPtr)) {
                return $docblockPtr;
            }
        }

        if ($ptr >= $count) {
            return max(0, $count - 1);
        }

        return $ptr;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $insertPtr
     *
     * @return int
     */
    /**
     * Global files whose first code is a structure docblock need the guard after the open tag.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $insertPtr
     *
     * @return bool
     */
    private function shouldInsertGuardAfterOpenTag(array $tokens, $insertPtr)
    {
        if ($this->fileHasNamespace($tokens)) {
            return false;
        }

        if ($this->isDocblockOpen($tokens, $insertPtr)
            && $this->isStructureDocblock($tokens, $insertPtr)
            && !$this->isFileHeaderDocblock($tokens, $insertPtr)
        ) {
            return true;
        }

        if ($this->isStructureKeyword($tokens, $insertPtr)
            || $this->tokenIsStructureDeclaration($tokens, $insertPtr)
        ) {
            $docblockPtr = $this->findStructureDocblockImmediatelyBefore($tokens, $insertPtr);

            return ($docblockPtr !== null
                && !$this->isFileHeaderDocblock($tokens, $docblockPtr));
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $lastUseEnd
     *
     * @return int|null
     */
    private function findGuardAtExpectedPosition(array $tokens, $lastUseEnd, array $guardContext)
    {
        $count = count($tokens);
        $ptr = $this->skipWhitespaceAndInlineComments($tokens, $lastUseEnd);

        while ($ptr < $count && $this->isDocblockOpen($tokens, $ptr)) {
            if ($this->isStructureDocblock($tokens, $ptr) && !$this->isFileHeaderDocblock($tokens, $ptr)) {
                return null;
            }

            $ptr = $this->docblockEnd($tokens, $ptr);
            $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);
        }

        if ($ptr < $count && $this->isStandardDirectAccessGuardAt($tokens, $ptr, $guardContext)) {
            return $ptr;
        }

        return null;
    }

    /**
     * Guard sitting between a structure docblock and that structure.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $insertPtr
     * @param array<string, bool>              $guardContext
     *
     * @return int|null
     */
    private function findGuardSplittingDocblock(array $tokens, $insertPtr, array $guardContext)
    {
        if (!$this->isDocblockOpen($tokens, $insertPtr)
            || !$this->isStructureDocblock($tokens, $insertPtr)
            || $this->isFileHeaderDocblock($tokens, $insertPtr)
        ) {
            return null;
        }

        $ptr = $this->docblockEnd($tokens, $insertPtr);
        $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);

        if (!$this->isStandardDirectAccessGuardAt($tokens, $ptr, $guardContext)
            && !$this->isIfStyleDirectAccessGuardAt($tokens, $ptr)
        ) {
            return null;
        }

        $afterGuard = $this->endOfGuardStatement($tokens, $ptr);
        $afterGuard = $this->skipWhitespaceAndInlineComments($tokens, $afterGuard);
        $afterGuard = $this->skipDeclarationModifiers($tokens, $afterGuard);

        if (!$this->isStructureKeyword($tokens, $afterGuard)) {
            return null;
        }

        return $ptr;
    }

    /**
     * @param \PHP_CodeSniffer\Files\File $phpcsFile
     * @param int                         $guardPtr
     * @param int                         $docblockPtr
     *
     * @return void
     */
    private function relocateGuardBeforeDocblock(File $phpcsFile, $guardPtr, $docblockPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $end = $this->endOfGuardStatement($tokens, $guardPtr);
        $chunk = '';

        for ($i = $guardPtr; $i < $end; $i++) {
            $chunk .= $tokens[$i]['content'];
        }

        $after = $end;
        $collapseAfter = (isset($tokens[$after])
            && $tokens[$after]['code'] === T_WHITESPACE
            && preg_match('/\A(?:\r\n|\n|\r)+([ \t]*)\z/', $tokens[$after]['content'], $matches) === 1);
        $before = $guardPtr - 1;

        $phpcsFile->fixer->beginChangeset();

        for ($i = $guardPtr; $i < $end; $i++) {
            $phpcsFile->fixer->replaceToken($i, '');
        }

        if ($collapseAfter) {
            $phpcsFile->fixer->replaceToken($after, $phpcsFile->eolChar . $matches[1]);

            if ($before >= 0
                && isset($tokens[$before])
                && $tokens[$before]['code'] === T_WHITESPACE
            ) {
                $phpcsFile->fixer->replaceToken($before, '');
            }
        }

        $phpcsFile->fixer->addContentBefore(
            $docblockPtr,
            rtrim($chunk) . $phpcsFile->eolChar . $phpcsFile->eolChar
        );
        $phpcsFile->fixer->endChangeset();
    }

    /**
     * @param \PHP_CodeSniffer\Files\File $phpcsFile
     * @param int                         $guardPtr
     * @param int                         $insertBeforePtr
     *
     * @return void
     */
    private function relocateGuardAfterUses(File $phpcsFile, $guardPtr, $insertBeforePtr)
    {
        $tokens = $phpcsFile->getTokens();
        $end = $this->endOfGuardStatement($tokens, $guardPtr);
        $chunk = '';

        for ($i = $guardPtr; $i < $end; $i++) {
            $chunk .= $tokens[$i]['content'];
        }

        $after = $end;
        $collapseAfter = (isset($tokens[$after])
            && $tokens[$after]['code'] === T_WHITESPACE
            && preg_match('/\A(?:\r\n|\n|\r)+([ \t]*)\z/', $tokens[$after]['content'], $matches) === 1);
        $before = $guardPtr - 1;

        $phpcsFile->fixer->beginChangeset();

        for ($i = $guardPtr; $i < $end; $i++) {
            $phpcsFile->fixer->replaceToken($i, '');
        }

        if ($collapseAfter) {
            $phpcsFile->fixer->replaceToken($after, $phpcsFile->eolChar . $matches[1]);

            if ($before >= 0
                && isset($tokens[$before])
                && $tokens[$before]['code'] === T_WHITESPACE
            ) {
                $phpcsFile->fixer->replaceToken($before, '');
            }
        }

        $phpcsFile->fixer->addContentBefore(
            $insertBeforePtr,
            rtrim($chunk) . $phpcsFile->eolChar . $phpcsFile->eolChar
        );
        $phpcsFile->fixer->endChangeset();
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $guardPtr
     *
     * @return int
     */
    private function endOfGuardStatement(array $tokens, $guardPtr)
    {
        $end = $this->skipStatement($tokens, $guardPtr);
        $count = count($tokens);
        $guardLine = $tokens[$guardPtr]['line'];

        while ($end < $count && $tokens[$end]['code'] === T_WHITESPACE) {
            if (strpos($tokens[$end]['content'], "\n") !== false
                || strpos($tokens[$end]['content'], "\r") !== false
            ) {
                break;
            }

            $end++;
        }

        if ($end < $count
            && $tokens[$end]['code'] === T_COMMENT
            && $tokens[$end]['line'] === $guardLine
        ) {
            $end++;
        }

        return $end;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isDocblockOpen(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        return in_array($tokens[$ptr]['code'], [T_DOC_COMMENT_OPEN_TAG, T_DOC_COMMENT], true);
    }

    /**
     * When the preamble ends on a structure keyword, point at its docblock instead.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function rewindToStructureDocblockIfNeeded(array $tokens, $ptr)
    {
        if (!$this->isStructureKeyword($tokens, $ptr)
            && !$this->tokenIsStructureDeclaration($tokens, $ptr)
        ) {
            return $ptr;
        }

        $docblockPtr = $this->findStructureDocblockImmediatelyBefore($tokens, $ptr);

        if ($docblockPtr === null) {
            return $ptr;
        }

        return $docblockPtr;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $structurePtr
     *
     * @return int|null
     */
    private function findStructureDocblockImmediatelyBefore(array $tokens, $structurePtr)
    {
        for ($ptr = ($structurePtr - 1); $ptr >= 0; $ptr--) {
            if (!$this->isDocblockOpen($tokens, $ptr)) {
                continue;
            }

            if ($this->isStructureDocblock($tokens, $ptr)) {
                return $ptr;
            }

            return null;
        }

        return null;
    }

    /**
     * First docblock in the file, before namespace or other code.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isFileHeaderDocblock(array $tokens, $ptr)
    {
        if (!$this->isDocblockOpen($tokens, $ptr)) {
            return false;
        }

        $count = count($tokens);
        $first = null;

        for ($i = 0; $i < $count; $i++) {
            if ($this->isDocblockOpen($tokens, $i)) {
                $first = $i;
                break;
            }
        }

        if ($first !== $ptr) {
            return false;
        }

        for ($i = 0; $i < $ptr; $i++) {
            $code = $tokens[$i]['code'];

            if ($code === T_OPEN_TAG || $code === T_WHITESPACE || $code === T_COMMENT) {
                continue;
            }

            if ($code === T_DECLARE) {
                $i = $this->skipStatement($tokens, $i) - 1;
                continue;
            }

            return false;
        }

        $after = $this->docblockEnd($tokens, $ptr);
        $after = $this->skipWhitespaceAndInlineComments($tokens, $after);
        $after = $this->skipDeclarationModifiers($tokens, $after);

        if ($this->isStructureKeyword($tokens, $after)
            || $this->tokenIsStructureDeclaration($tokens, $after)
        ) {
            return $this->docblockLooksLikeFileHeader($tokens, $ptr);
        }

        return true;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function docblockLooksLikeFileHeader(array $tokens, $ptr)
    {
        $end = $this->docblockEnd($tokens, $ptr);
        $content = '';

        for ($i = $ptr; $i < $end; $i++) {
            $content .= $tokens[$i]['content'];
        }

        return (preg_match('/\bPlugin\s+Name\s*:/i', $content) === 1
            || preg_match('/\bCopyright\b/i', $content) === 1
            || preg_match('/@package\b/i', $content) === 1);
    }

    /**
     * Docblock attached to the following class, interface, trait, or function.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isStructureDocblock(array $tokens, $ptr)
    {
        $after = $this->docblockEnd($tokens, $ptr);
        $after = $this->skipWhitespaceAndInlineComments($tokens, $after);

        if ($this->isStandardDirectAccessGuardAt($tokens, $after, $this->buildGuardContext($tokens))
            || $this->isIfStyleDirectAccessGuardAt($tokens, $after)
        ) {
            $after = $this->endOfGuardStatement($tokens, $after);
            $after = $this->skipWhitespaceAndInlineComments($tokens, $after);
        }

        $after = $this->skipDeclarationModifiers($tokens, $after);

        if ($this->isStructureKeyword($tokens, $after)) {
            return true;
        }

        return $this->tokenIsStructureDeclaration($tokens, $after);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int Index of the first token after the docblock.
     */
    private function docblockEnd(array $tokens, $ptr)
    {
        if (isset($tokens[$ptr]['comment_closer'])) {
            return $tokens[$ptr]['comment_closer'] + 1;
        }

        $count = count($tokens);

        for ($i = $ptr; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_DOC_COMMENT_CLOSE_TAG) {
                return $i + 1;
            }
        }

        return $count;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function skipWhitespaceAndInlineComments(array $tokens, $ptr)
    {
        $count = count($tokens);

        while ($ptr < $count
            && ($tokens[$ptr]['code'] === T_WHITESPACE || $tokens[$ptr]['code'] === T_COMMENT)
        ) {
            $ptr++;
        }

        return $ptr;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function skipDeclarationModifiers(array $tokens, $ptr)
    {
        $count = count($tokens);

        while ($ptr < $count) {
            $code = $tokens[$ptr]['code'];

            if ($code === T_ABSTRACT
                || $code === T_FINAL
                || (defined('T_READONLY') && $code === T_READONLY)
            ) {
                $ptr++;
                $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);
                continue;
            }

            if (defined('T_ATTRIBUTE') && $code === T_ATTRIBUTE) {
                if (!isset($tokens[$ptr]['attribute_closer'])) {
                    break;
                }

                $ptr = $tokens[$ptr]['attribute_closer'] + 1;
                $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);
                continue;
            }

            break;
        }

        return $ptr;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isStructureKeyword(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        $name = Tokens::tokenName($tokens[$ptr]['code']);
        $keywords = [
            'T_CLASS',
            'T_INTERFACE',
            'T_TRAIT',
            'T_FUNCTION',
            'T_CLOSURE',
            'T_FN',
        ];

        if (defined('T_ENUM')) {
            $keywords[] = 'T_ENUM';
        }

        if (in_array($name, $keywords, true)) {
            return true;
        }

        return $this->tokenIsStructureDeclaration($tokens, $ptr);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function tokenIsStructureDeclaration(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        if ($tokens[$ptr]['code'] !== T_STRING) {
            return false;
        }

        return in_array(strtolower($tokens[$ptr]['content']), ['class', 'interface', 'trait'], true);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $guardPtr
     *
     * @return bool
     */
    private function hasUseAfterGuard(array $tokens, $guardPtr)
    {
        $count = count($tokens);
        $stopCodes = $this->scopeStopCodes();

        for ($i = ($guardPtr + 1); $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_USE) {
                return true;
            }

            if (in_array($tokens[$i]['code'], $stopCodes, true)) {
                break;
            }
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $start
     * @param int                              $end
     *
     * @return bool
     */
    private function hasNonPreambleBetween(array $tokens, $start, $end)
    {
        $ptr = $start;
        $end = min($end, count($tokens));

        while ($ptr < $end) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $end) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_USE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_DECLARE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_NAMESPACE) {
                $ptr = $this->skipNamespaceStatement($tokens, $ptr);
                continue;
            }

            if ($this->isDocblockOpen($tokens, $ptr)) {
                $ptr = $this->docblockEnd($tokens, $ptr);
                continue;
            }

            return true;
        }

        return false;
    }

    /**
     * Tokens that end the file preamble. A `use` inside a closure imports
     * variables, not a namespace.
     *
     * @return int[]
     */
    private function scopeStopCodes()
    {
        return [
            T_CLASS,
            T_INTERFACE,
            T_TRAIT,
            T_FUNCTION,
            T_CLOSURE,
            T_FN,
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function skipIgnorable(array $tokens, $ptr)
    {
        $count = count($tokens);

        while ($ptr < $count && isset(Tokens::$emptyTokens[$tokens[$ptr]['code']])) {
            $ptr++;
        }

        return $ptr;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function skipStatement(array $tokens, $ptr)
    {
        $count = count($tokens);
        $depth = 0;
        $started = false;

        for ($i = $ptr; $i < $count; $i++) {
            $code = $tokens[$i]['code'];

            if ($code === T_OPEN_CURLY_BRACKET) {
                $depth++;
                $started = true;
            } elseif ($code === T_CLOSE_CURLY_BRACKET) {
                $depth--;

                if ($depth === 0 && $started) {
                    return $i + 1;
                }
            } elseif ($code === T_SEMICOLON && $depth === 0) {
                return $i + 1;
            }
        }

        return $count;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function skipNamespaceStatement(array $tokens, $ptr)
    {
        $count = count($tokens);
        $bracePtr = false;

        for ($i = $ptr; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_OPEN_CURLY_BRACKET) {
                $bracePtr = $i;
                break;
            }

            if ($tokens[$i]['code'] === T_SEMICOLON) {
                return $i + 1;
            }
        }

        if ($bracePtr === false) {
            return $this->skipStatement($tokens, $ptr);
        }

        return $bracePtr + 1;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isIfStyleDirectAccessGuardAt(array $tokens, $ptr)
    {
        $ptr = $this->skipIgnorable($tokens, $ptr);

        if (!isset($tokens[$ptr]) || $tokens[$ptr]['code'] !== T_IF) {
            return false;
        }

        $openParen = $this->skipIgnorable($tokens, $ptr + 1);

        if (!isset($tokens[$openParen]) || $tokens[$openParen]['code'] !== T_OPEN_PARENTHESIS) {
            return false;
        }

        $conditionEnd = $this->findMatchingParenthesisEnd($tokens, $openParen);

        if ($conditionEnd === false) {
            return false;
        }

        if (!$this->isAbspathUndefinedCondition($tokens, $openParen, $conditionEnd)) {
            return false;
        }

        $bodyPtr = $this->skipIgnorable($tokens, $conditionEnd + 1);

        if (!isset($tokens[$bodyPtr])) {
            return false;
        }

        if ($tokens[$bodyPtr]['code'] === T_EXIT
            && $this->isBareExitStatement($tokens, $bodyPtr)
        ) {
            return true;
        }

        if ($tokens[$bodyPtr]['code'] !== T_OPEN_CURLY_BRACKET) {
            return false;
        }

        $inner = $this->skipIgnorable($tokens, $bodyPtr + 1);

        if (!isset($tokens[$inner]) || $tokens[$inner]['code'] !== T_EXIT) {
            return false;
        }

        if (!$this->isBareExitStatement($tokens, $inner)) {
            return false;
        }

        $afterExit = $this->skipIgnorable($tokens, $inner + 2);

        return (isset($tokens[$afterExit])
            && $tokens[$afterExit]['code'] === T_CLOSE_CURLY_BRACKET);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $openParenPtr
     *
     * @return int|false
     */
    private function findMatchingParenthesisEnd(array $tokens, $openParenPtr)
    {
        if (!isset($tokens[$openParenPtr]) || $tokens[$openParenPtr]['code'] !== T_OPEN_PARENTHESIS) {
            return false;
        }

        $depth = 0;
        $count = count($tokens);

        for ($i = $openParenPtr; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_OPEN_PARENTHESIS) {
                $depth++;
            } elseif ($tokens[$i]['code'] === T_CLOSE_PARENTHESIS) {
                $depth--;

                if ($depth === 0) {
                    return $i;
                }
            }
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $openParenPtr
     * @param int                              $closeParenPtr
     *
     * @return bool
     */
    private function isAbspathUndefinedCondition(array $tokens, $openParenPtr, $closeParenPtr)
    {
        $slice = '';

        for ($i = ($openParenPtr + 1); $i < $closeParenPtr; $i++) {
            $slice .= $tokens[$i]['content'];
        }

        $normalized = preg_replace('/\s+/', '', $slice);

        return (bool) preg_match(
            '/^!\\\\?defined\([\'"]ABSPATH[\'"]\)$/',
            $normalized
        );
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $exitPtr
     *
     * @return bool
     */
    private function isBareExitStatement(array $tokens, $exitPtr)
    {
        if (!isset($tokens[$exitPtr]) || $tokens[$exitPtr]['code'] !== T_EXIT) {
            return false;
        }

        $next = $exitPtr + 1;

        if (!isset($tokens[$next])) {
            return false;
        }

        if ($tokens[$next]['code'] === T_SEMICOLON) {
            return true;
        }

        if ($tokens[$next]['code'] === T_OPEN_PARENTHESIS) {
            return false;
        }

        return false;
    }
}
