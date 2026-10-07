<?php

define('PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH', '/path/to/lib/vendor');

require_once PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH . '/publishpress/psr-container/lib/include.php';
require_once PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH . '/publishpress/pimple-pimple/lib/include.php';
include PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH . '/publishpress/foo-bar/lib/include.php';
require PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH . "/publishpress/baz-qux/lib/include.php";
