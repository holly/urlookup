import os

WORDPRESS_PLUGIN_PATTERNS = {
        'Yoast SEO': {
            'html_patterns': [
                '<meta name="generator" content="Yoast SEO',
                '<!-- This site is optimized with the Yoast SEO plugin'
            ],
            'url_patterns': [
                '/wp-content/plugins/wordpress-seo/'
            ]
        },
        'Jetpack': {
            'html_patterns': [
                'jetpack.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/jetpack/'
            ]
        },
        'WooCommerce': {
            'html_patterns': [
                'woocommerce.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/woocommerce/'
            ]
        },
        'Contact Form 7': {
            'html_patterns': [
                'wpcf7.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/contact-form-7/'
            ]
        },
        'Akismet': {
            'html_patterns': [
                'akismet.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/akismet/'
            ]
        },
        'Elementor': {
            'html_patterns': [
                'elementor-frontend.min.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/elementor/'
            ]
        },
        'Wordfence': {
            'html_patterns': [
                'wordfence.min.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/wordfence/'
            ]
        },
        'WP Super Cache': {
            'html_patterns': [
                'wp-cache.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/wp-super-cache/'
            ]
        },
        'All in One SEO Pack': {
            'html_patterns': [
                'aioseo.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/all-in-one-seo-pack/'
            ]
        },
        'Smush': {
            'html_patterns': [
                'smush-lazy-load.min.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/wp-smushit/'
            ]
        },
        'MonsterInsights': {
            'html_patterns': [
                'monsterinsights.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/google-analytics-for-wordpress/'
            ]
        },
        'WPForms': {
            'html_patterns': [
                'wpforms.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/wpforms/'
            ]
        },
        'Redirection': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/redirection/'
            ]
        },
        'Broken Link Checker': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/broken-link-checker/'
            ]
        },
        'Really Simple SSL': {
            'html_patterns': [
                'really-simple-ssl.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/really-simple-ssl/'
            ]
        },
        'Duplicate Post': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/duplicate-post/'
            ]
        },
        'Mailchimp for WordPress': {
            'html_patterns': [
                'mc4wp-form.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/mailchimp-for-wp/'
            ]
        },
        'UpdraftPlus': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/updraftplus/'
            ]
        },
        'WP-Optimize': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/wp-optimize/'
            ]
        },
        'TablePress': {
            'html_patterns': [
                'tablepress.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/tablepress/'
            ]
        },
        'Regenerate Thumbnails': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/regenerate-thumbnails/'
            ]
        },
        'Google XML Sitemaps': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/google-sitemap-generator/'
            ]
        },
        'WordPress Importer': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/wordpress-importer/'
            ]
        },
        'Sucuri Security': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/sucuri-scanner/'
            ]
        },
        'Limit Login Attempts Reloaded': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/limit-login-attempts-reloaded/'
            ]
        },
        'WP Mail SMTP': {
            'html_patterns': [
                'wp-mail-smtp.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/wp-mail-smtp/'
            ]
        },
        'Better Search Replace': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/better-search-replace/'
            ]
        },
        'TinyMCE Advanced': {
            'html_patterns': [
                'tinymce-advanced.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/tinymce-advanced/'
            ]
        },
        'bbPress': {
            'html_patterns': [
                'bbpress.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/bbpress/'
            ]
        },
        'BuddyPress': {
            'html_patterns': [
                'buddypress.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/buddypress/'
            ]
        },
        'EWWW Image Optimizer': {
            'html_patterns': [
                'ewww-image-optimizer.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/ewww-image-optimizer/'
            ]
        },
        'WP Multibyte Patch': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/wp-multibyte-patch/'
            ]
        },
        'All-in-One WP Migration': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/all-in-one-wp-migration/'
            ]
        },
        'Shortcodes Ultimate': {
            'html_patterns': [
                'shortcodes-ultimate.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/shortcodes-ultimate/'
            ]
        },
        'Table of Contents Plus': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/table-of-contents-plus/'
            ]
        },
        'BackWPup': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/backwpup/'
            ]
        },
        'Autoptimize': {
            'html_patterns': [
                'autoptimize.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/autoptimize/'
            ]
        },
        'Advanced Custom Fields': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/advanced-custom-fields/'
            ]
        },
        'WP-PageNavi': {
            'html_patterns': [
                'wp-pagenavi.css',
                'pagenavi-css.css',
            ],
            'url_patterns': [
                '/wp-content/plugins/wp-pagenavi/'
            ]
        },
        'Simple Local Avatars': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/simple-local-avatars/'
            ]
        },
        'WP Fastest Cache': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/wp-fastest-cache/'
            ]
        },
        'AddQuicktag': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/addquicktag/'
            ]
        },
        'Crazy Bone': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/crazy-bone/'
            ]
        },
        'PS Auto Sitemap': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/ps-auto-sitemap/'
            ]
        },
        'Head Cleaner': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/head-cleaner/'
            ]
        },
        'WordPress Popular Posts': {
            'html_patterns': [
                'wordpress-popular-posts.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/wordpress-popular-posts/'
            ]
        },
        'WP External Links': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/wp-external-links/'
            ]
        },
        'Search Regex': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/search-regex/'
            ]
        },
        'WordPress Related Posts': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/wordpress-23-related-posts-plugin/'
            ]
        },
        'Category Order and Taxonomy Terms Order': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/taxonomy-terms-order/'
            ]
        },
        'Post Types Order': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/post-types-order/'
            ]
        },
        'Media File Renamer': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/media-file-renamer/'
            ]
        },
        'WordPress Zero Spam': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/zero-spam/'
            ]
        },
        'Content Aware Sidebars': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/content-aware-sidebars/'
            ]
        },
        'Easy Table of Contents': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/easy-table-of-contents/'
            ]
        },
        'Custom Post Type UI': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/custom-post-type-ui/'
            ]
        },
        'WP User Avatar': {
            'html_patterns': [],
            'url_patterns': [
                '/wp-content/plugins/wp-user-avatar/'
            ]
        },
        'Site Kit by Google': {
            "html_patterns": [ '<meta name="generator" content="Site Kit by Google' ],
            'url_patterns': [
                '/wp-content/plugins/google-site-kit/'
            ]
        },
        'Async JavaScript': {
            "html_patterns": [],
            'url_patterns': [
                '/wp-content/plugins/async-javascript/'
            ]
        },
        'Code Snippets': {
            "html_patterns": [],
            'url_patterns': [
                '/wp-content/plugins/code-snippets/'
            ]
        },
        'Native LazyLoad': {
            "html_patterns": [],
            'url_patterns': [
                '/wp-content/plugins/native-lazyload/'
            ]
        },
        'Native LazyLoad': {
            "html_patterns": [],
            'url_patterns': [
                '/wp-content/plugins/native-lazyload/'
            ]
        },
        'LiteSpeed Cache': {
            "html_patterns": [],
            'url_patterns': [
                '/wp-content/plugins/litespeed-cache/'
            ]
        },
        'WP Advanced PDF': {
            "html_patterns": [
                '/plugins/wp-advanced-pdf/asset/css/front_end.css',
                '/plugins/wp-advanced-pdf/asset/js/ajaxsave.js',
            ],
            'url_patterns': [
                '/wp-content/plugins/wp-advanced-pdf/'
            ]
        },
        'VK All in One Expansion Unit': {
            "html_patterns": [
                "id='vkExUnit_common_style-css'",
            ],
            'url_patterns': [
                '/wp-content/plugins/vk-all-in-one-expansion-unit/'
            ]
        },
        'VK Blocks': {
            "html_patterns": [],
            'url_patterns': [
                '/wp-content/plugins/vk-blocks/'
            ]
        },
        'Easy FancyBox': {
            "html_patterns": [
                'jquery.fancybox.js'
            ],
            'url_patterns': [
                '/wp-content/plugins/easy-fancybox/'
            ]
        },
        'Smart Slider 3': {
            "html_patterns": [],
            'url_patterns': [
                '/wp-content/plugins/smart-slider-3/'
            ]
        },
        'whats-new-genarator': {
            "html_patterns": [
                "class='whatsnew'"
            ],
            'url_patterns': [
                '/wp-content/plugins/whats-new-genarator/'
            ]
        },
        'AddToAny Share Buttons': {
            "html_patterns": [],
            'url_patterns': [
                '/wp-content/plugins/add-to-any/'
            ]
        },
        'Elementor Website Builder': {
            "html_patterns": [
                "id='elementor-frontend-css'",
                "id='elementor-post-5-css'",
                "id='elementor-icons-css'",
                "id='elementor-icons-shared-0-css'",
                "id='elementor-icons-fa-brands-css'"
            ],
            'url_patterns': [
                '/wp-content/plugins/elementor/'
            ]
        }
    }
