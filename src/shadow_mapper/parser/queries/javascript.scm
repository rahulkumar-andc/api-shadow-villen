; Tree-sitter query for JavaScript HTTP client detection
; This file contains S-expression queries for finding API endpoints

; Fetch API calls
(call_expression
  function: (identifier) @func_name
  arguments: (arguments
    (string) @url
  )
  (#eq? @func_name "fetch")
) @fetch_call

; Fetch with template literal
(call_expression
  function: (identifier) @func_name
  arguments: (arguments
    (template_string) @url
  )
  (#eq? @func_name "fetch")
) @fetch_template_call

; Axios calls - axios(config) or axios.get/post/etc
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method
  )
  arguments: (arguments
    (string) @url
  )
  (#eq? @obj "axios")
) @axios_method_call

; Axios with config object
(call_expression
  function: (identifier) @func_name
  arguments: (arguments
    (object
      (pair
        key: (property_identifier) @key
        value: (string) @url
      )
      (#eq? @key "url")
    )
  )
  (#eq? @func_name "axios")
) @axios_config_call

; XMLHttpRequest.open
(call_expression
  function: (member_expression
    property: (property_identifier) @method
  )
  arguments: (arguments
    (string) @http_method
    (string) @url
  )
  (#eq? @method "open")
) @xhr_open_call

; jQuery.ajax
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method
  )
  arguments: (arguments
    (object
      (pair
        key: (property_identifier) @key
        value: (string) @url
      )
      (#eq? @key "url")
    )
  )
  (#match? @obj "^\\$|jQuery$")
  (#eq? @method "ajax")
) @jquery_ajax_call

; API route definitions (Express-style)
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method
  )
  arguments: (arguments
    (string) @route
  )
  (#match? @obj "^(app|router|express)$")
  (#match? @method "^(get|post|put|delete|patch|use|all)$")
) @express_route

; Base URL or API endpoint constants
(variable_declarator
  name: (identifier) @var_name
  value: (string) @value
  (#match? @var_name "(?i)(api|endpoint|base_?url|host|server)")
) @api_constant

; Object with API configuration
(pair
  key: (property_identifier) @key
  value: (string) @value
  (#match? @key "(?i)(url|endpoint|api|base_?url|host)")
) @api_config_property
