; Tree-sitter query for Python HTTP client detection

; requests library calls
(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method
  )
  arguments: (argument_list
    (string) @url
  )
  (#eq? @obj "requests")
  (#match? @method "^(get|post|put|delete|patch|head|options)$")
) @requests_call

; httpx library calls
(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method
  )
  arguments: (argument_list
    (string) @url
  )
  (#eq? @obj "httpx")
  (#match? @method "^(get|post|put|delete|patch|head|options)$")
) @httpx_call

; aiohttp session calls
(call
  function: (attribute
    attribute: (identifier) @method
  )
  arguments: (argument_list
    (string) @url
  )
  (#match? @method "^(get|post|put|delete|patch|head|options)$")
) @aiohttp_call

; urllib calls
(call
  function: (attribute
    object: (attribute
      object: (identifier) @mod1
      attribute: (identifier) @mod2
    )
    attribute: (identifier) @method
  )
  arguments: (argument_list
    (string) @url
  )
  (#eq? @mod1 "urllib")
  (#eq? @mod2 "request")
) @urllib_call

; Flask/FastAPI route decorators
(decorated_definition
  (decorator
    (call
      function: (attribute
        attribute: (identifier) @method
      )
      arguments: (argument_list
        (string) @route
      )
      (#match? @method "^(get|post|put|delete|patch|route)$")
    )
  )
) @flask_route

; Django URL patterns
(call
  function: (identifier) @func
  arguments: (argument_list
    (string) @pattern
  )
  (#match? @func "^(path|re_path|url)$")
) @django_url

; API URL constants
(assignment
  left: (identifier) @var_name
  right: (string) @value
  (#match? @var_name "(?i)(api|endpoint|base_?url|host|server)")
) @api_constant
