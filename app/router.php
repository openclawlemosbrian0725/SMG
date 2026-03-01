<?php
declare(strict_types=1);

function route(string $method, string $path, callable|string $handler): void {
  static $routes = [];
  $routes[] = [$method, $path, $handler];
  $GLOBALS['__routes'] = $routes;
}

function dispatch(string $method, string $uriPath): void {
  $routes = $GLOBALS['__routes'] ?? [];
  foreach ($routes as [$m, $p, $h]) {
    if ($m === $method && $p === $uriPath) {
      if (is_string($h) && str_contains($h, '::')) {
        [$cls, $fn] = explode('::', $h, 2);
        $cls::$fn();
        return;
      }
      $h();
      return;
    }
  }
  http_response_code(404);
  echo "Not Found";
}
