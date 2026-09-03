import { describe, expect, it } from 'vitest';

import { parseLaravelRoutes } from './laravelRoutes';
import { extractNamedRouteRefs, resolveNamedRouteRefs } from './routeHelpers';

const WEB = `
<?php
Route::resource('rooms', RoomController::class);
Route::prefix('api')->group(function () {
    Route::get('/me', [UserController::class, 'show'])->name('me');
    Route::apiResource('messages', MessageController::class);
});
`;

describe('parseLaravelRoutes', () => {
  it('expands resource and prefix groups', () => {
    const routes = parseLaravelRoutes(WEB, 'routes/web.php');
    expect(routes.some((route) => route.path === '/rooms' && route.helper === 'rooms.index')).toBe(true);
    expect(routes.some((route) => route.path === '/rooms/:param' && route.helper === 'rooms.show')).toBe(true);
    expect(routes.some((route) => route.path === '/api/me' && route.helper === 'me')).toBe(true);
    expect(routes.some((route) => route.path === '/api/messages' && route.helper.includes('messages'))).toBe(true);
    expect(routes.every((route) => !route.path.includes('/api/messages/create'))).toBe(true);
  });
});

describe('Blade route() helpers', () => {
  it('resolves route names', () => {
    const named = parseLaravelRoutes(WEB, 'routes/web.php');
    const refs = extractNamedRouteRefs(
      `<form action="{{ route('rooms.store') }}">\n<a href="{{ route('me') }}">`,
      'resources/views/rooms/index.blade.php'
    );
    const hits = resolveNamedRouteRefs(refs, named);
    expect(hits.some((hit) => hit.path === '/rooms')).toBe(true);
    expect(hits.some((hit) => hit.path === '/api/me')).toBe(true);
  });
});
