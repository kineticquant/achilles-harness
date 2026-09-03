import { describe, expect, it } from 'vitest';

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseRailsRoutes } from './railsRoutes';
import { extractNamedRouteRefs, resolveNamedRouteRefs } from './routeHelpers';
import { extractHttpHits, buildApiGraph } from './httpRoutes';

const CAMPFIRE_ROUTES = `
Rails.application.routes.draw do
  resource :session do
    scope module: "sessions" do
      resources :transfers, only: %i[ show update ]
    end
  end

  get "join/:join_code", to: "users#new", as: :join
  post "join/:join_code", to: "users#create"

  resources :users, only: :show do
    scope module: "users" do
      resource :sidebar, only: :show
    end
  end

  namespace :autocompletable do
    resources :users, only: :index
  end

  resources :rooms do
    resources :messages
    scope module: "rooms" do
      resource :refresh, only: :show
    end
  end

  resources :searches, only: %i[ index create ] do
    delete :clear, on: :collection
  end
end
`;

describe('parseRailsRoutes', () => {
  it('expands resources and nested Hotwire routes', () => {
    const routes = parseRailsRoutes(CAMPFIRE_ROUTES, 'config/routes.rb');
    const paths = routes.map((route) => `${route.method} ${route.path} ${route.helper}`);
    expect(paths.some((row) => row.includes('GET /rooms ') && row.includes(' rooms'))).toBe(true);
    expect(routes.some((route) => route.path === '/rooms/:param/messages' && route.helper === 'room_messages')).toBe(
      true
    );
    expect(routes.some((route) => route.path === '/rooms/:param/refresh' && route.helper === 'room_refresh')).toBe(
      true
    );
    expect(routes.some((route) => route.path === '/join/:param' && route.helper === 'join')).toBe(true);
    expect(routes.some((route) => route.path === '/autocompletable/users' && route.helper === 'autocompletable_users')).toBe(
      true
    );
    expect(routes.some((route) => route.path === '/users/:param/sidebar' && route.helper === 'user_sidebar')).toBe(
      true
    );
    expect(routes.some((route) => route.fn === 'rooms#show')).toBe(true);
    expect(routes.some((route) => route.fn === 'rooms/refreshes#show')).toBe(true);
  });

  it('parses the Village Chat routes file', () => {
    const file = path.resolve('H:/village/village-chat/config/routes.rb');
    let source: string;
    try {
      source = readFileSync(file, 'utf8');
    } catch {
      return;
    }
    const routes = parseRailsRoutes(source, 'config/routes.rb');
    expect(routes.length).toBeGreaterThan(40);
    expect(routes.some((route) => route.path === '/rooms/:param/messages')).toBe(true);
  });
});

describe('Hotwire helpers', () => {
  it('links form_with and link_to helpers to expanded routes', () => {
    const named = parseRailsRoutes(CAMPFIRE_ROUTES, 'config/routes.rb');
    const refs = extractNamedRouteRefs(
      `<%= form_with url: room_messages_path(room) do %>\n<%= link_to user_sidebar_path %>\n`,
      'app/views/rooms/show/_composer.html.erb'
    );
    const hits = resolveNamedRouteRefs(refs, named);
    expect(hits.some((hit) => hit.role === 'client' && hit.path === '/rooms/:param/messages')).toBe(true);
    expect(hits.some((hit) => hit.path === '/users/:param/sidebar')).toBe(true);
  });
});

describe('extractHttpHits', () => {
  it('ignores Twitter stub URLs and test files', () => {
    expect(
      extractHttpHits(
        `stub_successful_request url: "https://twitter.com/dhh/status/834146806594433025"\n`,
        'app/models/unfurl.rb'
      ).length
    ).toBe(0);
    expect(
      extractHttpHits(`fetch("/rooms/1")`, 'test/performance/chatter.js').length
    ).toBe(0);
  });

  it('still finds fetch in app JS', () => {
    const hits = extractHttpHits(
      `async function submit() {\n  await fetch('/api/messages', { method: 'POST' });\n}\n`,
      'app/javascript/composer.js'
    );
    expect(hits.some((hit) => hit.path === '/api/messages')).toBe(true);
  });
});

describe('buildApiGraph flow', () => {
  it('draws caller → route → handler', () => {
    const graph = buildApiGraph({
      focus: 'workspace',
      filesAnalyzed: 2,
      hits: [
        {
          method: 'POST',
          path: '/rooms/:param/messages',
          file: 'app/views/rooms/show/_composer.html.erb',
          line: 2,
          fn: '_composer.html.erb',
          role: 'client',
        },
        {
          method: 'POST',
          path: '/rooms/:param/messages',
          file: 'app/controllers/messages_controller.rb',
          line: 8,
          fn: 'messages#create',
          role: 'server',
        },
      ],
    });
    const route = graph.nodes.find((node) => node.kind === 'api');
    const caller = graph.nodes.find((node) => node.kind === 'caller');
    const handler = graph.nodes.find((node) => node.kind === 'callee');
    expect(route && caller && handler).toBeTruthy();
    expect(graph.edges.some((edge) => edge.source === caller?.id && edge.target === route?.id)).toBe(true);
    expect(graph.edges.some((edge) => edge.source === route?.id && edge.target === handler?.id)).toBe(true);
  });
});
