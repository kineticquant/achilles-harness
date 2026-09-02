import { buildApiGraph, extractHttpHits, normalizePath, pathsMatch } from './httpRoutes';

describe('normalizePath', () => {
  it('keeps pathname from a URL and collapses params', () => {
    expect(normalizePath('https://api.example.com/v1/users/${id}')).toBe('/v1/users/:param');
    expect(normalizePath('/messages/:id?foo=1')).toBe('/messages/:param');
  });
});

describe('pathsMatch', () => {
  it('matches params and trailing suffixes', () => {
    expect(pathsMatch('/v1/users/:param', '/users/12')).toBe(true);
    expect(pathsMatch('/api/messages', '/internal/api/messages')).toBe(true);
    expect(pathsMatch('/login', '/logout')).toBe(false);
  });
});

describe('extractHttpHits', () => {
  it('finds fetch and a Flask route', () => {
    const client = extractHttpHits(
      `async function submit() {\n  await fetch('/api/messages', { method: 'POST' });\n}\n`,
      'app/javascript/composer.js'
    );
    const server = extractHttpHits(
      `@app.route("/api/messages", methods=["POST"])\ndef create_message():\n    return "ok"\n`,
      'api/routes.py'
    );
    expect(client.some((hit) => hit.role === 'client' && hit.path === '/api/messages')).toBe(true);
    expect(server.some((hit) => hit.role === 'server' && hit.path === '/api/messages')).toBe(true);
  });
});

describe('buildApiGraph', () => {
  it('links a frontend function to a matching handler', () => {
    const graph = buildApiGraph({
      focus: 'submit',
      file: 'ui/composer.js',
      filesAnalyzed: 2,
      hits: [
        {
          method: 'POST',
          path: '/api/messages',
          file: 'ui/composer.js',
          line: 4,
          fn: 'submit',
          role: 'client',
        },
        {
          method: 'POST',
          path: '/api/messages',
          file: 'api/routes.py',
          line: 8,
          fn: 'create_message',
          role: 'server',
        },
      ],
    });
    expect(graph.found).toBe(true);
    expect(graph.nodes.some((node) => node.kind === 'api')).toBe(true);
    expect(graph.nodes.some((node) => node.name === 'create_message')).toBe(true);
    expect(graph.edges.length).toBeGreaterThanOrEqual(2);
  });

  it('maps every HTTP call in the file, not one function', () => {
    const graph = buildApiGraph({
      focus: 'offline',
      file: 'ui/composer.js',
      filesAnalyzed: 1,
      hits: [
        {
          method: 'GET',
          path: '/api/status',
          file: 'ui/composer.js',
          line: 4,
          fn: 'connect',
          role: 'client',
        },
        {
          method: 'POST',
          path: '/api/messages',
          file: 'ui/composer.js',
          line: 20,
          fn: 'submit',
          role: 'client',
        },
      ],
    });
    expect(graph.nodes.some((node) => node.name === 'connect')).toBe(true);
    expect(graph.nodes.some((node) => node.name === 'submit')).toBe(true);
  });

  it('maps the whole workspace when no file filter is set', () => {
    const graph = buildApiGraph({
      focus: 'workspace',
      filesAnalyzed: 2,
      hits: [
        {
          method: 'GET',
          path: '/api/status',
          file: 'ui/a.js',
          line: 1,
          fn: 'ping',
          role: 'client',
        },
        {
          method: 'GET',
          path: '/api/status',
          file: 'ui/b.js',
          line: 2,
          fn: 'health',
          role: 'client',
        },
      ],
    });
    expect(graph.nodes.some((node) => node.name === 'ping')).toBe(true);
    expect(graph.nodes.some((node) => node.name === 'health')).toBe(true);
  });
});
