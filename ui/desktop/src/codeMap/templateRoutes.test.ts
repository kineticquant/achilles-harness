import { describe, expect, it } from 'vitest';

import { isTemplatePath } from './templatePath';
import {
  buildTemplateGraph,
  extractRenderHits,
  extractTemplateDoc,
  normalizeTemplateName,
  templateFileMatches,
} from './templateRoutes';

describe('normalizeTemplateName', () => {
  it('strips views prefixes', () => {
    expect(normalizeTemplateName('templates/mail/welcome.html')).toBe('mail/welcome.html');
    expect(normalizeTemplateName('users/show')).toBe('users/show');
  });
});

describe('extractRenderHits', () => {
  it('reads Flask render_template context', () => {
    const hits = extractRenderHits(
      `def show():\n    return render_template("users/show.html", user=current_user, posts=posts)\n`,
      'app.py'
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.template).toBe('users/show.html');
    expect(hits[0]?.fn).toBe('show');
    expect(hits[0]?.context).toEqual(expect.arrayContaining(['user', 'posts']));
  });
});

describe('extractTemplateDoc', () => {
  it('finds jinja names and includes', () => {
    const doc = extractTemplateDoc(
      `{% extends "base.html" %}\n<p>{{ user.email }}</p>\n{% for post in posts %}{{ post.title }}{% endfor %}\n`,
      'templates/users/show.html'
    );
    expect(doc.includes).toContain('base.html');
    expect(doc.vars.map((item) => item.name)).toEqual(expect.arrayContaining(['user', 'posts']));
  });
});

describe('buildTemplateGraph', () => {
  it('links a handler to the template and the names it reads', () => {
    const graph = buildTemplateGraph({
      focus: 'show',
      file: 'app.py',
      filesAnalyzed: 2,
      renders: [
        {
          file: 'app.py',
          line: 4,
          fn: 'show',
          template: 'users/show.html',
          context: ['user', 'posts'],
        },
      ],
      templates: [
        {
          file: 'templates/users/show.html',
          vars: [
            { name: 'user', line: 2 },
            { name: 'posts', line: 3 },
          ],
          includes: ['base.html'],
        },
        { file: 'templates/base.html', vars: [], includes: [] },
      ],
    });
    expect(graph.found).toBe(true);
    expect(graph.nodes.some((node) => node.kind === 'template' && node.name === 'users/show.html')).toBe(
      true
    );
    expect(graph.nodes.some((node) => node.name === '{{ user }}')).toBe(true);
  });
});

describe('templateFileMatches', () => {
  it('matches a views path to a render name', () => {
    expect(templateFileMatches('app/views/users/show.html.erb', 'users/show')).toBe(true);
    expect(isTemplatePath('templates/mail/welcome.html')).toBe(true);
    expect(isTemplatePath('app/javascript/controllers/composer.html')).toBe(false);
  });
});
