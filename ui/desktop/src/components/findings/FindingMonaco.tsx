import { useCallback, useEffect, useRef } from 'react';
import Editor, { type Monaco, type OnMount } from '@monaco-editor/react';
import type { editor } from 'monaco-editor';
import './monacoEnv';

function cssVar(name: string, fallback: string): string {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

function defineAchillesTheme(monaco: Monaco) {
  const dark = document.documentElement.classList.contains('dark');
  monaco.editor.defineTheme('achilles-preview', {
    base: dark ? 'vs-dark' : 'vs',
    inherit: true,
    rules: [],
    colors: {
      'editor.background': cssVar('--color-background-primary', dark ? '#111111' : '#ffffff'),
      'editor.foreground': cssVar('--color-text-primary', dark ? '#e6e6e6' : '#3f434b'),
      'editorLineNumber.foreground': cssVar('--color-text-tertiary', dark ? '#5c5c5c' : '#a7b0b9'),
      'editorLineNumber.activeForeground': cssVar(
        '--color-text-secondary',
        dark ? '#8a8a8a' : '#878787'
      ),
      'editorGutter.background': cssVar('--color-background-primary', dark ? '#111111' : '#ffffff'),
      'editor.selectionBackground': dark ? '#3a3a3a' : '#e3e6ea',
      'editor.inactiveSelectionBackground': dark ? '#2c2c2c' : '#f4f6f7',
      'editorWidget.background': cssVar('--color-background-secondary', dark ? '#1a1a1a' : '#f4f6f7'),
      'editorWidget.border': cssVar('--color-border-primary', dark ? '#2c2c2c' : '#e3e6ea'),
      'editorCursor.foreground': cssVar('--color-text-primary', dark ? '#e6e6e6' : '#3f434b'),
      'editorIndentGuide.background1': cssVar('--color-border-primary', dark ? '#2c2c2c' : '#e3e6ea'),
      'scrollbarSlider.background': dark ? '#3a3a3a88' : '#cbd1d688',
      'scrollbarSlider.hoverBackground': dark ? '#5c5c5c88' : '#a7b0b988',
    },
  });
  monaco.editor.setTheme('achilles-preview');
}

export default function FindingMonaco({
  value,
  language,
  path,
  lineStart,
  lineEnd,
  editable,
  onChange,
  onActiveLine,
}: {
  value: string;
  language: string;
  path: string;
  lineStart?: number | null;
  lineEnd?: number | null;
  editable: boolean;
  onChange?: (value: string) => void;
  onActiveLine?: (line: number) => void;
}) {
  const decorations = useRef<string[]>([]);
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);
  const monacoRef = useRef<Monaco | null>(null);
  const onActiveLineRef = useRef(onActiveLine);
  onActiveLineRef.current = onActiveLine;

  const paintHit = useCallback(
    (instance: editor.IStandaloneCodeEditor, monaco: Monaco) => {
      const start = Math.max(1, lineStart ?? 0);
      if (!lineStart) {
        decorations.current = instance.deltaDecorations(decorations.current, []);
        return;
      }
      const end = Math.max(start, lineEnd ?? start);
      decorations.current = instance.deltaDecorations(decorations.current, [
        {
          range: new monaco.Range(start, 1, end, 1),
          options: {
            isWholeLine: true,
            className: 'finding-hit-line',
            linesDecorationsClassName: 'finding-hit-gutter',
          },
        },
      ]);
      instance.revealLineInCenter(start);
    },
    [lineStart, lineEnd]
  );

  const handleMount: OnMount = (instance, monaco) => {
    editorRef.current = instance;
    monacoRef.current = monaco;
    defineAchillesTheme(monaco);
    paintHit(instance, monaco);
    instance.onDidChangeCursorPosition((event) => {
      onActiveLineRef.current?.(event.position.lineNumber);
    });
    const line = instance.getPosition()?.lineNumber ?? lineStart;
    if (line) onActiveLineRef.current?.(line);
  };

  useEffect(() => {
    const instance = editorRef.current;
    const monaco = monacoRef.current;
    if (!instance || !monaco) return;
    paintHit(instance, monaco);
  }, [lineStart, lineEnd, value, path, paintHit]);

  useEffect(() => {
    editorRef.current?.updateOptions({
      readOnly: !editable,
      domReadOnly: !editable,
      cursorStyle: editable ? 'line' : 'line-thin',
    });
  }, [editable]);

  return (
    <div className="h-full min-h-0">
      <Editor
        height="100%"
        theme="achilles-preview"
        language={language}
        value={value}
        path={`achilles-preview/${path}`}
        loading={null}
        onMount={handleMount}
        onChange={(next) => {
          if (editable && next != null) onChange?.(next);
        }}
        options={{
          readOnly: !editable,
          domReadOnly: !editable,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          fontSize: 12,
          lineHeight: 18,
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
          padding: { top: 8, bottom: 8 },
          glyphMargin: false,
          folding: true,
          lineDecorationsWidth: 10,
          lineNumbersMinChars: 3,
          renderLineHighlight: 'none',
          overviewRulerLanes: 0,
          hideCursorInOverviewRuler: true,
          scrollbar: {
            verticalScrollbarSize: 8,
            horizontalScrollbarSize: 8,
            useShadows: false,
          },
          renderWhitespace: 'none',
          guides: { indentation: false, highlightActiveIndentation: false },
          occurrencesHighlight: 'off',
          matchBrackets: 'never',
          quickSuggestions: false,
          parameterHints: { enabled: false },
          hover: { enabled: 'off' },
          wordBasedSuggestions: 'off',
          renderValidationDecorations: 'off',
          unicodeHighlight: { ambiguousCharacters: false },
          automaticLayout: true,
          cursorStyle: editable ? 'line' : 'line-thin',
        }}
      />
    </div>
  );
}
